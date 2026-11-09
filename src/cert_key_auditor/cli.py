"""Command-line interface for ``cert-audit``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import warnings
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from cryptography.utils import CryptographyDeprecationWarning

from . import __version__, censys, keys
from .config import load_config
from .crl import CrlOptions
from .errors import CensysError, CertAuditError, InputError
from .loaders import (
    MAX_INPUT_BYTES,
    LoadResult,
    deduplicate,
    load_certificates,
    load_files,
    normalize_fingerprint,
)
from .models import Severity
from .pdf import PdfLimits, load_pdfs
from .policy import PUBLIC_TLS_MODES, VALIDITY_CONVENTIONS
from .render import (
    COLOR_MODES,
    OUTPUT_FORMATS,
    Palette,
    render_crl_csv,
    render_csv,
    render_json,
    render_sarif,
    render_text,
    resolve_color,
    write_output,
)
from .report import AuditOptions, audit_records

LOGGER = logging.getLogger("cert_key_auditor")

EXIT_CODES_HELP = """\
exit codes:
  0  completed; no findings at or above --fail-on, no errors
  1  at least one finding at or above --fail-on (default: medium)
  2  usage error, or no certificates could be loaded, or a fatal error
  3  completed with non-fatal errors (unreadable inputs, failed steps) and
     no findings at or above --fail-on
  130  interrupted

A clean result only means nothing was found within the bounded checks; it does
not prove a certificate or key is secure.
"""

FAIL_ON_CHOICES = ("never", *(severity.label for severity in Severity))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cert-audit",
        description=(
            "Audit X.509 certificates: weak EC/RSA keys, validity policy, CRL "
            "availability. Sources: Censys fingerprints, local files, PDFs."
        ),
        epilog=EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config", metavar="FILE", help="TOML config file (CLI options override it)"
    )

    src = parser.add_argument_group("inputs")
    src.add_argument(
        "fingerprint",
        nargs="*",
        help="SHA-256 fingerprint(s) to retrieve from Censys (colons allowed)",
    )
    src.add_argument(
        "--fingerprints-file",
        metavar="FILE",
        help="file with one fingerprint per line ('-' for stdin; # comments allowed)",
    )
    src.add_argument(
        "--pem",
        metavar="PATH",
        action="append",
        help="local PEM/DER/PKCS#7 certificate file; '-' reads stdin; repeatable",
    )
    src.add_argument(
        "--population",
        metavar="PATH",
        action="append",
        help="bundle or directory of certificates; enables population analysis; repeatable",
    )
    src.add_argument(
        "--pdf",
        metavar="PATH",
        action="append",
        help="PDF file or directory to extract certificates from (needs the 'pdf' extra); "
        "enables population analysis; repeatable",
    )
    src.add_argument(
        "--token", help="Censys token (prefer the CENSYS_API_TOKEN environment variable)"
    )
    src.add_argument("--organization-id", help="optional Censys organization UUID")
    src.add_argument(
        "--censys-timeout", type=float, default=censys.DEFAULT_TIMEOUT, metavar="SECONDS"
    )
    src.add_argument(
        "--pdf-max-pages",
        type=int,
        default=PdfLimits.max_pages,
        metavar="N",
        help="pages scanned for PEM text per PDF (default %(default)s)",
    )
    src.add_argument(
        "--pdf-max-bytes",
        type=int,
        default=PdfLimits.max_file_bytes,
        metavar="N",
        help="largest PDF accepted (default %(default)s)",
    )

    out = parser.add_argument_group("output")
    out.add_argument(
        "--format",
        "-F",
        choices=OUTPUT_FORMATS,
        default="text",
        help="output format (default: text)",
    )
    out.add_argument(
        "--output", "-o", metavar="FILE", help="write the report to FILE instead of stdout"
    )
    out.add_argument("--crl-csv", metavar="FILE", help="also write one CSV row per CRL result")
    out.add_argument(
        "--color",
        choices=COLOR_MODES,
        default="auto",
        help="colorize text output (honors NO_COLOR/FORCE_COLOR; default: auto)",
    )
    out.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="medium",
        help="lowest severity that makes the exit code 1 (default: medium)",
    )
    out.add_argument("-v", "--verbose", action="count", default=0, help="-v progress, -vv debug")
    out.add_argument("-q", "--quiet", action="store_true", help="only log errors")

    chk = parser.add_argument_group("key checks")
    chk.add_argument(
        "--ec-scalar-limit",
        type=int,
        default=keys.DEFAULT_EC_SCALAR_LIMIT,
        help="largest EC private scalar to test (default %(default)s; "
        "fast baby-step/giant-step on NIST/SEC prime curves)",
    )
    chk.add_argument(
        "--rsa-small-prime-limit",
        type=int,
        default=keys.DEFAULT_RSA_SMALL_PRIME_LIMIT,
        help="largest prime tested as an RSA factor (default %(default)s)",
    )
    chk.add_argument(
        "--known-weak-moduli",
        metavar="FILE",
        help="file of known-weak RSA moduli, one decimal/hex value per line",
    )
    chk.add_argument(
        "--no-roca", dest="roca", action="store_false", help="skip the optional ROCA detector"
    )
    chk.add_argument(
        "--population-analysis",
        action="store_true",
        help="run cross-certificate analysis (shared RSA factors, key reuse) on all inputs",
    )

    pol = parser.add_argument_group("policy")
    pol.add_argument(
        "--public-tls",
        choices=PUBLIC_TLS_MODES,
        default="auto",
        help="apply CA/B maximum-validity rules: auto (non-CA, non-self-signed "
        "serverAuth leaf), yes (every non-CA), no",
    )
    pol.add_argument(
        "--validity-convention",
        choices=VALIDITY_CONVENTIONS,
        default="inclusive",
        help="inclusive counts notBefore and notAfter seconds (default); "
        "elapsed uses the plain difference",
    )
    pol.add_argument(
        "--as-of",
        metavar="ISO8601",
        help="evaluate expiry/staleness as of this date/time (default: now)",
    )

    crl = parser.add_argument_group("CRL retrieval")
    crl.add_argument(
        "--fetch-crl", action="store_true", help="download and inspect advertised CRLs"
    )
    crl.add_argument("--crl-timeout", type=float, default=20.0, metavar="SECONDS")
    crl.add_argument("--crl-max-bytes", type=int, default=20 * 1024 * 1024, metavar="N")
    crl.add_argument(
        "--follow-crl-redirects",
        action="store_true",
        help="follow redirects, re-validating every hop",
    )
    crl.add_argument("--crl-max-redirects", type=int, default=3, metavar="N")
    crl.add_argument(
        "--allow-private-crl-urls",
        action="store_true",
        help="permit non-public CRL hosts (trusted internal PKI only)",
    )
    crl.add_argument(
        "--allow-nonstandard-crl-ports",
        action="store_true",
        help="permit CRL URLs on ports other than 80/443",
    )
    return parser


def _config_path(argv: Sequence[str]) -> str | None:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    known, _ = pre.parse_known_args(list(argv))
    return known.config or os.environ.get("CERT_AUDIT_CONFIG")


def _configure_logging(verbose: int, quiet: bool) -> None:
    level = logging.ERROR if quiet else logging.WARNING
    if verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    logging.basicConfig(
        level=level, stream=sys.stderr, format="%(levelname)s: %(message)s", force=True
    )
    logging.getLogger("pypdf").setLevel(logging.DEBUG if verbose >= 2 else logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def parse_as_of(value: str) -> datetime:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _read_stdin() -> bytes:
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise InputError(f"stdin exceeds the {MAX_INPUT_BYTES:,}-byte limit")
    return data


def _read_fingerprints(path: str) -> list[str]:
    try:
        if path == "-":
            text = _read_stdin().decode("utf-8")
        else:
            text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"{path}: cannot read fingerprint list ({exc})") from exc
    values = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    return [value for value in values if value]


def _validate(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not 1 <= args.ec_scalar_limit <= keys.MAX_EC_SCALAR_LIMIT:
        parser.error(f"--ec-scalar-limit must be between 1 and {keys.MAX_EC_SCALAR_LIMIT:,}")
    if not 2 <= args.rsa_small_prime_limit <= keys.MAX_RSA_SMALL_PRIME_LIMIT:
        parser.error(
            f"--rsa-small-prime-limit must be between 2 and {keys.MAX_RSA_SMALL_PRIME_LIMIT:,}"
        )
    if args.crl_timeout <= 0 or args.censys_timeout <= 0:
        parser.error("timeouts must be positive")
    if args.crl_max_bytes < 1 or args.pdf_max_bytes < 1 or args.pdf_max_pages < 1:
        parser.error("size and page limits must be positive")
    if not 0 <= args.crl_max_redirects <= 10:
        parser.error("--crl-max-redirects must be between 0 and 10")
    if args.fingerprints_file == "-" and "-" in (args.pem or []):
        parser.error("stdin cannot be used for both --fingerprints-file and --pem")
    if not (args.fingerprint or args.fingerprints_file or args.pem or args.population or args.pdf):
        parser.error(
            "no input: give a fingerprint, --fingerprints-file, --pem, --population or --pdf"
        )
    if args.crl_csv and not args.fetch_crl:
        parser.error("--crl-csv requires --fetch-crl")


def _collect_records(args: argparse.Namespace) -> LoadResult:
    """Gather certificates from every input; failures never stop other inputs."""
    result = LoadResult()

    fingerprints = list(args.fingerprint)
    if args.fingerprints_file:
        fingerprints.extend(_read_fingerprints(args.fingerprints_file))
    if fingerprints:
        token = args.token or os.environ.get("CENSYS_API_TOKEN")
        if args.token:
            LOGGER.warning(
                "--token is visible to other local users via the process list; "
                "prefer CENSYS_API_TOKEN"
            )
        if not token:
            raise InputError("Censys lookups need CENSYS_API_TOKEN (or --token)")
        session = censys.build_session()
        try:
            seen: set[str] = set()
            for raw in fingerprints:
                try:
                    fingerprint = normalize_fingerprint(raw)
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    LOGGER.info("fetching %s from Censys", fingerprint)
                    result.records.append(
                        censys.fetch_certificate(
                            fingerprint,
                            token,
                            session=session,
                            timeout=args.censys_timeout,
                            organization_id=args.organization_id,
                        )
                    )
                except (CensysError, InputError) as exc:
                    result.errors.append(str(exc))
        finally:
            session.close()

    for path in args.pem or []:
        if path == "-":
            try:
                result.extend(load_certificates(_read_stdin(), "stdin"))
            except InputError as exc:
                result.errors.append(str(exc))
        else:
            result.extend(load_files([path]))
    if args.population:
        result.extend(load_files(args.population))
    if args.pdf:
        limits = PdfLimits(max_file_bytes=args.pdf_max_bytes, max_pages=args.pdf_max_pages)
        result.extend(load_pdfs(args.pdf, limits))
    result.records = deduplicate(result.records)
    return result


def _options(args: argparse.Namespace) -> AuditOptions:
    return AuditOptions(
        ec_scalar_limit=args.ec_scalar_limit,
        rsa_prime_limit=args.rsa_small_prime_limit,
        known_weak_moduli=frozenset(keys.load_known_weak_moduli(args.known_weak_moduli)),
        check_roca=args.roca,
        fetch_crl=args.fetch_crl,
        crl=CrlOptions(
            timeout=args.crl_timeout,
            max_bytes=args.crl_max_bytes,
            allow_private_urls=args.allow_private_crl_urls,
            allow_any_port=args.allow_nonstandard_crl_ports,
            follow_redirects=args.follow_crl_redirects,
            max_redirects=args.crl_max_redirects,
        ),
        public_tls=args.public_tls,
        validity_convention=args.validity_convention,
        as_of=parse_as_of(args.as_of) if args.as_of else None,
        population=bool(
            args.population or args.pdf or args.fingerprints_file or args.population_analysis
        ),
    )


def run(args: argparse.Namespace) -> int:
    loaded = _collect_records(args)
    # In text mode written to the terminal, input errors appear in the report;
    # otherwise they would be invisible, so surface them on stderr.
    report_has_errors = args.format == "text" and not args.output
    if not report_has_errors:
        for error in loaded.errors:
            LOGGER.warning("%s", error)
    if not loaded.records:
        for error in loaded.errors if report_has_errors else []:
            LOGGER.error("%s", error)
        LOGGER.error("no valid X.509 certificates were loaded")
        return 2
    LOGGER.info("certificates loaded: %d", len(loaded.records))

    options = _options(args)
    audit = audit_records(loaded.records, options, input_errors=loaded.errors)
    audit.fail_on = None if args.fail_on == "never" else Severity.parse(args.fail_on)

    if args.format == "json":
        text = render_json(audit)
    elif args.format == "csv":
        text = render_csv(audit)
    elif args.format == "sarif":
        text = render_sarif(audit)
    else:
        use_color = (
            resolve_color(args.color, sys.stdout) if not args.output else args.color == "always"
        )
        text = render_text(audit, Palette(use_color))

    try:
        write_output(text, args.output)
        if args.crl_csv:
            write_output(render_crl_csv(audit), args.crl_csv)
        sys.stdout.flush()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except OSError as exc:
        LOGGER.error("cannot write output: %s", exc)
        return 2
    return audit.exit_code()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        config_file = _config_path(arguments)
        if config_file:
            parser.set_defaults(**load_config(config_file))
        args = parser.parse_args(arguments)
    except CertAuditError as exc:
        print(f"cert-audit: error: {exc}", file=sys.stderr)
        return 2

    _configure_logging(args.verbose, args.quiet)
    try:
        _validate(parser, args)
        with warnings.catch_warnings():
            # Real-world roots include certificates with non-positive serial numbers.
            # They are reported as SERIAL_INVALID findings, so the library's own
            # per-certificate deprecation warning would only be noise.
            warnings.filterwarnings(
                "ignore",
                message=".*serial number which wasn't positive.*",
                category=CryptographyDeprecationWarning,
            )
            return run(args)
    except KeyboardInterrupt:
        LOGGER.error("interrupted")
        return 130
    except CertAuditError as exc:
        LOGGER.error("%s", exc)
        return 2
    except ValueError as exc:  # e.g. an unparseable --as-of
        LOGGER.error("invalid value: %s", exc)
        return 2
    except Exception as exc:  # last resort: no raw traceback unless -vv
        LOGGER.error(
            "internal error (%s: %s); re-run with -vv for details", type(exc).__name__, exc
        )
        LOGGER.debug("traceback", exc_info=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
