"""Audit pipeline.

``print_certificate_metadata`` builds the :class:`CertificateReport` for one
certificate - identity, validity, key details, validity-period policy *and* CRL
discovery/retrieval - and returns it. ``audit_certificate`` then adds the
key-level checks to the same object, so everything about a certificate lives in
one place and is rendered as a single block.

Error handling: each step runs inside :func:`_step`, which converts any
exception into an entry in ``report.errors``. A malformed extension, an
unsupported key algorithm or a CRL bug therefore degrades one certificate's
report instead of aborting the run.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import IO, Any, TypeVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from . import keys, policy
from .crl import CrlFetcher, CrlOptions, get_crl_distribution_uris
from .errors import CrlError
from .models import (
    CertificateRecord,
    CertificateReport,
    KeyCheck,
    KeyInfo,
    PopulationReport,
    RunReport,
    Severity,
)
from .render import render_certificate_block

LOGGER = logging.getLogger(__name__)
T = TypeVar("T")


@dataclass
class AuditOptions:
    """All behaviour switches for one audit run."""

    ec_scalar_limit: int = keys.DEFAULT_EC_SCALAR_LIMIT
    rsa_prime_limit: int = keys.DEFAULT_RSA_SMALL_PRIME_LIMIT
    known_weak_moduli: frozenset[int] = frozenset()
    check_roca: bool = True
    fetch_crl: bool = False
    crl: CrlOptions = field(default_factory=CrlOptions)
    public_tls: str = "auto"
    validity_convention: str = "inclusive"
    as_of: datetime | None = None
    population: bool = False

    def now(self) -> datetime:
        return self.as_of or datetime.now(UTC)


class AuditContext:
    """Shared state for a run: CRL cache, RSA screen, optional ROCA detector."""

    def __init__(self, options: AuditOptions, records: list[CertificateRecord]) -> None:
        self.options = options
        self.fetcher: CrlFetcher | None = (
            CrlFetcher(options.crl, now=options.now) if options.fetch_crl else None
        )
        rsa_count = sum(1 for r in records if _is_rsa(r))
        self.rsa_screen = keys.SmallPrimeScreen.for_population(options.rsa_prime_limit, rsa_count)
        self.roca_detector: Any = None
        self.roca_error: str | None = None
        if options.check_roca and rsa_count:
            self.roca_detector, self.roca_error = keys.load_roca_detector()

    def close(self) -> None:
        if self.fetcher is not None:
            self.fetcher.close()


def _is_rsa(record: CertificateRecord) -> bool:
    try:
        return isinstance(record.public_key, rsa.RSAPublicKey)
    except Exception:  # unsupported key algorithms are reported later
        return False


def _step(report: CertificateReport, name: str, func: Callable[[], T]) -> T | None:
    """Run one audit step, recording (not raising) any failure."""
    try:
        return func()
    except Exception as exc:  # deliberate: isolate failures per step
        LOGGER.debug("%s: step %r failed", report.source, name, exc_info=True)
        report.errors.append(f"{name}: {type(exc).__name__}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Metadata (+ CRL) collection
# ---------------------------------------------------------------------------


def print_certificate_metadata(
    record: CertificateRecord,
    options: AuditOptions | None = None,
    *,
    context: AuditContext | None = None,
    stream: IO[str] | None = None,
) -> CertificateReport:
    """Collect identifying, validity, policy and CRL metadata for a certificate.

    Returns the :class:`CertificateReport`; CRL results are part of it. The
    historical name is kept for compatibility: nothing is printed unless a
    ``stream`` is given, in which case the certificate's complete text block is
    written to it. Normal runs leave printing to the renderers so that all
    results for a certificate appear together.
    """
    options = options or (context.options if context else AuditOptions())
    certificate = record.certificate
    report = CertificateReport(
        source=record.source,
        sha256=record.fingerprint,
        also_seen_in=list(record.duplicates),
    )

    def identity() -> None:
        report.subject = record.subject
        report.issuer = certificate.issuer.rfc4514_string()
        report.serial_decimal = str(certificate.serial_number)
        report.serial_hex = policy.format_serial_hex(certificate.serial_number)
        report.version = certificate.version.name
        oid = certificate.signature_algorithm_oid
        name = getattr(oid, "_name", "") or ""
        report.signature_algorithm = oid.dotted_string if name.startswith("Unknown") else name
        report.signature_algorithm_oid = oid.dotted_string
        report.signature_hash = policy.signature_hash_name(certificate)
        report.findings.extend(policy.serial_findings(certificate.serial_number))

    def validity() -> None:
        not_before, not_after = policy.validity_bounds(certificate)
        report.not_before, report.not_after = not_before, not_after
        try:
            report.validity_seconds = policy.validity_duration_seconds(certificate)
        except ValueError as exc:
            report.validity_error = str(exc)
        report.findings.extend(policy.time_findings(not_before, not_after, options.now()))

    def usage() -> None:
        report.is_ca = policy.is_ca(certificate)
        report.self_signed = policy.is_self_signed(certificate)
        report.extended_key_usage = policy.extended_key_usage_names(certificate)
        report.san_dns, report.san_ip, report.san_other_count = policy.subject_alt_names(
            certificate
        )

    def public_key() -> None:
        try:
            report.public_key = policy.describe_public_key(record.public_key)
        except Exception as exc:  # unsupported/exotic key algorithms
            report.public_key = KeyInfo(error=f"{type(exc).__name__}: {exc}")
            report.add(
                "PUBLIC_KEY_UNREADABLE",
                Severity.LOW,
                f"public key could not be parsed ({type(exc).__name__})",
            )

    def policies() -> None:
        san_count = len(report.san_dns) + len(report.san_ip) + report.san_other_count
        report.findings.extend(
            policy.algorithm_findings(
                report.public_key, report.signature_hash, self_signed=report.self_signed
            )
        )
        report.findings.extend(
            policy.missing_san_findings(
                ca=report.is_ca,
                self_signed=report.self_signed,
                eku=report.extended_key_usage,
                san_count=san_count,
            )
        )
        if report.validity_error is None:
            result = policy.evaluate_validity_policy(
                certificate,
                mode=options.public_tls,
                convention=options.validity_convention,
            )
            report.validity_policy = result
            report.findings.extend(policy.validity_policy_findings(result))

    for name, step in (
        ("identity", identity),
        ("validity", validity),
        ("usage", usage),
        ("public key", public_key),
        ("policy", policies),
    ):
        _step(report, name, step)
    _step(report, "CRL", lambda: _collect_crls(report, record, context))

    if stream is not None:
        stream.write(render_certificate_block(report))
    return report


def _collect_crls(
    report: CertificateReport,
    record: CertificateRecord,
    context: AuditContext | None,
) -> None:
    """Discover CRL URLs and (when enabled) fetch them into ``report``."""
    try:
        uris = get_crl_distribution_uris(record.certificate)
    except CrlError as exc:
        report.crl_status = "error"
        report.add("CRL_EXTENSION_MALFORMED", Severity.LOW, str(exc))
        return
    report.crl_urls = list(uris.urls)
    report.crl_unsupported_uris = list(uris.unsupported)
    fetcher = context.fetcher if context else None
    if fetcher is None:
        report.crl_status = "not_requested"
        return
    if not uris.urls:
        report.crl_status = "none_advertised"
        if uris.unsupported:
            report.add(
                "CRL_UNSUPPORTED_URI",
                Severity.INFO,
                "CRL advertised only through unsupported URI schemes: "
                + ", ".join(uris.unsupported[:3]),
            )
        return

    for url in uris.urls:
        result = fetcher.fetch_for_certificate(url, record.certificate)
        report.crls.append(result)
        if not result.ok:
            report.add(
                "CRL_FETCH_FAILED",
                Severity.MEDIUM,
                f"CRL retrieval failed for {url}: {result.error}",
                url=url,
                kind=result.error_kind,
            )
            continue
        if result.stale:
            report.add("CRL_STALE", Severity.LOW, f"CRL {url} is past its nextUpdate time", url=url)
        if result.certificate_listed:
            report.add(
                "CERT_LISTED_IN_CRL",
                Severity.HIGH,
                f"certificate serial is listed as revoked in {url} (CRL signature not verified)",
                url=url,
            )
    good = sum(1 for crl in report.crls if crl.ok)
    report.crl_status = "ok" if good == len(report.crls) else "partial" if good else "failed"


# ---------------------------------------------------------------------------
# Key-level checks
# ---------------------------------------------------------------------------


def _check_ec(report: CertificateReport, public_key: Any, options: AuditOptions) -> None:
    outcome = keys.find_small_ec_private_scalar(public_key, options.ec_scalar_limit)
    if outcome.scalar is not None:
        report.key_checks.append(
            KeyCheck(
                "ec_small_scalar",
                "fail",
                f"public key equals {outcome.scalar}*G (private scalar {outcome.scalar})",
                {"scalar": outcome.scalar, "method": outcome.method},
            )
        )
        report.add(
            "EC_SMALL_SCALAR",
            Severity.CRITICAL,
            f"EC public key corresponds to the tiny private scalar {outcome.scalar}; "
            "the private key is publicly derivable",
            scalar=outcome.scalar,
        )
        return
    summary = f"no private scalar in 1..{outcome.searched:,} ({outcome.method})"
    if outcome.note:
        summary += f"; {outcome.note}"
    report.key_checks.append(
        KeyCheck(
            "ec_small_scalar",
            "pass",
            summary,
            {"searched": outcome.searched, "method": outcome.method},
        )
    )


def _check_rsa(
    report: CertificateReport,
    public_key: Any,
    context: AuditContext,
) -> None:
    options = context.options
    modulus = public_key.public_numbers().n

    if options.known_weak_moduli:
        if modulus in options.known_weak_moduli:
            report.key_checks.append(
                KeyCheck("known_weak_modulus", "fail", "modulus is on the supplied weak list")
            )
            report.add(
                "RSA_KNOWN_WEAK",
                Severity.CRITICAL,
                "RSA modulus appears in the supplied known-weak modulus list",
            )
        else:
            report.key_checks.append(
                KeyCheck(
                    "known_weak_modulus",
                    "pass",
                    f"not among {len(options.known_weak_moduli):,} listed moduli",
                )
            )

    factor = context.rsa_screen.find(modulus)
    if factor is not None:
        report.key_checks.append(
            KeyCheck(
                "rsa_small_factor", "fail", f"modulus divisible by {factor}", {"factor": factor}
            )
        )
        report.add(
            "RSA_SMALL_FACTOR",
            Severity.CRITICAL,
            f"RSA modulus has the small prime factor {factor}; the key is trivially factorable",
            factor=factor,
        )
    else:
        report.key_checks.append(
            KeyCheck("rsa_small_factor", "pass", f"no prime factor <= {options.rsa_prime_limit:,}")
        )

    if options.check_roca:
        if context.roca_detector is None:
            report.key_checks.append(
                KeyCheck("roca", "unavailable", context.roca_error or "detector unavailable")
            )
            return
        detected, error = keys.check_roca(modulus, context.roca_detector)
        if error is not None:
            report.key_checks.append(KeyCheck("roca", "error", error))
        elif detected:
            report.key_checks.append(KeyCheck("roca", "fail", "ROCA fingerprint detected"))
            report.add(
                "ROCA_FINGERPRINT",
                Severity.CRITICAL,
                "RSA modulus carries the ROCA (CVE-2017-15361) fingerprint; "
                "the private key may be recoverable",
            )
        else:
            report.key_checks.append(KeyCheck("roca", "pass", "no ROCA fingerprint"))


def audit_certificate(record: CertificateRecord, context: AuditContext) -> CertificateReport:
    """Build the complete report for one certificate."""
    report = print_certificate_metadata(record, context.options, context=context)
    try:
        public_key = record.public_key
    except Exception:
        report.key_checks.append(KeyCheck("key_scan", "skipped", "public key unreadable"))
        return report

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        _step(report, "EC scalar search", lambda: _check_ec(report, public_key, context.options))
    elif isinstance(public_key, rsa.RSAPublicKey):
        _step(report, "RSA checks", lambda: _check_rsa(report, public_key, context))
    else:
        report.key_checks.append(
            KeyCheck(
                "key_scan",
                "skipped",
                f"{report.public_key.algorithm}: no small-scalar/factor test for this key type",
            )
        )
    return report


# ---------------------------------------------------------------------------
# Population analysis
# ---------------------------------------------------------------------------


def analyze_population(
    pairs: list[tuple[CertificateRecord, CertificateReport]],
) -> PopulationReport:
    """Cross-certificate checks: key reuse and shared RSA prime factors.

    Findings are attached to the affected certificates' own reports so each
    certificate's block remains complete.
    """
    summary = PopulationReport(ran=True, certificates=len(pairs))

    # Key reuse across distinct certificates (any algorithm), by SPKI bytes.
    by_spki: dict[bytes, list[tuple[CertificateRecord, CertificateReport]]] = {}
    for record, report in pairs:
        try:
            spki = record.public_key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception:  # nosec - failure is logged at debug and the certificate is skipped for key-reuse analysis only
            LOGGER.debug("%s: SPKI encoding failed; skipped for key-reuse analysis", record.source)
            continue
        by_spki.setdefault(spki, []).append((record, report))
    for group in by_spki.values():
        if len(group) < 2:
            continue
        summary.reused_key_groups += 1
        for record, report in group:
            others = [o.fingerprint for o, _ in group if o is not record]
            report.add(
                "KEY_REUSE",
                Severity.INFO,
                f"public key is reused by {len(others)} other certificate(s) in this "
                "population (key reuse, not by itself a factoring weakness)",
                other_sha256=others,
            )

    moduli: dict[int, list[tuple[CertificateRecord, CertificateReport]]] = {}
    for record, report in pairs:
        if report.public_key.algorithm == "RSA":
            moduli.setdefault(record.public_key.public_numbers().n, []).append((record, report))
    summary.rsa_certificates = sum(len(group) for group in moduli.values())
    summary.distinct_rsa_moduli = len(moduli)

    if len(moduli) < 2:
        summary.note = "fewer than two distinct RSA moduli; shared-factor analysis not applicable"
        return summary

    distinct = list(moduli)
    for modulus, divisor in keys.batch_gcd(distinct).items():
        summary.shared_factor_groups += 1
        details: dict[str, Any] = {"common_divisor_hex": f"{divisor:x}"}
        if divisor == modulus:
            explained = keys.pairwise_divisors(modulus, distinct)
            details["pairwise_divisors_hex"] = {
                f"{o:x}"[:32]: f"{d:x}" for o, d in explained.items()
            }
        for _record, report in moduli[modulus]:
            report.add(
                "RSA_SHARED_FACTOR",
                Severity.CRITICAL,
                "RSA modulus shares a prime factor with another certificate in this "
                "population; both private keys can be recovered",
                **details,
            )
    summary.note = (
        f"{summary.shared_factor_groups} modulus group(s) with shared factors"
        if summary.shared_factor_groups
        else "no shared prime factor among distinct RSA moduli (applies only to the supplied set)"
    )
    return summary


# ---------------------------------------------------------------------------
# Run orchestration
# ---------------------------------------------------------------------------


def audit_records(
    records: list[CertificateRecord],
    options: AuditOptions,
    *,
    input_errors: list[str] | None = None,
) -> RunReport:
    """Audit every record; a failure in one never prevents the others."""
    run = RunReport(
        input_errors=list(input_errors or []),
        generated_at=datetime.now(UTC),
    )
    context = AuditContext(options, records)
    pairs: list[tuple[CertificateRecord, CertificateReport]] = []
    try:
        total = len(records)
        for index, record in enumerate(records, start=1):
            LOGGER.info("[%d/%d] auditing %s", index, total, record.source)
            try:
                report = audit_certificate(record, context)
            except Exception as exc:  # last-resort guard around one certificate
                LOGGER.debug("%s: audit failed", record.source, exc_info=True)
                report = CertificateReport(source=record.source, sha256=record.fingerprint)
                report.errors.append(f"audit aborted: {type(exc).__name__}: {exc}")
            run.reports.append(report)
            pairs.append((record, report))
        if options.population:
            try:
                run.population = analyze_population(pairs)
            except Exception as exc:
                LOGGER.debug("population analysis failed", exc_info=True)
                run.population = PopulationReport(
                    ran=False, note=f"population analysis failed: {type(exc).__name__}: {exc}"
                )
                run.input_errors.append(run.population.note)
    finally:
        context.close()
    return run
