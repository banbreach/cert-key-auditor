"""Output renderers: text (with colour), JSON, CSV and SARIF.

Security notes
--------------
* Certificate fields are attacker-controlled. The text renderer replaces control
  characters (including ESC) so a hostile subject cannot inject terminal escape
  sequences.
* CSV cells that start with ``= + - @`` (or tab/CR) are prefixed with ``'`` so a
  spreadsheet will not evaluate them as formulas.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from collections.abc import Mapping
from pathlib import PurePath
from typing import IO, Any
from urllib.parse import quote

from . import __version__
from .models import (
    CertificateReport,
    CrlResult,
    Finding,
    KeyCheck,
    RunReport,
    Severity,
    to_jsonable,
)

LABEL_WIDTH = 25
RULE = "=" * 78
OUTPUT_FORMATS = ("text", "json", "csv", "sarif")
COLOR_MODES = ("auto", "always", "never")

# ---------------------------------------------------------------------------
# Colour
# ---------------------------------------------------------------------------

_SEVERITY_STYLE = {
    Severity.CRITICAL: "1;97;41",
    Severity.HIGH: "1;31",
    Severity.MEDIUM: "33",
    Severity.LOW: "36",
    Severity.INFO: "2",
}
_STATUS_STYLE = {
    "pass": "32",  # nosec B105 - ANSI colour code, not a credential
    "ok": "32",
    "fail": "1;31",
    "failed": "1;31",
    "error": "1;31",
    "partial": "33",
    "unavailable": "33",
    "skipped": "2",
    "not_requested": "2",
    "none_advertised": "2",
}


class Palette:
    """ANSI styling that degrades to plain text when disabled."""

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    def _wrap(self, style: str, text: str) -> str:
        return f"\x1b[{style}m{text}\x1b[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def severity(self, severity: Severity, text: str) -> str:
        return self._wrap(_SEVERITY_STYLE[severity], text)

    def status(self, status: str, text: str | None = None) -> str:
        return self._wrap(_STATUS_STYLE.get(status, "0"), text if text is not None else status)


def _enable_windows_vt() -> bool:
    """Turn on ANSI processing for the Windows console; False if unavailable."""
    if os.name != "nt":
        return True
    try:
        import ctypes  # noqa: PLC0415

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined,unused-ignore]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def resolve_color(mode: str, stream: IO[str], env: Mapping[str, str] | None = None) -> bool:
    """Decide whether to colour output (honours NO_COLOR and FORCE_COLOR)."""
    env = os.environ if env is None else env
    if mode == "never":
        return False
    if mode == "always":
        return True
    if env.get("NO_COLOR"):
        return False
    if env.get("FORCE_COLOR", "0") not in ("", "0"):
        return True
    is_tty = getattr(stream, "isatty", lambda: False)()
    return bool(is_tty and env.get("TERM") != "dumb" and _enable_windows_vt())


def clean(value: object) -> str:
    """Make untrusted text safe to print: escape control characters."""
    text = str(value)
    if text.isprintable():
        return text
    return "".join(
        ch
        if ch.isprintable()
        else (f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        for ch in text
    )


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------


def _line(label: str, value: object, *, styled: bool = False) -> str:
    """One ``Label:   value`` line. ``styled`` marks values built by us (with ANSI)."""
    return f"{label + ':':<{LABEL_WIDTH}}{value if styled else clean(value)}\n"


def _utc(value: Any) -> str:
    return "(unknown)" if value is None else to_jsonable(value)


def _render_key_check(check: KeyCheck, palette: Palette) -> str:
    tag = palette.status(check.status, f"[{check.status}]")
    return f"  {tag} {clean(check.name)}: {clean(check.summary)}\n"


def _render_crl(crl: CrlResult, palette: Palette) -> str:
    head = clean(crl.url)
    if crl.ok:
        tag = palette.status("ok", "[OK]") + (" (cached)" if crl.from_cache else "")
        out = f"  - {head} {tag}\n"
        facts = [
            f"HTTP {crl.http_status}" if crl.http_status else None,
            crl.encoding,
            f"{crl.size_bytes:,} bytes" if crl.size_bytes is not None else None,
        ]
        out += f"      {' | '.join(clean(f) for f in facts if f)}\n"
        if crl.sha256:
            out += f"      SHA-256: {crl.sha256}\n"
        if crl.redirects:
            out += f"      Redirects: {' -> '.join(clean(r) for r in crl.redirects)}\n"
        out += f"      Issuer: {clean(crl.issuer)}\n"
        stale = palette.status("failed", " (STALE)") if crl.stale else ""
        out += (
            f"      This update: {_utc(crl.this_update)} | Next update: "
            f"{_utc(crl.next_update)}{stale}\n"
        )
        numbers = [
            f"CRL number: {crl.crl_number}" if crl.crl_number is not None else None,
            f"delta base: {crl.delta_base_crl_number}"
            if crl.delta_base_crl_number is not None
            else None,
            f"revoked entries: {crl.revoked_count:,}" if crl.revoked_count is not None else None,
        ]
        out += f"      {' | '.join(n for n in numbers if n) or 'no CRL number'}\n"
        if crl.certificate_listed is not None:
            listed = "LISTED" if crl.certificate_listed else "not listed"
            style = "fail" if crl.certificate_listed else "pass"
            out += (
                f"      This certificate: {palette.status(style, listed)} "
                "(CRL signature not verified)\n"
            )
        for note in crl.notes:
            out += f"      Note: {clean(note)}\n"
        return out
    tag = palette.status("failed", f"[FAILED: {clean(crl.error_kind)}]")
    out = f"  - {head} {tag}\n      {clean(crl.error)}\n"
    if crl.redirects:
        out += f"      Redirects: {' -> '.join(clean(r) for r in crl.redirects)}\n"
    return out


def _render_finding(finding: Finding, palette: Palette) -> str:
    tag = palette.severity(finding.severity, f"[{finding.severity.label.upper()}]")
    return f"  {tag} {clean(finding.code)}: {clean(finding.message)}\n"


def render_certificate_block(
    report: CertificateReport,
    palette: Palette | None = None,
    *,
    index: int | None = None,
    total: int | None = None,
) -> str:
    """One self-contained text block with every result for a certificate."""
    palette = palette or Palette(False)
    out = "\n" + RULE + "\n"
    if index is not None and total is not None:
        out += palette.bold(f"Certificate {index} of {total}") + "\n"
    out += _line("Source", report.source)
    out += _line("Subject", report.subject or "(empty subject)")
    out += _line("Issuer", report.issuer)
    out += _line("SHA-256", report.sha256)
    if report.also_seen_in:
        out += _line("Also seen in", ", ".join(report.also_seen_in[:5]))
    out += _line("Serial number (hex)", report.serial_hex)
    out += _line("Serial number (decimal)", report.serial_decimal)
    out += _line("Certificate version", report.version)
    sig = report.signature_algorithm or "(unknown)"
    out += _line("Signature algorithm", f"{sig} ({report.signature_algorithm_oid})")
    out += _line("Not before (UTC)", _utc(report.not_before))
    out += _line("Not after (UTC)", _utc(report.not_after))
    if report.validity_seconds is not None:
        days = report.validity_seconds / 86400
        out += _line("Validity duration", f"{report.validity_seconds:,} seconds ({days:.2f} days)")
    elif report.validity_error:
        out += _line("Validity duration", f"invalid ({report.validity_error})")
    key = report.public_key
    if key.error:
        out += _line("Public key", f"unreadable ({key.error})")
    else:
        detail = key.algorithm
        if key.curve:
            detail += f" {key.curve}"
        if key.bits:
            detail += f" ({key.bits} bits)"
        if key.rsa_exponent is not None:
            detail += f", e={key.rsa_exponent}"
        out += _line("Public key", f"{detail} [{key.type_name}]")
    if report.is_ca is not None or report.self_signed:
        role = "CA" if report.is_ca else "end-entity"
        out += _line("Role", role + (", self-signed (by name)" if report.self_signed else ""))
    if report.extended_key_usage:
        out += _line("Extended key usage", ", ".join(report.extended_key_usage))
    names = report.san_dns + report.san_ip
    if names:
        shown = ", ".join(names[:8]) + (f" (+{len(names) - 8} more)" if len(names) > 8 else "")
        out += _line("Subject alt names", shown)

    policy = report.validity_policy
    if policy is not None:
        out += "\n" + palette.bold("Validity policy (CA/B Forum maximum)") + "\n"
        if not policy.applicable:
            out += f"  not applicable: {clean(policy.reason)}\n"
        else:
            verdict = "compliant" if policy.compliant else "EXCEEDS LIMIT"
            style = "pass" if policy.compliant else "fail"
            out += (
                f"  {palette.status(style, verdict)}: {policy.validity_days:g} days vs "
                f"{policy.max_days}-day maximum ({clean(policy.not_before_rule)}; "
                f"{policy.convention} count)\n"
            )

    if report.key_checks:
        out += "\n" + palette.bold("Key checks (bounded; a pass is not proof of security)") + "\n"
        for check in report.key_checks:
            out += _render_key_check(check, palette)

    out += "\n" + palette.bold("CRL") + "\n"
    out += f"  status: {palette.status(report.crl_status)}\n"
    if report.crl_status == "not_requested" and report.crl_urls:
        out += f"  advertised: {', '.join(clean(u) for u in report.crl_urls[:5])}\n"
    for crl in report.crls:
        out += _render_crl(crl, palette)
    if report.crl_unsupported_uris:
        out += (
            f"  unsupported URIs: {', '.join(clean(u) for u in report.crl_unsupported_uris[:5])}\n"
        )

    out += "\n" + palette.bold("Findings") + "\n"
    if report.findings:
        for finding in sorted(report.findings, key=lambda f: -f.severity):
            out += _render_finding(finding, palette)
    else:
        out += "  none\n"
    if report.errors:
        out += (
            "\n"
            + palette.severity(Severity.MEDIUM, "Errors (results above may be incomplete)")
            + "\n"
        )
        for error in report.errors:
            out += f"  ! {clean(error)}\n"
    return out


def render_text(run: RunReport, palette: Palette | None = None) -> str:
    palette = palette or Palette(False)
    total = len(run.reports)
    parts = [
        render_certificate_block(report, palette, index=number, total=total)
        for number, report in enumerate(run.reports, start=1)
    ]
    if run.population is not None:
        pop = run.population
        block = "\n" + RULE + "\n" + palette.bold("POPULATION ANALYSIS") + "\n"
        block += _line("Certificates", pop.certificates)
        block += _line("RSA certificates", pop.rsa_certificates)
        block += _line("Distinct RSA moduli", pop.distinct_rsa_moduli)
        block += _line("Reused-key groups", pop.reused_key_groups)
        block += _line("Shared-factor groups", pop.shared_factor_groups)
        block += _line("Result", pop.note)
        parts.append(block)
    if run.input_errors:
        block = "\n" + RULE + "\n" + palette.severity(Severity.MEDIUM, "INPUT ERRORS") + "\n"
        block += "".join(f"  ! {clean(error)}\n" for error in run.input_errors)
        parts.append(block)

    counts = run.severity_counts()
    findings = ", ".join(
        palette.severity(Severity.parse(name), f"{name} {count}") if count else f"{name} 0"
        for name, count in counts.items()
    )
    summary = "\n" + RULE + "\n" + palette.bold("SUMMARY") + "\n"
    summary += _line("Certificates audited", total)
    summary += _line("Findings", findings, styled=True)
    summary += _line("Errors", run.error_count)
    if run.fail_on is not None:
        summary += _line("Fail threshold", f"{run.fail_on.label} -> exit code {run.exit_code()}")
    parts.append(summary)
    return "".join(parts)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def render_json(run: RunReport) -> str:
    document = {
        "tool": {"name": "cert-key-auditor", "version": __version__},
        "generated_at": to_jsonable(run.generated_at),
        "fail_on": run.fail_on.label if run.fail_on else None,
        "summary": {
            "certificates": len(run.reports),
            "findings": run.severity_counts(),
            "errors": run.error_count,
            "exit_code": run.exit_code(),
        },
        "population": to_jsonable(run.population),
        "certificates": [to_jsonable(report) for report in run.reports],
        "input_errors": list(run.input_errors),
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

CSV_COLUMNS = (
    "source", "sha256", "subject", "issuer", "serial_hex", "version",
    "signature_algorithm", "not_before", "not_after", "validity_days", "is_ca",
    "self_signed", "key_algorithm", "key_bits", "key_curve", "rsa_exponent",
    "validity_policy_applicable", "validity_policy_max_days",
    "validity_policy_compliant", "crl_status", "crl_urls", "crl_ok", "crl_failed",
    "key_checks", "max_severity", "finding_codes", "findings", "errors",
)  # fmt: skip
CRL_CSV_COLUMNS = (
    "certificate_sha256", "certificate_source", "url", "ok", "error_kind", "error",
    "http_status", "encoding", "size_bytes", "sha256", "issuer", "this_update",
    "next_update", "stale", "revoked_count", "crl_number", "delta_base_crl_number",
    "certificate_listed", "from_cache", "redirects", "notes",
)  # fmt: skip


def csv_cell(value: object) -> str:
    """Render a CSV cell, neutralising spreadsheet formula injection in text."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Severity):
        return value.label
    if not isinstance(value, str):
        return str(to_jsonable(value))
    if value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _csv_text(columns: tuple[str, ...], rows: list[dict[str, object]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([csv_cell(row.get(column)) for column in columns])
    return buffer.getvalue()


def render_csv(run: RunReport) -> str:
    rows: list[dict[str, object]] = []
    for report in run.reports:
        policy = report.validity_policy
        days = (
            None if report.validity_seconds is None else round(report.validity_seconds / 86400, 4)
        )
        rows.append(
            {
                "source": report.source,
                "sha256": report.sha256,
                "subject": report.subject,
                "issuer": report.issuer,
                "serial_hex": report.serial_hex,
                "version": report.version,
                "signature_algorithm": report.signature_algorithm,
                "not_before": report.not_before,
                "not_after": report.not_after,
                "validity_days": days,
                "is_ca": report.is_ca,
                "self_signed": report.self_signed,
                "key_algorithm": report.public_key.algorithm,
                "key_bits": report.public_key.bits,
                "key_curve": report.public_key.curve,
                "rsa_exponent": report.public_key.rsa_exponent,
                "validity_policy_applicable": policy.applicable if policy else None,
                "validity_policy_max_days": policy.max_days if policy else None,
                "validity_policy_compliant": policy.compliant if policy else None,
                "crl_status": report.crl_status,
                "crl_urls": " | ".join(report.crl_urls),
                "crl_ok": sum(1 for c in report.crls if c.ok),
                "crl_failed": sum(1 for c in report.crls if not c.ok),
                "key_checks": "; ".join(f"{c.name}:{c.status}" for c in report.key_checks),
                "max_severity": report.max_severity,
                "finding_codes": ";".join(f.code for f in report.findings),
                "findings": " | ".join(f.message for f in report.findings),
                "errors": " | ".join(report.errors),
            }
        )
    return _csv_text(CSV_COLUMNS, rows)


def render_crl_csv(run: RunReport) -> str:
    rows: list[dict[str, object]] = []
    for report in run.reports:
        for crl in report.crls:
            rows.append(
                {
                    "certificate_sha256": report.sha256,
                    "certificate_source": report.source,
                    "url": crl.url,
                    "ok": crl.ok,
                    "error_kind": crl.error_kind,
                    "error": crl.error,
                    "http_status": crl.http_status,
                    "encoding": crl.encoding,
                    "size_bytes": crl.size_bytes,
                    "sha256": crl.sha256,
                    "issuer": crl.issuer,
                    "this_update": crl.this_update,
                    "next_update": crl.next_update,
                    "stale": crl.stale,
                    "revoked_count": crl.revoked_count,
                    "crl_number": crl.crl_number,
                    "delta_base_crl_number": crl.delta_base_crl_number,
                    "certificate_listed": crl.certificate_listed,
                    "from_cache": crl.from_cache,
                    "redirects": " -> ".join(crl.redirects),
                    "notes": " | ".join(crl.notes),
                }
            )
    return _csv_text(CRL_CSV_COLUMNS, rows)


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}


def _sarif_uri(source: str) -> str:
    base = source.split("#", 1)[0]
    if ":" in base and not PurePath(base).is_absolute() and "\\" not in base:
        scheme, _, rest = base.partition(":")
        if scheme.isalpha() and len(scheme) > 1:
            return f"{scheme}:{quote(rest)}"
    return quote(PurePath(base).as_posix())


def render_sarif(run: RunReport) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for report in run.reports:
        for finding in report.findings:
            rules.setdefault(
                finding.code,
                {
                    "id": finding.code,
                    "name": finding.code,
                    "shortDescription": {"text": finding.code.replace("_", " ").title()},
                    "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
                    "properties": {"security-severity": _SECURITY_SEVERITY[finding.severity]},
                },
            )
            results.append(
                {
                    "ruleId": finding.code,
                    "level": _SARIF_LEVEL[finding.severity],
                    "message": {"text": f"{finding.message} [certificate {report.sha256}]"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": _sarif_uri(report.source)}
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "certificateFinding/v1": f"{report.sha256}:{finding.code}"
                    },
                    "properties": {
                        "severity": finding.severity.label,
                        "sha256": report.sha256,
                        "source": report.source,
                        "details": to_jsonable(finding.details),
                    },
                }
            )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cert-key-auditor",
                        "version": __version__,
                        "informationUri": "https://github.com/banbreach/cert-key-auditor",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def write_output(text: str, path: str | None, stream: IO[str] | None = None) -> None:
    """Write ``text`` to ``path`` (UTF-8) or to the stream (default stdout)."""
    if path is None or path == "-":
        (stream or sys.stdout).write(text)
        return
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
