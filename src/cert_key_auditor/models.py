"""Data model shared by the audit pipeline and the renderers.

The central object is :class:`CertificateReport`. One report holds *everything*
learned about one certificate: identity and validity metadata, public-key
details, key checks, the validity-period policy result, CRL retrieval results
and the findings derived from all of those. Renderers print one block per
report, so nothing about a certificate is ever scattered across the output.
"""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes


class Severity(enum.IntEnum):
    """Finding severity, ordered so that comparisons work."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, name: str) -> Severity:
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(member.label for member in cls)
            raise ValueError(f"unknown severity {name!r} (use: {valid})") from exc


@dataclass(frozen=True)
class Finding:
    """One audit result worth a human's attention."""

    code: str
    severity: Severity
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(eq=False)
class CertificateRecord:
    """A parsed certificate plus where it came from."""

    certificate: x509.Certificate
    source: str
    duplicates: list[str] = field(default_factory=list)

    @cached_property
    def fingerprint(self) -> str:
        """Lower-case hex SHA-256 over the DER encoding."""
        return self.certificate.fingerprint(hashes.SHA256()).hex()

    @cached_property
    def subject(self) -> str:
        return self.certificate.subject.rfc4514_string()

    @cached_property
    def public_key(self) -> Any:
        """The certificate's public key object (may raise for exotic keys)."""
        return self.certificate.public_key()


@dataclass
class KeyInfo:
    """Public-key summary."""

    type_name: str = "unknown"
    algorithm: str = "unknown"
    bits: int | None = None
    curve: str | None = None
    rsa_exponent: int | None = None
    error: str | None = None


@dataclass
class KeyCheck:
    """Outcome of one key-level check.

    ``status`` is one of ``pass``, ``fail``, ``skipped``, ``unavailable`` or
    ``error``. ``pass`` only means *nothing was found within the tested
    bounds*; it never proves a key is secure.
    """

    name: str
    status: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidityPolicyResult:
    """Result of the CA/Browser-Forum maximum-validity check."""

    applicable: bool
    reason: str
    not_before_rule: str | None = None
    max_days: int | None = None
    validity_days: float | None = None
    compliant: bool | None = None
    convention: str = "inclusive"
    legacy_period: bool = False


@dataclass
class CrlResult:
    """Retrieval and parse result for a single CRL URL."""

    url: str
    ok: bool = False
    from_cache: bool = False
    http_status: int | None = None
    content_type: str | None = None
    final_url: str | None = None
    redirects: list[str] = field(default_factory=list)
    size_bytes: int | None = None
    sha256: str | None = None
    encoding: str | None = None
    issuer: str | None = None
    issuer_matches_certificate: bool | None = None
    signature_algorithm_oid: str | None = None
    this_update: datetime | None = None
    next_update: datetime | None = None
    stale: bool | None = None
    revoked_count: int | None = None
    crl_number: int | None = None
    delta_base_crl_number: int | None = None
    certificate_listed: bool | None = None
    notes: list[str] = field(default_factory=list)
    error_kind: str | None = None
    error: str | None = None


@dataclass
class CertificateReport:
    """Everything known about one certificate (see module docstring)."""

    # Identity
    source: str
    sha256: str
    subject: str = ""
    issuer: str = ""
    serial_hex: str = ""
    serial_decimal: str = ""
    version: str = ""
    also_seen_in: list[str] = field(default_factory=list)
    # Signature
    signature_algorithm: str = ""
    signature_algorithm_oid: str = ""
    signature_hash: str | None = None
    # Validity
    not_before: datetime | None = None
    not_after: datetime | None = None
    validity_seconds: int | None = None
    validity_error: str | None = None
    # Usage
    is_ca: bool | None = None
    self_signed: bool = False
    extended_key_usage: list[str] = field(default_factory=list)
    san_dns: list[str] = field(default_factory=list)
    san_ip: list[str] = field(default_factory=list)
    san_other_count: int = 0
    # Key
    public_key: KeyInfo = field(default_factory=KeyInfo)
    key_checks: list[KeyCheck] = field(default_factory=list)
    # Policy
    validity_policy: ValidityPolicyResult | None = None
    # CRLs
    crl_status: str = "not_requested"
    crl_urls: list[str] = field(default_factory=list)
    crl_unsupported_uris: list[str] = field(default_factory=list)
    crls: list[CrlResult] = field(default_factory=list)
    # Verdict
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    def add(
        self,
        code: str,
        severity: Severity,
        message: str,
        **details: Any,
    ) -> Finding:
        finding = Finding(code, severity, message, dict(details))
        self.findings.append(finding)
        return finding


@dataclass
class PopulationReport:
    """Cross-certificate analysis (shared RSA factors, key reuse)."""

    certificates: int = 0
    rsa_certificates: int = 0
    distinct_rsa_moduli: int = 0
    ran: bool = False
    note: str = ""
    shared_factor_groups: int = 0
    reused_key_groups: int = 0


@dataclass
class RunReport:
    """Top-level result of one invocation."""

    reports: list[CertificateReport] = field(default_factory=list)
    population: PopulationReport | None = None
    input_errors: list[str] = field(default_factory=list)
    generated_at: datetime | None = None
    fail_on: Severity | None = None

    def findings_at_or_above(self, threshold: Severity) -> int:
        return sum(
            1
            for report in self.reports
            for finding in report.findings
            if finding.severity >= threshold
        )

    @property
    def error_count(self) -> int:
        return len(self.input_errors) + sum(len(r.errors) for r in self.reports)

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.label: 0 for severity in reversed(Severity)}
        for report in self.reports:
            for finding in report.findings:
                counts[finding.severity.label] += 1
        return counts

    def exit_code(self) -> int:
        """0 clean, 1 findings at/above ``fail_on``, 3 completed with errors.

        (Exit code 2 - fatal/usage error - is decided by the CLI.)
        """
        if self.fail_on is not None and self.findings_at_or_above(self.fail_on):
            return 1
        return 3 if self.error_count else 0


def to_jsonable(value: Any) -> Any:
    """Convert report objects to plain JSON-serialisable structures."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.label if isinstance(value, Severity) else value.name
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    return value
