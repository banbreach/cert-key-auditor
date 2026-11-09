"""Certificate attributes and policy checks.

Contains the CA/Browser-Forum maximum-validity schedule for publicly trusted
TLS server certificates, plus lightweight algorithm, time and serial checks.
Whether a certificate is *actually* publicly trusted cannot be determined from
the certificate alone; applicability is a heuristic that can be overridden.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from .models import Finding, KeyInfo, Severity, ValidityPolicyResult

SECONDS_PER_DAY = 86_400

# (issued on or after, maximum validity in days), newest first.
VALIDITY_SCHEDULE: tuple[tuple[datetime, int], ...] = (
    (datetime(2029, 3, 15, tzinfo=UTC), 47),
    (datetime(2027, 3, 15, tzinfo=UTC), 100),
    (datetime(2026, 3, 15, tzinfo=UTC), 200),
)
BASELINE_MAX_DAYS = 398
# Certificates issued before this date were legitimately allowed up to 825
# days, so exceeding 398 days is historical rather than a current violation.
LEGACY_CUTOFF = datetime(2020, 9, 1, tzinfo=UTC)

PUBLIC_TLS_MODES = ("auto", "yes", "no")
VALIDITY_CONVENTIONS = ("inclusive", "elapsed")


# ---------------------------------------------------------------------------
# Attribute helpers
# ---------------------------------------------------------------------------


def validity_bounds(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    """notBefore/notAfter as UTC-aware datetimes."""
    return certificate.not_valid_before_utc, certificate.not_valid_after_utc


def validity_duration_seconds(certificate: x509.Certificate) -> int:
    """Elapsed seconds between notBefore and notAfter (not an inclusive count)."""
    not_before, not_after = validity_bounds(certificate)
    if not_after < not_before:
        raise ValueError("notAfter precedes notBefore")
    return int((not_after - not_before).total_seconds())


def format_serial_hex(serial: int) -> str:
    """Upper-case hex, zero-padded to a whole number of octets."""
    digits = f"{abs(serial):X}"
    if len(digits) % 2:
        digits = "0" + digits
    return ("-" if serial < 0 else "") + digits


def _extension_value(certificate: x509.Certificate, extension_class: type) -> Any:
    """Extension value or ``None`` if absent. Malformed/duplicate ones raise."""
    try:
        return certificate.extensions.get_extension_for_class(extension_class).value
    except x509.ExtensionNotFound:
        return None


def is_ca(certificate: x509.Certificate) -> bool | None:
    value = _extension_value(certificate, x509.BasicConstraints)
    return None if value is None else bool(value.ca)


def is_self_signed(certificate: x509.Certificate) -> bool:
    """Name-based check (issuer == subject); the signature is not verified."""
    return bool(certificate.issuer == certificate.subject)


def extended_key_usage_names(certificate: x509.Certificate) -> list[str]:
    value = _extension_value(certificate, x509.ExtendedKeyUsage)
    if value is None:
        return []
    return [getattr(oid, "_name", None) or oid.dotted_string for oid in value]


def has_server_auth(certificate: x509.Certificate) -> bool:
    value = _extension_value(certificate, x509.ExtendedKeyUsage)
    return value is not None and ExtendedKeyUsageOID.SERVER_AUTH in value


def subject_alt_names(certificate: x509.Certificate) -> tuple[list[str], list[str], int]:
    """Return ``(dns names, ip addresses, count of other name types)``."""
    value = _extension_value(certificate, x509.SubjectAlternativeName)
    if value is None:
        return [], [], 0
    dns = value.get_values_for_type(x509.DNSName)
    ips = [str(ip) for ip in value.get_values_for_type(x509.IPAddress)]
    return list(dns), ips, len(value) - len(dns) - len(ips)


def signature_hash_name(certificate: x509.Certificate) -> str | None:
    try:
        algorithm = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return None
    return None if algorithm is None else algorithm.name


def describe_public_key(public_key: Any) -> KeyInfo:
    """Summarise a public key object."""
    info = KeyInfo(type_name=type(public_key).__name__.lstrip("_"))
    if isinstance(public_key, rsa.RSAPublicKey):
        info.algorithm = "RSA"
        info.bits = public_key.key_size
        info.rsa_exponent = public_key.public_numbers().e
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        info.algorithm = "EC"
        info.bits = public_key.curve.key_size
        info.curve = public_key.curve.name
    elif isinstance(public_key, dsa.DSAPublicKey):
        info.algorithm = "DSA"
        info.bits = public_key.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        info.algorithm = "Ed25519"
    elif isinstance(public_key, ed448.Ed448PublicKey):
        info.algorithm = "Ed448"
    return info


# ---------------------------------------------------------------------------
# CA/Browser-Forum maximum validity
# ---------------------------------------------------------------------------


def max_validity_days(issued: datetime) -> tuple[int, str]:
    """Maximum allowed validity (days) and a label of the rule that applies."""
    for start, days in VALIDITY_SCHEDULE:
        if issued >= start:
            return days, f"issued on or after {start:%Y-%m-%d}"
    return BASELINE_MAX_DAYS, f"issued before {VALIDITY_SCHEDULE[-1][0]:%Y-%m-%d}"


def evaluate_validity_policy(
    certificate: x509.Certificate,
    *,
    mode: str = "auto",
    convention: str = "inclusive",
) -> ValidityPolicyResult:
    """Check the certificate's lifetime against the CA/B maximum-validity schedule.

    ``mode``: ``auto`` applies the rule to non-CA, non-self-signed certificates
    carrying the serverAuth EKU; ``yes`` applies it to every non-CA certificate;
    ``no`` disables it. ``convention``: ``inclusive`` counts both the notBefore
    and notAfter seconds (elapsed + 1 s, RFC 5280 style); ``elapsed`` uses the
    plain difference.
    """
    if mode not in PUBLIC_TLS_MODES:
        raise ValueError(f"mode must be one of {PUBLIC_TLS_MODES}")
    if convention not in VALIDITY_CONVENTIONS:
        raise ValueError(f"convention must be one of {VALIDITY_CONVENTIONS}")

    def skipped(reason: str) -> ValidityPolicyResult:
        return ValidityPolicyResult(False, reason, convention=convention)

    if mode == "no":
        return skipped("disabled (--public-tls no)")
    if is_ca(certificate):
        return skipped("CA certificate")
    if mode == "auto":
        if is_self_signed(certificate):
            return skipped("self-signed certificate (not a publicly trusted TLS certificate)")
        if not has_server_auth(certificate):
            return skipped("no serverAuth extended key usage")

    not_before, _ = validity_bounds(certificate)
    seconds = validity_duration_seconds(certificate) + (1 if convention == "inclusive" else 0)
    allowed_days, rule = max_validity_days(not_before)
    return ValidityPolicyResult(
        applicable=True,
        reason="publicly trusted TLS server certificate rules apply",
        not_before_rule=rule,
        max_days=allowed_days,
        validity_days=round(seconds / SECONDS_PER_DAY, 4),
        compliant=seconds <= allowed_days * SECONDS_PER_DAY,
        convention=convention,
        legacy_period=not_before < LEGACY_CUTOFF,
    )


def validity_policy_findings(result: ValidityPolicyResult) -> list[Finding]:
    if not result.applicable or result.compliant is not False:
        return []
    severity = Severity.LOW if result.legacy_period else Severity.HIGH
    message = (
        f"validity of {result.validity_days:g} days exceeds the {result.max_days}-day "
        f"maximum for certificates {result.not_before_rule}"
    )
    if result.legacy_period:
        message += (
            " (issued before 2020-09-01, when up to 825 days was permitted; "
            "historical rather than current non-compliance)"
        )
    return [
        Finding(
            "VALIDITY_EXCEEDS_POLICY",
            severity,
            message,
            {
                "validity_days": result.validity_days,
                "max_days": result.max_days,
                "rule": result.not_before_rule,
                "convention": result.convention,
            },
        )
    ]


# ---------------------------------------------------------------------------
# Algorithm, time and serial checks
# ---------------------------------------------------------------------------


def algorithm_findings(
    key: KeyInfo,
    signature_hash: str | None,
    *,
    self_signed: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    if signature_hash in ("md5", "sha1") and not self_signed:
        findings.append(
            Finding(
                "WEAK_SIGNATURE_HASH",
                Severity.HIGH,
                f"certificate is signed with {signature_hash.upper()}, which is broken "
                "for collision resistance",
                {"hash": signature_hash},
            )
        )
    if key.algorithm == "RSA" and key.bits is not None:
        if key.bits < 1024:
            findings.append(
                Finding(
                    "RSA_SHORT_MODULUS",
                    Severity.CRITICAL,
                    f"RSA modulus is only {key.bits} bits",
                    {"bits": key.bits},
                )
            )
        elif key.bits < 2048:
            findings.append(
                Finding(
                    "RSA_SHORT_MODULUS",
                    Severity.HIGH,
                    f"RSA modulus of {key.bits} bits is below the 2048-bit minimum",
                    {"bits": key.bits},
                )
            )
        exponent = key.rsa_exponent
        if exponent is not None and exponent != 65537:
            if exponent % 2 == 0:
                findings.append(
                    Finding(
                        "RSA_LOW_EXPONENT",
                        Severity.HIGH,
                        f"RSA public exponent {exponent} is even and therefore invalid",
                        {"exponent": exponent},
                    )
                )
            elif exponent == 3:
                findings.append(
                    Finding(
                        "RSA_LOW_EXPONENT",
                        Severity.MEDIUM,
                        "RSA public exponent 3 enables several padding/signature attacks",
                        {"exponent": exponent},
                    )
                )
            elif exponent < 65537:
                findings.append(
                    Finding(
                        "RSA_LOW_EXPONENT",
                        Severity.LOW,
                        f"RSA public exponent {exponent} is below the recommended 65537",
                        {"exponent": exponent},
                    )
                )
    elif key.algorithm == "EC" and key.bits is not None and key.bits < 224:
        findings.append(
            Finding(
                "EC_WEAK_CURVE",
                Severity.HIGH,
                f"EC curve {key.curve} ({key.bits} bits) is below 224 bits",
                {"curve": key.curve, "bits": key.bits},
            )
        )
    elif key.algorithm == "DSA" and key.bits is not None and key.bits < 2048:
        findings.append(
            Finding(
                "DSA_SHORT_KEY",
                Severity.HIGH,
                f"DSA key of {key.bits} bits is below 2048 bits",
                {"bits": key.bits},
            )
        )
    return findings


def time_findings(not_before: datetime, not_after: datetime, now: datetime) -> list[Finding]:
    if not_after < not_before:
        return [
            Finding(
                "VALIDITY_INVALID",
                Severity.HIGH,
                "notAfter precedes notBefore (invalid validity interval)",
            )
        ]
    if now > not_after:
        return [
            Finding(
                "CERT_EXPIRED",
                Severity.MEDIUM,
                f"certificate expired on {not_after:%Y-%m-%d} (as of {now:%Y-%m-%d})",
            )
        ]
    if now < not_before:
        return [
            Finding(
                "CERT_NOT_YET_VALID",
                Severity.LOW,
                f"certificate is not valid until {not_before:%Y-%m-%d} (as of {now:%Y-%m-%d})",
            )
        ]
    return []


def serial_findings(serial: int) -> list[Finding]:
    """RFC 5280: serial numbers are positive and at most 20 octets."""
    octets = serial.bit_length() // 8 + 1
    if serial <= 0 or octets > 20:
        return [
            Finding(
                "SERIAL_INVALID",
                Severity.LOW,
                "serial number is not a positive integer of at most 20 octets",
                {"octets": octets},
            )
        ]
    return []


def missing_san_findings(
    *,
    ca: bool | None,
    self_signed: bool,
    eku: list[str],
    san_count: int,
) -> list[Finding]:
    tls_capable = not eku or "serverAuth" in eku
    if not ca and not self_signed and tls_capable and san_count == 0:
        return [
            Finding(
                "MISSING_SAN",
                Severity.LOW,
                "TLS-capable leaf certificate has no Subject Alternative Name",
            )
        ]
    return []
