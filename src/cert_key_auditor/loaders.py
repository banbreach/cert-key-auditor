"""Load X.509 certificates from PEM, DER and PKCS#7 data.

Design rule: **one bad block never discards its neighbours.** Every loader
returns a :class:`LoadResult` holding the certificates that parsed plus a list
of human-readable errors for the pieces that did not.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

from .errors import CertificateParseError, InputError
from .models import CertificateRecord

LOGGER = logging.getLogger(__name__)

MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_PEM_BLOCKS = 200_000
CERTIFICATE_SUFFIXES = frozenset({".pem", ".crt", ".cer", ".cert", ".der", ".p7b", ".p7c", ".txt"})

PEM_CERTIFICATE_RE = re.compile(
    rb"-----BEGIN (?P<label>(?:TRUSTED |X509 )?CERTIFICATE)-----"
    rb"(?P<body>.*?)"
    rb"-----END (?P=label)-----",
    re.DOTALL,
)
PEM_PKCS7_RE = re.compile(
    rb"-----BEGIN PKCS7-----.*?-----END PKCS7-----",
    re.DOTALL,
)
_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")


@dataclass
class LoadResult:
    """Certificates that parsed, and errors for everything that did not."""

    records: list[CertificateRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def extend(self, other: LoadResult) -> None:
        self.records.extend(other.records)
        self.errors.extend(other.errors)


def normalize_fingerprint(value: str) -> str:
    """Return a lower-case, colon-free SHA-256 fingerprint or raise."""
    cleaned = value.strip().replace(":", "").replace(" ", "").lower()
    if not _FINGERPRINT_RE.fullmatch(cleaned):
        raise InputError(
            f"invalid SHA-256 fingerprint {value[:80]!r}: expected 64 hexadecimal "
            "characters (colons are allowed)"
        )
    return cleaned


def trim_der(data: bytes) -> bytes:
    """Return the first DER SEQUENCE in ``data``, dropping trailing bytes.

    Needed for OpenSSL ``TRUSTED CERTIFICATE`` blobs (certificate followed by
    trust metadata) and for zero-padded PDF signature containers.
    """
    if len(data) < 2 or data[0] != 0x30:
        raise ValueError("data does not start with a DER SEQUENCE")
    first = data[1]
    if first < 0x80:
        total = 2 + first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or len(data) < 2 + count:
            raise ValueError("unsupported DER length encoding")
        total = 2 + count + int.from_bytes(data[2 : 2 + count], "big")
    if total > len(data):
        raise ValueError("truncated DER data")
    return data[:total]


def _parse_der(der: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise CertificateParseError(f"not a valid X.509 certificate: {exc}") from exc


def _short(exc: BaseException, limit: int = 160) -> str:
    text = " ".join(str(exc).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def load_certificates(data: bytes, source: str) -> LoadResult:
    """Parse every certificate found in ``data``.

    Accepts concatenated PEM (any surrounding text is ignored), a single DER
    certificate, and PKCS#7/CMS certificate bundles (PEM or DER).
    """
    result = LoadResult()
    pem_blocks = list(PEM_CERTIFICATE_RE.finditer(data))
    pkcs7_blocks = list(PEM_PKCS7_RE.finditer(data))

    if pem_blocks or pkcs7_blocks:
        if len(pem_blocks) > MAX_PEM_BLOCKS:
            result.errors.append(
                f"{source}: more than {MAX_PEM_BLOCKS:,} PEM blocks; extra blocks ignored"
            )
            pem_blocks = pem_blocks[:MAX_PEM_BLOCKS]
        for number, match in enumerate(pem_blocks, start=1):
            label = f"{source}#pem{number}" if len(pem_blocks) > 1 else source
            try:
                body = re.sub(rb"\s+", b"", match.group("body"))
                der = base64.b64decode(body, validate=True)  # nosec - decoding PEM certificate bodies, not obfuscated code
                if match.group("label") == b"TRUSTED CERTIFICATE":
                    der = trim_der(der)
                certificate = _parse_der(der)
            except (binascii.Error, ValueError, CertificateParseError) as exc:  # nosec - error is recorded in LoadResult.errors
                result.errors.append(f"{label}: unparseable certificate block ({_short(exc)})")
                continue
            result.records.append(CertificateRecord(certificate, label))
        for number, match in enumerate(pkcs7_blocks, start=1):
            try:
                bundle = pkcs7.load_pem_pkcs7_certificates(match.group(0))
            except (ValueError, TypeError) as exc:  # nosec - error is recorded in LoadResult.errors
                result.errors.append(f"{source}#pkcs7-{number}: {_short(exc)}")
                continue
            for index, certificate in enumerate(bundle, start=1):
                result.records.append(
                    CertificateRecord(certificate, f"{source}#pkcs7-{number}.{index}")
                )
        return result

    # No PEM markers: DER certificate, then DER PKCS#7.
    try:
        result.records.append(CertificateRecord(_parse_der(data), source))
        return result
    except CertificateParseError as der_error:
        try:
            bundle = pkcs7.load_der_pkcs7_certificates(data)
        except (ValueError, TypeError):
            result.errors.append(
                f"{source}: no PEM certificate, DER certificate or PKCS#7 bundle "
                f"found ({_short(der_error)})"
            )
            return result
    for index, certificate in enumerate(bundle, start=1):
        label = f"{source}#pkcs7.{index}" if len(bundle) > 1 else source
        result.records.append(CertificateRecord(certificate, label))
    return result


def read_input_file(path: Path, max_bytes: int = MAX_INPUT_BYTES) -> bytes:
    """Read ``path`` refusing anything larger than ``max_bytes``."""
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise InputError(f"{path}: file is {size:,} bytes, above the {max_bytes:,}-byte limit")
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise InputError(f"{path}: cannot read file ({exc.strerror or exc})") from exc
    if len(data) > max_bytes:
        raise InputError(f"{path}: file exceeds the {max_bytes:,}-byte limit")
    return data


def expand_paths(paths: list[str]) -> tuple[list[Path], list[str]]:
    """Expand files/directories into a sorted, de-duplicated file list."""
    files: list[Path] = []
    errors: list[str] = []
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            candidates = sorted(
                item
                for item in path.rglob("*")
                if item.is_file() and item.suffix.lower() in CERTIFICATE_SUFFIXES
            )
            if not candidates:
                errors.append(f"{path}: directory contains no certificate files")
        elif path.is_file():
            candidates = [path]
        else:
            errors.append(f"{path}: no such file or directory")
            continue
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                files.append(candidate)
    return files, errors


def load_files(paths: list[str], max_bytes: int = MAX_INPUT_BYTES) -> LoadResult:
    """Load certificates from files and directories, isolating per-file errors."""
    result = LoadResult()
    files, errors = expand_paths(paths)
    result.errors.extend(errors)
    for path in files:
        try:
            data = read_input_file(path, max_bytes)
        except InputError as exc:  # nosec - error is recorded in LoadResult.errors
            result.errors.append(str(exc))
            continue
        loaded = load_certificates(data, str(path))
        LOGGER.debug("%s: %d certificate(s)", path, len(loaded.records))
        result.extend(loaded)
    return result


def deduplicate(records: list[CertificateRecord]) -> list[CertificateRecord]:
    """Drop repeated certificates (by SHA-256), remembering the other sources."""
    unique: dict[str, CertificateRecord] = {}
    for record in records:
        existing = unique.get(record.fingerprint)
        if existing is None:
            unique[record.fingerprint] = record
        elif record.source not in existing.duplicates:
            existing.duplicates.append(record.source)
    return list(unique.values())
