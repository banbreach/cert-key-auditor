"""Extract X.509 certificates embedded in PDF files.

Sources searched, in priority order (the first label wins when the same
certificate appears several times):

1. ``/DSS`` Document Security Store (PAdES long-term-validation material)
2. digital-signature containers (``/Contents`` PKCS#7/CMS, ``/Cert`` entries)
3. embedded file attachments
4. any other stream that decodes to a DER certificate / PKCS#7 bundle or PEM
5. certificates pasted as PEM text on pages
6. PEM blocks found in the raw (uncompressed) file bytes

PDFs are untrusted input. Hard limits bound file size, object count, per
stream and total decoded bytes, and page count for text extraction; every phase
is isolated so one malformed object cannot hide certificates found elsewhere.
Nothing in the document is executed and no network access happens.
"""

from __future__ import annotations

import io
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

from .errors import InputError, PdfError
from .loaders import LoadResult, deduplicate, load_certificates, read_input_file, trim_der
from .models import CertificateRecord

LOGGER = logging.getLogger(__name__)

_TEXT_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(?P<body>.*?)-----END CERTIFICATE-----", re.DOTALL
)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_ATTACHMENT_CERT_SUFFIXES = (".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".cert")
_MAX_DER_STREAM = 1024 * 1024


@dataclass(frozen=True)
class PdfLimits:
    """Safety limits for processing one PDF."""

    max_file_bytes: int = 100 * 1024 * 1024
    max_pages: int = 500
    max_objects: int = 250_000
    max_stream_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024


def _import_pypdf() -> Any:
    try:
        import pypdf  # noqa: PLC0415
    except ImportError as exc:
        raise PdfError(
            "PDF support needs the optional dependency: pip install 'cert-key-auditor[pdf]'"
        ) from exc
    return pypdf


def _pkcs7_certificates(data: bytes) -> list[x509.Certificate]:
    try:
        return list(pkcs7.load_der_pkcs7_certificates(trim_der(data)))
    except (ValueError, TypeError):
        return []


def _add_all(
    result: LoadResult,
    certificates: list[x509.Certificate],
    label: str,
) -> None:
    for index, certificate in enumerate(certificates, start=1):
        suffix = f".{index}" if len(certificates) > 1 else ""
        result.records.append(CertificateRecord(certificate, f"{label}{suffix}"))


def _iter_objects(reader: Any, limit: int) -> Iterator[tuple[int, Any]]:
    from pypdf.generic import IndirectObject  # noqa: PLC0415

    numbers: set[tuple[int, int]] = set()
    for generation, table in getattr(reader, "xref", {}).items():
        numbers.update((number, generation) for number in table)
    numbers.update((number, 0) for number in getattr(reader, "xref_objStm", {}))
    if len(numbers) > limit:
        raise PdfError(f"PDF has more than {limit:,} objects; refusing to scan them all")
    for number, generation in sorted(numbers):
        try:
            yield number, reader.get_object(IndirectObject(number, generation, reader))
        except Exception:
            LOGGER.debug("PDF object %d unreadable", number, exc_info=True)


def _as_bytes(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


def _normalise_text_pem(body: str) -> bytes | None:
    compact = re.sub(r"[\s\u00ad\u200b]+", "", body)
    if not compact or not _BASE64_RE.fullmatch(compact):
        return None
    wrapped = "\n".join(compact[i : i + 64] for i in range(0, len(compact), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n".encode("ascii")


def _pem_in_text(text: str, label: str, result: LoadResult) -> None:
    for number, match in enumerate(_TEXT_PEM_RE.finditer(text), start=1):
        pem = _normalise_text_pem(match.group("body"))
        where = f"{label}.{number}"
        if pem is None:
            result.errors.append(f"{where}: PEM text is not valid base64")
            continue
        loaded = load_certificates(pem, where)
        result.records.extend(loaded.records)
        result.errors.extend(loaded.errors)


def extract_certificates_from_pdf(path: Path, limits: PdfLimits | None = None) -> LoadResult:
    """Extract every certificate found in the PDF at ``path``.

    Raises :class:`PdfError`/:class:`InputError` only when the file as a whole
    cannot be processed; problems with individual objects become entries in
    ``LoadResult.errors``.
    """
    limits = limits or PdfLimits()
    pypdf = _import_pypdf()
    data = read_input_file(path, limits.max_file_bytes)
    if not data.lstrip(b"\x00 \t\r\n")[:5] == b"%PDF-":
        raise PdfError(f"{path}: not a PDF file (missing %PDF- header)")
    name = str(path)
    result = LoadResult()

    try:
        reader = pypdf.PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            try:
                decrypted = reader.decrypt("")
            except Exception as exc:
                raise PdfError(f"{name}: encrypted PDF could not be opened ({exc})") from exc
            if not decrypted:
                raise PdfError(f"{name}: PDF is password protected")
    except PdfError:
        raise
    except Exception as exc:
        raise PdfError(f"{name}: cannot parse PDF ({type(exc).__name__}: {exc})") from exc

    def phase(label: str, func: Any) -> None:
        try:
            func()
        except PdfError as exc:
            result.errors.append(str(exc))
        except Exception as exc:  # isolate each phase from the others
            LOGGER.debug("%s: %s phase failed", name, label, exc_info=True)
            result.errors.append(f"{name}: {label} extraction failed ({type(exc).__name__})")

    def dss() -> None:
        root = reader.trailer["/Root"]
        store = root.get("/DSS") if hasattr(root, "get") else None
        if store is None:
            return
        for index, ref in enumerate(store.get_object().get("/Certs", []), start=1):
            stream = ref.get_object()
            blob = stream.get_data()
            if len(blob) > _MAX_DER_STREAM:
                continue
            loaded = load_certificates(blob, f"{name}#dss-cert{index}")
            result.records.extend(loaded.records)

    def objects() -> None:
        total = 0
        for number, obj in _iter_objects(reader, limits.max_objects):
            if hasattr(obj, "get_data"):
                try:
                    blob = obj.get_data()
                except Exception:  # nosec - undecodable stream is logged at debug and skipped
                    LOGGER.debug("PDF object %d: stream could not be decoded", number)
                    continue
                if len(blob) > limits.max_stream_bytes:
                    continue
                total += len(blob)
                if total > limits.max_total_bytes:
                    raise PdfError(f"{name}: decoded stream data exceeded the safety limit")
                if b"-----BEGIN" in blob or (blob[:1] == b"\x30" and len(blob) <= _MAX_DER_STREAM):
                    loaded = load_certificates(blob, f"{name}#stream{number}")
                    result.records.extend(loaded.records)
            if hasattr(obj, "get") and not hasattr(obj, "get_data"):
                contents = _as_bytes(obj.get("/Contents"))
                if contents is not None and obj.get("/ByteRange") is not None:
                    _add_all(result, _pkcs7_certificates(contents), f"{name}#signature{number}")
                legacy = obj.get("/Cert")
                if legacy is not None:
                    values = legacy if isinstance(legacy, list) else [legacy]
                    for index, item in enumerate(values, start=1):
                        blob = _as_bytes(item.get_object() if hasattr(item, "get_object") else item)
                        if blob:
                            loaded = load_certificates(
                                blob, f"{name}#signature{number}.cert{index}"
                            )
                            result.records.extend(loaded.records)

    def attachments() -> None:
        for filename, blobs in reader.attachments.items():
            for index, blob in enumerate(blobs, start=1):
                if len(blob) > limits.max_stream_bytes:
                    continue
                label = f"{name}#attachment:{filename}" + (f"[{index}]" if len(blobs) > 1 else "")
                loaded = load_certificates(blob, label)
                result.records.extend(loaded.records)
                if str(filename).lower().endswith(_ATTACHMENT_CERT_SUFFIXES):
                    result.errors.extend(loaded.errors)

    def page_text() -> None:
        for number, page in enumerate(reader.pages, start=1):
            if number > limits.max_pages:
                result.errors.append(f"{name}: text scan stopped after {limits.max_pages} pages")
                break
            try:
                text = page.extract_text() or ""
            except Exception:  # nosec - page text failure is logged at debug and the page skipped
                LOGGER.debug("%s: page %d text extraction failed", name, number)
                continue
            if "BEGIN CERTIFICATE" in text:
                _pem_in_text(text, f"{name}#page{number}", result)

    def raw() -> None:
        if b"-----BEGIN" in data:
            loaded = load_certificates(data, f"{name}#raw")
            result.records.extend(loaded.records)

    phase("DSS", dss)
    phase("attachment", attachments)
    phase("signature/stream", objects)
    phase("page text", page_text)
    phase("raw bytes", raw)
    result.records = deduplicate(result.records)
    return result


def expand_pdf_paths(paths: list[str]) -> tuple[list[Path], list[str]]:
    """Expand files and directories into PDF files."""
    files: list[Path] = []
    errors: list[str] = []
    seen: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            found = sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() == ".pdf")
            if not found:
                errors.append(f"{path}: directory contains no PDF files")
        elif path.is_file():
            found = [path]
        else:
            errors.append(f"{path}: no such file or directory")
            continue
        for item in found:
            resolved = item.resolve()
            if resolved not in seen:
                seen.add(resolved)
                files.append(item)
    return files, errors


def load_pdfs(paths: list[str], limits: PdfLimits | None = None) -> LoadResult:
    """Extract certificates from PDFs, isolating failures per file."""
    result = LoadResult()
    files, errors = expand_pdf_paths(paths)
    result.errors.extend(errors)
    for path in files:
        try:
            extracted = extract_certificates_from_pdf(path, limits)
        except (PdfError, InputError) as exc:  # nosec - error is recorded in LoadResult.errors
            result.errors.append(str(exc))
            continue
        except Exception as exc:  # defensive: malformed PDFs trigger odd library errors  # nosec - error is recorded in LoadResult.errors
            LOGGER.debug("%s: unexpected PDF failure", path, exc_info=True)
            result.errors.append(f"{path}: unexpected {type(exc).__name__} while reading PDF")
            continue
        LOGGER.info("%s: %d certificate(s) in PDF", path, len(extracted.records))
        if not extracted.records and not extracted.errors:
            LOGGER.warning("%s: no certificates found in PDF", path)
        result.extend(extracted)
    return result
