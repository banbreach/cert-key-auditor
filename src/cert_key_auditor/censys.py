"""Retrieve certificates from the Censys Platform API (v3)."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from collections.abc import Iterator
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .errors import CensysError
from .loaders import LoadResult, deduplicate, load_certificates, normalize_fingerprint
from .models import CertificateRecord

LOGGER = logging.getLogger(__name__)

API_BASE = "https://api.platform.censys.io"
CERTIFICATE_RAW_PATH = "/v3/global/asset/certificate/{certificate_id}/raw"
ACCEPT_HEADER = "application/x-pem-file, application/json;q=0.9"
DEFAULT_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_JSON_DEPTH = 20

# JSON keys that may hold encoded DER (hex or base64) rather than PEM text.
_DER_KEYS = frozenset({"raw", "der", "certificate", "cert", "data", "raw_der"})
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def build_session(retries: int = 3) -> requests.Session:
    """Session that retries 429/5xx with exponential backoff and Retry-After."""
    retry = Retry(
        total=retries,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def _walk_strings(
    node: Any, key: str | None = None, depth: int = 0
) -> Iterator[tuple[str | None, str]]:
    if depth > MAX_JSON_DEPTH:
        return
    if isinstance(node, str):
        yield key, node
    elif isinstance(node, dict):
        for child_key, child in node.items():
            yield from _walk_strings(child, str(child_key), depth + 1)
    elif isinstance(node, list):
        for child in node:
            yield from _walk_strings(child, key, depth + 1)


def _decode_der_text(text: str) -> bytes | None:
    """Decode hex or base64 text into bytes, or return None."""
    compact = "".join(text.split())
    if not compact:
        return None
    if _HEX_RE.fullmatch(compact):
        return bytes.fromhex(compact)
    try:
        return base64.b64decode(compact, validate=True)  # nosec - decoding certificate DER from an API field, not obfuscated code
    except (binascii.Error, ValueError):
        return None


def extract_certificates(body: bytes, source: str) -> LoadResult:
    """Find certificates in a Censys response body.

    JSON is decoded *first*. Searching the raw body for PEM markers would
    match inside a JSON string, where newlines are still escaped as ``\\n``
    and the block cannot be parsed. After decoding, PEM strings are parsed
    normally and encoded-DER fields (hex or base64) are tried on known keys.
    """
    stripped = body.lstrip(b"\xef\xbb\xbf \t\r\n")
    document: Any = None
    if stripped[:1] in (b"{", b"[", b'"'):
        try:
            document = json.loads(stripped.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            document = None

    if document is None:
        return load_certificates(body, source)

    result = LoadResult()
    for key, text in _walk_strings(document):
        if "-----BEGIN" in text:
            loaded = load_certificates(text.encode("utf-8"), source)
            result.records.extend(loaded.records)
            result.errors.extend(loaded.errors)
        elif key is not None and key.lower() in _DER_KEYS:
            der = _decode_der_text(text)
            if der is None:
                continue
            loaded = load_certificates(der, source)
            result.records.extend(loaded.records)
            # Encoded-text fields are speculative; only successes are reported.
    result.records = deduplicate(result.records)
    if not result.records and not result.errors:
        keys = sorted(document) if isinstance(document, dict) else []
        result.errors.append(
            f"{source}: JSON response held no certificate data (top-level keys: "
            f"{', '.join(map(str, keys[:10])) or 'none'})"
        )
    return result


def _read_limited(response: requests.Response, limit: int) -> bytes:
    declared = response.headers.get("Content-Length", "")
    if declared.isdigit() and int(declared) > limit:
        raise CensysError(f"Censys response too large ({int(declared):,} bytes)")
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        total += len(chunk)
        if total > limit:
            raise CensysError(f"Censys response exceeded {limit:,} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _http_error(response: requests.Response, fingerprint: str) -> CensysError:
    status = response.status_code
    hints = {
        401: "authentication failed - check CENSYS_API_TOKEN",
        403: "access denied - the token lacks permission for this endpoint",
        404: f"certificate {fingerprint} not found in Censys",
        429: "rate limited by Censys (retries exhausted)",
    }
    detail = hints.get(status)
    if detail is None:
        snippet = " ".join(response.text[:200].split())
        detail = f"unexpected HTTP {status}" + (f": {snippet}" if snippet else "")
    return CensysError(f"Censys lookup failed: {detail}", status_code=status)


def fetch_certificate(
    fingerprint: str,
    token: str,
    *,
    session: requests.Session | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = API_BASE,
    max_bytes: int = MAX_RESPONSE_BYTES,
    organization_id: str | None = None,
) -> CertificateRecord:
    """Fetch one certificate by SHA-256 fingerprint and verify its identity."""
    fingerprint = normalize_fingerprint(fingerprint)
    params: dict[str, str] = {}
    if organization_id:
        if not _UUID_RE.fullmatch(organization_id):
            raise CensysError("--organization-id must be a UUID")
        params["organization_id"] = organization_id
    if not token:
        raise CensysError("no Censys token: set CENSYS_API_TOKEN")
    url = base_url.rstrip("/") + CERTIFICATE_RAW_PATH.format(certificate_id=fingerprint)
    owns_session = session is None
    session = session or build_session()
    source = f"Censys:{fingerprint}"
    try:
        try:
            response = session.get(
                url,
                headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT_HEADER},
                params=params,
                timeout=timeout,
                stream=True,
            )
        except requests.Timeout as exc:
            raise CensysError(f"Censys request timed out after {timeout:g}s") from exc
        except requests.RequestException as exc:
            raise CensysError(f"Censys request failed: {type(exc).__name__}") from exc
        with response:
            if response.status_code != 200:
                raise _http_error(response, fingerprint)
            body = _read_limited(response, max_bytes)
    finally:
        if owns_session:
            session.close()

    loaded = extract_certificates(body, source)
    for record in loaded.records:
        if record.fingerprint == fingerprint:
            record.source = source
            return record
    if loaded.records:
        found = ", ".join(r.fingerprint for r in loaded.records[:5])
        raise CensysError(
            f"Censys returned certificate(s) {found} but none match the requested "
            f"fingerprint {fingerprint}"
        )
    detail = loaded.errors[0] if loaded.errors else "empty response"
    raise CensysError(f"could not read a certificate from the Censys response ({detail})")
