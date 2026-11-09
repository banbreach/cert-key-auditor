"""CRL discovery, defensive fetching and parsing.

Certificates are untrusted input and their CRL Distribution Points are
attacker-controlled URLs, so fetching them is an SSRF surface. Defences:

* only ``http``/``https``; no embedded credentials; ports limited to 80/443
  unless explicitly relaxed;
* the hostname is resolved and every address must be globally routable
  (IPv4-mapped IPv6, 6to4, Teredo and NAT64 forms are checked or rejected);
* redirects are refused by default; when enabled every hop is re-validated,
  hops are capped and an HTTPS->HTTP downgrade is refused;
* proxies from the environment are ignored, TLS verification is never
  disabled and downloads are size-capped (``Content-Length`` and streamed).

IMPORTANT: DNS resolution here and the connection made by ``requests`` are
separate lookups, so a hostile DNS server could still answer differently the
second time (TOCTOU / DNS rebinding). Use network egress controls when
processing untrusted certificates.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import logging
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import requests
from cryptography import x509

from . import __version__
from .errors import CrlError
from .models import CrlResult

LOGGER = logging.getLogger(__name__)

DEFAULT_MAX_CRL_BYTES = 20 * 1024 * 1024
DEFAULT_TIMEOUT = 20.0
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_ALLOWED_PORTS = frozenset({80, 443})
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


@dataclass(frozen=True)
class CrlOptions:
    """Behaviour switches for CRL retrieval."""

    timeout: float = DEFAULT_TIMEOUT
    max_bytes: int = DEFAULT_MAX_CRL_BYTES
    allow_private_urls: bool = False
    allow_any_port: bool = False
    follow_redirects: bool = False
    max_redirects: int = DEFAULT_MAX_REDIRECTS


@dataclass(frozen=True)
class CrlUris:
    """HTTP(S) and unsupported CRL distribution-point URIs of a certificate."""

    urls: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()


def get_crl_distribution_uris(certificate: x509.Certificate) -> CrlUris:
    """Extract CRL URLs from the certificate.

    Raises :class:`CrlError` (kind ``parse``) if the extension is malformed or
    duplicated; a missing extension simply yields no URLs.
    """
    try:
        extension = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return CrlUris()
    except (x509.DuplicateExtension, ValueError) as exc:
        raise CrlError(f"malformed CRL Distribution Points extension: {exc}", kind="parse") from exc

    urls: list[str] = []
    unsupported: list[str] = []
    for point in extension.value:
        for name in point.full_name or ():
            if not isinstance(name, x509.UniformResourceIdentifier):
                continue
            uri = name.value.strip()
            if not uri:
                continue
            bucket = urls if urlsplit(uri).scheme.lower() in ("http", "https") else unsupported
            if uri not in bucket:
                bucket.append(uri)
    return CrlUris(tuple(urls), tuple(unsupported))


def is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable addresses.

    Interpreters without the CVE-2024-4032 fix report IPv4-mapped IPv6
    loopback/private addresses as global, so those are unwrapped explicitly.
    """
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return is_public_address(address.ipv4_mapped)
        if address.sixtofour is not None or address.teredo is not None:
            return False
        if address in _NAT64:
            return False
    return bool(address.is_global)


def validate_crl_url(
    url: str,
    *,
    allow_private: bool = False,
    allow_any_port: bool = False,
) -> None:
    """Reject URLs the tool must not fetch. Raises :class:`CrlError` (kind ``url``)."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise CrlError(f"invalid CRL URL: {exc}", kind="url") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise CrlError("only HTTP and HTTPS CRL URLs are supported", kind="url")
    hostname = parsed.hostname
    if not hostname:
        raise CrlError("CRL URL has no hostname", kind="url")
    if parsed.username is not None or parsed.password is not None:
        raise CrlError("CRL URLs with embedded credentials are rejected", kind="url")

    effective_port = port or (443 if scheme == "https" else 80)
    if not allow_any_port and effective_port not in DEFAULT_ALLOWED_PORTS:
        raise CrlError(
            f"CRL URL port {effective_port} is not 80/443 "
            "(use --allow-nonstandard-crl-ports to permit it)",
            kind="url",
        )
    if allow_private:
        return

    try:
        addresses = {ipaddress.ip_address(hostname)}
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, effective_port, type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(info[4][0]) for info in infos}
        except (OSError, ValueError) as exc:
            raise CrlError(f"could not resolve CRL host {hostname!r}: {exc}", kind="url") from exc
    if not addresses:
        raise CrlError(f"no addresses resolved for {hostname!r}", kind="url")
    blocked = sorted(str(a) for a in addresses if not is_public_address(a))
    if blocked:
        raise CrlError(
            "CRL host resolves to a non-public address "
            f"({', '.join(blocked)}); use --allow-private-crl-urls only inside a "
            "trusted internal PKI",
            kind="url",
        )


def _read_limited(response: requests.Response, maximum: int) -> bytes:
    declared = response.headers.get("Content-Length", "")
    if declared.isdigit() and int(declared) > maximum:
        raise CrlError(
            f"CRL Content-Length ({int(declared):,} bytes) exceeds the {maximum:,}-byte limit",
            kind="size",
        )
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > maximum:
            raise CrlError(f"CRL download exceeded the {maximum:,}-byte limit", kind="size")
        chunks.append(chunk)
    return b"".join(chunks)


def parse_crl(data: bytes) -> tuple[x509.CertificateRevocationList, str]:
    """Parse DER (preferred) or PEM CRL data. Returns ``(crl, encoding)``."""
    if not data:
        raise CrlError("CRL response body is empty", kind="empty")
    try:
        return x509.load_der_x509_crl(data), "DER"
    except ValueError:  # nosec - deliberate DER-then-PEM fallback; failure of both raises CrlError
        pass
    try:
        return x509.load_pem_x509_crl(data), "PEM"
    except ValueError as exc:
        raise CrlError("content is neither a DER nor a PEM CRL", kind="parse") from exc


def _crl_number(crl: x509.CertificateRevocationList, extension: type) -> int | None:
    try:
        return int(crl.extensions.get_extension_for_class(extension).value.crl_number)
    except x509.ExtensionNotFound:
        return None
    except (x509.DuplicateExtension, ValueError, AttributeError):
        return None


def describe_crl(
    crl: x509.CertificateRevocationList,
    result: CrlResult,
    now: datetime,
) -> None:
    """Populate the descriptive fields of ``result`` from a parsed CRL."""
    result.issuer = crl.issuer.rfc4514_string()
    result.signature_algorithm_oid = crl.signature_algorithm_oid.dotted_string
    result.this_update = crl.last_update_utc
    next_update = crl.next_update_utc
    result.next_update = next_update
    if next_update is None:
        result.notes.append("CRL has no nextUpdate field")
    else:
        result.stale = next_update < now
    try:
        result.revoked_count = len(crl)
    except ValueError as exc:
        result.notes.append(f"revoked-certificate list unreadable ({exc})")
    result.crl_number = _crl_number(crl, x509.CRLNumber)
    result.delta_base_crl_number = _crl_number(crl, x509.DeltaCRLIndicator)


def evaluate_for_certificate(
    result: CrlResult,
    crl: x509.CertificateRevocationList,
    certificate: x509.Certificate,
) -> None:
    """Fill in certificate-specific fields (issuer match, listed in CRL).

    The CRL signature is **not** verified, so ``certificate_listed`` is
    informational: a hostile or stale CRL can omit or add serials.
    """
    result.issuer_matches_certificate = crl.issuer == certificate.issuer
    if not result.issuer_matches_certificate:
        result.notes.append("CRL issuer differs from the certificate issuer (indirect CRL?)")
        return
    if result.delta_base_crl_number is not None:
        result.notes.append("delta CRL: absence of the serial is not meaningful")
        return
    try:
        result.certificate_listed = (
            crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None
        )
    except ValueError as exc:
        result.notes.append(f"could not search the revoked list ({exc})")


class CrlFetcher:
    """Fetch CRLs once per URL and share results across certificates."""

    def __init__(
        self,
        options: CrlOptions | None = None,
        *,
        now: Callable[[], datetime] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.options = options or CrlOptions()
        self._now = now or (lambda: datetime.now(UTC))
        self._session = session or requests.Session()
        self._session.trust_env = False
        self._cache: dict[str, tuple[CrlResult, x509.CertificateRevocationList | None]] = {}

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> CrlFetcher:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def fetch_for_certificate(self, url: str, certificate: x509.Certificate) -> CrlResult:
        """Return the (possibly cached) CRL result evaluated for ``certificate``."""
        cached = self._cache.get(url)
        from_cache = cached is not None
        if cached is None:
            cached = self._download(url)
            self._cache[url] = cached
        base, crl = cached
        result = copy.deepcopy(base)
        result.from_cache = from_cache
        if crl is not None:
            evaluate_for_certificate(result, crl, certificate)
        return result

    def _download(self, url: str) -> tuple[CrlResult, x509.CertificateRevocationList | None]:
        result = CrlResult(url=url)
        try:
            data = self._get(url, result)
            crl, encoding = parse_crl(data)
        except CrlError as exc:
            result.error_kind = exc.kind
            result.error = str(exc)
            LOGGER.debug("CRL %s failed (%s): %s", url, exc.kind, exc)
            return result, None
        except Exception as exc:  # defensive: one malformed CRL must not end the run
            LOGGER.debug("CRL %s unexpected error", url, exc_info=True)
            result.error_kind = "request"
            result.error = f"unexpected {type(exc).__name__}: {exc}"
            return result, None
        result.encoding = encoding
        result.size_bytes = len(data)
        result.sha256 = hashlib.sha256(data).hexdigest()
        try:
            describe_crl(crl, result, self._now())
        except Exception as exc:  # parsing succeeded; metadata is best-effort
            LOGGER.debug("CRL %s metadata error", url, exc_info=True)
            result.notes.append(f"metadata incomplete ({type(exc).__name__}: {exc})")
        result.ok = True
        return result, crl

    def _get(self, url: str, result: CrlResult) -> bytes:
        opts = self.options
        current = url
        headers = {
            "Accept": "application/pkix-crl, application/x-pkcs7-crl;q=0.9, */*;q=0.1",
            "User-Agent": f"cert-key-auditor/{__version__}",
        }
        for hop in range(opts.max_redirects + 1):
            validate_crl_url(
                current,
                allow_private=opts.allow_private_urls,
                allow_any_port=opts.allow_any_port,
            )
            try:
                response = self._session.get(
                    current,
                    headers=headers,
                    timeout=opts.timeout,
                    stream=True,
                    allow_redirects=False,
                )
            except requests.Timeout as exc:
                raise CrlError(f"timed out after {opts.timeout:g}s", kind="timeout") from exc
            except requests.exceptions.SSLError as exc:
                raise CrlError(f"TLS error: {_brief(exc)}", kind="tls") from exc
            except requests.ConnectionError as exc:
                raise CrlError(f"connection failed: {_brief(exc)}", kind="connection") from exc
            except requests.RequestException as exc:
                raise CrlError(f"request failed: {_brief(exc)}", kind="request") from exc

            with response:
                result.http_status = response.status_code
                result.content_type = response.headers.get("Content-Type")
                location = response.headers.get("Location")
                if response.is_redirect and location:
                    target = urljoin(current, location)
                    if not opts.follow_redirects:
                        raise CrlError(
                            f"redirect to {target} refused (use --follow-crl-redirects)",
                            kind="redirect",
                        )
                    if hop >= opts.max_redirects:
                        raise CrlError(f"more than {opts.max_redirects} redirects", kind="redirect")
                    if (
                        urlsplit(current).scheme.lower() == "https"
                        and urlsplit(target).scheme.lower() == "http"
                    ):
                        raise CrlError("refusing HTTPS to HTTP redirect downgrade", kind="redirect")
                    result.redirects.append(target)
                    current = target
                    continue
                if response.status_code != 200:
                    raise CrlError(f"HTTP {response.status_code}", kind="http")
                result.final_url = current
                return _read_limited(response, opts.max_bytes)
        raise CrlError("redirect loop", kind="redirect")  # pragma: no cover


def _brief(exc: BaseException, limit: int = 160) -> str:
    text = " ".join(str(exc).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
