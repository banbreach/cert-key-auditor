from __future__ import annotations

import ipaddress
from datetime import datetime
from types import SimpleNamespace
from typing import ClassVar

import pytest
import requests
import responses
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import helpers as h
from cert_key_auditor import crl
from cert_key_auditor.errors import CrlError
from cert_key_auditor.models import CrlResult

PUBLIC = "http://93.184.216.34/ca.crl"  # IP literal: no DNS needed
NOW = h.utc(2026, 10, 3)


# ------------------------------------------------------------- URL validation


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/x.crl",
        "file:///etc/passwd",
        "http:///nohost",
        "http://user:pw@93.184.216.34/x.crl",
        "http://93.184.216.34:8080/x.crl",
        "http://127.0.0.1/x.crl",
        "http://10.0.0.5/x.crl",
        "http://169.254.169.254/latest/meta-data",
        "http://100.64.0.1/x.crl",
        "http://[::1]/x.crl",
        "http://[::ffff:127.0.0.1]/x.crl",
        "http://[::ffff:10.0.0.1]/x.crl",
        "http://[::ffff:169.254.169.254]/x.crl",
        "http://[64:ff9b::7f00:1]/x.crl",
        "http://[2002:7f00:1::]/x.crl",
        "http://localhost/x.crl",
        "http://93.184.216.34:99999/x.crl",
    ],
)
def test_dangerous_urls_are_rejected(url: str) -> None:
    with pytest.raises(CrlError) as info:
        crl.validate_crl_url(url)
    assert info.value.kind == "url"


@pytest.mark.parametrize(
    "url", [PUBLIC, "https://93.184.216.34/x.crl", "http://93.184.216.34:443/x"]
)
def test_public_urls_pass(url: str) -> None:
    crl.validate_crl_url(url)


def test_relaxation_flags() -> None:
    crl.validate_crl_url("http://10.0.0.5:8080/x.crl", allow_private=True, allow_any_port=True)
    with pytest.raises(CrlError, match="port"):
        crl.validate_crl_url("http://10.0.0.5:8080/x.crl", allow_private=True)
    with pytest.raises(CrlError, match="non-public"):
        crl.validate_crl_url("http://10.0.0.5/x.crl", allow_any_port=True)


def test_ipv4_mapped_is_unwrapped_even_if_interpreter_says_global(monkeypatch) -> None:
    """Pythons without the CVE-2024-4032 fix call ::ffff:127.0.0.1 'global'."""

    class Lenient(ipaddress.IPv6Address):
        is_global = True  # type: ignore[assignment]

    mapped = Lenient("::ffff:127.0.0.1")
    assert crl.is_public_address(mapped) is False


def test_dns_resolving_to_private_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(
        crl.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.168.1.10", 80))]
    )
    with pytest.raises(CrlError, match="non-public"):
        crl.validate_crl_url("http://crl.example.test/x.crl")


def test_dns_with_one_private_answer_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(
        crl.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 80)), (2, 1, 6, "", ("127.0.0.1", 80))],
    )
    with pytest.raises(CrlError):
        crl.validate_crl_url("http://crl.example.test/x.crl")


def test_dns_failure_is_reported(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise OSError("no such host")

    monkeypatch.setattr(crl.socket, "getaddrinfo", boom)
    with pytest.raises(CrlError, match="resolve"):
        crl.validate_crl_url("http://crl.example.test/x.crl")


# ----------------------------------------------------- distribution points


def test_distribution_uri_extraction() -> None:
    cert = h.build_cert(
        crl_urls=("http://a.example/x.crl", "ldap://dir/cn=x", "https://b.example/y.crl")
    )
    uris = crl.get_crl_distribution_uris(cert)
    assert uris.urls == ("http://a.example/x.crl", "https://b.example/y.crl")
    assert uris.unsupported == ("ldap://dir/cn=x",)


def test_no_extension_yields_nothing() -> None:
    assert crl.get_crl_distribution_uris(h.build_cert()) == crl.CrlUris()


@pytest.mark.parametrize(
    "exc", [x509.DuplicateExtension("dup", x509.CRLDistributionPoints.oid), ValueError("bad")]
)
def test_duplicate_or_malformed_extension_becomes_crl_error(exc: Exception) -> None:
    """Review bug #3: DuplicateExtension is not a ValueError and used to escape."""

    class Extensions:
        def get_extension_for_class(self, cls):
            raise exc

    fake = SimpleNamespace(extensions=Extensions())
    with pytest.raises(CrlError) as info:
        crl.get_crl_distribution_uris(fake)  # type: ignore[arg-type]
    assert info.value.kind == "parse"


def test_duplicate_crl_number_extension_is_tolerated() -> None:
    class Extensions:
        def get_extension_for_class(self, cls):
            raise x509.DuplicateExtension("dup", x509.CRLNumber.oid)

    fake = SimpleNamespace(extensions=Extensions())
    assert crl._crl_number(fake, x509.CRLNumber) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------- fetching


def fetcher(**kwargs) -> crl.CrlFetcher:
    return crl.CrlFetcher(crl.CrlOptions(**kwargs), now=lambda: NOW)


def leaf(serial: int = 12345, issuer: str = "Test Issuing CA"):
    return h.build_cert(serial=serial, issuer_cn=issuer, crl_urls=(PUBLIC,))


@responses.activate
def test_successful_fetch_populates_everything() -> None:
    data = h.build_crl(revoked=(1, 2, 3), number=42)
    responses.add(responses.GET, PUBLIC, body=data, status=200, content_type="application/pkix-crl")
    with fetcher() as f:
        result = f.fetch_for_certificate(PUBLIC, leaf())
    assert result.ok and result.error is None
    assert result.encoding == "DER"
    assert result.size_bytes == len(data)
    assert len(result.sha256 or "") == 64
    assert result.revoked_count == 3
    assert result.crl_number == 42
    assert result.http_status == 200
    assert result.content_type == "application/pkix-crl"
    assert result.issuer == "CN=Test Issuing CA"
    assert result.stale is False
    assert result.issuer_matches_certificate is True
    assert result.certificate_listed is False


@responses.activate
def test_pem_encoded_crl() -> None:
    data = h.build_crl(encoding=serialization.Encoding.PEM)
    responses.add(responses.GET, PUBLIC, body=data, status=200)
    with fetcher() as f:
        assert f.fetch_for_certificate(PUBLIC, leaf()).encoding == "PEM"


@responses.activate
def test_certificate_listed_in_crl() -> None:
    responses.add(responses.GET, PUBLIC, body=h.build_crl(revoked=(12345,)), status=200)
    with fetcher() as f:
        assert f.fetch_for_certificate(PUBLIC, leaf(12345)).certificate_listed is True


@responses.activate
def test_other_issuer_is_not_evaluated_for_listing() -> None:
    responses.add(responses.GET, PUBLIC, body=h.build_crl(revoked=(12345,)), status=200)
    with fetcher() as f:
        result = f.fetch_for_certificate(PUBLIC, leaf(12345, issuer="Some Other CA"))
    assert result.issuer_matches_certificate is False
    assert result.certificate_listed is None
    assert any("indirect" in note for note in result.notes)


@responses.activate
def test_stale_crl_and_missing_next_update() -> None:
    data = h.build_crl(last_update=h.utc(2026, 1, 1), next_update=h.utc(2026, 1, 8))
    responses.add(responses.GET, PUBLIC, body=data, status=200)
    with fetcher() as f:
        assert f.fetch_for_certificate(PUBLIC, leaf()).stale is True


@responses.activate
def test_results_are_cached_per_url_but_evaluated_per_certificate() -> None:
    responses.add(responses.GET, PUBLIC, body=h.build_crl(revoked=(111,)), status=200)
    with fetcher() as f:
        first = f.fetch_for_certificate(PUBLIC, leaf(111))
        second = f.fetch_for_certificate(PUBLIC, leaf(222))
    assert len(responses.calls) == 1
    assert first.from_cache is False and second.from_cache is True
    assert first.certificate_listed is True and second.certificate_listed is False
    assert first is not second


@responses.activate
def test_failures_are_cached_too() -> None:
    responses.add(responses.GET, PUBLIC, status=404)
    with fetcher() as f:
        a = f.fetch_for_certificate(PUBLIC, leaf())
        b = f.fetch_for_certificate(PUBLIC, leaf())
    assert len(responses.calls) == 1
    assert not a.ok and a.error_kind == "http" and a.http_status == 404
    assert b.from_cache


@responses.activate
@pytest.mark.parametrize(
    ("body", "kind"),
    [
        (requests.Timeout(), "timeout"),
        (requests.exceptions.SSLError("bad cert"), "tls"),
        (requests.ConnectionError("refused"), "connection"),
        (requests.RequestException("odd"), "request"),
    ],
)
def test_network_error_categories(body: Exception, kind: str) -> None:
    responses.add(responses.GET, PUBLIC, body=body)
    with fetcher() as f:
        result = f.fetch_for_certificate(PUBLIC, leaf())
    assert not result.ok
    assert result.error_kind == kind


@responses.activate
def test_garbage_and_empty_bodies() -> None:
    responses.add(responses.GET, PUBLIC, body=b"<html>not a crl</html>", status=200)
    with fetcher() as f:
        assert f.fetch_for_certificate(PUBLIC, leaf()).error_kind == "parse"
    other = "http://93.184.216.35/e.crl"
    responses.add(responses.GET, other, body=b"", status=200)
    with fetcher() as f:
        assert f.fetch_for_certificate(other, leaf()).error_kind == "empty"


@responses.activate
def test_oversized_download_is_refused() -> None:
    responses.add(
        responses.GET, PUBLIC, body=b"x" * 5000, status=200, headers={"Content-Length": "5000"}
    )
    with fetcher(max_bytes=1000) as f:
        result = f.fetch_for_certificate(PUBLIC, leaf())
    assert result.error_kind == "size"


def test_streamed_size_cap_without_content_length() -> None:
    class FakeResponse:
        headers: ClassVar[dict[str, str]] = {}

        def iter_content(self, chunk_size: int):
            yield b"a" * 600
            yield b"b" * 600

    with pytest.raises(CrlError) as info:
        crl._read_limited(FakeResponse(), 1000)  # type: ignore[arg-type]
    assert info.value.kind == "size"


@responses.activate
def test_unsafe_url_is_refused_without_a_request() -> None:
    with fetcher() as f:
        result = f.fetch_for_certificate("http://127.0.0.1/x.crl", leaf())
    assert result.error_kind == "url"
    assert len(responses.calls) == 0


@responses.activate
def test_redirects_refused_by_default() -> None:
    responses.add(
        responses.GET, PUBLIC, status=302, headers={"Location": "http://93.184.216.40/real.crl"}
    )
    with fetcher() as f:
        result = f.fetch_for_certificate(PUBLIC, leaf())
    assert result.error_kind == "redirect"
    assert "--follow-crl-redirects" in (result.error or "")
    assert len(responses.calls) == 1


@responses.activate
def test_redirects_followed_when_enabled() -> None:
    target = "https://93.184.216.40/real.crl"
    responses.add(responses.GET, PUBLIC, status=301, headers={"Location": target})
    responses.add(responses.GET, target, body=h.build_crl(), status=200)
    with fetcher(follow_redirects=True) as f:
        result = f.fetch_for_certificate(PUBLIC, leaf())
    assert result.ok
    assert result.redirects == [target]
    assert result.final_url == target


@responses.activate
def test_relative_redirect_is_resolved() -> None:
    responses.add(responses.GET, PUBLIC, status=302, headers={"Location": "/other.crl"})
    responses.add(responses.GET, "http://93.184.216.34/other.crl", body=h.build_crl(), status=200)
    with fetcher(follow_redirects=True) as f:
        assert f.fetch_for_certificate(PUBLIC, leaf()).ok


@responses.activate
def test_every_redirect_hop_is_revalidated() -> None:
    responses.add(
        responses.GET,
        PUBLIC,
        status=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data"},
    )
    with fetcher(follow_redirects=True) as f:
        result = f.fetch_for_certificate(PUBLIC, leaf())
    assert result.error_kind == "url"
    assert len(responses.calls) == 1


@responses.activate
def test_https_to_http_downgrade_is_refused() -> None:
    start = "https://93.184.216.34/ca.crl"
    responses.add(
        responses.GET, start, status=302, headers={"Location": "http://93.184.216.40/x.crl"}
    )
    with fetcher(follow_redirects=True) as f:
        result = f.fetch_for_certificate(start, leaf())
    assert result.error_kind == "redirect"
    assert "downgrade" in (result.error or "")


@responses.activate
def test_redirect_hop_cap() -> None:
    for index in range(6):
        responses.add(
            responses.GET,
            f"http://93.184.216.{50 + index}/c.crl",
            status=302,
            headers={"Location": f"http://93.184.216.{51 + index}/c.crl"},
        )
    with fetcher(follow_redirects=True, max_redirects=2) as f:
        result = f.fetch_for_certificate("http://93.184.216.50/c.crl", leaf())
    assert result.error_kind == "redirect"
    assert "more than 2" in (result.error or "")


@responses.activate
def test_unexpected_exception_is_contained(monkeypatch) -> None:
    responses.add(responses.GET, PUBLIC, body=h.build_crl(), status=200)

    def explode(*args, **kwargs):
        raise RuntimeError("parser bug")

    monkeypatch.setattr(crl, "describe_crl", explode)
    with fetcher() as f:
        result = f.fetch_for_certificate(PUBLIC, leaf())
    assert result.ok  # parse succeeded; metadata is best-effort
    assert any("metadata incomplete" in note for note in result.notes)

    monkeypatch.setattr(crl, "parse_crl", explode)
    with fetcher() as f:
        failed = f.fetch_for_certificate(PUBLIC, leaf())
    assert not failed.ok and "RuntimeError" in (failed.error or "")


def test_describe_crl_handles_datetime_types() -> None:
    parsed, _ = crl.parse_crl(h.build_crl())
    result = CrlResult(url="x")
    crl.describe_crl(parsed, result, NOW)
    assert isinstance(result.this_update, datetime)
    assert result.this_update.tzinfo is not None
