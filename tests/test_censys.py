from __future__ import annotations

import base64
import json

import pytest
import responses

import helpers as h
from cert_key_auditor import censys
from cert_key_auditor.errors import CensysError


def url_for(fingerprint: str) -> str:
    return f"{censys.API_BASE}/v3/global/asset/certificate/{fingerprint}/raw"


@pytest.fixture
def cert():
    return h.build_cert()


def test_json_with_pem_string_is_parsed(cert) -> None:
    """Review bug #1: PEM inside a JSON string must be decoded before parsing."""
    body = json.dumps({"result": {"pem": h.pem(cert).decode()}}).encode()
    assert b"\\n" in body  # newlines are escaped in the raw bytes
    result = censys.extract_certificates(body, "t")
    assert [r.fingerprint for r in result.records] == [h.sha256_hex(cert)]
    assert not result.errors


def test_json_hex_der_in_raw_field(cert) -> None:
    body = json.dumps({"raw": h.der(cert).hex()}).encode()
    assert censys.extract_certificates(body, "t").records[0].fingerprint == h.sha256_hex(cert)


def test_json_base64_der(cert) -> None:
    body = json.dumps({"data": {"der": base64.b64encode(h.der(cert)).decode()}}).encode()
    assert censys.extract_certificates(body, "t").records[0].fingerprint == h.sha256_hex(cert)


def test_json_list_of_pems_is_deduplicated(cert) -> None:
    text = h.pem(cert).decode()
    body = json.dumps([{"pem": text}, {"certificate": text}]).encode()
    assert len(censys.extract_certificates(body, "t").records) == 1


def test_json_without_certificate_data_is_an_error() -> None:
    result = censys.extract_certificates(b'{"status": "ok", "count": 0}', "t")
    assert not result.records
    assert "no certificate data" in result.errors[0]


def test_direct_pem_and_der(cert) -> None:
    assert len(censys.extract_certificates(h.pem(cert), "t").records) == 1
    assert len(censys.extract_certificates(h.der(cert), "t").records) == 1


def test_bom_prefixed_json(cert) -> None:
    body = b"\xef\xbb\xbf" + json.dumps({"pem": h.pem(cert).decode()}).encode()
    assert len(censys.extract_certificates(body, "t").records) == 1


@responses.activate
def test_fetch_success_pem(cert) -> None:
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, url_for(fp), body=h.pem(cert), status=200)
    record = censys.fetch_certificate(fp.upper(), "tok")
    assert record.fingerprint == fp
    assert record.source == f"Censys:{fp}"
    request = responses.calls[0].request
    assert request.headers["Authorization"] == "Bearer tok"
    assert "application/x-pem-file" in request.headers["Accept"]


@responses.activate
def test_fetch_success_json_wrapper(cert) -> None:
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, url_for(fp), json={"pem": h.pem(cert).decode()}, status=200)
    assert censys.fetch_certificate(fp, "tok").fingerprint == fp


@responses.activate
def test_fetch_picks_requested_certificate_from_chain(cert) -> None:
    other = h.build_cert()
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, url_for(fp), body=h.pem(other, cert), status=200)
    assert censys.fetch_certificate(fp, "tok").fingerprint == fp


@responses.activate
def test_fingerprint_mismatch_is_rejected(cert) -> None:
    other = h.build_cert()
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, url_for(fp), body=h.pem(other), status=200)
    with pytest.raises(CensysError, match="none match"):
        censys.fetch_certificate(fp, "tok")


@responses.activate
@pytest.mark.parametrize(
    ("status", "text"),
    [
        (401, "authentication"),
        (403, "access denied"),
        (404, "not found"),
        (429, "rate limited"),
        (500, "HTTP 500"),
    ],
)
def test_http_errors_have_helpful_messages(status: int, text: str) -> None:
    fp = "ab" * 32
    responses.add(responses.GET, url_for(fp), body="secret-token-xyz in body?", status=status)
    with pytest.raises(CensysError) as info:
        censys.fetch_certificate(fp, "secret-token-xyz")
    assert text in str(info.value)
    assert info.value.status_code == status
    assert "Bearer" not in str(info.value)


@responses.activate
def test_network_failure_is_wrapped() -> None:
    import requests

    fp = "ab" * 32
    responses.add(responses.GET, url_for(fp), body=requests.ConnectionError("boom token=SECRET"))
    with pytest.raises(CensysError) as info:
        censys.fetch_certificate(fp, "tok")
    assert "SECRET" not in str(info.value)

    responses.replace(responses.GET, url_for(fp), body=requests.Timeout())
    with pytest.raises(CensysError, match="timed out"):
        censys.fetch_certificate(fp, "tok", timeout=2)


@responses.activate
def test_oversized_response_is_rejected(cert) -> None:
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, url_for(fp), body=b"x" * 5000, status=200)
    with pytest.raises(CensysError, match=r"exceeded|too large"):
        censys.fetch_certificate(fp, "tok", max_bytes=1000)


@responses.activate
def test_organization_id_is_sent_and_validated(cert) -> None:
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, url_for(fp), body=h.pem(cert), status=200)
    org = "123e4567-e89b-12d3-a456-426614174000"
    censys.fetch_certificate(fp, "tok", organization_id=org)
    assert f"organization_id={org}" in responses.calls[0].request.url
    with pytest.raises(CensysError, match="UUID"):
        censys.fetch_certificate(fp, "tok", organization_id="x&admin=1")


def test_missing_token_and_bad_fingerprint() -> None:
    with pytest.raises(CensysError, match="token"):
        censys.fetch_certificate("ab" * 32, "")
    with pytest.raises(Exception, match="fingerprint"):
        censys.fetch_certificate("nothex", "tok")


def test_session_retries_rate_limits_and_server_errors() -> None:
    session = censys.build_session(retries=4)
    retry = session.get_adapter("https://api.platform.censys.io").max_retries
    assert retry.total == 4
    assert 429 in retry.status_forcelist
    assert 503 in retry.status_forcelist
    assert retry.respect_retry_after_header
