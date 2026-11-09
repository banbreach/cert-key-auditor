from __future__ import annotations

import base64
from pathlib import Path

import pytest

import helpers as h
from cert_key_auditor import loaders
from cert_key_auditor.errors import InputError


def test_normalize_fingerprint_accepts_colons_and_case() -> None:
    raw = "AA:" * 31 + "BB"
    assert loaders.normalize_fingerprint(raw) == ("aa" * 31) + "bb"


@pytest.mark.parametrize("bad", ["", "abc", "zz" * 32, "aa" * 31, "aa" * 33])
def test_normalize_fingerprint_rejects_garbage(bad: str) -> None:
    with pytest.raises(InputError):
        loaders.normalize_fingerprint(bad)


def test_one_bad_block_does_not_discard_neighbours() -> None:
    """Review bug #2: good + garbage + good must yield both good certificates."""
    good1, good2 = h.build_cert(), h.build_cert()
    garbage = b"-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n"
    result = loaders.load_certificates(h.pem(good1) + garbage + h.pem(good2), "bundle.pem")
    assert [r.fingerprint for r in result.records] == [h.sha256_hex(good1), h.sha256_hex(good2)]
    assert len(result.errors) == 1
    assert "bundle.pem#pem2" in result.errors[0]


def test_invalid_base64_block_is_reported_not_raised() -> None:
    data = b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n"
    result = loaders.load_certificates(data, "x.pem")
    assert not result.records
    assert result.errors


def test_single_block_keeps_plain_source_label() -> None:
    result = loaders.load_certificates(h.pem(h.build_cert()), "one.pem")
    assert result.records[0].source == "one.pem"


def test_trusted_and_x509_labels_are_accepted() -> None:
    cert = h.build_cert()
    body = base64.b64encode(h.der(cert) + b"\x30\x03\x0c\x01aux-trust-data").decode()
    trusted = f"-----BEGIN TRUSTED CERTIFICATE-----\n{body}\n-----END TRUSTED CERTIFICATE-----\n"
    plain = base64.b64encode(h.der(cert)).decode()
    x509_label = f"-----BEGIN X509 CERTIFICATE-----\n{plain}\n-----END X509 CERTIFICATE-----\n"
    for data in (trusted, x509_label):
        result = loaders.load_certificates(data.encode(), "t.pem")
        assert [r.fingerprint for r in result.records] == [h.sha256_hex(cert)], result.errors


def test_der_input() -> None:
    cert = h.build_cert()
    result = loaders.load_certificates(h.der(cert), "c.der")
    assert result.records[0].fingerprint == h.sha256_hex(cert)


def test_pkcs7_der_and_pem_bundles() -> None:
    certs = [h.build_cert(), h.build_cert()]
    blob = h.pkcs7_der(*certs)
    der_result = loaders.load_certificates(blob, "b.p7b")
    assert {r.fingerprint for r in der_result.records} == {h.sha256_hex(c) for c in certs}
    pem_blob = b"-----BEGIN PKCS7-----\n" + base64.encodebytes(blob) + b"-----END PKCS7-----\n"
    pem_result = loaders.load_certificates(pem_blob, "b.p7b")
    assert len(pem_result.records) == 2


def test_garbage_is_an_error_not_an_exception() -> None:
    result = loaders.load_certificates(b"hello world", "junk.bin")
    assert not result.records
    assert "junk.bin" in result.errors[0]


def test_surrounding_text_is_ignored() -> None:
    cert = h.build_cert()
    data = b"Subject: whatever\nIssuer: foo\n" + h.pem(cert) + b"\ntrailing notes\n"
    assert len(loaders.load_certificates(data, "t").records) == 1


def test_trim_der_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        loaders.trim_der(b"\x31\x00")
    with pytest.raises(ValueError):
        loaders.trim_der(b"\x30\x05\x00")
    assert loaders.trim_der(b"\x30\x01\x05\x00\x00") == b"\x30\x01\x05"


def test_file_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "big.pem"
    path.write_bytes(b"x" * 100)
    with pytest.raises(InputError, match="limit"):
        loaders.read_input_file(path, max_bytes=50)


def test_load_files_isolates_failures(tmp_path: Path) -> None:
    good = tmp_path / "good.pem"
    good.write_bytes(h.pem(h.build_cert()))
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a certificate")
    result = loaders.load_files([str(good), str(bad), str(tmp_path / "missing.pem")])
    assert len(result.records) == 1
    assert len(result.errors) == 2


def test_directory_expansion_filters_suffixes(tmp_path: Path) -> None:
    (tmp_path / "a.pem").write_bytes(h.pem(h.build_cert()))
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.crt").write_bytes(h.pem(h.build_cert()))
    (tmp_path / "ignored.bin").write_bytes(h.pem(h.build_cert()))
    result = loaders.load_files([str(tmp_path)])
    assert len(result.records) == 2


def test_empty_directory_reports_error(tmp_path: Path) -> None:
    result = loaders.load_files([str(tmp_path)])
    assert not result.records
    assert "no certificate files" in result.errors[0]


def test_deduplicate_keeps_first_and_records_other_sources() -> None:
    cert = h.build_cert()
    one = loaders.load_certificates(h.pem(cert), "one.pem").records
    two = loaders.load_certificates(h.der(cert), "two.der").records
    unique = loaders.deduplicate(one + two)
    assert len(unique) == 1
    assert unique[0].source == "one.pem"
    assert unique[0].duplicates == ["two.der"]


def test_fingerprint_matches_independent_computation() -> None:
    cert = h.build_cert()
    record = loaders.load_certificates(h.pem(cert), "x").records[0]
    assert record.fingerprint == h.sha256_hex(cert)
