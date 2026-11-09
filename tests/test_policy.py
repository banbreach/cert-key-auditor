from __future__ import annotations

import datetime as dt

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

import helpers as h
from cert_key_auditor import policy
from cert_key_auditor.models import KeyInfo, Severity

DAY = dt.timedelta(days=1)


# ------------------------------------------------------ schedule boundaries


@pytest.mark.parametrize(
    ("issued", "expected"),
    [
        (h.utc(2015, 1, 1), 398),
        (h.utc(2026, 3, 14, 23, 59, 59), 398),
        (h.utc(2026, 3, 15), 200),
        (h.utc(2026, 10, 31), 200),
        (h.utc(2027, 3, 14, 23, 59, 59), 200),
        (h.utc(2027, 3, 15), 100),
        (h.utc(2028, 12, 31), 100),
        (h.utc(2029, 3, 14, 23, 59, 59), 100),
        (h.utc(2029, 3, 15), 47),
        (h.utc(2035, 1, 1), 47),
    ],
)
def test_schedule_boundaries(issued: dt.datetime, expected: int) -> None:
    assert policy.max_validity_days(issued)[0] == expected


def leaf(not_before: dt.datetime, duration: dt.timedelta, **kwargs):
    return h.build_cert(not_before=not_before, duration=duration, **kwargs)


@pytest.mark.parametrize(
    ("issued", "limit"),
    [
        (h.utc(2026, 1, 1), 398),
        (h.utc(2026, 3, 15), 200),
        (h.utc(2027, 3, 15), 100),
        (h.utc(2029, 3, 15), 47),
    ],
)
def test_limit_edges_inclusive_and_elapsed(issued: dt.datetime, limit: int) -> None:
    # Exactly `limit` days elapsed: inclusive counting adds one second -> over.
    exactly = leaf(issued, limit * DAY)
    assert policy.evaluate_validity_policy(exactly, convention="elapsed").compliant is True
    assert policy.evaluate_validity_policy(exactly, convention="inclusive").compliant is False
    # One second less elapsed is compliant under both conventions.
    shorter = leaf(issued, limit * DAY - dt.timedelta(seconds=1))
    assert policy.evaluate_validity_policy(shorter, convention="inclusive").compliant is True
    # One day over is non-compliant under both.
    longer = leaf(issued, (limit + 1) * DAY)
    assert policy.evaluate_validity_policy(longer, convention="elapsed").compliant is False


def test_typical_ninety_day_certificate_is_compliant_after_2026() -> None:
    result = policy.evaluate_validity_policy(leaf(h.utc(2026, 4, 1), 90 * DAY))
    assert result.applicable and result.compliant and result.max_days == 200
    assert policy.validity_policy_findings(result) == []


def test_398_day_certificate_issued_in_2026_is_flagged_high() -> None:
    result = policy.evaluate_validity_policy(leaf(h.utc(2026, 4, 1), 398 * DAY))
    findings = policy.validity_policy_findings(result)
    assert [f.code for f in findings] == ["VALIDITY_EXCEEDS_POLICY"]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].details["max_days"] == 200


def test_pre_2020_long_certificate_is_downgraded_to_historical_low() -> None:
    result = policy.evaluate_validity_policy(leaf(h.utc(2019, 6, 1), 800 * DAY))
    assert result.legacy_period and result.compliant is False
    finding = policy.validity_policy_findings(result)[0]
    assert finding.severity is Severity.LOW
    assert "825" in finding.message


def test_2021_certificate_over_398_days_is_still_high() -> None:
    result = policy.evaluate_validity_policy(leaf(h.utc(2021, 1, 1), 500 * DAY))
    assert policy.validity_policy_findings(result)[0].severity is Severity.HIGH


# ------------------------------------------------------------ applicability


def test_applicability_rules() -> None:
    long = 500 * DAY
    ca = leaf(h.utc(2026, 4, 1), long, ca=True, server_auth=False, san=None)
    assert not policy.evaluate_validity_policy(ca).applicable
    assert "CA" in policy.evaluate_validity_policy(ca, mode="yes").reason

    selfsigned = leaf(h.utc(2026, 4, 1), long, issuer_cn=None)
    assert not policy.evaluate_validity_policy(selfsigned).applicable
    assert policy.evaluate_validity_policy(selfsigned, mode="yes").applicable

    no_eku = leaf(h.utc(2026, 4, 1), long, server_auth=False)
    assert not policy.evaluate_validity_policy(no_eku).applicable
    assert policy.evaluate_validity_policy(no_eku, mode="yes").compliant is False

    normal = leaf(h.utc(2026, 4, 1), long)
    assert not policy.evaluate_validity_policy(normal, mode="no").applicable


def test_invalid_modes_rejected() -> None:
    cert = leaf(h.utc(2026, 4, 1), DAY)
    with pytest.raises(ValueError):
        policy.evaluate_validity_policy(cert, mode="maybe")
    with pytest.raises(ValueError):
        policy.evaluate_validity_policy(cert, convention="odd")


# ------------------------------------------------------------ attributes


def test_serial_hex_is_zero_padded() -> None:
    assert policy.format_serial_hex(0xABC) == "0ABC"
    assert policy.format_serial_hex(0xAB) == "AB"
    assert policy.format_serial_hex(1) == "01"


def test_serial_findings() -> None:
    assert policy.serial_findings(2**158) == []
    assert policy.serial_findings(2**159 - 1) == []
    assert policy.serial_findings(2**160)[0].code == "SERIAL_INVALID"
    assert policy.serial_findings(0)[0].code == "SERIAL_INVALID"


def test_describe_public_keys() -> None:
    ec_info = policy.describe_public_key(ec.generate_private_key(ec.SECP384R1()).public_key())
    assert (ec_info.algorithm, ec_info.curve, ec_info.bits) == ("EC", "secp384r1", 384)
    assert not ec_info.type_name.startswith("_")
    rsa_info = policy.describe_public_key(h.rsa_public(2**2047 + 1, 3))
    assert (rsa_info.algorithm, rsa_info.bits, rsa_info.rsa_exponent) == ("RSA", 2048, 3)
    assert (
        policy.describe_public_key(ed25519.Ed25519PrivateKey.generate().public_key()).algorithm
        == "Ed25519"
    )


def test_san_and_eku_extraction() -> None:
    cert = h.build_cert(san=("a.example", "b.example"))
    dns, ips, other = policy.subject_alt_names(cert)
    assert dns == ["a.example", "b.example"] and ips == [] and other == 0
    assert policy.extended_key_usage_names(cert) == ["serverAuth"]
    assert policy.has_server_auth(cert)
    assert policy.is_ca(cert) is False
    bare = h.build_cert(san=None, server_auth=False)
    assert policy.subject_alt_names(bare) == ([], [], 0)
    assert policy.extended_key_usage_names(bare) == []


# --------------------------------------------------------------- findings


def codes(findings) -> list[str]:
    return [f.code for f in findings]


def test_weak_signature_hash() -> None:
    key = KeyInfo(algorithm="EC", bits=256, curve="secp256r1")
    assert codes(policy.algorithm_findings(key, "sha1", self_signed=False)) == [
        "WEAK_SIGNATURE_HASH"
    ]
    assert policy.algorithm_findings(key, "sha1", self_signed=True) == []
    assert policy.algorithm_findings(key, "sha256", self_signed=False) == []
    assert policy.signature_hash_name(h.build_cert(sig_hash=hashes.SHA384())) == "sha384"
    try:
        legacy = h.build_cert(sig_hash=hashes.SHA1())
    except UnsupportedAlgorithm:
        return  # this OpenSSL build refuses to sign with SHA-1
    assert policy.signature_hash_name(legacy) == "sha1"


@pytest.mark.parametrize(
    ("bits", "exponent", "expected"),
    [
        (512, 65537, [("RSA_SHORT_MODULUS", Severity.CRITICAL)]),
        (1024, 65537, [("RSA_SHORT_MODULUS", Severity.HIGH)]),
        (2048, 65537, []),
        (2048, 3, [("RSA_LOW_EXPONENT", Severity.MEDIUM)]),
        (2048, 17, [("RSA_LOW_EXPONENT", Severity.LOW)]),
        (2048, 4, [("RSA_LOW_EXPONENT", Severity.HIGH)]),
        (2048, 1_000_003, []),
    ],
)
def test_rsa_findings(bits: int, exponent: int, expected: list[tuple[str, Severity]]) -> None:
    key = KeyInfo(algorithm="RSA", bits=bits, rsa_exponent=exponent)
    got = [
        (f.code, f.severity) for f in policy.algorithm_findings(key, "sha256", self_signed=False)
    ]
    assert got == expected


def test_weak_ec_and_dsa() -> None:
    weak = KeyInfo(algorithm="EC", bits=192, curve="secp192r1")
    assert codes(policy.algorithm_findings(weak, None, self_signed=False)) == ["EC_WEAK_CURVE"]
    dsa = KeyInfo(algorithm="DSA", bits=1024)
    assert codes(policy.algorithm_findings(dsa, None, self_signed=False)) == ["DSA_SHORT_KEY"]


def test_time_findings() -> None:
    start, end = h.utc(2026, 1, 1), h.utc(2026, 4, 1)
    assert policy.time_findings(start, end, h.utc(2026, 2, 1)) == []
    assert codes(policy.time_findings(start, end, h.utc(2026, 5, 1))) == ["CERT_EXPIRED"]
    assert codes(policy.time_findings(start, end, h.utc(2025, 12, 1))) == ["CERT_NOT_YET_VALID"]
    assert codes(policy.time_findings(end, start, h.utc(2026, 2, 1))) == ["VALIDITY_INVALID"]


def test_missing_san() -> None:
    kwargs = {"ca": False, "self_signed": False, "eku": ["serverAuth"], "san_count": 0}
    assert codes(policy.missing_san_findings(**kwargs)) == ["MISSING_SAN"]
    assert policy.missing_san_findings(**{**kwargs, "san_count": 1}) == []
    assert policy.missing_san_findings(**{**kwargs, "ca": True}) == []
    assert policy.missing_san_findings(**{**kwargs, "self_signed": True}) == []
    assert policy.missing_san_findings(**{**kwargs, "eku": ["clientAuth"]}) == []


def test_validity_duration_rejects_inverted_interval() -> None:
    # Builders refuse inverted intervals, so exercise the guard through a stub.
    class Inverted:
        not_valid_before_utc = h.utc(2026, 5, 1)
        not_valid_after_utc = h.utc(2026, 4, 1)

    with pytest.raises(ValueError):
        policy.validity_duration_seconds(Inverted())  # type: ignore[arg-type]
    _ = rsa  # keep import used for key-type coverage above
