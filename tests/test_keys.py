from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import helpers as h
from cert_key_auditor import keys
from cert_key_auditor.errors import InputError

FAST_CURVES = [
    ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1(), ec.SECP256K1(), ec.SECP224R1(), ec.SECP192R1(),
]  # fmt: skip


@pytest.mark.parametrize("curve", FAST_CURVES, ids=lambda c: c.name)
@pytest.mark.parametrize("scalar", [1, 2, 3, 1000, 1024, 99_999, 100_000])
def test_bsgs_finds_scalars_including_boundaries(curve: ec.EllipticCurve, scalar: int) -> None:
    result = keys.find_small_ec_private_scalar(h.ec_public(scalar, curve), 100_000)
    assert result.scalar == scalar
    assert result.method == "baby-step/giant-step"


@pytest.mark.parametrize("curve", FAST_CURVES, ids=lambda c: c.name)
def test_bsgs_does_not_match_outside_limit_or_random_keys(curve: ec.EllipticCurve) -> None:
    assert keys.find_small_ec_private_scalar(h.ec_public(100_001, curve), 100_000).scalar is None
    random_key = ec.generate_private_key(curve).public_key()
    assert keys.find_small_ec_private_scalar(random_key, 100_000).scalar is None


def test_bsgs_agrees_with_linear_search_on_small_limits() -> None:
    for scalar in (1, 7, 50, 64):
        public = h.ec_public(scalar)
        fast = keys.find_small_ec_private_scalar(public, 64)
        assert fast.scalar == scalar
    assert keys.find_small_ec_private_scalar(h.ec_public(65), 64).scalar is None


def test_limit_of_one() -> None:
    assert keys.find_small_ec_private_scalar(h.ec_public(1), 1).scalar == 1
    assert keys.find_small_ec_private_scalar(h.ec_public(2), 1).scalar is None


def test_large_limit_is_fast_enough() -> None:
    result = keys.find_small_ec_private_scalar(h.ec_public(123_456_789), 200_000_000)
    assert result.scalar == 123_456_789


@pytest.mark.parametrize("limit", [0, -1, keys.MAX_EC_SCALAR_LIMIT + 1])
def test_invalid_ec_limits(limit: int) -> None:
    with pytest.raises(ValueError):
        keys.find_small_ec_private_scalar(h.ec_public(5), limit)


def test_linear_fallback_for_other_curves_is_capped_with_note() -> None:
    curve = ec.BrainpoolP256R1()
    found = keys.find_small_ec_private_scalar(h.ec_public(500, curve), 1_000_000)
    assert found.scalar == 500 and found.method == "linear"
    assert found.note and "reduced" in found.note
    beyond = keys.find_small_ec_private_scalar(h.ec_public(5_000, curve), 1_000_000)
    assert beyond.scalar is None and beyond.searched == keys.LINEAR_EC_SCALAR_LIMIT


# ------------------------------------------------------------------- RSA


def test_primes_up_to() -> None:
    assert list(keys.primes_up_to(30)) == [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    assert len(keys.primes_up_to(1_000_000)) == 78_498
    assert len(keys.primes_up_to(1)) == 0


@pytest.mark.parametrize("bulk", [False, True])
def test_small_prime_screen(bulk: bool) -> None:
    screen = keys.SmallPrimeScreen(1_000_000, bulk=bulk)
    big_prime = 1_000_000_007
    assert screen.find(3 * big_prime) == 3
    assert screen.find(999_983 * big_prime) == 999_983
    assert screen.find(1_000_003 * big_prime) is None  # just above the limit
    assert screen.find(big_prime * 1_000_000_009) is None
    assert screen.find(2 * big_prime) == 2


def test_bulk_and_linear_screens_agree() -> None:
    linear = keys.SmallPrimeScreen(50_000)
    bulk = keys.SmallPrimeScreen(50_000, bulk=True)
    for modulus in (
        2**127 - 1,
        3 * 5 * 7**3 * 1_000_003,
        49_999 * 1_000_003,
        1_000_003 * 1_000_033,
    ):
        assert linear.find(modulus) == bulk.find(modulus)


def test_population_screen_chooses_bulk_mode() -> None:
    assert keys.SmallPrimeScreen.for_population(1_000_000, 100).bulk is True
    assert keys.SmallPrimeScreen.for_population(1_000_000, 2).bulk is False
    assert keys.SmallPrimeScreen.for_population(9_000_000, 1000).bulk is False


def test_screen_validation() -> None:
    with pytest.raises(ValueError):
        keys.SmallPrimeScreen(1)
    with pytest.raises(ValueError):
        keys.SmallPrimeScreen(keys.MAX_RSA_SMALL_PRIME_LIMIT + 1)
    with pytest.raises(ValueError):
        keys.SmallPrimeScreen(100).find(1)


def test_find_small_rsa_factor_wrapper() -> None:
    assert keys.find_small_rsa_factor(3 * (2**89 - 1), 100) == 3


# ------------------------------------------------------------- batch GCD


def test_batch_gcd_detects_shared_primes() -> None:
    p1, p2, p3, p4, p5 = 1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_081
    found = keys.batch_gcd([p1 * p2, p1 * p3, p4 * p5])
    assert set(found) == {p1 * p2, p1 * p3}
    assert found[p1 * p2] == p1 and found[p1 * p3] == p1


def test_batch_gcd_no_overlap_and_edge_sizes() -> None:
    assert keys.batch_gcd([]) == {}
    assert keys.batch_gcd([15]) == {}
    assert keys.batch_gcd([15, 15]) == {}  # identical moduli are de-duplicated
    assert keys.batch_gcd([1_000_003 * 1_000_033, 1_000_037 * 1_000_039]) == {}
    with pytest.raises(ValueError):
        keys.batch_gcd([1, 5])


def test_batch_gcd_with_real_sized_moduli() -> None:
    n1, n2, n3 = h.shared_factor_moduli()
    assert set(keys.batch_gcd([n1, n2, n3])) == {n1, n2}


def test_batch_gcd_odd_population_sizes() -> None:
    primes = [1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_081, 1_000_099, 1_000_117]
    moduli = [primes[i] * primes[(i + 1) % 7] for i in range(7)]
    assert len(keys.batch_gcd(moduli)) == 7


def test_pairwise_divisors() -> None:
    assert keys.pairwise_divisors(15, [15, 21, 35, 77]) == {21: 3, 35: 5}


# --------------------------------------------------------- weak list / ROCA


def test_known_weak_modulus_file(tmp_path: Path) -> None:
    path = tmp_path / "weak.txt"
    path.write_text("# comment\n\n12345\n0xFF\nabcdef  # inline\n  777  \n", encoding="utf-8")
    assert keys.load_known_weak_moduli(str(path)) == {12345, 0xFF, 0xABCDEF, 777}
    assert keys.load_known_weak_moduli(None) == set()


@pytest.mark.parametrize("content", ["not-a-number\n", "-5\n", "0\n"])
def test_known_weak_modulus_errors(tmp_path: Path, content: str) -> None:
    path = tmp_path / "weak.txt"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(InputError, match=r"weak\.txt:1"):
        keys.load_known_weak_moduli(str(path))
    with pytest.raises(InputError, match=r"cannot read"):
        keys.load_known_weak_moduli(str(tmp_path / "missing.txt"))


def test_known_weak_modulus_binary_file(tmp_path: Path) -> None:
    path = tmp_path / "bin.txt"
    path.write_bytes(b"\xff\xfe\x00\x80")
    with pytest.raises(InputError):
        keys.load_known_weak_moduli(str(path))


def test_roca_unavailable_is_distinguished_from_errors() -> None:
    detector, error = keys.load_roca_detector()
    if detector is None:
        assert error and "roca-detect" in error
    assert keys.check_roca(15, None) == (None, None)

    class Broken:
        def fprint(self, modulus: int) -> bool:
            raise RuntimeError("boom")

    result, message = keys.check_roca(15, Broken())
    assert result is None and message and "RuntimeError" in message

    class Positive:
        def fprint(self, modulus: int) -> bool:
            return True

    assert keys.check_roca(15, Positive()) == (True, None)
