"""Public-key analysis primitives.

Nothing here recovers a private key from a certificate. The EC check asks
"is the public point equal to ``k*G`` for some tiny ``k``?", and the RSA
checks look for small prime factors or factors shared with other moduli.
A negative result is only ever a *bounded* result.
"""

from __future__ import annotations

import itertools
import math
import re
from array import array
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .errors import InputError

DEFAULT_EC_SCALAR_LIMIT = 1_000_000
MAX_EC_SCALAR_LIMIT = 1_000_000_000
LINEAR_EC_SCALAR_LIMIT = 4_096
DEFAULT_RSA_SMALL_PRIME_LIMIT = 1_000_000
MAX_RSA_SMALL_PRIME_LIMIT = 10_000_000
BULK_SCREEN_MIN_MODULI = 8
BULK_SCREEN_MAX_LIMIT = 5_000_000

# Field prime and ``a`` coefficient for the prime-field curves supported by the
# fast search. Everything else (G, b) is derived from ``cryptography`` itself
# and the result is self-checked before use.
_PRIME_CURVES: dict[str, tuple[int, int]] = {
    "secp192r1": (2**192 - 2**64 - 1, -3),
    "secp224r1": (2**224 - 2**96 + 1, -3),
    "secp256r1": (2**256 - 2**224 + 2**192 + 2**96 - 1, -3),
    "secp384r1": (2**384 - 2**128 - 2**96 + 2**32 - 1, -3),
    "secp521r1": (2**521 - 1, -3),
    "secp256k1": (2**256 - 2**32 - 977, 0),
}

Point = tuple[int, int] | None


# ---------------------------------------------------------------------------
# EC small-scalar search
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EcScalarResult:
    """Outcome of a bounded EC private-scalar search."""

    scalar: int | None
    searched: int
    method: str
    note: str | None = None


class _PrimeCurve:
    """Minimal affine short-Weierstrass arithmetic for BSGS."""

    def __init__(self, curve: ec.EllipticCurve) -> None:
        p, a = _PRIME_CURVES[curve.name]
        generator = ec.derive_private_key(1, curve).public_key().public_numbers()
        self.p = p
        self.a = a % p
        self.g: Point = (generator.x, generator.y)
        self.b = (generator.y**2 - generator.x**3 - self.a * generator.x) % p
        two = ec.derive_private_key(2, curve).public_key().public_numbers()
        if self.add(self.g, self.g) != (two.x, two.y):  # constants self-check
            raise ValueError(f"curve parameter self-check failed for {curve.name}")

    def add(self, first: Point, second: Point) -> Point:
        if first is None:
            return second
        if second is None:
            return first
        p = self.p
        x1, y1 = first
        x2, y2 = second
        if x1 == x2:
            if (y1 + y2) % p == 0:
                return None
            slope = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (slope * slope - x1 - x2) % p
        return x3, (slope * (x1 - x3) - y1) % p

    def negate(self, point: Point) -> Point:
        return None if point is None else (point[0], (-point[1]) % self.p)

    def multiply(self, scalar: int, point: Point) -> Point:
        result: Point = None
        addend = point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            scalar >>= 1
        return result


def _bsgs(curve: _PrimeCurve, target: tuple[int, int], limit: int) -> int | None:
    """Find ``k`` in ``[1, limit]`` with ``k*G == target`` in O(sqrt(limit))."""
    width = math.isqrt(limit) + 1
    baby: dict[tuple[int, int], int] = {}
    point = curve.g
    for index in range(1, width + 1):
        if point is None:  # k*G reached infinity: the group order is tiny; nothing to find
            return None
        baby.setdefault(point, index)
        point = curve.add(point, curve.g)
    giant = curve.negate(curve.multiply(width, curve.g))
    current: Point = target
    for step in range(limit // width + 2):
        if current is None:
            candidate = step * width
        elif current in baby:
            candidate = step * width + baby[current]
        else:
            current = curve.add(current, giant)
            continue
        if 1 <= candidate <= limit:
            return candidate
        current = curve.add(current, giant)
    return None


def find_small_ec_private_scalar(
    public_key: ec.EllipticCurvePublicKey,
    limit: int = DEFAULT_EC_SCALAR_LIMIT,
) -> EcScalarResult:
    """Search private scalars ``1..limit`` for one producing ``public_key``.

    Prime-field NIST/SEC curves use baby-step/giant-step (milliseconds even
    for large limits). Other curves fall back to a linear search that is
    capped at :data:`LINEAR_EC_SCALAR_LIMIT`.
    """
    if not 1 <= limit <= MAX_EC_SCALAR_LIMIT:
        raise ValueError(f"EC scalar limit must be between 1 and {MAX_EC_SCALAR_LIMIT:,}")
    numbers = public_key.public_numbers()
    curve = public_key.curve

    if curve.name in _PRIME_CURVES:
        try:
            prime_curve = _PrimeCurve(curve)
        except ValueError:
            prime_curve = None
        if prime_curve is not None:
            found = _bsgs(prime_curve, (numbers.x, numbers.y), limit)
            if found is not None and not _confirm(curve, found, numbers):
                found = None  # never report an unconfirmed match
            return EcScalarResult(found, limit, "baby-step/giant-step")

    effective = min(limit, LINEAR_EC_SCALAR_LIMIT)
    note = None
    if effective < limit:
        note = (
            f"curve {curve.name} has no fast search; limit reduced from {limit:,} to {effective:,}"
        )
    for scalar in range(1, effective + 1):
        try:
            candidate = ec.derive_private_key(scalar, curve).public_key().public_numbers()
        except ValueError:  # nosec - scalars >= group order are invalid by construction and skipped
            continue
        if candidate.x == numbers.x and candidate.y == numbers.y:
            return EcScalarResult(scalar, effective, "linear", note)
    return EcScalarResult(None, effective, "linear", note)


def _confirm(curve: ec.EllipticCurve, scalar: int, expected: Any) -> bool:
    actual = ec.derive_private_key(scalar, curve).public_key().public_numbers()
    return bool(actual.x == expected.x and actual.y == expected.y)


# ---------------------------------------------------------------------------
# RSA small-prime screening
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def primes_up_to(limit: int) -> array[int]:
    """Primes <= ``limit`` (sieve of Eratosthenes), compactly stored."""
    if limit < 2:
        return array("I")
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for prime in range(2, math.isqrt(limit) + 1):
        if sieve[prime]:
            start = prime * prime
            sieve[start : limit + 1 : prime] = bytes(((limit - start) // prime) + 1)
    return array("I", itertools.compress(range(limit + 1), sieve))


def _product(values: list[int]) -> int:
    numbers = list(values)
    while len(numbers) > 1:
        paired = [numbers[i] * numbers[i + 1] for i in range(0, len(numbers) - 1, 2)]
        if len(numbers) % 2:
            paired.append(numbers[-1])
        numbers = paired
    return numbers[0] if numbers else 1


class SmallPrimeScreen:
    """Find prime factors <= ``limit`` of RSA moduli.

    Per-modulus trial division is fastest for a handful of keys. For many keys
    ``bulk=True`` builds the product of all primes <= limit once and needs a
    single ``gcd`` per modulus.
    """

    def __init__(self, limit: int = DEFAULT_RSA_SMALL_PRIME_LIMIT, *, bulk: bool = False) -> None:
        if not 2 <= limit <= MAX_RSA_SMALL_PRIME_LIMIT:
            raise ValueError(f"RSA prime limit must be between 2 and {MAX_RSA_SMALL_PRIME_LIMIT:,}")
        self.limit = limit
        self.bulk = bulk
        self._product: int | None = None

    @classmethod
    def for_population(cls, limit: int, modulus_count: int) -> SmallPrimeScreen:
        bulk = modulus_count >= BULK_SCREEN_MIN_MODULI and limit <= BULK_SCREEN_MAX_LIMIT
        return cls(limit, bulk=bulk)

    def find(self, modulus: int) -> int | None:
        """Smallest prime factor <= limit, or ``None`` (a bounded result only)."""
        if modulus < 2:
            raise ValueError("RSA modulus must be >= 2")
        primes = primes_up_to(self.limit)
        if self.bulk:
            if self._product is None:
                self._product = _product(list(primes))
            shared = math.gcd(modulus, self._product)
            if shared == 1:
                return None
            for prime in primes:
                if shared % prime == 0:
                    return int(prime)
            return None  # pragma: no cover - shared > 1 implies a prime divides it
        for prime in primes:
            if modulus % prime == 0:
                return int(prime)
        return None


def find_small_rsa_factor(modulus: int, limit: int = DEFAULT_RSA_SMALL_PRIME_LIMIT) -> int | None:
    """Convenience wrapper: trial division by all primes <= ``limit``."""
    return SmallPrimeScreen(limit).find(modulus)


# ---------------------------------------------------------------------------
# Known-weak moduli and ROCA
# ---------------------------------------------------------------------------


def load_known_weak_moduli(path: str | None) -> set[int]:
    """Load known-weak RSA moduli (one per line, decimal or hex, ``#`` comments)."""
    if path is None:
        return set()
    moduli: set[int] = set()
    try:
        handle = Path(path).open("r", encoding="utf-8")  # noqa: SIM115 - closed below
    except OSError as exc:
        raise InputError(f"{path}: cannot read weak-modulus list ({exc.strerror or exc})") from exc
    with handle:
        try:
            for number, raw in enumerate(handle, start=1):
                value = raw.split("#", 1)[0].strip()
                if not value:
                    continue
                try:
                    hexish = value.lower().startswith("0x") or re.search(r"[a-fA-F]", value)
                    modulus = int(value, 16) if hexish else int(value, 10)
                except ValueError as exc:
                    raise InputError(f"{path}:{number}: invalid modulus {value[:40]!r}") from exc
                if modulus <= 0:
                    raise InputError(f"{path}:{number}: modulus must be positive")
                moduli.add(modulus)
        except UnicodeDecodeError as exc:
            raise InputError(f"{path}: not valid UTF-8 text") from exc
    return moduli


def load_roca_detector() -> tuple[Any, str | None]:
    """Load the optional ``roca-detect`` package. Returns ``(detector, error)``."""
    try:
        from roca.detect import DlogFprint  # type: ignore[import-not-found,unused-ignore]  # noqa: PLC0415

        return DlogFprint(), None
    except ImportError:
        return None, "roca-detect is not installed (pip install roca-detect)"
    except Exception as exc:  # optional dependency must never break the run
        return None, f"roca-detect failed to load: {type(exc).__name__}: {exc}"


def check_roca(modulus: int, detector: Any) -> tuple[bool | None, str | None]:
    """Return ``(fingerprint_detected, error)``; ``None`` means the check did not run."""
    if detector is None:
        return None, None
    try:
        return bool(detector.fprint(modulus)), None
    except Exception as exc:
        return None, f"ROCA check raised {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Batch GCD
# ---------------------------------------------------------------------------


def batch_gcd(moduli: list[int]) -> dict[int, int]:
    """Find RSA moduli sharing a nontrivial factor with the rest of the population.

    Product tree plus remainder tree: with ``P`` the product of all distinct
    moduli, ``gcd(N_i, (P mod N_i^2) // N_i)`` is > 1 exactly when ``N_i`` shares
    a factor with another modulus.
    """
    unique = sorted(set(moduli))
    if len(unique) < 2:
        return {}
    if unique[0] <= 1:
        raise ValueError("all RSA moduli must be greater than 1")

    levels: list[list[int]] = [unique]
    while len(levels[-1]) > 1:
        previous = levels[-1]
        current = [previous[i] * previous[i + 1] for i in range(0, len(previous) - 1, 2)]
        if len(previous) % 2:
            current.append(previous[-1])
        levels.append(current)

    remainders = levels[-1][:]
    for depth in range(len(levels) - 2, -1, -1):
        remainders = [
            remainders[index // 2] % (value * value) for index, value in enumerate(levels[depth])
        ]

    results: dict[int, int] = {}
    for modulus, remainder in zip(unique, remainders, strict=True):
        divisor = math.gcd(modulus, remainder // modulus)
        if divisor > 1:
            results[modulus] = divisor
    return results


def pairwise_divisors(modulus: int, others: list[int]) -> dict[int, int]:
    """Explain a batch-GCD hit equal to the whole modulus via pairwise GCDs."""
    explained: dict[int, int] = {}
    for other in others:
        if other == modulus:
            continue
        divisor = math.gcd(modulus, other)
        if divisor > 1:
            explained[other] = divisor
    return explained
