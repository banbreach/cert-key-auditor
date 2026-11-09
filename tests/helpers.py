"""Builders for synthetic certificates, CRLs, weak keys and PDFs (offline tests)."""

from __future__ import annotations

import datetime as dt
from functools import cache
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = dt.UTC


def utc(
    year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0
) -> dt.datetime:
    return dt.datetime(year, month, day, hour, minute, second, tzinfo=UTC)


def name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


@cache
def ca_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


CA_NAME = name("Test Issuing CA")


def build_cert(
    *,
    public_key: Any = None,
    signing_key: Any = None,
    subject_cn: str = "leaf.example.test",
    issuer_cn: str | None = "Test Issuing CA",
    not_before: dt.datetime | None = None,
    duration: dt.timedelta = dt.timedelta(days=90),
    san: tuple[str, ...] | None = ("leaf.example.test",),
    server_auth: bool = True,
    ca: bool = False,
    crl_urls: tuple[str, ...] = (),
    sig_hash: hashes.HashAlgorithm | None = None,
    serial: int | None = None,
    subject: x509.Name | None = None,
) -> x509.Certificate:
    """Build a certificate. ``issuer_cn=None`` makes it self-signed."""
    sign_with = signing_key
    if public_key is None:
        key = ec.generate_private_key(ec.SECP256R1())
        public_key = key.public_key()
        if sign_with is None and issuer_cn is None:
            sign_with = key
    if sign_with is None:
        sign_with = ca_key()
    subject_name = subject or name(subject_cn)
    issuer_name = subject_name if issuer_cn is None else name(issuer_cn)
    start = not_before or utc(2026, 4, 1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + duration)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(item) for item in san]), critical=False
        )
    if server_auth and not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    if crl_urls:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                    for url in crl_urls
                ]
            ),
            critical=False,
        )
    algorithm = sig_hash or hashes.SHA256()
    return builder.sign(sign_with, algorithm)


def pem(*certificates: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certificates)


def der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def sha256_hex(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def build_crl(
    *,
    issuer_cn: str = "Test Issuing CA",
    revoked: tuple[int, ...] = (),
    last_update: dt.datetime | None = None,
    next_update: dt.datetime | None = None,
    number: int | None = 1,
    encoding: serialization.Encoding = serialization.Encoding.DER,
) -> bytes:
    last = last_update or utc(2026, 10, 1)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name(issuer_cn))
        .last_update(last)
        .next_update(next_update or last + dt.timedelta(days=7))
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    for serial in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(last).build()
        )
    return builder.sign(ca_key(), hashes.SHA256()).public_bytes(encoding)


# ----------------------------------------------------------------- weak keys


def ec_public(scalar: int, curve: ec.EllipticCurve | None = None) -> ec.EllipticCurvePublicKey:
    return ec.derive_private_key(scalar, curve or ec.SECP256R1()).public_key()


def rsa_public(modulus: int, exponent: int = 65537) -> rsa.RSAPublicKey:
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


@cache
def rsa_primes() -> tuple[int, int, int, int, int, int]:
    """Six distinct ~1024-bit primes taken from freshly generated keys."""
    numbers = [rsa.generate_private_key(65537, 2048).private_numbers() for _ in range(3)]
    return (numbers[0].p, numbers[0].q, numbers[1].p, numbers[1].q, numbers[2].p, numbers[2].q)


def shared_factor_moduli() -> tuple[int, int, int]:
    """``(n1, n2, n3)``: n1 and n2 share a prime; n3 is unrelated."""
    p1, q1, _p2, q2, p3, q3 = rsa_primes()
    return p1 * q1, p1 * q2, p3 * q3


def roca_modulus(seed: int = 7) -> int:
    """A 1023-bit modulus whose primes have the ROCA structure ``k*M + 65537**a mod M``."""
    import random

    rng = random.Random(seed)

    def probably_prime(n: int, rounds: int = 24) -> bool:
        if n < 2:
            return False
        for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
            if n % small == 0:
                return n == small
        d, s = n - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(rounds):
            x = pow(rng.randrange(2, n - 1), d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    primes: list[int] = []
    candidate = 2
    while len(primes) < 39:  # primes up to 167
        if all(candidate % p for p in primes):
            primes.append(candidate)
        candidate += 1
    product = 1
    for prime in primes:
        product *= prime

    def roca_prime() -> int:
        kbits = 512 - product.bit_length()
        while True:
            k = rng.getrandbits(kbits) | (1 << (kbits - 1))
            value = k * product + pow(65537, rng.randrange(2, 400), product)
            if value.bit_length() == 512 and probably_prime(value):
                return value

    return roca_prime() * roca_prime()


# ------------------------------------------------------------------- PDFs


def pkcs7_der(*certificates: x509.Certificate) -> bytes:
    return pkcs7.serialize_certificates(list(certificates), serialization.Encoding.DER)


def make_pdf(
    path: Path,
    *,
    page_pem: tuple[x509.Certificate, ...] = (),
    attachments: dict[str, bytes] | None = None,
    signature: tuple[x509.Certificate, ...] = (),
    dss: tuple[x509.Certificate, ...] = (),
    encrypt: str | None = None,
) -> Path:
    """Create a PDF carrying certificates in the supported places."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        ByteStringObject,
        DecodedStreamObject,
        DictionaryObject,
        NameObject,
        NumberObject,
    )

    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)

    if page_pem:
        lines: list[str] = []
        for certificate in page_pem:
            lines.extend(pem(certificate).decode().splitlines())
        stream = DecodedStreamObject()
        body = ["BT", "/F1 6 Tf", "20 780 Td", "7 TL"]
        body.extend(f"({line}) '" for line in lines)
        body.append("ET")
        stream.set_data("\n".join(body).encode("latin-1"))
        font = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Courier"),
            }
        )
        page[NameObject("/Resources")] = DictionaryObject(
            {NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})}
        )
        page[NameObject("/Contents")] = writer._add_object(stream)

    for filename, data in (attachments or {}).items():
        writer.add_attachment(filename, data)

    if signature:
        blob = pkcs7_der(*signature)
        signature_dict = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Sig"),
                NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
                NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
                NameObject("/ByteRange"): ArrayObject([NumberObject(0)] * 4),
                NameObject("/Contents"): ByteStringObject(blob + b"\x00" * 256),
            }
        )
        sig_ref = writer._add_object(signature_dict)
        widget = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Annot"),
                NameObject("/Subtype"): NameObject("/Widget"),
                NameObject("/FT"): NameObject("/Sig"),
                NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
                NameObject("/V"): sig_ref,
            }
        )
        page[NameObject("/Annots")] = ArrayObject([writer._add_object(widget)])

    if dss:
        refs = []
        for certificate in dss:
            stream = DecodedStreamObject()
            stream.set_data(der(certificate))
            refs.append(writer._add_object(stream))
        writer._root_object[NameObject("/DSS")] = DictionaryObject(
            {NameObject("/Certs"): ArrayObject(refs)}
        )

    if encrypt:
        writer.encrypt(encrypt)
    with path.open("wb") as handle:
        writer.write(handle)
    return path
