from __future__ import annotations

import datetime as dt
import io

import pytest
import responses
from cryptography import x509

import helpers as h
from cert_key_auditor import policy, render
from cert_key_auditor.crl import CrlOptions
from cert_key_auditor.loaders import load_certificates
from cert_key_auditor.models import CertificateRecord, CertificateReport, Severity
from cert_key_auditor.report import (
    AuditContext,
    AuditOptions,
    audit_certificate,
    audit_records,
    print_certificate_metadata,
)

AS_OF = h.utc(2026, 5, 1)
CRL_URL = "http://93.184.216.34/ca.crl"


def record(cert: x509.Certificate, source: str = "test.pem") -> CertificateRecord:
    return CertificateRecord(cert, source)


def options(**kwargs) -> AuditOptions:
    kwargs.setdefault("as_of", AS_OF)
    kwargs.setdefault("check_roca", False)
    return AuditOptions(**kwargs)


def codes(report: CertificateReport) -> list[str]:
    return [f.code for f in report.findings]


# ---------------------------------------------- task 2: one object, one block


@responses.activate
def test_metadata_function_returns_object_containing_crl_results() -> None:
    responses.add(responses.GET, CRL_URL, body=h.build_crl(revoked=(5,), number=9), status=200)
    cert = h.build_cert(crl_urls=(CRL_URL,))
    opts = options(fetch_crl=True, crl=CrlOptions())
    context = AuditContext(opts, [record(cert)])
    try:
        report = print_certificate_metadata(record(cert), opts, context=context)
    finally:
        context.close()
    assert isinstance(report, CertificateReport)
    assert report.crl_status == "ok"
    assert report.crl_urls == [CRL_URL]
    assert len(report.crls) == 1 and report.crls[0].ok
    assert report.crls[0].crl_number == 9
    assert report.sha256 == h.sha256_hex(cert)
    assert report.serial_hex  # metadata is there too
    assert report.key_checks == []  # key checks are added by audit_certificate


@responses.activate
def test_stream_argument_prints_the_complete_block() -> None:
    responses.add(responses.GET, CRL_URL, body=h.build_crl(), status=200)
    cert = h.build_cert(crl_urls=(CRL_URL,))
    opts = options(fetch_crl=True)
    context = AuditContext(opts, [record(cert)])
    buffer = io.StringIO()
    try:
        print_certificate_metadata(record(cert), opts, context=context, stream=buffer)
    finally:
        context.close()
    text = buffer.getvalue()
    for expected in ("Source:", "Subject:", "SHA-256:", "CRL", CRL_URL, "Findings"):
        assert expected in text


def test_nothing_is_printed_without_a_stream(capsys) -> None:
    print_certificate_metadata(record(h.build_cert()), options())
    assert capsys.readouterr().out == ""


@responses.activate
def test_full_audit_renders_everything_for_a_certificate_in_one_block() -> None:
    """Metadata, key checks, policy, CRL and findings share one block per cert."""
    responses.add(responses.GET, CRL_URL, body=h.build_crl(revoked=(777,)), status=200)
    weak = h.build_cert(
        public_key=h.ec_public(99),
        serial=777,
        crl_urls=(CRL_URL,),
        subject_cn="weak.test",
        san=("weak.test",),
    )
    clean = h.build_cert(crl_urls=(CRL_URL,), subject_cn="clean.test", san=("clean.test",))
    run = audit_records(
        [record(weak, "weak.pem"), record(clean, "clean.pem")],
        options(fetch_crl=True, as_of=h.utc(2026, 10, 3)),
    )
    blocks = render.render_text(run).split(render.RULE)
    weak_block = next(b for b in blocks if "weak.pem" in b)
    clean_block = next(b for b in blocks if "clean.pem" in b)
    for expected in (
        "EC_SMALL_SCALAR",
        "CERT_LISTED_IN_CRL",
        "ec_small_scalar",
        CRL_URL,
        "Validity policy",
    ):
        assert expected in weak_block, expected
    assert "EC_SMALL_SCALAR" not in clean_block
    assert "CERT_LISTED_IN_CRL" not in clean_block


def test_findings_stay_with_their_own_certificate_header() -> None:
    """Review bug #4: a finding must not attach to the previous certificate."""
    expired = h.build_cert(
        not_before=h.utc(2025, 1, 1),
        duration=dt.timedelta(days=30),
        subject_cn="expired.test",
        san=("expired.test",),
    )
    fine1 = h.build_cert(subject_cn="fine1.test", san=("fine1.test",))
    fine2 = h.build_cert(subject_cn="fine2.test", san=("fine2.test",))
    run = audit_records(
        [record(fine1, "fine1"), record(expired, "expired"), record(fine2, "fine2")], options()
    )
    blocks = [b for b in render.render_text(run).split(render.RULE) if "Source:" in b]
    assert len(blocks) == 3
    assert "CERT_EXPIRED" not in blocks[0]
    assert "CERT_EXPIRED" in blocks[1] and "expired" in blocks[1]
    assert "CERT_EXPIRED" not in blocks[2]


# -------------------------------------------------------- key checks/findings


def test_ec_small_scalar_report() -> None:
    run = audit_records([record(h.build_cert(public_key=h.ec_public(4242)))], options())
    report = run.reports[0]
    assert "EC_SMALL_SCALAR" in codes(report)
    assert report.max_severity is Severity.CRITICAL
    assert report.key_checks[0].status == "fail"
    assert report.key_checks[0].details["scalar"] == 4242


def test_clean_ec_key_passes_with_bounded_wording() -> None:
    report = audit_records([record(h.build_cert())], options()).reports[0]
    assert report.key_checks[0].status == "pass"
    assert report.findings == []
    assert "1,000,000" in report.key_checks[0].summary


def test_rsa_small_factor_and_short_modulus() -> None:
    big_prime = 2**2000 - 1  # odd; exact primality is irrelevant for a trial-division hit
    cert = h.build_cert(public_key=h.rsa_public(3 * big_prime))
    report = audit_records([record(cert)], options()).reports[0]
    assert "RSA_SMALL_FACTOR" in codes(report)
    short = h.build_cert(public_key=h.rsa_public(2**1023 + 1_000_000_007))
    assert "RSA_SHORT_MODULUS" in codes(audit_records([record(short)], options()).reports[0])


def test_rsa_exponent_three_is_medium() -> None:
    cert = h.build_cert(public_key=h.rsa_public(2**2047 + 12_345_678_901, exponent=3))
    finding = next(
        f
        for f in audit_records([record(cert)], options()).reports[0].findings
        if f.code == "RSA_LOW_EXPONENT"
    )
    assert finding.severity is Severity.MEDIUM


def test_known_weak_modulus_list() -> None:
    modulus = 2**2047 + 98_765_432_101
    cert = h.build_cert(public_key=h.rsa_public(modulus))
    run = audit_records([record(cert)], options(known_weak_moduli=frozenset({modulus})))
    assert "RSA_KNOWN_WEAK" in codes(run.reports[0])


def test_roca_unavailable_is_recorded_not_fatal() -> None:
    cert = h.build_cert(public_key=h.rsa_public(2**2047 + 12_345_678_903))
    report = audit_records([record(cert)], options(check_roca=True)).reports[0]
    roca = next(c for c in report.key_checks if c.name == "roca")
    assert roca.status in {"unavailable", "pass", "fail", "error"}


def test_roca_fingerprint_detected_end_to_end() -> None:
    pytest.importorskip("roca.detect")
    roca_cert = h.build_cert(
        public_key=h.rsa_public(h.roca_modulus()), subject_cn="roca.test", san=("roca.test",)
    )
    plain_cert = h.build_cert(
        public_key=h.rsa_public(h.shared_factor_moduli()[0]),
        subject_cn="plain.test",
        san=("plain.test",),
    )
    run = audit_records(
        [record(roca_cert, "roca"), record(plain_cert, "plain")], options(check_roca=True)
    )
    assert "ROCA_FINGERPRINT" in codes(run.reports[0])
    assert "ROCA_FINGERPRINT" not in codes(run.reports[1])
    assert next(c for c in run.reports[1].key_checks if c.name == "roca").status == "pass"


def test_unsupported_key_type_is_skipped_cleanly() -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    cert = h.build_cert(public_key=key.public_key(), signing_key=h.ca_key())
    report = audit_records([record(cert)], options()).reports[0]
    assert report.public_key.algorithm == "Ed25519"
    assert report.key_checks[0].status == "skipped"


def test_expired_and_validity_policy_findings_together() -> None:
    cert = h.build_cert(not_before=h.utc(2026, 4, 1), duration=dt.timedelta(days=398))
    run = audit_records([record(cert)], options(as_of=h.utc(2027, 6, 1)))
    assert {"CERT_EXPIRED", "VALIDITY_EXCEEDS_POLICY"} <= set(codes(run.reports[0]))


def test_public_tls_override_applies_to_self_signed() -> None:
    cert = h.build_cert(
        issuer_cn=None, not_before=h.utc(2026, 4, 1), duration=dt.timedelta(days=398)
    )
    assert "VALIDITY_EXCEEDS_POLICY" not in codes(
        audit_records([record(cert)], options()).reports[0]
    )
    forced = audit_records([record(cert)], options(public_tls="yes")).reports[0]
    assert "VALIDITY_EXCEEDS_POLICY" in codes(forced)


# --------------------------------------------------------- error isolation


def test_duplicate_extension_in_one_step_does_not_abort_the_run(monkeypatch) -> None:
    """Review bug #3: DuplicateExtension (not a ValueError) must be contained."""
    victim = h.build_cert(subject_cn="victim.test", san=("victim.test",))
    other = h.build_cert(subject_cn="other.test", san=("other.test",))
    original = policy.subject_alt_names

    def flaky(certificate):
        if certificate.subject == victim.subject:
            raise x509.DuplicateExtension("duplicate SAN", x509.SubjectAlternativeName.oid)
        return original(certificate)

    monkeypatch.setattr(policy, "subject_alt_names", flaky)
    run = audit_records([record(victim, "victim"), record(other, "other")], options())
    assert len(run.reports) == 2
    assert any("DuplicateExtension" in e for e in run.reports[0].errors)
    assert run.reports[1].errors == []
    assert run.reports[1].key_checks[0].status == "pass"
    assert run.exit_code() == 3  # completed, with errors


def test_unreadable_public_key_does_not_abort_the_run(monkeypatch) -> None:
    broken = h.build_cert(subject_cn="broken.test")
    good = h.build_cert(subject_cn="good.test", san=("good.test",))
    original = CertificateRecord.public_key.func  # type: ignore[attr-defined]

    def selective(self):
        if self.certificate.subject == broken.subject:
            raise ValueError("unsupported key algorithm")
        return original(self)

    monkeypatch.setattr(CertificateRecord, "public_key", property(selective))
    run = audit_records([record(broken, "broken"), record(good, "good")], options())
    assert "PUBLIC_KEY_UNREADABLE" in codes(run.reports[0])
    assert run.reports[0].key_checks[0].status == "skipped"
    assert run.reports[1].key_checks[0].status == "pass"


def test_last_resort_guard_around_a_certificate(monkeypatch) -> None:
    import cert_key_auditor.report as report_module

    calls = {"n": 0}
    real = report_module.audit_certificate

    def exploding(rec, context):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("kaboom")
        return real(rec, context)

    monkeypatch.setattr(report_module, "audit_certificate", exploding)
    run = audit_records([record(h.build_cert(), "a"), record(h.build_cert(), "b")], options())
    assert "kaboom" in run.reports[0].errors[0]
    assert run.reports[1].errors == []


# ------------------------------------------------------------------- CRLs


@responses.activate
def test_crl_failure_partial_and_stale_findings() -> None:
    good, bad = "http://93.184.216.34/good.crl", "http://93.184.216.35/bad.crl"
    responses.add(responses.GET, good, body=h.build_crl(), status=200)
    responses.add(responses.GET, bad, status=503)
    cert = h.build_cert(crl_urls=(good, bad))
    report = audit_records(
        [record(cert)], options(fetch_crl=True, as_of=h.utc(2026, 11, 30))
    ).reports[0]
    assert report.crl_status == "partial"
    assert {"CRL_FETCH_FAILED", "CRL_STALE"} <= set(codes(report))
    failed = next(f for f in report.findings if f.code == "CRL_FETCH_FAILED")
    assert failed.severity is Severity.MEDIUM and failed.details["kind"] == "http"


@responses.activate
def test_all_crls_failing_and_no_crl_cases() -> None:
    responses.add(responses.GET, CRL_URL, status=500)
    failing = audit_records(
        [record(h.build_cert(crl_urls=(CRL_URL,)))], options(fetch_crl=True)
    ).reports[0]
    assert failing.crl_status == "failed"
    none = audit_records([record(h.build_cert())], options(fetch_crl=True)).reports[0]
    assert none.crl_status == "none_advertised"
    ldap = audit_records(
        [record(h.build_cert(crl_urls=("ldap://dir/cn=x",)))], options(fetch_crl=True)
    ).reports[0]
    assert "CRL_UNSUPPORTED_URI" in codes(ldap)


def test_crl_not_fetched_by_default_but_urls_are_listed() -> None:
    report = audit_records([record(h.build_cert(crl_urls=(CRL_URL,)))], options()).reports[0]
    assert report.crl_status == "not_requested"
    assert report.crl_urls == [CRL_URL]
    assert report.crls == []


@responses.activate
def test_shared_crl_is_downloaded_once_for_many_certificates() -> None:
    responses.add(responses.GET, CRL_URL, body=h.build_crl(), status=200)
    certs = [record(h.build_cert(crl_urls=(CRL_URL,)), f"c{i}") for i in range(5)]
    run = audit_records(certs, options(fetch_crl=True, as_of=h.utc(2026, 10, 3)))
    assert len(responses.calls) == 1
    assert [r.crls[0].from_cache for r in run.reports] == [False, True, True, True, True]


def test_malformed_crl_extension_is_a_finding_not_a_crash(monkeypatch) -> None:
    import cert_key_auditor.report as report_module
    from cert_key_auditor.errors import CrlError

    def bad(certificate):
        raise CrlError("malformed CRL Distribution Points extension: dup", kind="parse")

    monkeypatch.setattr(report_module, "get_crl_distribution_uris", bad)
    report = audit_records([record(h.build_cert())], options(fetch_crl=True)).reports[0]
    assert "CRL_EXTENSION_MALFORMED" in codes(report)
    assert report.crl_status == "error"


# ---------------------------------------------------------- population


def rsa_record(modulus: int, label: str) -> CertificateRecord:
    return record(
        h.build_cert(public_key=h.rsa_public(modulus), subject_cn=label, san=(label,)), label
    )


def test_population_shared_factor_attached_to_both_certificates() -> None:
    n1, n2, n3 = h.shared_factor_moduli()
    run = audit_records(
        [rsa_record(n1, "a.test"), rsa_record(n2, "b.test"), rsa_record(n3, "c.test")],
        options(population=True),
    )
    by_name = {r.subject: r for r in run.reports}
    assert "RSA_SHARED_FACTOR" in codes(by_name["CN=a.test"])
    assert "RSA_SHARED_FACTOR" in codes(by_name["CN=b.test"])
    assert "RSA_SHARED_FACTOR" not in codes(by_name["CN=c.test"])
    assert run.population is not None and run.population.shared_factor_groups == 2
    finding = next(f for f in by_name["CN=a.test"].findings if f.code == "RSA_SHARED_FACTOR")
    assert finding.severity is Severity.CRITICAL
    assert "common_divisor_hex" in finding.details


def test_population_with_clean_moduli_and_few_keys() -> None:
    n1, _n2, n3 = h.shared_factor_moduli()
    run = audit_records(
        [rsa_record(n1, "a.test"), rsa_record(n3, "c.test")], options(population=True)
    )
    assert run.population is not None and run.population.shared_factor_groups == 0
    assert "applies only to the supplied set" in run.population.note
    single = audit_records([rsa_record(n1, "a.test")], options(population=True))
    assert "not applicable" in (single.population.note if single.population else "")


def test_key_reuse_across_distinct_certificates() -> None:
    key = h.ec_public(10**12 + 7)
    first = record(h.build_cert(public_key=key, subject_cn="one.test", san=("one.test",)), "one")
    second = record(h.build_cert(public_key=key, subject_cn="two.test", san=("two.test",)), "two")
    run = audit_records([first, second], options(population=True))
    assert run.population is not None and run.population.reused_key_groups == 1
    assert all("KEY_REUSE" in codes(r) for r in run.reports)


def test_population_off_by_default() -> None:
    run = audit_records(
        [rsa_record(n, f"{i}.test") for i, n in enumerate(h.shared_factor_moduli())], options()
    )
    assert run.population is None
    assert all("RSA_SHARED_FACTOR" not in codes(r) for r in run.reports)


def test_bulk_screen_used_for_larger_populations() -> None:
    big = 2**2000 - 1
    records = [
        rsa_record(big * (2 * i + 1) + 2 * i * 1_000_000 + 2, f"n{i}.test") for i in range(10)
    ]
    context = AuditContext(options(), records)
    assert context.rsa_screen.bulk is True
    context.close()


def test_audit_certificate_direct_use() -> None:
    cert = h.build_cert()
    context = AuditContext(options(), [record(cert)])
    try:
        report = audit_certificate(record(cert), context)
    finally:
        context.close()
    assert report.key_checks and report.validity_policy is not None


def test_load_then_audit_roundtrip_from_pem() -> None:
    cert = h.build_cert()
    loaded = load_certificates(h.pem(cert), "x.pem")
    run = audit_records(loaded.records, options())
    assert run.reports[0].sha256 == h.sha256_hex(cert)
    assert run.exit_code() == 0 or run.fail_on is None
    _ = pytest  # fixtures not needed here
