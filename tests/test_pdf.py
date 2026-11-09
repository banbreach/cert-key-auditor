from __future__ import annotations

import contextlib
from pathlib import Path

import pytest

import helpers as h

pytest.importorskip("pypdf")

from cert_key_auditor import pdf
from cert_key_auditor.errors import PdfError


def fingerprints(result) -> set[str]:
    return {r.fingerprint for r in result.records}


@pytest.fixture
def certs():
    return [h.build_cert(subject_cn=f"pdf{i}.test", san=(f"pdf{i}.test",)) for i in range(3)]


def test_certificates_pasted_as_page_text(tmp_path: Path, certs) -> None:
    path = h.make_pdf(tmp_path / "text.pdf", page_pem=tuple(certs[:2]))
    result = pdf.extract_certificates_from_pdf(path)
    assert fingerprints(result) == {h.sha256_hex(c) for c in certs[:2]}, result.errors


def test_attachments_pem_der_and_pkcs7(tmp_path: Path, certs) -> None:
    path = h.make_pdf(
        tmp_path / "attach.pdf",
        attachments={
            "a.pem": h.pem(certs[0]),
            "b.der": h.der(certs[1]),
            "c.p7b": h.pkcs7_der(certs[2]),
        },
    )
    result = pdf.extract_certificates_from_pdf(path)
    assert fingerprints(result) == {h.sha256_hex(c) for c in certs}
    assert any("attachment:a.pem" in r.source for r in result.records)


def test_non_certificate_attachment_is_ignored_quietly(tmp_path: Path, certs) -> None:
    path = h.make_pdf(
        tmp_path / "x.pdf", attachments={"notes.txt": b"just notes", "a.pem": h.pem(certs[0])}
    )
    result = pdf.extract_certificates_from_pdf(path)
    assert len(result.records) == 1
    assert result.errors == []


def test_corrupt_certificate_attachment_is_reported(tmp_path: Path) -> None:
    path = h.make_pdf(tmp_path / "x.pdf", attachments={"broken.pem": b"not a certificate"})
    result = pdf.extract_certificates_from_pdf(path)
    assert not result.records
    assert any("broken.pem" in e for e in result.errors)


def test_signature_container_with_zero_padding(tmp_path: Path, certs) -> None:
    path = h.make_pdf(tmp_path / "signed.pdf", signature=tuple(certs))
    result = pdf.extract_certificates_from_pdf(path)
    assert fingerprints(result) == {h.sha256_hex(c) for c in certs}, result.errors
    assert any("signature" in r.source for r in result.records)


def test_document_security_store(tmp_path: Path, certs) -> None:
    path = h.make_pdf(tmp_path / "dss.pdf", dss=tuple(certs[:2]))
    result = pdf.extract_certificates_from_pdf(path)
    assert fingerprints(result) == {h.sha256_hex(c) for c in certs[:2]}
    assert all("dss" in r.source for r in result.records)


def test_same_certificate_in_several_places_is_deduplicated(tmp_path: Path, certs) -> None:
    path = h.make_pdf(
        tmp_path / "multi.pdf",
        page_pem=(certs[0],),
        attachments={"a.pem": h.pem(certs[0])},
        signature=(certs[0], certs[1]),
        dss=(certs[0],),
    )
    result = pdf.extract_certificates_from_pdf(path)
    assert fingerprints(result) == {h.sha256_hex(certs[0]), h.sha256_hex(certs[1])}
    assert len(result.records) == 2
    first = next(r for r in result.records if r.fingerprint == h.sha256_hex(certs[0]))
    assert "dss" in first.source or "attachment" in first.source  # most specific label wins


def test_pdf_without_certificates(tmp_path: Path) -> None:
    result = pdf.extract_certificates_from_pdf(h.make_pdf(tmp_path / "empty.pdf"))
    assert result.records == [] and result.errors == []


def test_not_a_pdf_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "fake.pdf"
    path.write_bytes(b"MZ this is not a pdf")
    with pytest.raises(PdfError, match="not a PDF"):
        pdf.extract_certificates_from_pdf(path)


def test_truncated_pdf_does_not_crash(tmp_path: Path, certs) -> None:
    good = h.make_pdf(tmp_path / "good.pdf", attachments={"a.pem": h.pem(certs[0])})
    broken = tmp_path / "broken.pdf"
    broken.write_bytes(good.read_bytes()[:200])
    with contextlib.suppress(PdfError):  # a clean, typed failure is acceptable
        pdf.extract_certificates_from_pdf(broken)


def test_encrypted_pdf_is_reported(tmp_path: Path, certs) -> None:
    path = h.make_pdf(
        tmp_path / "enc.pdf", attachments={"a.pem": h.pem(certs[0])}, encrypt="secret"
    )
    with pytest.raises(PdfError, match=r"password|encrypted"):
        pdf.extract_certificates_from_pdf(path)


def test_file_size_limit(tmp_path: Path, certs) -> None:
    path = h.make_pdf(tmp_path / "big.pdf", attachments={"a.pem": h.pem(certs[0])})
    with pytest.raises(Exception, match="limit"):
        pdf.extract_certificates_from_pdf(path, pdf.PdfLimits(max_file_bytes=100))


def test_page_limit_is_reported(tmp_path: Path, certs) -> None:
    path = h.make_pdf(tmp_path / "x.pdf", page_pem=(certs[0],))
    result = pdf.extract_certificates_from_pdf(path, pdf.PdfLimits(max_pages=0))
    assert any("stopped after 0 pages" in e for e in result.errors)


def test_object_count_limit(tmp_path: Path, certs) -> None:
    path = h.make_pdf(tmp_path / "x.pdf", signature=(certs[0],))
    result = pdf.extract_certificates_from_pdf(path, pdf.PdfLimits(max_objects=2))
    assert any("more than 2 objects" in e for e in result.errors)


def test_missing_pypdf_gives_actionable_error(tmp_path: Path, monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake(name, *args, **kwargs):
        if name == "pypdf":
            raise ImportError("no pypdf")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(PdfError, match=r"cert-key-auditor\[pdf\]"):
        pdf.extract_certificates_from_pdf(tmp_path / "x.pdf")


def test_load_pdfs_isolates_per_file_failures(tmp_path: Path, certs) -> None:
    h.make_pdf(tmp_path / "good.pdf", attachments={"a.pem": h.pem(certs[0])})
    (tmp_path / "bad.pdf").write_bytes(b"not a pdf")
    result = pdf.load_pdfs([str(tmp_path), str(tmp_path / "nope.pdf")])
    assert len(result.records) == 1
    assert len(result.errors) == 2


def test_load_pdfs_directory_recursion_and_empty_dir(tmp_path: Path, certs) -> None:
    (tmp_path / "sub").mkdir()
    h.make_pdf(tmp_path / "sub" / "deep.pdf", signature=(certs[0],))
    assert len(pdf.load_pdfs([str(tmp_path)]).records) == 1
    empty = tmp_path / "emptydir"
    empty.mkdir()
    assert "no PDF files" in pdf.load_pdfs([str(empty)]).errors[0]


def test_extracted_certificates_flow_into_the_audit(tmp_path: Path) -> None:
    from cert_key_auditor.report import AuditOptions, audit_records

    weak = h.build_cert(
        public_key=h.ec_public(321), subject_cn="pdf-weak.test", san=("pdf-weak.test",)
    )
    path = h.make_pdf(tmp_path / "weak.pdf", signature=(weak,))
    loaded = pdf.load_pdfs([str(path)])
    run = audit_records(loaded.records, AuditOptions(check_roca=False))
    assert "EC_SMALL_SCALAR" in {f.code for f in run.reports[0].findings}
    assert str(path) in run.reports[0].source
