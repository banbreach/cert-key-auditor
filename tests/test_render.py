from __future__ import annotations

import csv
import io
import json

import pytest
import responses

import helpers as h
from cert_key_auditor import render
from cert_key_auditor.models import CertificateRecord, RunReport, Severity
from cert_key_auditor.report import AuditOptions, audit_records

CRL_URL = "http://93.184.216.34/ca.crl"
EVIL_SUBJECT = '=HYPERLINK("http://evil.test","x")'
EVIL_SOURCE = "=cmd|' /C calc'!A0.pem"  # a hostile *file name* can start a cell


@pytest.fixture
@responses.activate
def run() -> RunReport:
    responses.add(responses.GET, CRL_URL, body=h.build_crl(revoked=(31337,)), status=200)
    weak = h.build_cert(
        public_key=h.ec_public(77),
        serial=31337,
        crl_urls=(CRL_URL,),
        subject_cn="weak.test",
        san=("weak.test",),
    )
    clean = h.build_cert(
        subject_cn="clean.test", san=("clean.test",), not_before=h.utc(2026, 9, 20)
    )
    evil = h.build_cert(
        subject=h.x509.Name([h.x509.NameAttribute(h.NameOID.COMMON_NAME, EVIL_SUBJECT)]),
        san=("evil.test",),
    )
    options = AuditOptions(
        fetch_crl=True, check_roca=False, as_of=h.utc(2026, 10, 3), population=True
    )
    result = audit_records(
        [
            CertificateRecord(c, s)
            for c, s in ((weak, "weak.pem"), (clean, "clean file.pem#pem2"), (evil, EVIL_SOURCE))
        ],
        options,
        input_errors=["missing.pem: no such file or directory"],
    )
    result.fail_on = Severity.MEDIUM
    return result


# ---------------------------------------------------------------- text/colour


def test_text_contains_every_section(run: RunReport) -> None:
    text = render.render_text(run)
    for expected in (
        "Certificate 1 of 3",
        "Serial number (hex):",
        "Validity policy",
        "Key checks",
        "CRL",
        "[OK]",
        "LISTED",
        "Findings",
        "POPULATION ANALYSIS",
        "INPUT ERRORS",
        "SUMMARY",
        "exit code 1",
    ):
        assert expected in text, expected
    assert "\x1b" not in text


def test_color_adds_ansi_only_when_enabled(run: RunReport) -> None:
    plain = render.render_text(run, render.Palette(False))
    colored = render.render_text(run, render.Palette(True))
    assert "\x1b[" not in plain
    assert "\x1b[1;97;41m[CRITICAL]" in colored  # critical badge
    assert colored.replace("\x1b[0m", "").count("\x1b[") > 5
    import re

    stripped = re.sub(r"\x1b\[[0-9;]*m", "", colored)
    assert stripped == plain  # colour changes nothing but styling


def test_resolve_color_rules() -> None:
    class Tty:
        def isatty(self) -> bool:
            return True

    class Pipe:
        def isatty(self) -> bool:
            return False

    assert render.resolve_color("always", Pipe(), {}) is True
    assert render.resolve_color("never", Tty(), {}) is False
    assert render.resolve_color("auto", Tty(), {}) is True
    assert render.resolve_color("auto", Pipe(), {}) is False
    assert render.resolve_color("auto", Tty(), {"NO_COLOR": "1"}) is False
    assert render.resolve_color("auto", Tty(), {"TERM": "dumb"}) is False
    assert render.resolve_color("auto", Pipe(), {"FORCE_COLOR": "1"}) is True
    assert render.resolve_color("auto", Pipe(), {"FORCE_COLOR": "0"}) is False
    assert render.resolve_color("auto", Pipe(), {"NO_COLOR": "1", "FORCE_COLOR": "1"}) is False


def test_terminal_escape_injection_is_neutralised() -> None:
    hostile = "\x1b[2J\x1b]0;pwned\x07evil\u202e\x00"
    cleaned = render.clean(hostile)
    assert "\x1b" not in cleaned and "\x07" not in cleaned and "\x00" not in cleaned
    assert "\\x1b" in cleaned
    assert render.clean("plain text ünïcode") == "plain text ünïcode"

    cert = h.build_cert(
        subject=h.x509.Name([h.x509.NameAttribute(h.NameOID.COMMON_NAME, "a\x1b[31mred")])
    )
    result = audit_records(
        [CertificateRecord(cert, "evil\x1b[0m.pem")], AuditOptions(check_roca=False)
    )
    text = render.render_text(result)
    assert "\x1b" not in text


# ------------------------------------------------------------------- JSON


def test_json_is_valid_and_nests_crl_results_in_the_certificate(run: RunReport) -> None:
    document = json.loads(render.render_json(run))
    assert document["tool"]["name"] == "cert-key-auditor"
    assert document["summary"]["certificates"] == 3
    assert document["summary"]["exit_code"] == 1
    assert document["summary"]["findings"]["critical"] >= 1
    assert document["input_errors"] == ["missing.pem: no such file or directory"]
    weak = next(c for c in document["certificates"] if c["source"] == "weak.pem")
    assert weak["crl_status"] == "ok"
    crl = weak["crls"][0]
    assert crl["url"] == CRL_URL and crl["ok"] is True
    assert crl["certificate_listed"] is True
    assert crl["this_update"].endswith("Z")
    assert {f["code"] for f in weak["findings"]} >= {"EC_SMALL_SCALAR", "CERT_LISTED_IN_CRL"}
    assert weak["findings"][0]["severity"] in {"critical", "high", "medium", "low", "info"}
    assert weak["public_key"]["algorithm"] == "EC"
    assert weak["validity_policy"]["max_days"] == 200
    assert document["population"]["ran"] is True


def test_json_control_characters_stay_escaped() -> None:
    cert = h.build_cert(
        subject=h.x509.Name([h.x509.NameAttribute(h.NameOID.COMMON_NAME, "x\x1b[31m")])
    )
    out = render.render_json(
        audit_records([CertificateRecord(cert, "s")], AuditOptions(check_roca=False))
    )
    assert "\x1b" not in out
    json.loads(out)


# -------------------------------------------------------------------- CSV


def parse_csv(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


def test_csv_has_one_row_per_certificate_and_stable_columns(run: RunReport) -> None:
    rows = parse_csv(render.render_csv(run))
    assert len(rows) == 3
    assert tuple(rows[0]) == render.CSV_COLUMNS
    weak = next(r for r in rows if r["source"] == "weak.pem")
    assert weak["crl_status"] == "ok" and weak["crl_ok"] == "1" and weak["crl_failed"] == "0"
    assert weak["max_severity"] == "critical"
    assert "EC_SMALL_SCALAR" in weak["finding_codes"]
    assert weak["key_algorithm"] == "EC" and weak["key_curve"] == "secp256r1"
    assert weak["validity_policy_compliant"] == "true"
    clean = next(r for r in rows if r["source"].startswith("clean"))
    assert clean["max_severity"] == ""


def test_csv_formula_injection_is_neutralised(run: RunReport) -> None:
    rows = parse_csv(render.render_csv(run))
    evil = next(r for r in rows if r["source"].endswith("calc'!A0.pem"))
    assert evil["source"].startswith("'=")
    for row in rows:
        for value in row.values():
            assert not value.startswith(("=", "+", "@", "\t", "\r"))


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-cmd", "@SUM(A1)", "\tx", "\rx"])
def test_csv_cell_prefixes_dangerous_values(value: str) -> None:
    assert render.csv_cell(value).startswith("'")
    assert render.csv_cell("ordinary") == "ordinary"
    assert render.csv_cell(None) == ""
    assert render.csv_cell(True) == "true" and render.csv_cell(False) == "false"
    assert render.csv_cell(-5) == "-5"  # numbers are not text and stay numeric
    assert render.csv_cell(Severity.HIGH) == "high"


def test_crl_csv_has_one_row_per_crl(run: RunReport) -> None:
    rows = parse_csv(render.render_crl_csv(run))
    assert len(rows) == 1
    row = rows[0]
    assert row["url"] == CRL_URL and row["ok"] == "true"
    assert row["certificate_listed"] == "true" and row["revoked_count"] == "1"
    assert len(row["certificate_sha256"]) == 64


# ------------------------------------------------------------------ SARIF


def test_sarif_structure(run: RunReport) -> None:
    document = json.loads(render.render_sarif(run))
    assert document["version"] == "2.1.0"
    driver = document["runs"][0]["tool"]["driver"]
    assert driver["name"] == "cert-key-auditor"
    rule_ids = {r["id"] for r in driver["rules"]}
    results = document["runs"][0]["results"]
    assert results and {r["ruleId"] for r in results} <= rule_ids
    critical = next(r for r in results if r["ruleId"] == "EC_SMALL_SCALAR")
    assert critical["level"] == "error"
    assert critical["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "weak.pem"
    assert critical["properties"]["sha256"]
    rule = next(r for r in driver["rules"] if r["id"] == "EC_SMALL_SCALAR")
    assert float(rule["properties"]["security-severity"]) >= 9
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert all(" " not in uri for uri in uris)


@pytest.mark.parametrize(
    ("source", "uri"),
    [
        ("dir/cert.pem#pem2", "dir/cert.pem"),
        ("my certs/a b.pem", "my%20certs/a%20b.pem"),
        ("Censys:" + "ab" * 32, "Censys:" + "ab" * 32),
        ("stdin", "stdin"),
    ],
)
def test_sarif_uri(source: str, uri: str) -> None:
    assert render._sarif_uri(source) == uri


def test_write_output(tmp_path, capsys) -> None:
    target = tmp_path / "out.txt"
    render.write_output("héllo\n", str(target))
    assert target.read_text(encoding="utf-8") == "héllo\n"
    render.write_output("to stdout\n", None)
    render.write_output("also stdout\n", "-")
    assert capsys.readouterr().out == "to stdout\nalso stdout\n"
