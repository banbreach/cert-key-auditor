from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
import responses

import helpers as h
from cert_key_auditor import __version__, cli
from cert_key_auditor.censys import API_BASE

AS_OF = "2026-05-01"


def run_cli(*argv: str) -> int:
    return cli.main(["--color", "never", "--as-of", AS_OF, "--no-roca", *argv])


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("CENSYS_API_TOKEN", raising=False)
    monkeypatch.delenv("CERT_AUDIT_CONFIG", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)


@pytest.fixture
def good_pem(tmp_path: Path) -> Path:
    path = tmp_path / "good.pem"
    path.write_bytes(h.pem(h.build_cert()))
    return path


@pytest.fixture
def weak_pem(tmp_path: Path) -> Path:
    path = tmp_path / "weak.pem"
    path.write_bytes(h.pem(h.build_cert(public_key=h.ec_public(555))))
    return path


# ---------------------------------------------------------------- exit codes


def test_clean_run_exits_zero(good_pem: Path, capsys) -> None:
    assert run_cli("--pem", str(good_pem)) == 0
    out = capsys.readouterr().out
    assert "SUMMARY" in out and "Certificate 1 of 1" in out


def test_findings_exit_one(weak_pem: Path, capsys) -> None:
    assert run_cli("--pem", str(weak_pem)) == 1
    assert "EC_SMALL_SCALAR" in capsys.readouterr().out


def test_fail_on_threshold(weak_pem: Path, tmp_path: Path) -> None:
    assert run_cli("--pem", str(weak_pem), "--fail-on", "never") == 0
    expired = tmp_path / "expired.pem"
    expired.write_bytes(h.pem(h.build_cert(not_before=h.utc(2025, 1, 1))))
    assert run_cli("--pem", str(expired)) == 1  # expired is medium; default threshold medium
    assert run_cli("--pem", str(expired), "--fail-on", "high") == 0


def test_no_certificates_is_fatal(tmp_path: Path, capsys) -> None:
    junk = tmp_path / "junk.pem"
    junk.write_bytes(b"junk")
    assert run_cli("--pem", str(junk)) == 2
    assert "no valid X.509 certificates" in capsys.readouterr().err


def test_partial_input_errors_exit_three(good_pem: Path, tmp_path: Path, capsys) -> None:
    code = run_cli("--population", str(good_pem), "--population", str(tmp_path / "missing.pem"))
    assert code == 3
    out = capsys.readouterr().out
    assert "INPUT ERRORS" in out and "missing.pem" in out


def test_findings_take_precedence_over_errors(weak_pem: Path, tmp_path: Path) -> None:
    assert run_cli("--pem", str(weak_pem), "--population", str(tmp_path / "missing.pem")) == 1


def test_usage_errors_exit_two(capsys) -> None:
    with pytest.raises(SystemExit) as info:
        run_cli()
    assert info.value.code == 2
    assert "no input" in capsys.readouterr().err


@pytest.mark.parametrize(
    "bad",
    [
        ["--ec-scalar-limit", "0"],
        ["--ec-scalar-limit", "99999999999"],
        ["--rsa-small-prime-limit", "1"],
        ["--crl-timeout", "0"],
        ["--crl-max-redirects", "99"],
        ["--pdf-max-pages", "0"],
    ],
)
def test_range_validation(good_pem: Path, bad: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        run_cli("--pem", str(good_pem), *bad)
    assert info.value.code == 2


def test_crl_csv_requires_fetch(good_pem: Path, tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        run_cli("--pem", str(good_pem), "--crl-csv", str(tmp_path / "c.csv"))


def test_invalid_as_of_is_reported_not_raised(good_pem: Path, capsys) -> None:
    code = cli.main(["--no-roca", "--pem", str(good_pem), "--as-of", "not-a-date"])
    assert code == 2
    assert "invalid value" in capsys.readouterr().err


def test_as_of_accepts_z_and_dates() -> None:
    assert cli.parse_as_of("2026-05-01T12:00:00Z") == h.utc(2026, 5, 1, 12)
    assert cli.parse_as_of("2026-05-01") == h.utc(2026, 5, 1)
    assert cli.parse_as_of("2026-05-01T12:00:00+02:00") == h.utc(2026, 5, 1, 10)


def test_version(capsys) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 0
    assert __version__ in capsys.readouterr().out


# ------------------------------------------------------------------ formats


def test_json_output_is_clean_on_stdout(weak_pem: Path, capsys) -> None:
    code = run_cli("--pem", str(weak_pem), "--format", "json", "-v")
    captured = capsys.readouterr()
    document = json.loads(captured.out)  # only JSON on stdout, even with -v
    assert code == 1 == document["summary"]["exit_code"]
    assert "auditing" in captured.err  # progress goes to stderr


def test_csv_output_and_input_errors_go_to_stderr(good_pem: Path, tmp_path: Path, capsys) -> None:
    code = run_cli(
        "--pem", str(good_pem), "--population", str(tmp_path / "gone.pem"), "--format", "csv"
    )
    captured = capsys.readouterr()
    rows = list(csv.DictReader(io.StringIO(captured.out)))
    assert len(rows) == 1 and code == 3
    assert "gone.pem" in captured.err


def test_sarif_output(weak_pem: Path, capsys) -> None:
    run_cli("--pem", str(weak_pem), "--format", "sarif")
    document = json.loads(capsys.readouterr().out)
    assert document["runs"][0]["results"][0]["ruleId"] == "EC_SMALL_SCALAR"


def test_output_file(weak_pem: Path, tmp_path: Path, capsys) -> None:
    target = tmp_path / "report.json"
    code = run_cli("--pem", str(weak_pem), "-F", "json", "-o", str(target))
    assert code == 1
    assert capsys.readouterr().out == ""
    assert json.loads(target.read_text(encoding="utf-8"))["summary"]["certificates"] == 1


def test_unwritable_output_is_a_clean_error(good_pem: Path, tmp_path: Path, capsys) -> None:
    code = run_cli("--pem", str(good_pem), "-o", str(tmp_path / "no" / "dir" / "out.txt"))
    assert code == 2
    assert "cannot write output" in capsys.readouterr().err


def test_color_always_and_never(good_pem: Path, capsys) -> None:
    cli.main(["--no-roca", "--color", "always", "--as-of", AS_OF, "--pem", str(good_pem)])
    assert "\x1b[" in capsys.readouterr().out
    cli.main(["--no-roca", "--color", "never", "--as-of", AS_OF, "--pem", str(good_pem)])
    assert "\x1b[" not in capsys.readouterr().out


def test_no_color_env_respected_in_auto_mode(good_pem: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    cli.main(["--no-roca", "--as-of", AS_OF, "--pem", str(good_pem)])
    assert "\x1b[" not in capsys.readouterr().out


# -------------------------------------------------------------------- stdin


def test_pem_from_stdin(monkeypatch, capsys) -> None:
    data = h.pem(h.build_cert(public_key=h.ec_public(9)))
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(data)))
    assert run_cli("--pem", "-") == 1
    assert "stdin" in capsys.readouterr().out


def test_stdin_conflict_is_rejected(monkeypatch) -> None:
    with pytest.raises(SystemExit):
        run_cli("--pem", "-", "--fingerprints-file", "-")


# ------------------------------------------------------------------- Censys


def censys_url(fingerprint: str) -> str:
    return f"{API_BASE}/v3/global/asset/certificate/{fingerprint}/raw"


@responses.activate
def test_censys_lookup_with_env_token(monkeypatch, capsys) -> None:
    cert = h.build_cert(public_key=h.ec_public(31))
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, censys_url(fp), body=h.pem(cert))
    monkeypatch.setenv("CENSYS_API_TOKEN", "env-token")
    assert run_cli(fp) == 1
    assert responses.calls[0].request.headers["Authorization"] == "Bearer env-token"
    assert f"Censys:{fp}" in capsys.readouterr().out


@responses.activate
def test_token_flag_warns_about_process_list(capsys) -> None:
    cert = h.build_cert()
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, censys_url(fp), body=h.pem(cert))
    run_cli(fp, "--token", "flag-token")
    assert "process list" in capsys.readouterr().err


def test_missing_token_is_fatal(capsys) -> None:
    assert run_cli("ab" * 32) == 2
    assert "CENSYS_API_TOKEN" in capsys.readouterr().err


@responses.activate
def test_fingerprint_batch_file_partial_failure(tmp_path: Path, monkeypatch, capsys) -> None:
    good, missing = h.build_cert(), "cd" * 32
    fp_good = h.sha256_hex(good)
    responses.add(responses.GET, censys_url(fp_good), body=h.pem(good))
    responses.add(responses.GET, censys_url(missing), status=404)
    listing = tmp_path / "fps.txt"
    listing.write_text(
        f"# batch\n{fp_good}  # first\n\n{missing}\nnot-a-fingerprint\n", encoding="utf-8"
    )
    monkeypatch.setenv("CENSYS_API_TOKEN", "t")
    code = run_cli("--fingerprints-file", str(listing), "--format", "json")
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["summary"]["certificates"] == 1
    assert len(document["input_errors"]) == 2
    assert code == 3
    assert document["population"]["ran"] is True  # batch input enables population analysis


@responses.activate
def test_duplicate_fingerprints_are_fetched_once(monkeypatch) -> None:
    cert = h.build_cert()
    fp = h.sha256_hex(cert)
    responses.add(responses.GET, censys_url(fp), body=h.pem(cert))
    monkeypatch.setenv("CENSYS_API_TOKEN", "t")
    run_cli(fp, fp.upper(), ":".join(fp[i : i + 2] for i in range(0, 64, 2)))
    assert len(responses.calls) == 1


# ---------------------------------------------------------------------- CRL


@responses.activate
def test_fetch_crl_and_crl_csv(tmp_path: Path, capsys) -> None:
    url = "http://93.184.216.34/ca.crl"
    responses.add(responses.GET, url, body=h.build_crl(revoked=(4242,)))
    cert = h.build_cert(serial=4242, crl_urls=(url,), not_before=h.utc(2026, 4, 20))
    pem_path = tmp_path / "c.pem"
    pem_path.write_bytes(h.pem(cert))
    crl_csv = tmp_path / "crls.csv"
    code = cli.main(
        [
            "--no-roca",
            "--color",
            "never",
            "--as-of",
            "2026-05-01",
            "--pem",
            str(pem_path),
            "--fetch-crl",
            "--crl-csv",
            str(crl_csv),
            "--format",
            "json",
        ]
    )
    document = json.loads(capsys.readouterr().out)
    assert code == 1
    certificate = document["certificates"][0]
    assert certificate["crls"][0]["certificate_listed"] is True
    rows = list(csv.DictReader(crl_csv.open(encoding="utf-8")))
    assert rows[0]["url"] == url and rows[0]["certificate_listed"] == "true"


@responses.activate
def test_crl_redirect_flags(tmp_path: Path, capsys) -> None:
    start, target = "http://93.184.216.34/a.crl", "http://93.184.216.40/b.crl"
    responses.add(responses.GET, start, status=302, headers={"Location": target})
    responses.add(responses.GET, target, body=h.build_crl())
    pem_path = tmp_path / "c.pem"
    pem_path.write_bytes(h.pem(h.build_cert(crl_urls=(start,), not_before=h.utc(2026, 4, 20))))
    common = [
        "--no-roca",
        "--as-of",
        "2026-04-25",
        "--pem",
        str(pem_path),
        "--fetch-crl",
        "-F",
        "json",
    ]
    cli.main(common)
    refused = json.loads(capsys.readouterr().out)["certificates"][0]
    assert refused["crl_status"] == "failed"
    cli.main([*common, "--follow-crl-redirects"])
    followed = json.loads(capsys.readouterr().out)["certificates"][0]
    assert followed["crl_status"] == "ok" and followed["crls"][0]["redirects"] == [target]


# ---------------------------------------------------------------------- PDF


def test_pdf_input_via_cli(tmp_path: Path, capsys) -> None:
    pytest.importorskip("pypdf")
    weak = h.build_cert(public_key=h.ec_public(808))
    path = h.make_pdf(
        tmp_path / "doc.pdf", signature=(weak,), attachments={"ok.pem": h.pem(h.build_cert())}
    )
    code = run_cli("--pdf", str(path), "--format", "json")
    document = json.loads(capsys.readouterr().out)
    assert document["summary"]["certificates"] == 2
    assert code == 1
    assert document["population"]["ran"] is True


# ------------------------------------------------------------------- config


def write_config(tmp_path: Path, text: str) -> str:
    path = tmp_path / "audit.toml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_config_sets_defaults_and_cli_overrides(weak_pem: Path, tmp_path: Path, capsys) -> None:
    config = write_config(tmp_path, 'fail-on = "never"\nformat = "json"\nec_scalar_limit = 100\n')
    code = cli.main(["--config", config, "--no-roca", "--as-of", AS_OF, "--pem", str(weak_pem)])
    document = json.loads(capsys.readouterr().out)  # format from config
    assert code == 0  # fail-on never from config
    assert document["certificates"][0]["key_checks"][0]["status"] == "pass"  # 555 > limit 100
    code = cli.main(
        [
            "--config",
            config,
            "--ec-scalar-limit",
            "1000",
            "--fail-on",
            "low",
            "--no-roca",
            "--as-of",
            AS_OF,
            "--pem",
            str(weak_pem),
        ]
    )
    capsys.readouterr()
    assert code == 1  # CLI overrides both


def test_config_table_form_and_env_variable(
    good_pem: Path, tmp_path: Path, monkeypatch, capsys
) -> None:
    config = write_config(tmp_path, '[cert-audit]\nformat = "csv"\n')
    monkeypatch.setenv("CERT_AUDIT_CONFIG", config)
    cli.main(["--no-roca", "--as-of", AS_OF, "--pem", str(good_pem)])
    assert capsys.readouterr().out.startswith("source,sha256")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('token = "secret"\n', "CENSYS_API_TOKEN"),
        ("bogus = 1\n", "unknown option"),
        ('ec_scalar_limit = "ten"\n', "wrong type"),
        ("roca = 1\n", "wrong type"),
        ('fetch_crl = "yes"\n', "wrong type"),
        ('format = "xml"\n', "must be one of"),
        ("crl_timeout = true\n", "boolean"),
        ("this is not toml", "invalid TOML"),
    ],
)
def test_bad_config_is_rejected_with_clear_message(
    text: str, message: str, good_pem: Path, tmp_path: Path, capsys
) -> None:
    code = cli.main(["--config", write_config(tmp_path, text), "--pem", str(good_pem)])
    assert code == 2
    assert message in capsys.readouterr().err


def test_missing_config_file(good_pem: Path, tmp_path: Path, capsys) -> None:
    assert cli.main(["--config", str(tmp_path / "nope.toml"), "--pem", str(good_pem)]) == 2
    assert "cannot read config" in capsys.readouterr().err


def test_config_is_never_auto_discovered(
    good_pem: Path, tmp_path: Path, monkeypatch, capsys
) -> None:
    (tmp_path / "cert-audit.toml").write_text('format = "csv"\n', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.cert-audit]\nformat = "csv"\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    cli.main(["--no-roca", "--as-of", AS_OF, "--pem", str(good_pem)])
    assert "Certificate 1 of 1" in capsys.readouterr().out  # still text


# -------------------------------------------------------- robustness / logging


def test_internal_error_has_no_traceback_by_default(good_pem: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "run", lambda args: (_ for _ in ()).throw(RuntimeError("boom")))
    code = cli.main(["--pem", str(good_pem)])
    err = capsys.readouterr().err
    assert code == 2 and "internal error" in err and "Traceback" not in err


def test_keyboard_interrupt(good_pem: Path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "run", lambda args: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main(["--pem", str(good_pem)]) == 130


def test_quiet_suppresses_warnings(good_pem: Path, tmp_path: Path, capsys) -> None:
    run_cli("--pem", str(good_pem), "--population", str(tmp_path / "gone.pem"), "-F", "csv", "-q")
    assert capsys.readouterr().err == ""


def test_known_weak_moduli_file_errors_are_fatal(good_pem: Path, tmp_path: Path, capsys) -> None:
    bad = tmp_path / "weak.txt"
    bad.write_text("garbage\n", encoding="utf-8")
    assert run_cli("--pem", str(good_pem), "--known-weak-moduli", str(bad)) == 2
    assert "weak.txt:1" in capsys.readouterr().err


def test_non_positive_serial_deprecation_noise_is_filtered(good_pem: Path, monkeypatch) -> None:
    import warnings

    from cryptography.utils import CryptographyDeprecationWarning

    def noisy_run(args) -> int:
        warnings.warn(
            "Parsed a serial number which wasn't positive (i.e., it was negative or zero)",
            CryptographyDeprecationWarning,
            stacklevel=1,
        )
        warnings.warn("some other deprecation", DeprecationWarning, stacklevel=1)
        return 0

    monkeypatch.setattr(cli, "run", noisy_run)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert cli.main(["--pem", str(good_pem)]) == 0
    messages = [str(w.message) for w in caught]
    assert not any("serial number" in m for m in messages)
    assert any("some other deprecation" in m for m in messages)  # only the known noise is filtered
