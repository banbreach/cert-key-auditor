# cert-key-auditor

[![CI](https://github.com/banbreach/cert-key-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/banbreach/cert-key-auditor/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/banbreach/cert-key-auditor/badge)](https://securityscorecards.dev/viewer/?uri=github.com/banbreach/cert-key-auditor)

A command-line tool that audits X.509 certificates for weak keys, validity-period
policy violations and CRL problems. Certificates can come from the
[Censys Platform API](https://docs.censys.com/reference/v3-globaldata-asset-certificate-raw)
(by SHA-256 fingerprint), from local PEM/DER/PKCS#7 files, or from PDF documents.

> **Alpha security-research software.** A clean result means *nothing was found within
> the bounded checks that were run*. It is never proof that a certificate or key is safe.

## Features

| Area | What it does |
|---|---|
| **Weak EC keys** | Tests whether an EC public key equals `k·G` for a tiny private scalar `k` (default `k ≤ 1,000,000`). Uses baby-step/giant-step on NIST/SEC prime curves, so a million-scalar search takes ~30 ms instead of ~30 s. |
| **Weak RSA keys** | Small prime factors (bulk product-GCD mode for large sets), user-supplied known-weak moduli, optional ROCA fingerprint detection, short moduli, bad exponents. |
| **Population analysis** | Batch-GCD across all supplied RSA moduli finds **shared prime factors**; also flags public-key reuse. |
| **Validity policy** | Checks lifetimes against the CA/Browser Forum maximum-validity schedule (398 → 200 → 100 → 47 days). See [below](#validity-period-policy). |
| **CRL inspection** | Finds CRL distribution points, downloads CRLs with SSRF defences, parses them, and reports status, size, hash, issuer, update times, staleness, CRL number, revoked-entry count and whether the certificate's serial is listed. Everything is part of the certificate's own report. |
| **PDF extraction** | Pulls certificates out of signature containers, the PAdES DSS store, attachments, streams and page text. |
| **Output formats** | Colorized text, JSON, CSV (plus per-CRL CSV) and SARIF 2.1.0. |
| **Policy checks** | Expiry, weak signature hashes (MD5/SHA-1), short RSA/DSA keys, weak curves, missing SAN, invalid serial numbers. |
| **CI-friendly** | Documented exit codes, `--fail-on` threshold, quiet stdout for machine formats, TOML config file. |

## Requirements

- Python **3.11 or newer**
- For Censys lookups: a Censys Platform Personal Access Token and network access to `api.platform.censys.io`
- Optional extras: `pdf` (PDF extraction, installs `pypdf`), `roca` (ROCA detector)

## Installation

```bash
git clone https://github.com/banbreach/cert-key-auditor.git
cd cert-key-auditor

python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install .            # core
python -m pip install ".[pdf]"     # + PDF extraction
python -m pip install ".[all]"     # + PDF and ROCA detector
```

Confirm it works:

```bash
cert-audit --version
python -m cert_key_auditor --version     # equivalent
```

## Quick start

```bash
# Audit local certificates (PEM, DER, PKCS#7; single files or bundles)
cert-audit --pem server.pem

# A directory of certificates as a population (enables shared-factor analysis)
cert-audit --population ./certs/

# Download and inspect each certificate's CRLs
cert-audit --pem server.pem --fetch-crl

# Certificates embedded in PDFs
cert-audit --pdf signed-contract.pdf

# From Censys
export CENSYS_API_TOKEN="YOUR_PERSONAL_ACCESS_TOKEN"
cert-audit 3daf2843a77b6f4e6af43cd9b6f6746053b8c928e056e8a724808db8905a94cf
cert-audit --fingerprints-file fingerprints.txt

# Machine-readable output for pipelines
cert-audit --pem server.pem --format json -o report.json
cert-audit --population ./certs --format sarif -o results.sarif
```

Put the Censys token in the **environment**, not on the command line. `--token` works but
the value is visible in the process list, and the tool warns when it is used.

## Inputs

| Option | Description |
|---|---|
| `FINGERPRINT ...` | One or more SHA-256 fingerprints to fetch from Censys (colons and upper-case accepted; duplicates are fetched once). |
| `--fingerprints-file FILE` | One fingerprint per line (`#` comments allowed); `-` reads stdin. |
| `--pem PATH` | A PEM/DER/PKCS#7 file; `-` reads stdin; repeatable. |
| `--population PATH` | A bundle or directory (recursive; `.pem .crt .cer .cert .der .p7b .p7c .txt`); repeatable. |
| `--pdf PATH` | A PDF or directory of PDFs; repeatable. |
| `--organization-id UUID` | Optional Censys organization. |

Supported PEM labels: `CERTIFICATE`, `X509 CERTIFICATE`, `TRUSTED CERTIFICATE`, and
`PKCS7`. Surrounding text is ignored. **One unparseable block never discards the others**:
bad pieces are reported and the good certificates are still audited.

Population analysis (shared RSA factors, key reuse) runs automatically for `--population`,
`--pdf` and `--fingerprints-file`, or on demand with `--population-analysis`. Its findings
are attached to each affected certificate's own report.

## Output

### Text (default)

Every result for a certificate appears in **one block**: metadata, validity-policy result,
key checks, CRL results and findings.

```text
==============================================================================
Certificate 1 of 1
Source:                  shop.pem
Subject:                 CN=shop.example.com
Issuer:                  CN=Test Issuing CA
SHA-256:                 7ff1daad79eaed4d17d84da7e7901220fcb2fccb459b31635d653ba4ae7c1741
Serial number (hex):     A3F19C0D5E27B684
Not before (UTC):        2026-09-01T00:00:00Z
Not after (UTC):         2027-10-04T00:00:00Z
Validity duration:       34,387,200 seconds (398.00 days)
Public key:              EC secp256r1 (256 bits) [ECPublicKey]

Validity policy (CA/B Forum maximum)
  EXCEEDS LIMIT: 398 days vs 200-day maximum (issued on or after 2026-03-15; inclusive count)

Key checks (bounded; a pass is not proof of security)
  [fail] ec_small_scalar: public key equals 1337*G (private scalar 1337)

CRL
  status: ok
  - http://crl.example-ca.test/issuing.crl [OK]
      HTTP 200 | DER | 224 bytes
      SHA-256: 29fa20ae42f32a79737c37fc2cff9335b25c8ab8d576fb2dfbf5d6a995c08587
      Issuer: CN=Test Issuing CA
      This update: 2026-10-29T00:00:00Z | Next update: 2026-11-05T00:00:00Z
      CRL number: 4217 | revoked entries: 2
      This certificate: not listed (CRL signature not verified)

Findings
  [CRITICAL] EC_SMALL_SCALAR: EC public key corresponds to the tiny private scalar 1337; ...
  [HIGH] VALIDITY_EXCEEDS_POLICY: validity of 398 days exceeds the 200-day maximum ...
```
*(abridged; some metadata lines omitted)*

**Color** is applied automatically on a terminal. Control it with `--color auto|always|never`.
`NO_COLOR` disables it and `FORCE_COLOR` enables it in `auto` mode. Colors are never written
to files unless `--color always` is given.

### JSON, CSV, SARIF

| Format | Shape |
|---|---|
| `--format json` | One document: `tool`, `generated_at`, `summary` (counts, exit code), `population`, `certificates[]`, `input_errors[]`. Each certificate carries its `key_checks`, `validity_policy`, `crls[]` and `findings[]`. |
| `--format csv` | One row per certificate with a stable column set (identity, key, policy, CRL summary, finding codes, errors). Add `--crl-csv FILE` (needs `--fetch-crl`) for one row **per CRL**. |
| `--format sarif` | SARIF 2.1.0 for GitHub code scanning and similar tools; one result per finding with a `security-severity` rating. |

Use `-o FILE` to write to a file. In `json`/`csv`/`sarif` modes stdout contains **only** the
report; progress and warnings go to stderr.

CSV cells that start with `=`, `+`, `-`, `@`, tab or CR are prefixed with `'` so a hostile
subject name or file name cannot become a spreadsheet formula. Text output escapes
control characters so a hostile certificate cannot inject terminal escape sequences.

## Findings

| Code | Severity | Meaning |
|---|---|---|
| `EC_SMALL_SCALAR` | critical | EC public key matches a tiny private scalar: the private key is derivable |
| `RSA_SMALL_FACTOR` | critical | Modulus has a small prime factor |
| `RSA_SHARED_FACTOR` | critical | Modulus shares a prime with another certificate in the population |
| `RSA_KNOWN_WEAK` | critical | Modulus is on your supplied weak list |
| `ROCA_FINGERPRINT` | critical | ROCA (CVE-2017-15361) fingerprint detected |
| `RSA_SHORT_MODULUS` | critical / high | `< 1024` bits / `< 2048` bits |
| `VALIDITY_EXCEEDS_POLICY` | high (low if issued before 2020-09-01) | Lifetime exceeds the CA/B maximum |
| `WEAK_SIGNATURE_HASH` | high | MD5 or SHA-1 signature (not reported for self-signed roots) |
| `EC_WEAK_CURVE`, `DSA_SHORT_KEY` | high | Curve `< 224` bits; DSA `< 2048` bits |
| `CERT_LISTED_IN_CRL` | high | Serial appears in the issuer's CRL (CRL signature **not** verified) |
| `VALIDITY_INVALID` | high | `notAfter` precedes `notBefore` |
| `CERT_EXPIRED`, `RSA_LOW_EXPONENT` (e=3), `CRL_FETCH_FAILED` | medium | |
| `CERT_NOT_YET_VALID`, `MISSING_SAN`, `SERIAL_INVALID`, `CRL_STALE`, `PUBLIC_KEY_UNREADABLE`, `CRL_EXTENSION_MALFORMED` | low | |
| `KEY_REUSE`, `CRL_UNSUPPORTED_URI` | info | |

## Validity-period policy

For publicly trusted TLS server certificates the maximum lifetime depends on the
certificate's **`notBefore`** date (the issuance date):

| Issued | Maximum validity |
|---|---|
| before 2026-03-15 | 398 days |
| 2026-03-15 – 2027-03-14 | 200 days |
| 2027-03-15 – 2029-03-14 | 100 days |
| on or after 2029-03-15 | 47 days |

Whether a certificate is *actually* publicly trusted cannot be known from the certificate
alone, so applicability is a heuristic you can override with `--public-tls`:

- `auto` (default): non-CA, **not** self-signed, and carries the `serverAuth` extended key usage
- `yes`: every non-CA certificate
- `no`: disable the check

`--validity-convention` selects how a lifetime is counted. `inclusive` (default) counts
both the `notBefore` and `notAfter` seconds (elapsed time + 1 s, RFC 5280 style), so a
certificate valid for *exactly* N days elapsed is one second over. `elapsed` uses the plain
difference. The report always shows the numbers it compared.

Certificates issued before 2020-09-01 could legitimately be valid for up to 825 days, so an
over-398-day lifetime on such a certificate is reported as **low severity** and labelled
historical rather than as a current violation.

## CRL inspection

`--fetch-crl` downloads each CRL advertised in a certificate. Results are part of the
certificate's report (and `crls[]` in JSON). Each unique URL is downloaded **once** and shared
across certificates. Retrieval failures are categorised (`url`, `timeout`, `tls`,
`connection`, `http`, `redirect`, `size`, `empty`, `parse`) so scripts can react to them.

CRL URLs inside certificates are attacker-controlled, so fetching them is guarded:

- only `http`/`https`; credentials in URLs rejected; ports limited to 80/443
  (`--allow-nonstandard-crl-ports` to relax)
- the host must resolve only to globally routable addresses (loopback, private, link-local,
  CGNAT, cloud-metadata, IPv4-mapped/6to4/Teredo/NAT64 IPv6 forms are refused;
  `--allow-private-crl-urls` for trusted internal PKI)
- redirects are refused by default. `--follow-crl-redirects` follows up to
  `--crl-max-redirects` hops, re-validating **every** hop and refusing HTTPS→HTTP downgrades
- downloads are size-capped (`--crl-max-bytes`) and time-limited (`--crl-timeout`); proxies
  from the environment are ignored; TLS verification is never disabled

> **Limitation:** the hostname is resolved for validation and again when connecting, so a
> hostile DNS server could answer differently the second time (DNS rebinding). When
> auditing untrusted certificates, also apply network egress controls.

The CRL's own signature is **not** verified, so "listed / not listed" is informational.

## PDF extraction

`--pdf` looks (in priority order) in: the DSS store, digital-signature containers
(`/Contents` PKCS#7, legacy `/Cert`), embedded file attachments, any other stream holding a
DER/PEM/PKCS#7 certificate, PEM text on pages, and raw file bytes. Each certificate is labeled
with where it was found (for example `contract.pdf#signature12.1`), and duplicates collapse
to the most specific label.

PDFs are treated as hostile input: nothing is executed and no network access happens.
Limits bound file size (`--pdf-max-bytes`), page count for text scanning (`--pdf-max-pages`),
object count and total decoded bytes. Encrypted PDFs that need a password are reported, not
opened. Requires `pip install "cert-key-auditor[pdf]"`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed; no findings at or above `--fail-on`; no errors |
| `1` | At least one finding at or above `--fail-on` (default `medium`) |
| `2` | Usage error, no certificates could be loaded, or a fatal error |
| `3` | Completed with non-fatal errors (unreadable inputs, failed steps) and no qualifying findings |
| `130` | Interrupted |

`--fail-on never` always yields `0`/`3` regardless of findings. Failures of individual steps
(one malformed extension, one unreadable key, one broken CRL) are recorded in that certificate's
`errors` and never stop the rest of the run.

## Configuration file

Defaults can be stored in TOML and loaded with `--config FILE` (or `CERT_AUDIT_CONFIG`).
Command-line options always win. The file is **never auto-discovered**, and `token` is
rejected: use the environment variable.

```toml
# cert-audit.toml
format = "json"
fail-on = "high"
fetch-crl = true
follow-crl-redirects = true
public-tls = "auto"
ec-scalar-limit = 1000000
```

## Security and privacy notes

- The tool never extracts private keys: a certificate holds only a public key.
- Findings of `critical` severity indicate the private key may be derivable. Independently
  reproduce them and follow your disclosure process before publishing.
- Do not include tokens, private keys or sensitive certificates in issue reports.
- Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
- Use the tool only on systems and data you are authorized to assess, and follow Censys's terms.

## What it does not do

- Recover private keys, or prove keys were generated with a good random-number generator.
- Validate certificate chains, hostnames, trust, revocation (it does not verify CRL signatures) or OCSP.
- Detect every weak-key class. Searches are bounded: scalars up to `--ec-scalar-limit`
  (curves without a fast search, such as Brainpool and the binary curves, are capped at 4,096), primes up to `--rsa-small-prime-limit`.
- Audit non-EC/RSA keys beyond basic size and algorithm checks.

## Development

```bash
python -m pip install -e ".[dev,test,pdf]"
pre-commit install --install-hooks && pre-commit install --hook-type pre-push

pytest                       # offline; no token or network required
ruff check . && ruff format --check .
mypy
pre-commit run --all-files --hook-stage pre-push     # everything, incl. pip-audit

python -m build && python -m twine check --strict dist/*
```

Pre-commit runs hygiene checks, ruff (lint + format), mypy (strict), Bandit,
[Python Code Audit](https://github.com/nocomplexity/codeaudit) (`codeaudit cimode`),
gitleaks, actionlint and zizmor on commit, and `pip-audit` on push. CI repeats them across
Linux/macOS/Windows and Python 3.11–3.13, plus CodeQL, dependency review and OpenSSF
Scorecard. Releases are built from tags and published through PyPI Trusted Publishing with
build-provenance attestations and a CycloneDX SBOM. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Upgrading from 0.1

- The single script became a package: use `cert-audit` or `python -m cert_key_auditor`
  instead of `python cert_audit.py`. Python 3.11+ is required.
- Existing flags are unchanged (`--pem`, `--population`, `--token`, `--organization-id`,
  `--ec-scalar-limit`, `--rsa-small-prime-limit`, `--known-weak-moduli`, `--no-roca`,
  `--fetch-crl`, `--crl-timeout`, `--crl-max-bytes`, `--allow-private-crl-urls`).
- `--ec-scalar-limit` now defaults to `1,000,000` (it is fast now).
- The positional fingerprint accepts several values.
- Results for a certificate are printed together after the audit, and CRL details are no
  longer a separate block.
- Exit code `3` is new; `--fail-on` (default `medium`) replaces "any finding exits 1".
- Redirected CRL URLs fail by default; add `--follow-crl-redirects` to follow them safely.

## License

MIT; see [LICENSE](LICENSE). Provided without warranty; not a substitute for expert
cryptographic review or incident response.
