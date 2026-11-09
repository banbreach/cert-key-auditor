# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-11-10

### Added
- Certificate report object: `print_certificate_metadata` now returns a `CertificateReport`
  that contains metadata, key checks, validity-policy result, **CRL results** and findings;
  all results for a certificate print as a single block.
- Output formats: `--format text|json|csv|sarif`, `--output`, per-CRL `--crl-csv`.
- Colorized text output (`--color`, `NO_COLOR`, `FORCE_COLOR`).
- CA/Browser Forum maximum-validity check (398/200/100/47 days) with
  `--public-tls`, `--validity-convention` and `--as-of`.
- PDF certificate extraction (`--pdf`): signatures, DSS, attachments, streams, page text.
- `--fingerprints-file` batch Censys lookups; multiple positional fingerprints.
- `--fail-on` threshold, documented exit codes (new code `3`), `-v`/`-q` logging.
- TOML configuration (`--config`, `CERT_AUDIT_CONFIG`); tokens are rejected in config files.
- `--follow-crl-redirects` (every hop re-validated), `--allow-nonstandard-crl-ports`.
- CRL results cached per URL; CRL staleness, CRL number, delta CRL and "serial listed" details.
- Policy findings: expiry, weak signature hash, short RSA/DSA keys, weak curves, bad exponents,
  missing SAN, invalid serial numbers, key reuse.
- Retry/backoff (429/5xx, `Retry-After`) for Censys.
- Pre-commit (ruff, mypy, Bandit, Python Code Audit, gitleaks, actionlint, zizmor, pip-audit),
  CI matrix, CodeQL, Scorecard, dependency review, Dependabot, Trusted-Publishing release
  workflow with provenance attestation and SBOM, SECURITY/CONTRIBUTING docs.

### Changed
- Reorganized into a `src/` package; entry point is `cert_key_auditor.cli:main`.
- Requires Python 3.11+ (3.9 is end-of-life).
- EC small-scalar search uses baby-step/giant-step on prime curves (~1000× faster); default
  limit raised to 1,000,000. Other curves fall back to a linear search capped at 4,096.
- Bulk RSA small-prime screening via a prime-product GCD for larger populations.
- Fixed `pyproject.toml` packaging metadata (license, sdist contents).

### Fixed
- Censys responses wrapping PEM in JSON could never be parsed (the raw-body PEM match ran
  first and returned still-escaped JSON). JSON is now decoded first; hex/base64 DER fields
  are supported; the requested fingerprint is selected from multiple returned certificates.
- One unparseable PEM block discarded every certificate in its file.
- `x509.DuplicateExtension` (not a `ValueError`) escaped all handlers and crashed runs.
- A failure auditing one certificate aborted the audit of all remaining certificates.
- A finding could print before its own certificate header, attaching to the previous one.
- `TRUSTED CERTIFICATE` and `X509 CERTIFICATE` PEM labels were rejected.
- IPv4-mapped IPv6 addresses could bypass CRL URL checks on interpreters lacking the
  CVE-2024-4032 fix; now unwrapped explicitly.
- Version printed as `Version.v3`; serial hex was not zero-padded; public-key type name had a
  leading underscore; "roca-detect not installed" was shown even when detection errored.

### Security
- Text output escapes control characters from certificate fields (terminal injection).
- CSV output neutralizes spreadsheet-formula prefixes.
- Hard limits on input, PDF, CRL and Censys response sizes.
