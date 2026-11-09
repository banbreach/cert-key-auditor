# Security policy

## Supported versions

This project is in alpha. Security fixes are made against the latest release on the
default branch.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
<https://github.com/banbreach/cert-key-auditor/security/advisories/new>

Include the version (`cert-audit --version`), what you observed, and a minimal reproduction.
**Do not include real access tokens, private keys, or sensitive certificates**; synthetic
test data is preferred. You can expect an acknowledgement within a few days and a status
update as the fix progresses. Please allow reasonable time to fix an issue before disclosing
it publicly.

## Scope and threat model

The tool is designed to process **untrusted input**: certificates, CRLs, PDFs and Censys
responses may all be attacker-controlled. In scope examples:

- SSRF or request smuggling through CRL URLs (`crl.py`), including redirect handling
- Resource exhaustion from certificates, CRLs or PDFs (size, object count, decompression)
- Crashes or misleading output caused by malformed input
- Terminal-escape or spreadsheet-formula injection through rendered certificate fields
- Credential exposure (tokens in logs, errors, output or config files)

Known, documented limitations (not vulnerabilities): the DNS lookup used for CRL URL
validation is separate from the connection (DNS rebinding); CRL signatures are not verified;
all key checks are bounded and a clean result does not prove a key is secure.

## Handling findings the tool reports

A `critical` key finding can mean a real private key is derivable. Reproduce it independently,
verify the certificate identity, and follow your organization's coordinated-disclosure
process before publishing details.
