## What and why

<!-- Describe the change and link the issue it addresses. -->

## Checklist

- [ ] Tests added or updated (offline; no real certificates, tokens or network)
- [ ] `pre-commit run --all-files --hook-stage pre-push` passes
- [ ] README / CHANGELOG updated for user-visible changes
- [ ] No secrets, tokens, private keys or real-world sensitive certificates included
- [ ] For changes touching `crl.py` / `pdf.py` / input parsing: considered SSRF, resource limits and hostile input
