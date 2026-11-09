"""Allow ``python -m cert_key_auditor``."""

from __future__ import annotations

from .cli import main

raise SystemExit(main())
