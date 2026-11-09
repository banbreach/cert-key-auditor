"""Optional TOML configuration file.

Only an explicit ``--config PATH`` (or ``CERT_AUDIT_CONFIG``) is read; the tool
never auto-loads a file from the working directory, because scanning an
untrusted directory must not let its contents change tool behaviour.

Keys are the long option names with ``-`` or ``_`` (``fail-on`` == ``fail_on``),
either at the top level or inside a ``[cert-audit]`` table. Command-line options
always override the file. Secrets are refused: set ``CENSYS_API_TOKEN`` in the
environment instead.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from .errors import ConfigError

# key -> (type, allowed values or None)
SCHEMA: dict[str, tuple[type | tuple[type, ...], tuple[str, ...] | None]] = {
    "format": (str, ("text", "json", "csv", "sarif")),
    "color": (str, ("auto", "always", "never")),
    "output": (str, None),
    "crl_csv": (str, None),
    "fail_on": (str, ("never", "info", "low", "medium", "high", "critical")),
    "ec_scalar_limit": (int, None),
    "rsa_small_prime_limit": (int, None),
    "known_weak_moduli": (str, None),
    "roca": (bool, None),
    "population_analysis": (bool, None),
    "fetch_crl": (bool, None),
    "crl_timeout": ((int, float), None),
    "crl_max_bytes": (int, None),
    "crl_max_redirects": (int, None),
    "follow_crl_redirects": (bool, None),
    "allow_private_crl_urls": (bool, None),
    "allow_nonstandard_crl_ports": (bool, None),
    "public_tls": (str, ("auto", "yes", "no")),
    "validity_convention": (str, ("inclusive", "elapsed")),
    "as_of": (str, None),
    "censys_timeout": ((int, float), None),
    "organization_id": (str, None),
    "pdf_max_pages": (int, None),
    "pdf_max_bytes": (int, None),
}
FORBIDDEN = {  # nosec B105 - an error message, not a credential
    "token": "put the Censys token in the CENSYS_API_TOKEN environment variable"
}


def load_config(path: str) -> dict[str, Any]:
    """Parse and validate a configuration file; returns parser defaults."""
    try:
        with Path(path).open("rb") as handle:
            raw = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read config file ({exc.strerror or exc})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML ({exc})") from exc

    table = raw.get("cert-audit", raw)
    if not isinstance(table, dict):
        raise ConfigError(f"{path}: [cert-audit] must be a table")

    values: dict[str, Any] = {}
    for key, value in table.items():
        name = key.replace("-", "_")
        if name in FORBIDDEN:
            raise ConfigError(f"{path}: '{key}' is not allowed in a config file; {FORBIDDEN[name]}")
        if name not in SCHEMA:
            if name == "cert_audit":
                continue
            valid = ", ".join(sorted(SCHEMA))
            raise ConfigError(f"{path}: unknown option '{key}' (valid: {valid})")
        expected, choices = SCHEMA[name]
        if isinstance(value, bool) and expected is not bool:
            raise ConfigError(f"{path}: '{key}' must not be a boolean")
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            raise ConfigError(f"{path}: '{key}' has the wrong type ({type(value).__name__})")
        if choices is not None and value not in choices:
            raise ConfigError(f"{path}: '{key}' must be one of {', '.join(choices)}")
        values[name] = value
    return values
