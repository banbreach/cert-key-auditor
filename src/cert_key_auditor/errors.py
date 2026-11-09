"""Exception hierarchy.

Every error the tool raises on purpose derives from :class:`CertAuditError`,
so callers can distinguish expected failures (bad input, network problems)
from genuine bugs.
"""

from __future__ import annotations


class CertAuditError(Exception):
    """Base class for all expected cert-key-auditor failures."""


class InputError(CertAuditError):
    """An input file, stream or value could not be read or understood."""


class CertificateParseError(InputError):
    """Certificate bytes could not be parsed as X.509."""


class PdfError(InputError):
    """A PDF could not be read or exceeded a safety limit."""


class ConfigError(CertAuditError):
    """The configuration file is missing, malformed or contains bad values."""


class CensysError(CertAuditError):
    """A Censys lookup failed."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class CrlError(CertAuditError):
    """A CRL could not be fetched or parsed.

    ``kind`` is a short machine-readable category: ``url``, ``timeout``,
    ``tls``, ``connection``, ``http``, ``redirect``, ``size``, ``empty``,
    ``parse`` or ``request``.
    """

    def __init__(self, message: str, *, kind: str = "request") -> None:
        super().__init__(message)
        self.kind = kind
