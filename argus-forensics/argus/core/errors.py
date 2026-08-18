"""Exception hierarchy for ARGUS Forensics.

Every failure surface in the toolkit raises a subclass of :class:`ArgusError`
so that the CLI and the REST layer can map failures onto stable exit codes and
HTTP statuses instead of leaking arbitrary tracebacks into an operator's
audit trail.
"""

from __future__ import annotations


class ArgusError(Exception):
    """Base class for all ARGUS errors."""

    exit_code = 1


class CaseError(ArgusError):
    """Raised for invalid case state, duplicate case IDs, locked cases."""

    exit_code = 2


class ContainerError(ArgusError):
    """Raised when an evidence container is malformed or fails verification."""

    exit_code = 3


class IntegrityError(ContainerError):
    """Raised when a stored hash does not match recomputed content.

    This is the most serious error the toolkit can raise: it means evidence
    on disk no longer matches what was acquired.
    """

    exit_code = 4


class AcquisitionError(ArgusError):
    """Raised when a device acquisition cannot start or fails mid-run."""

    exit_code = 5


class DeviceNotSupportedError(AcquisitionError):
    """Raised when the capability matrix has no method for a device/state."""

    exit_code = 6


class ParserError(ArgusError):
    """Raised when a parser cannot handle the data it was given."""

    exit_code = 7


class WriteBlockViolation(ArgusError):
    """Raised when code attempts to mutate a source evidence path.

    ARGUS treats every source path as read-only. Any attempt to open a source
    file for writing is a bug and is fatal by design.
    """

    exit_code = 8


class QueryError(ArgusError):
    """Raised on malformed AQL (ARGUS Query Language) input."""

    exit_code = 9


class ReportError(ArgusError):
    """Raised when a report cannot be rendered or written."""

    exit_code = 10
