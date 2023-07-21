"""Apport Python module."""

import gettext
import warnings

from apport.logging import error, fatal, log, memdbg, warning
from apport.packaging_impl import impl as packaging
from apport.report import Report

__all__ = [
    "Report",
    "error",
    "fatal",
    "log",
    "memdbg",
    "packaging",
    "unicode_gettext",
    "warning",
]


def unicode_gettext(message):
    """Return the localized translation of message."""
    warnings.warn(
        "apport.unicode_gettext() is deprecated."
        " Please use gettext.gettext() directly instead.",
        PendingDeprecationWarning,
        stacklevel=2,
    )
    return gettext.gettext(message)
