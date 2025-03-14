"""Apport Python module."""

# for faster module loading and avoiding circular dependencies
# pylint: disable=import-outside-toplevel

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


def _logging_function(function_name):
    def _wrapped_logging_function(*args, **kwargs):
        import apport.logging

        return getattr(apport.logging, function_name)(*args, **kwargs)

    return _wrapped_logging_function


error = _logging_function("error")
fatal = _logging_function("fatal")
log = _logging_function("log")
memdbg = _logging_function("memdbg")
warning = _logging_function("warning")


def unicode_gettext(message):
    """Return the localized translation of message."""
    import gettext
    import warnings

    warnings.warn(
        "apport.unicode_gettext() is deprecated."
        " Please use gettext.gettext() directly instead.",
        PendingDeprecationWarning,
        stacklevel=2,
    )
    return gettext.gettext(message)
