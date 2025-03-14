"""Apport Python module."""

# for faster module loading and avoiding circular dependencies
# pylint: disable=import-outside-toplevel

# Sadly importing apport.packaging is needed here to shadow it later
import apport.packaging

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


# wraps an object; pylint: disable-next=invalid-name
def Report(*args, **kwargs):
    """Lazy loading of apport.report.Report()."""
    from apport.report import Report as cls

    return cls(*args, **kwargs)


# wrapper object; pylint: disable-next=too-few-public-methods
class _LazyLoadingPackaging:
    def __getattribute__(self, name):
        # The packaging object will be replaced by the imported object.
        # pylint: disable-next=global-statement
        global packaging
        # pylint: disable-next=redefined-outer-name
        from apport.packaging_impl import impl as packaging

        return packaging.__getattribute__(name)


packaging = _LazyLoadingPackaging()


def _logging_function(function_name):
    def _wrapped_logging_function(*args, **kwargs):
        from apport import logging

        return getattr(logging, function_name)(*args, **kwargs)

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
