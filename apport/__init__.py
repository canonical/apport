"""Apport Python module."""

# for faster module loading and avoiding circular dependencies
# pylint: disable=import-outside-toplevel

from typing import TYPE_CHECKING

# Import apport.packaging to shadow it afterwards.
import apport.packaging as _  # noqa: F401

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

if TYPE_CHECKING:
    from apport.packaging_impl import impl as packaging
    from apport.report import Report
else:
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
            from apport.packaging_impl import impl as packaging

            return packaging.__getattribute__(name)

    packaging = _LazyLoadingPackaging()


def _logging_function(function_name):
    def _wrapped_logging_function(*args, **kwargs):
        import warnings

        import apport.logging

        warnings.warn(
            f"apport.{function_name}() is deprecated."
            f" Please use apport.logging.{function_name}() directly instead.",
            DeprecationWarning,
            stacklevel=2,
        )
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
