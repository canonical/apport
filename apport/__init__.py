import gettext

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
    return gettext.gettext(message)
