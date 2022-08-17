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
    trans = gettext.gettext(message)
    if isinstance(trans, bytes):
        return trans.decode("UTF-8")
    return trans
