"""Test helper functions around modifying paths."""

import os
import pathlib
from collections.abc import Mapping
from typing import Any

_SRCDIR = pathlib.Path(__file__).absolute().parent.parent
_BINDIR = _SRCDIR / "bin"
_CRASHDB_CONF = _SRCDIR / "etc" / "apport" / "crashdb.conf"
_DATADIR = _SRCDIR / "data"


def get_data_directory(local_path: (str | None) = None) -> pathlib.Path:
    """Return absolute path for apport's data directory.

    If the tests are executed in the local source code directory,
    return the absolute path to the local data directory or to the
    given local path (if specified). Otherwise return the path to the
    system installed data directory. The returned data directory can be
    overridden by setting the environment variable APPORT_DATA_DIR.
    """
    if "APPORT_DATA_DIR" in os.environ:
        return pathlib.Path(os.environ["APPORT_DATA_DIR"])
    if is_local_source_directory():
        if local_path is None:
            return _DATADIR
        return _SRCDIR / local_path
    return pathlib.Path("/usr/share/apport")


def is_local_source_directory() -> bool:
    """Return True if the current working directory is the source directory.

    The local source directory is expected to have a tests directory
    and a setup.py file.
    """
    return os.path.isdir("tests") and os.path.exists("setup.py")


def local_test_environment() -> Mapping[str, str]:
    """Return needed environment variables when running tests locally."""
    if not is_local_source_directory():
        return {}
    return {
        "APPORT_CRASHDB_CONF": str(_CRASHDB_CONF),
        "APPORT_DATA_DIR": str(_DATADIR),
        "PATH": f"{_BINDIR}:{os.environ.get('PATH', os.defpath)}",
        "PYTHONPATH": str(_SRCDIR),
    }


def patch_data_dir(report: Any) -> Mapping[str, str] | None:
    """Patch APPORT_DATA_DIR in apport.report for local tests."""
    if not is_local_source_directory():
        return None

    # pylint: disable=protected-access
    orig = {
        "data_dir": report._data_dir,
        "general_hook_dir": report.GENERAL_HOOK_DIR,
        "package_hook_dir": report.PACKAGE_HOOK_DIR,
    }

    data_dir = get_data_directory()
    report._data_dir = data_dir
    report.GENERAL_HOOK_DIR = f"{data_dir}/general-hooks/"
    report.PACKAGE_HOOK_DIR = f"{data_dir}/package-hooks/"

    return orig


def restore_data_dir(report: Any, orig: (Mapping[str, str] | None)) -> None:
    """Restore APPORT_DATA_DIR in apport.report from local tests.

    The parameter orig is the result from the patch_data_dir() call.
    """
    if not orig:
        return

    # pylint: disable=protected-access
    report._data_dir = orig["data_dir"]
    report.GENERAL_HOOK_DIR = orig["general_hook_dir"]
    report.PACKAGE_HOOK_DIR = orig["package_hook_dir"]
