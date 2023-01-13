import os
import typing

_SRCDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BINDIR = os.path.join(_SRCDIR, "bin")
_CRASHDB_CONF = os.path.join(_SRCDIR, "etc", "apport", "crashdb.conf")
_DATADIR = os.path.join(_SRCDIR, "data")


def get_data_directory(local_path: typing.Optional[str] = None) -> str:
    """Return absolute path for apport's data directory.

    If the tests are executed in the local source code directory,
    return the absolute path to the local data directory or to the
    given local path (if specified). Otherwise return the path to the
    system installed data directory. The returned data directory can be
    overridden by setting the environment variable APPORT_DATA_DIR.
    """
    if "APPORT_DATA_DIR" in os.environ:
        return os.environ["APPORT_DATA_DIR"]
    if is_local_source_directory():
        if local_path is None:
            return _DATADIR
        return os.path.join(_SRCDIR, local_path)
    return "/usr/share/apport"


def is_local_source_directory() -> bool:
    """Return True if the current working directory is the source directory.

    The local source directory is expected to have a tests directory
    and a setup.py file.
    """
    return os.path.isdir("tests") and os.path.exists("setup.py")


def local_test_environment() -> typing.Mapping[str, str]:
    """Return needed environment variables when running tests locally."""
    if not is_local_source_directory():
        return {}
    return {
        "APPORT_CRASHDB_CONF": _CRASHDB_CONF,
        "APPORT_DATA_DIR": _DATADIR,
        "PATH": f"{_BINDIR}:{os.environ.get('PATH', os.defpath)}",
        "PYTHONPATH": _SRCDIR,
    }


def patch_data_dir(report) -> typing.Optional[typing.Mapping[str, str]]:
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


def restore_data_dir(
    report, orig: typing.Optional[typing.Mapping[str, str]]
) -> None:
    """Restore APPORT_DATA_DIR in apport.report from local tests.

    The parameter orig is the result from the patch_data_dir() call.
    """
    if not orig:
        return

    # pylint: disable=protected-access
    report._data_dir = orig["data_dir"]
    report.GENERAL_HOOK_DIR = orig["general_hook_dir"]
    report.PACKAGE_HOOK_DIR = orig["package_hook_dir"]
