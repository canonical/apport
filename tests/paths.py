import os
import typing

SRCDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BINDIR = os.path.join(SRCDIR, "bin")
CRASHDB_CONF = os.path.join(SRCDIR, "etc", "apport", "crashdb.conf")
DATADIR = os.path.join(SRCDIR, "data")


def get_data_directory() -> str:
    """Return absolute path for apport's data directory.

    If the tests are executed in the local source code directory,
    return the path to the local source directory. Otherwise
    return the path to the system installed version. The data
    directory can be specified by setting the environment variable
    APPORT_DATA_DIR.
    """
    if "APPORT_DATA_DIR" in os.environ:
        return os.environ["APPORT_DATA_DIR"]
    if is_local_source_directory():
        return DATADIR
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
        "APPORT_CRASHDB_CONF": CRASHDB_CONF,
        "APPORT_DATA_DIR": DATADIR,
        "PATH": f"{BINDIR}:{os.environ.get('PATH', os.defpath)}",
        "PYTHONPATH": SRCDIR,
    }


def patch_data_dir(report) -> typing.Optional[typing.Mapping[str, str]]:
    """Patch APPORT_DATA_DIR in apport.report for local tests."""
    if not is_local_source_directory():
        return None

    # pylint: disable=protected-access
    orig = {
        "data_dir": report._data_dir,
        "hook_dir": report._hook_dir,
        "common_hook_dir": report._common_hook_dir,
    }

    data_dir = get_data_directory()
    report._data_dir = data_dir
    report._hook_dir = f"{data_dir}/package-hooks/"
    report._common_hook_dir = f"{data_dir}/general-hooks/"

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
    report._hook_dir = orig["hook_dir"]
    report._common_hook_dir = orig["common_hook_dir"]
