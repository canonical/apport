"""Helper functions for the test cases."""

import contextlib
import functools
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import typing
import unittest.mock
import urllib.error
import urllib.request


def get_init_system() -> str:
    """Return the name of the running init system (PID 1)."""
    with open("/proc/1/comm", encoding="utf-8") as comm:
        return comm.read().rstrip()


@functools.lru_cache(maxsize=1)
def has_internet() -> bool:
    """Return if there is sufficient network connection for the tests.

    This checks if https://api.launchpad.net/devel/ubuntu/ can be downloaded
    from, to check if we can run the online tests.
    """
    if os.environ.get("SKIP_ONLINE_TESTS"):
        return False
    try:
        with urllib.request.urlopen(
            "https://api.launchpad.net/devel/ubuntu/", timeout=30
        ) as url:
            return b"web_link" in url.readline()
    except urllib.error.URLError:
        return False


def import_module_from_file(filename: str):
    """Import a module by its filename."""
    name = os.path.splitext(os.path.basename(filename))[0].replace("-", "_")
    spec = importlib.util.spec_from_loader(
        name, importlib.machinery.SourceFileLoader(name, filename)
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pidof(program):
    """Find the process ID of a running program.

    This function wraps the pidof command and returns a set of
    process IDs.
    """
    try:
        stdout = subprocess.check_output(["/bin/pidof", "-nx", program])
    except subprocess.CalledProcessError as error:
        if error.returncode == 1:
            return set()
        raise  # pragma: no cover
    return set(int(pid) for pid in stdout.decode().split())


def read_shebang(command: str) -> typing.Optional[str]:
    """Return the shebang of the given file.

    If the given file is a script, return the executable from the
    shebang. Otherwise `None`.
    """
    with open(command, "rb") as command_file:
        first_line = command_file.readline(100).strip()
    if not first_line.startswith(b"#!"):
        return None
    return first_line.decode().split(" ", 1)[0][2:]


def _id(obj):
    return obj


def skip_if_command_is_missing(cmd: str):
    """Skip a test if the command is not found."""
    if shutil.which(cmd) is None:
        return unittest.skip(f"{cmd} not installed")
    return _id


@contextlib.contextmanager
def wrap_object(
    target: object, attribute: str, include_instance: bool = False
) -> typing.Generator[unittest.mock.MagicMock, None, None]:
    """Wrap the named member on an object with a mock object.

    wrap_object() can be used as a context manager. Inside the
    body of the with statement, the attribute of the target is
    wrapped with a :class:`unittest.mock.MagicMock` object. When
    the with statement exits the patch is undone.

    The instance argument 'self' of the wrapped attribute will
    not be logged in the MagicMock call if include_instance is
    set to False. This allows using the assert calls on the mock
    without differentiating between different instances.

    See also https://stackoverflow.com/questions/44768483 for
    the use case.
    """
    mock = unittest.mock.MagicMock()
    real_attribute = getattr(target, attribute)

    def mocked_attribute(self, *args, **kwargs):
        if include_instance:
            mock.__call__(self, *args, **kwargs)
        else:
            mock.__call__(*args, **kwargs)
        return real_attribute(self, *args, **kwargs)

    with unittest.mock.patch.object(target, attribute, mocked_attribute):
        yield mock
