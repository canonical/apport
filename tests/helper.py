"""Helper functions for the test cases."""

import contextlib
import importlib.machinery
import importlib.util
import os
import subprocess
import typing
import unittest.mock
import urllib.error
import urllib.request


def has_internet():
    """Return if there is sufficient network connection for the tests.

    This checks if https://api.launchpad.net/devel/ubuntu/ can be downloaded
    from, to check if we can run the online tests.
    """
    if os.environ.get("SKIP_ONLINE_TESTS"):
        return False
    if has_internet.cache is None:
        has_internet.cache = False
        try:
            f = urllib.request.urlopen(
                "https://api.launchpad.net/devel/ubuntu/", timeout=30
            )
            if b"web_link" in f.readline():
                has_internet.cache = True
        except urllib.error.URLError:
            pass
    return has_internet.cache


has_internet.cache = None


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


@contextlib.contextmanager
def wrap_object(
    target: object, attribute: str
) -> typing.Generator[unittest.mock.MagicMock, None, None]:
    """Wrap the named member on an object with a mock object.

    wrap_object() can be used as a context manager. Inside the
    body of the with statement, the attribute of the target is
    wrapped with a :class:`unittest.mock.MagicMock` object. When
    the with statement exits the patch is undone.

    The instance argument 'self' of the wrapped attribute is
    intentionally not logged in the MagicMock call. Therefore
    wrap_object() can be used to check all calls to the object,
    but not differentiate between different instances.

    See also https://stackoverflow.com/questions/44768483 for
    the use case.
    """
    mock = unittest.mock.MagicMock()
    real_attribute = getattr(target, attribute)

    def mocked_attribute(self, *args, **kwargs):
        mock.__call__(*args, **kwargs)
        return real_attribute(self, *args, **kwargs)

    with unittest.mock.patch.object(target, attribute, mocked_attribute):
        yield mock
