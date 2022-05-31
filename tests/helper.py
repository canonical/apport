"""Helper functions for the test cases."""

import contextlib
import os
import os.path
import subprocess
import typing
import unittest.mock
from urllib.error import URLError
from urllib.request import urlopen


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
            f = urlopen("https://api.launchpad.net/devel/ubuntu/", timeout=30)
            if b"web_link" in f.readline():
                has_internet.cache = True
        except URLError:
            pass
    return has_internet.cache


has_internet.cache = None


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
