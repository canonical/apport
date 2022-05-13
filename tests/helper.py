"""Helper functions for the test cases."""

import os
import os.path
import subprocess
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
