"""Helper functions for the test cases."""

import subprocess


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
