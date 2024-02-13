"""Legacy logging functions."""

import os
import sys
import time
import typing


def log(message, timestamp=False):
    """Log the given string to stdout. Prepend timestamp if requested."""
    if timestamp:
        sys.stdout.write(f"{time.strftime('%x %X')}: ")
    print(message)


def fatal(msg: str, *args: typing.Any) -> typing.NoReturn:
    """Print out an error message and exit the program."""
    error(msg, *args)
    sys.exit(1)


def error(msg, *args):
    """Print out an error message."""
    if sys.stderr:
        sys.stderr.write("ERROR: ")
        sys.stderr.write(msg % args)
        sys.stderr.write("\n")


def warning(msg, *args):
    """Print out an warning message."""
    if sys.stderr:
        sys.stderr.write("WARNING: ")
        sys.stderr.write(msg % args)
        sys.stderr.write("\n")


def memdbg(checkpoint):
    """Print current memory usage.

    This is only done if $APPORT_MEMDEBUG is set.
    """
    if "APPORT_MEMDEBUG" not in os.environ or not sys.stderr:
        return

    memstat = {}
    with open("/proc/self/status", encoding="utf-8") as status_file:
        for line in status_file:
            if line.startswith("Vm"):
                (field, size, _) = line.split()
                memstat[field[:-1]] = int(size) / 1024.0

    sys.stderr.write(
        f"Size: {memstat['VmSize']:.1f} MB, RSS: {memstat['VmRSS']:.1f} MB,"
        f" Stk: {memstat['VmStk']:.1f} MB @ {checkpoint}\n"
    )
