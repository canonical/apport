"""Helper functions for the test cases."""

import contextlib
import functools
import importlib.machinery
import importlib.util
import os
import pathlib
import shutil
import subprocess
import time
import unittest.mock
import urllib.error
import urllib.request
from collections.abc import Callable, Generator, Iterator, Sequence, Set
from typing import Any
from unittest.mock import MagicMock

import psutil


def get_gnu_coreutils_cmd(cmd: str) -> str:
    """Determine path to GNU coreutils command."""
    path = shutil.which(f"gnu{cmd}")
    if path is not None:
        return path
    return os.path.realpath(f"/bin/{cmd}")


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


def import_module_from_file(path: pathlib.Path) -> Any:
    """Import a module by its filename."""
    name = path.stem.replace("-", "_")
    spec = importlib.util.spec_from_loader(
        name, importlib.machinery.SourceFileLoader(name, str(path))
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def pidfd_open(pid: int) -> Iterator[int]:
    """Return a file descriptor referring to the process pid.

    This function provides os.pidfd_open() as context manager."""
    pidfd = os.pidfd_open(pid)
    try:
        yield pidfd
    finally:
        os.close(pidfd)


def pids_of(program: str) -> set[int]:
    """Find the process IDs of a running program.

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


def read_shebang(command: str) -> str | None:
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
def restore_os_environ() -> Generator[None]:
    """Restore os.environ after leaving this context manager."""
    orig_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(orig_env)


@contextlib.contextmanager
def run_test_executable(
    args: Sequence[str] | None = None, env: dict[str, str] | None = None
) -> Iterator[int]:
    """Run test executable and yield the process ID. Kill process afterwards."""
    if args is None:
        args = (get_gnu_coreutils_cmd("sleep"), "86400")
    with subprocess.Popen(args, env=env) as test_process:
        try:
            yield test_process.pid
        finally:
            test_process.kill()


def _id(obj: Any) -> Any:
    return obj


def skip_if_command_is_missing(cmd: str) -> Callable:
    """Skip a test if the command is not found."""
    if shutil.which(cmd) is None:
        return unittest.skip(f"{cmd} not installed")
    return _id


@contextlib.contextmanager
def wrap_object(
    target: object, attribute: str, include_instance: bool = False
) -> Generator[MagicMock]:
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
    mock = MagicMock()
    real_attribute = getattr(target, attribute)

    def mocked_attribute(self: object, *args: Any, **kwargs: Any) -> Any:
        if include_instance:
            mock(self, *args, **kwargs)
        else:
            mock(*args, **kwargs)
        return real_attribute(self, *args, **kwargs)

    with unittest.mock.patch.object(target, attribute, mocked_attribute):
        yield mock


def wait_for_sleeping_state(pid: int, timeout: float = 5.0) -> None:
    """Wait for sleep command to enter sleeping state."""
    proc = psutil.Process(pid)
    waited = 0.0
    last_state = ""
    while waited < timeout:
        last_state = proc.status()
        if last_state == "sleeping":
            return

        time.sleep(0.1)
        waited += 0.1

    raise TimeoutError(
        f"{pid=} did not enter 'sleeping' state after {timeout=} seconds."
        f" Got {last_state!r} instead."
    )


def wait_for_process_to_appear(
    process: str, already_running: Set[int], timeout: float = 5.0
) -> int:
    """Wait for process to appear and return its PID."""
    waited = 0.0
    while waited < timeout:
        pids = pids_of(process) - already_running
        if pids:
            assert len(pids) == 1, f"Found more than one PID for {process!r}"
            return pids.pop()
        time.sleep(0.1)
        timeout -= 0.1

    raise TimeoutError(f"PID for {process!r} not found within {timeout=} seconds.")
