"""System tests for apport-retrace."""

import os
import pathlib
import re
import shutil
import signal
import subprocess
import tempfile
import textwrap
from collections.abc import Iterator

import pytest

from apport.packaging_impl.apt_dpkg import impl
from apport.report import Report
from tests.helper import has_internet
from tests.paths import get_test_data_directory, local_test_environment

CODENAME_DISTRO_RELEASE_MAP = {"jammy": "Ubuntu 22.04"}


@pytest.fixture(name="module_workdir", scope="module")
def fixture_module_workdir() -> Iterator[pathlib.Path]:
    """Create a temporary work directory for all test case in this module."""
    workdir = tempfile.mkdtemp(prefix="apport_retrace_system_tests_", dir="/var/tmp")
    yield pathlib.Path(workdir)
    shutil.rmtree(workdir)


@pytest.fixture(name="module_cachedir", scope="module")
def fixture_module_cachedir(module_workdir: pathlib.Path) -> pathlib.Path:
    """Return sandbox cache directory used for all test in this module."""
    return module_workdir / "cache"


@pytest.fixture(name="divide_by_zero_crash", scope="module")
def fixture_divide_by_zero_crash(module_workdir: pathlib.Path) -> str:
    """Generate a Report with a crash of divide-by-zero."""
    executable = "/usr/bin/divide-by-zero"
    assert pathlib.Path(executable).exists()
    core_path = module_workdir / "divide-by-zero.core"
    gdb = subprocess.run(
        [
            "gdb",
            "--batch",
            "-iex",
            "set debuginfod enable off",
            "--ex",
            "run",
            "--ex",
            f"generate-core-file {core_path}",
            executable,
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert core_path.exists()
    signal_match = re.search("Program received signal (SIG[A-Z]+)", gdb.stdout)
    assert signal_match, gdb.stdout

    # generate crash report
    report = Report()
    report["ExecutablePath"] = executable
    report["Signal"] = str(signal.Signals[signal_match.group(1)].value)
    report["SignalName"] = signal_match.group(1)
    report.add_os_info()
    report.add_package_info()
    report["CoreDump"] = (str(core_path),)

    report_filename = module_workdir / "divide-by-zero.crash"
    with open(report_filename, "wb") as report_file:
        report.write(report_file)

    return str(report_filename)


@pytest.fixture(name="workdir")
def fixture_workdir() -> Iterator[pathlib.Path]:
    """Create a temporary work directory for the test case."""
    workdir = tempfile.mkdtemp()
    yield pathlib.Path(workdir)
    shutil.rmtree(workdir)


def setup_ubuntu_sandbox_config(configdir: pathlib.Path, release: str) -> None:
    """Set up sandbox configuration for retracing Ubuntu crashes."""
    config_release_dir = configdir / CODENAME_DISTRO_RELEASE_MAP[release]
    codename_file = config_release_dir / "codename"
    sources_dir = config_release_dir / "sources.list.d"
    sources_file = sources_dir / "ubuntu.sources"
    # pylint: disable-next=protected-access
    uri = impl._get_mirror()

    sources_dir.mkdir(parents=True)
    codename_file.write_text(release)
    sources_file.write_text(
        textwrap.dedent(
            f"""\
            Types: deb deb-src
            URIs: {uri}
            Suites: {release}
            Components: main
            Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
            """
        )
    )


@pytest.fixture(name="sandbox_config")
def fixture_sandbox_config(workdir: pathlib.Path) -> str:
    """Setup a sandbox configuration that supports Ubuntu jammy."""
    config = workdir / "config"
    config.mkdir()
    setup_ubuntu_sandbox_config(config, "jammy")
    return str(config)


def _read_and_print_retraced_report(report_filename: pathlib.Path) -> Report:
    report = Report()
    with open(report_filename, "rb") as report_file:
        report.load(report_file)

    assert "CoreDump" in report
    del report["CoreDump"]
    print(f"Retraced report without CoreDump: {report}")

    return report


def _assert_is_retraced(report: Report) -> None:
    for expected_key in (
        "Disassembly",
        "Registers",
        "Stacktrace",
        "StacktraceSource",
        "StacktraceTop",
        "ThreadStacktrace",
    ):
        assert expected_key in report


def _assert_divide_by_zero_retrace(report: Report) -> None:
    stack_top = "divide_by_zero () at /usr/src/chaos-marmosets"
    if report["DistroRelease"] == "Ubuntu 22.04":
        stack_top = "divide_by_zero () at ./divide-by-zero.c"
    assert "divide_by_zero" in report["Disassembly"]
    # Expect RIP point to divide_by_zero
    assert "divide_by_zero" in report["Registers"]
    assert f"#0  {stack_top}" in report["Stacktrace"]
    assert f"#0  {stack_top}" in report["StacktraceSource"]
    assert "42 / zero" in report["StacktraceSource"]
    assert stack_top in report["StacktraceTop"]
    assert f"#0  {stack_top}" in report["ThreadStacktrace"]


def _assert_sleep_retrace(report: Report) -> None:
    stack_top = " in __GI___clock_nanosleep "
    assert "__GI___clock_nanosleep" in report["Disassembly"]
    # Expect RIP point to offset of __GI___clock_nanosleep
    assert "__GI___clock_nanosleep" in report["Registers"]
    assert stack_top in report["Stacktrace"]
    assert "seconds = 86400" in report["Stacktrace"]
    assert stack_top in report["StacktraceSource"]
    assert "return nanosleep" in report["StacktraceSource"]
    assert "__GI___clock_nanosleep (clock_id=" in report["StacktraceTop"]
    assert stack_top in report["ThreadStacktrace"]
    assert "seconds = 86400" in report["ThreadStacktrace"]


def _assert_cache_has_content(cachedir: pathlib.Path, codename: str) -> None:
    distro_cache = cachedir / CODENAME_DISTRO_RELEASE_MAP[codename]
    assert list((distro_cache / "apt/var/lib/apt/lists").iterdir())
    assert list((distro_cache / "apt/var/cache/apt/archives").iterdir())


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_retrace_system_sandbox(
    workdir: pathlib.Path, module_cachedir: pathlib.Path, divide_by_zero_crash: str
) -> None:
    """Retrace a divide-by-zero crash in a system sandbox."""
    retraced_report_filename = workdir / "retraced.crash"
    env = os.environ | local_test_environment()
    cmd = [
        "apport-retrace",
        "-v",
        "-o",
        str(retraced_report_filename),
        "--sandbox",
        "system",
        "--cache",
        str(module_cachedir),
        divide_by_zero_crash,
    ]
    subprocess.run(cmd, check=True, env=env)

    report = _read_and_print_retraced_report(retraced_report_filename)
    _assert_is_retraced(report)
    _assert_divide_by_zero_retrace(report)


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_retrace_system_sandbox_gdb_sandbox(
    workdir: pathlib.Path, module_cachedir: pathlib.Path, divide_by_zero_crash: str
) -> None:
    """Retrace a divide-by-zero crash in a system sandbox with a GDB sandbox."""
    retraced_report_filename = workdir / "retraced.crash"
    env = os.environ | local_test_environment()
    cmd = [
        "apport-retrace",
        "-v",
        "-o",
        str(retraced_report_filename),
        "--sandbox",
        "system",
        "--gdb-sandbox",
        "--cache",
        str(module_cachedir),
        divide_by_zero_crash,
    ]
    subprocess.run(cmd, check=True, env=env)

    report = _read_and_print_retraced_report(retraced_report_filename)
    _assert_is_retraced(report)
    _assert_divide_by_zero_retrace(report)


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_retrace_jammy_sandbox(
    workdir: pathlib.Path, module_cachedir: pathlib.Path, sandbox_config: pathlib.Path
) -> None:
    """Retrace a sleep crash from jammy in a sandbox."""
    crash = get_test_data_directory() / "jammy_usr_bin_sleep.1000.crash"
    retraced_report_filename = workdir / "retraced.crash"
    env = os.environ | local_test_environment()
    cmd = [
        "apport-retrace",
        "-v",
        "-o",
        str(retraced_report_filename),
        "--sandbox",
        str(sandbox_config),
        "--cache",
        str(module_cachedir),
        "--sandbox-dir",
        str(workdir / "apport_sandbox"),
        str(crash),
    ]
    subprocess.run(cmd, check=True, env=env)

    report = _read_and_print_retraced_report(retraced_report_filename)
    _assert_is_retraced(report)
    _assert_sleep_retrace(report)
    _assert_cache_has_content(module_cachedir, "jammy")


@pytest.mark.skipif(not has_internet(), reason="online test")
def test_retrace_jammy_sandbox_gdb_sandbox(
    workdir: pathlib.Path, module_cachedir: pathlib.Path, sandbox_config: pathlib.Path
) -> None:
    """Retrace a sleep crash from jammy in a sandbox with a GDB sandbox."""
    crash = get_test_data_directory() / "jammy_usr_bin_sleep.1000.crash"
    retraced_report_filename = workdir / "retraced.crash"
    env = os.environ | local_test_environment()
    cmd = [
        "apport-retrace",
        "-v",
        "-o",
        str(retraced_report_filename),
        "--sandbox",
        str(sandbox_config),
        "--gdb-sandbox",
        "--cache",
        str(module_cachedir),
        "--sandbox-dir",
        str(workdir / "apport_sandbox"),
        str(crash),
    ]
    subprocess.run(cmd, check=True, env=env)

    report = _read_and_print_retraced_report(retraced_report_filename)
    _assert_is_retraced(report)
    _assert_sleep_retrace(report)
    _assert_cache_has_content(module_cachedir, "jammy")
