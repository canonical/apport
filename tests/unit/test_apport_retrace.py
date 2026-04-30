"""Unit tests for apport-retrace."""

import io
import pathlib
import tempfile
import unittest
import unittest.mock
from unittest.mock import MagicMock

from apport.report import Report
from tests.helper import import_module_from_file
from tests.paths import get_bin_directory

apport_retrace = import_module_from_file(get_bin_directory() / "apport-retrace")


def add_mocked_gdb_info(
    self: Report, rootdir: str | None = None, gdb_sandbox: str | None = None
) -> None:
    # keep API unchanged, pylint: disable=unused-argument
    """Mock Report.add_gdb_info() for tests."""
    self["Registers"] = "mocked registers"
    self["Stacktrace"] = "mocked stacktrace"
    self["ThreadStacktrace"] = "mocked thread stacktrace"


def mocked_gen_source_stacktrace(report: Report, sandbox: str | None) -> None:
    # keep API unchanged, pylint: disable=unused-argument
    """Mock Report.add_gdb_info() for tests."""
    assert "SourcePackage" in report
    report["StacktraceSource"] = "mocked stacktrace source"


@unittest.mock.patch.object(apport_retrace.Report, "add_gdb_info", autospec=True)
@unittest.mock.patch.object(apport_retrace, "gen_source_stacktrace")
@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_main(
    get_crashdb_mock: MagicMock,
    gen_source_stacktrace_mock: MagicMock,
    add_gdb_info_mock: MagicMock,
) -> None:
    """Test main() from apport-retrace on a crash file."""
    add_gdb_info_mock.side_effect = add_mocked_gdb_info
    gen_source_stacktrace_mock.side_effect = mocked_gen_source_stacktrace
    report = (
        "ProblemType: Crash\n"
        "Architecture: amd64\n"
        "DistroRelease: Ubuntu 26.04\n"
        "ExecutablePath: /usr/bin/divide-by-zero\n"
        "Package: chaos-marmosets 0.2.0-1build1\n"
        "SourcePackage: chaos-marmosets\n"
        "CoreDump: base64\n"
        " c29tZSBiaW5hcnkgZGF0YQ==\n"
    )
    expected_report = (
        "ProblemType: Crash\n"
        "Architecture: amd64\n"
        "DistroRelease: Ubuntu 26.04\n"
        "ExecutablePath: /usr/bin/divide-by-zero\n"
        "Package: chaos-marmosets 0.2.0-1build1\n"
        "Registers: mocked registers\n"
        "SourcePackage: chaos-marmosets\n"
        "Stacktrace: mocked stacktrace\n"
        "StacktraceSource: mocked stacktrace source\n"
        "ThreadStacktrace: mocked thread stacktrace\n"
        "CoreDump: base64\n"
        " c29tZSBiaW5hcnkgZGF0YQ==\n"
    )
    with (
        tempfile.NamedTemporaryFile(mode="w+", suffix=".crash") as crash_file,
        unittest.mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        crash_file.write(report)
        crash_file.flush()
        return_code = apport_retrace.main([crash_file.name])

        crash_file.seek(0)
        report_afterwards = crash_file.read()

    assert stderr.getvalue() == ""
    assert return_code == 0
    assert stdout.getvalue() == ""
    assert report_afterwards == expected_report
    assert add_gdb_info_mock.call_count == 1
    get_crashdb_mock.assert_called_once_with(None)
    gen_source_stacktrace_mock.assert_called_once()


@unittest.mock.patch.object(apport_retrace.Report, "add_gdb_info", autospec=True)
@unittest.mock.patch.object(apport_retrace, "gen_source_stacktrace")
@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_main_stdout(
    get_crashdb_mock: MagicMock,
    gen_source_stacktrace_mock: MagicMock,
    add_gdb_info_mock: MagicMock,
) -> None:
    """Test main() from apport-retrace to report on stdout."""
    add_gdb_info_mock.side_effect = add_mocked_gdb_info
    gen_source_stacktrace_mock.side_effect = mocked_gen_source_stacktrace
    report = (
        "ProblemType: Crash\n"
        "Architecture: amd64\n"
        "DistroRelease: Ubuntu 26.04\n"
        "ExecutablePath: /usr/bin/divide-by-zero\n"
        "Package: chaos-marmosets 0.2.0-1build1\n"
        "SourcePackage: chaos-marmosets\n"
        "CoreDump: base64\n"
        " c29tZSBiaW5hcnkgZGF0YQ==\n"
    )
    with (
        tempfile.NamedTemporaryFile(mode="w+", suffix=".crash") as crash_file,
        unittest.mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        crash_file.write(report)
        crash_file.flush()
        return_code = apport_retrace.main(["--stdout", crash_file.name])

        crash_file.seek(0)
        report_afterwards = crash_file.read()

    assert stderr.getvalue() == ""
    assert return_code == 0
    expected_output = (
        "--- stack trace ---\n"
        "mocked stacktrace\n"
        "--- thread stack trace ---\n"
        "mocked thread stacktrace\n"
        "--- source code stack trace ---\n"
        "mocked stacktrace source\n"
    )
    assert stdout.getvalue() == expected_output
    assert add_gdb_info_mock.call_count == 1
    assert report_afterwards == report
    get_crashdb_mock.assert_called_once_with(None)
    gen_source_stacktrace_mock.assert_called_once()


@unittest.mock.patch.object(apport_retrace.Report, "add_gdb_info", autospec=True)
@unittest.mock.patch.object(apport_retrace, "gen_source_stacktrace")
@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_main_ouput_to_stdout(
    get_crashdb_mock: MagicMock,
    gen_source_stacktrace_mock: MagicMock,
    add_gdb_info_mock: MagicMock,
) -> None:
    """Test main() from apport-retrace to write retraced report on stdout."""
    add_gdb_info_mock.side_effect = add_mocked_gdb_info
    gen_source_stacktrace_mock.side_effect = mocked_gen_source_stacktrace
    report = (
        "ProblemType: Crash\n"
        "Architecture: amd64\n"
        "DistroRelease: Ubuntu 26.04\n"
        "ExecutablePath: /usr/bin/divide-by-zero\n"
        "Package: chaos-marmosets 0.2.0-1build1\n"
        "SourcePackage: chaos-marmosets\n"
        "CoreDump: base64\n"
        " c29tZSBiaW5hcnkgZGF0YQ==\n"
    )
    expected_report = (
        "ProblemType: Crash\n"
        "Architecture: amd64\n"
        "DistroRelease: Ubuntu 26.04\n"
        "ExecutablePath: /usr/bin/divide-by-zero\n"
        "Package: chaos-marmosets 0.2.0-1build1\n"
        "Registers: mocked registers\n"
        "SourcePackage: chaos-marmosets\n"
        "Stacktrace: mocked stacktrace\n"
        "StacktraceSource: mocked stacktrace source\n"
        "ThreadStacktrace: mocked thread stacktrace\n"
        "CoreDump: base64\n"
        " c29tZSBiaW5hcnkgZGF0YQ==\n"
    )
    stdout_bytes = io.BytesIO()
    stdout_wrapper = io.TextIOWrapper(stdout_bytes, encoding="utf-8")
    with (
        tempfile.NamedTemporaryFile(mode="w+", suffix=".crash") as crash_file,
        unittest.mock.patch("sys.stdout", new=stdout_wrapper),
        unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        crash_file.write(report)
        crash_file.flush()
        return_code = apport_retrace.main(["--output", "-", crash_file.name])

        crash_file.seek(0)
        report_afterwards = crash_file.read()

    assert stderr.getvalue() == ""
    assert return_code == 0
    assert stdout_bytes.getvalue().decode("utf-8") == expected_report
    assert report_afterwards == report
    assert add_gdb_info_mock.call_count == 1
    get_crashdb_mock.assert_called_once_with(None)
    gen_source_stacktrace_mock.assert_called_once()


@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_malformed_crash_report(get_crashdb_mock: MagicMock) -> None:
    """Test apport-retrace on a crash file that is malformed."""
    with (
        tempfile.NamedTemporaryFile(mode="w+", suffix=".crash") as crash_file,
        unittest.mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        crash_file.write("Problem/Type: Crash\n")
        crash_file.flush()
        return_code = apport_retrace.main([crash_file.name])

    assert (
        stderr.getvalue()
        == "ERROR: Cannot open report file: key 'Problem/Type' contains invalid"
        " characters (only numbers, letters, '.', '_', and '-' are allowed)\n"
    )
    assert return_code == 1
    assert stdout.getvalue() == ""
    get_crashdb_mock.assert_called_once_with(None)


@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_main_missing_crash_file(get_crashdb_mock: MagicMock) -> None:
    """Test main() from apport-retrace on a crash file that does not exist."""
    with (
        unittest.mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        return_code = apport_retrace.main(["/non-existent.crash"])

    assert (
        stderr.getvalue() == 'ERROR: "/non-existent.crash"'
        " is neither an existing report file nor a crash ID\n"
    )
    assert return_code == 1
    assert stdout.getvalue() == ""
    get_crashdb_mock.assert_called_once_with(None)


@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_missing_fields_crash_report(get_crashdb_mock: MagicMock) -> None:
    """Test apport-retrace to fail on crash report with missing fields."""
    with (
        tempfile.NamedTemporaryFile(mode="w+", suffix=".crash") as crash_file,
        unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        crash_file.write(
            "ProblemType: Crash\nArchitecture: amd64\nPackage: gedit 46.2-2\n"
        )
        crash_file.flush()
        return_code = apport_retrace.main(["-x", "/usr/bin/gedit", crash_file.name])

    assert return_code == 2
    assert (
        stderr.getvalue()
        == "ERROR: report file does not contain one of the required fields:"
        " CoreDump DistroRelease\n"
    )
    get_crashdb_mock.assert_called_once_with(None)


@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_missing_fields_kernel_crash_report(get_crashdb_mock: MagicMock) -> None:
    """Test apport-retrace to fail on kernel crash report with missing fields."""
    with (
        tempfile.NamedTemporaryFile(mode="w+", suffix=".crash") as crash_file,
        unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        crash_file.write("ProblemType: KernelCrash\n")
        crash_file.flush()
        return_code = apport_retrace.main([crash_file.name])

    assert return_code == 2
    assert (
        stderr.getvalue() == "ERROR: report file does not contain the required fields\n"
    )
    get_crashdb_mock.assert_called_once_with(None)


@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_processing_kernel_crash_report(get_crashdb_mock: MagicMock) -> None:
    """Test apport-retrace to fail on kernel crash report (not implemented)."""
    with (
        tempfile.NamedTemporaryFile(mode="w+", suffix=".crash") as crash_file,
        unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr,
    ):
        crash_file.write(
            "ProblemType: KernelCrash\n"
            "Package: linux-image-7.0.0-38-generic\n"
            "VmCore: mocked\n"
        )
        crash_file.flush()
        return_code = apport_retrace.main([crash_file.name])

    assert stderr.getvalue() == "ERROR: KernelCrash processing not implemented yet\n"
    assert return_code == 3
    get_crashdb_mock.assert_called_once_with(None)


@unittest.mock.patch.object(apport_retrace.packaging, "get_source_tree")
def test_gen_source_stacktrace_ignores_frame_info_noise(
    get_source_tree_mock: MagicMock,
) -> None:
    """Test that gen_source_stacktrace() ignores warnings and "No locals."
    lines in the stacktrace output from gdb."""
    with tempfile.TemporaryDirectory() as srcdir:
        posix_file = pathlib.Path(srcdir) / "gthread-posix.c"
        thread_file = pathlib.Path(srcdir) / "gthread.c"

        posix_file.write_text(
            "".join(
                (
                    f"line {line}\n"
                    if line != 822
                    else "pthread_setname_np (pthread_self (), name_); "
                    "/* on Linux and Solaris */\n"
                )
                for line in range(1, 831)
            ),
            encoding="utf-8",
        )
        thread_file.write_text(
            "".join(
                (
                    f"line {line}\n"
                    if line != 889
                    else "g_system_thread_set_name (thread->name);\n"
                )
                for line in range(1, 896)
            ),
            encoding="utf-8",
        )
        get_source_tree_mock.return_value = srcdir

        report = apport_retrace.Report()
        report["SourcePackage"] = "glib2.0"
        report["Package"] = "glib2.0 2.78.0"
        # pylint: disable=line-too-long
        report["Stacktrace"] = (
            '#2  0x00007ffff7eebd45 in g_system_thread_set_name (name=0x5555556e2d80 "unref-target2") at ../../glib/glib/gthread-posix.c:822\n'  # noqa: E501
            "822\tpthread_setname_np (pthread_self (), name_); /* on Linux and Solaris */\n"  # noqa: E501
            '        name_ = "unref-target2\\000\\233", <incomplete sequence \\Í>\n'  # noqa: E501
            "#3  g_thread_proxy (data=0x5555556e2d60) at ../../glib/glib/gthread.c:889\n"  # noqa: E501
            "889\tg_system_thread_set_name (thread->name);\n"  # noqa: E501
            "warning: 889\t../../glib/glib/gthread.c: No such file or directory\n"  # noqa: E501
            "No locals.\n"  # noqa: E501
        )

        apport_retrace.gen_source_stacktrace(report, sandbox=None)

        stacktrace_source = report["StacktraceSource"]
        assert (
            "#2  0x00007ffff7eebd45 in g_system_thread_set_name"
            ' (name=0x5555556e2d80 "unref-target2")'
            " at ../../glib/glib/gthread-posix.c:822\n"
        ) in stacktrace_source
        assert (
            "#3  g_thread_proxy (data=0x5555556e2d60) at "
            "../../glib/glib/gthread.c:889\n"
        ) in stacktrace_source
        assert "822: pthread_setname_np (pthread_self (), name_);" in stacktrace_source
        assert "889: g_system_thread_set_name (thread->name);" in stacktrace_source
        assert "warning:" not in stacktrace_source
        assert "No locals." not in stacktrace_source
        get_source_tree_mock.assert_called_once()
