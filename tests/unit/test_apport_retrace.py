"""Unit tests for apport-retrace."""

import argparse
import io
import pathlib
import tempfile
import unittest
import unittest.mock
from unittest.mock import MagicMock

from tests.helper import import_module_from_file
from tests.paths import get_bin_directory

apport_retrace = import_module_from_file(get_bin_directory() / "apport-retrace")


@unittest.mock.patch.object(apport_retrace, "get_crashdb")
def test_malformed_crash_report(get_crashdb_mock: MagicMock) -> None:
    """Test apport-retrace to fail on malformed crash report."""
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
def test_malformed_kernel_crash_report(get_crashdb_mock: MagicMock) -> None:
    """Test apport-retrace to fail on malformed kernel crash report."""
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
                    + "/* on Linux and Solaris */\n"
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
        report["Stacktrace"] = (
            "#2  0x00007ffff7eebd45 in g_system_thread_set_name ("
            'name=0x5555556e2d80 "unref-target2") at '
            "../../glib/glib/gthread-posix.c:822\n"
            "822\tpthread_setname_np (pthread_self (), name_); /* on Linux "
            "and Solaris */\n"
            '        name_ = "unref-target2\\000\\233", <incomplete '
            "sequence \\\315>\n"
            "#3  g_thread_proxy (data=0x5555556e2d60) at "
            "../../glib/glib/gthread.c:889\n"
            "889\tg_system_thread_set_name (thread->name);\n"
            "warning: 889\t../../glib/glib/gthread.c: No such file or "
            "directory\n"
            "No locals.\n"
        )

        apport_retrace.gen_source_stacktrace(report, sandbox=None)

        stacktrace_source = report["StacktraceSource"]
        assert (
            "#2  0x00007ffff7eebd45 in g_system_thread_set_name "
            + '(name=0x5555556e2d80 "unref-target2")'
            " at ../../glib/glib/gthread-posix.c:822\n"
        ) in stacktrace_source
        assert (
            "#3  g_thread_proxy (data=0x5555556e2d60) at "
            + "../../glib/glib/gthread.c:889\n"
        ) in stacktrace_source
        assert "822: pthread_setname_np (pthread_self (), name_);" in stacktrace_source
        assert "889: g_system_thread_set_name (thread->name);" in stacktrace_source
        assert "warning:" not in stacktrace_source
        assert "No locals." not in stacktrace_source


@unittest.mock.patch.object(apport_retrace.packaging, "get_source_tree")
def test_gen_source_stacktrace_with_preloaded_source_tree(
    get_source_tree_mock: MagicMock,
) -> None:
    """Test reusing a provided source tree without re-fetching sources."""
    with tempfile.TemporaryDirectory() as srcdir:
        pathlib.Path(srcdir, "example.c").write_text(
            "".join(
                "crash_happens_here();\n" if line == 10 else f"line {line}\n"
                for line in range(1, 20)
            ),
            encoding="utf-8",
        )
        report = apport_retrace.Report()
        report["SourcePackage"] = "example"
        report["Package"] = "example 1.0"
        report["Stacktrace"] = "#0  0x1 in fn () at /build/example.c:10\n"

        apport_retrace.gen_source_stacktrace(report, sandbox=None, srcdirs=srcdir)

        assert report["StacktraceSource"].startswith(
            "#0  0x1 in fn () at /build/example.c:10\n"
        )
        assert "10: crash_happens_here();" in report["StacktraceSource"]
        get_source_tree_mock.assert_not_called()


@unittest.mock.patch.object(apport_retrace.packaging, "get_source_tree")
def test_gen_source_stacktrace_without_available_source_tree(
    get_source_tree_mock: MagicMock,
) -> None:
    """Test skipping StacktraceSource when source fetching returns no tree."""
    get_source_tree_mock.return_value = None
    report = apport_retrace.Report()
    report["SourcePackage"] = "example"
    report["Package"] = "example 1.0"
    report["Stacktrace"] = "#0  0x1 in fn () at /build/example.c:10\n"

    apport_retrace.gen_source_stacktrace(report, sandbox=None)

    assert "StacktraceSource" not in report


@unittest.mock.patch.object(apport_retrace.packaging, "get_source")
def test_report_relevant_sources_sourcepackage_overrides_with_package_version(
    get_source_mock: MagicMock,
) -> None:
    """Test SourcePackage override uses Package version over related values."""
    report = apport_retrace.Report()
    report["SourcePackage"] = "foo-src"
    report["Package"] = "foo-bin 1.2"
    report["RelatedPackageVersions"] = (
        "foo-bin                     0.9\nbar-bin                     3.0\n"
    )
    get_source_mock.side_effect = lambda binary: {
        "foo-bin": "foo-src",
        "bar-bin": "bar-src",
    }[binary]

    source_versions = apport_retrace.get_report_relevant_source_packages(report)

    assert source_versions == {"bar-src": "3.0", "foo-src": "1.2"}


@unittest.mock.patch.object(apport_retrace.packaging, "get_source")
def test_report_relevant_sources_keeps_related_version_without_package_version(
    get_source_mock: MagicMock,
) -> None:
    """Test SourcePackage keeps related version when Package has no version."""
    report = apport_retrace.Report()
    report["SourcePackage"] = "foo-src"
    report["Package"] = "foo-bin"
    report["RelatedPackageVersions"] = "foo-bin                     2.4\n"
    get_source_mock.side_effect = lambda binary: {"foo-bin": "foo-src"}[binary]

    source_versions = apport_retrace.get_report_relevant_source_packages(report)

    assert source_versions == {"foo-src": "2.4"}


@unittest.mock.patch.object(apport_retrace.packaging, "get_source")
def test_report_relevant_sources_all_versions_none(get_source_mock: MagicMock) -> None:
    """Test source mapping when all candidate versions are None."""
    report = apport_retrace.Report()
    report["SourcePackage"] = "foo-src"
    report["Package"] = "foo-bin"
    report["RelatedPackageVersions"] = (
        "foo-bin                     N/A\nfoo-extra                   N/A\n"
    )
    get_source_mock.side_effect = lambda binary: {
        "foo-bin": "foo-src",
        "foo-extra": "foo-src",
    }[binary]

    source_versions = apport_retrace.get_report_relevant_source_packages(report)

    assert source_versions == {"foo-src": None}


@unittest.mock.patch.object(apport_retrace.packaging, "get_source")
def test_report_relevant_sources_falls_back_to_package_source(
    get_source_mock: MagicMock,
) -> None:
    """Test falling back to Package source when SourcePackage is missing."""
    report = apport_retrace.Report()
    report["Package"] = "gnomes-shell 50.1-1ubuntu1~26.04.1"
    report["RelatedPackageVersions"] = "gnomes-shell-common              0:0.0-0\n"

    get_source_mock.side_effect = lambda binary: {
        "gnomes-shell": "gnomes-shell",
        "gnomes-shell-common": "gnomes-shell",
    }[binary]

    source_versions = apport_retrace.get_report_relevant_source_packages(report)

    assert source_versions == {"gnomes-shell": "50.1-1ubuntu1~26.04.1"}


@unittest.mock.patch.object(apport_retrace.packaging, "get_source")
def test_report_relevant_sources_include_extra_packages(
    get_source_mock: MagicMock,
) -> None:
    """Test extra packages are considered as source candidates."""
    report = apport_retrace.Report()
    report["Package"] = "coreutils 9.4-1"

    get_source_mock.side_effect = lambda binary: {
        "coreutils": "coreutils",
        "libc6-dbgsym": "glibc",
    }[binary]

    source_versions = apport_retrace.get_report_relevant_source_packages(
        report, ["libc6-dbgsym"]
    )

    assert source_versions == {"coreutils": "9.4-1", "glibc": None}


@unittest.mock.patch.object(apport_retrace.packaging, "get_source_tree")
@unittest.mock.patch.object(apport_retrace.packaging, "get_source")
def test_get_source_dirs_uses_related_package_versions(
    get_source_mock: MagicMock, get_source_tree_mock: MagicMock
) -> None:
    """Test fetching source trees for SourcePackage and related binary packages."""
    report = apport_retrace.Report()
    report["SourcePackage"] = "gdm3"
    report["Package"] = "gdm3 46.2-1ubuntu1~24.04.1"
    report["RelatedPackageVersions"] = (
        "mutter-common            46.2-1ubuntu1\n"
        "libglib2.0-0t64          2.80.0-1ubuntu1\n"
        "gdm3-common              0:0.0-0\n"
        "it-has-no-version        N/A\n"
        "does-not-exist           N/A\n"
    )

    source_by_binary = {
        "mutter-common": "mutter",
        "libglib2.0-0t64": "glib2.0",
        "gdm3-common": "gdm3",
        "it-has-no-version": "no-version-source",
    }

    def _get_source(binary: str) -> str:
        if binary not in source_by_binary:
            raise ValueError(binary)
        return source_by_binary[binary]

    def _get_source_tree(
        srcpackage: str, output_dir: str, _version: str, sandbox: str | None = None
    ) -> str:
        assert sandbox is None
        return str(pathlib.Path(output_dir) / srcpackage)

    get_source_mock.side_effect = _get_source
    get_source_tree_mock.side_effect = _get_source_tree

    source_dirs, workdir = apport_retrace.get_source_dirs(report, sandbox=None)
    try:
        assert len(source_dirs) == 4
        assert get_source_tree_mock.call_count == 4
        get_source_tree_mock.assert_any_call(
            "gdm3", unittest.mock.ANY, "46.2-1ubuntu1~24.04.1", sandbox=None
        )
        get_source_tree_mock.assert_any_call(
            "glib2.0", unittest.mock.ANY, "2.80.0-1ubuntu1", sandbox=None
        )
        get_source_tree_mock.assert_any_call(
            "mutter", unittest.mock.ANY, "46.2-1ubuntu1", sandbox=None
        )
        get_source_tree_mock.assert_any_call(
            "no-version-source", unittest.mock.ANY, None, sandbox=None
        )
    finally:
        if workdir:
            workdir.cleanup()


@unittest.mock.patch.object(apport_retrace.packaging, "get_source_tree")
@unittest.mock.patch.object(apport_retrace.packaging, "get_source")
def test_get_source_dirs_with_extra_packages(
    get_source_mock: MagicMock, get_source_tree_mock: MagicMock
) -> None:
    """Test fetching source trees includes extra package sources."""
    report = apport_retrace.Report()
    report["Package"] = "coreutils 9.4-1"
    get_source_mock.side_effect = lambda binary: {
        "coreutils": "coreutils",
        "libc6-dbgsym": "glibc",
    }[binary]
    get_source_tree_mock.side_effect = (
        lambda srcpackage, output_dir, _version, sandbox=None: str(
            pathlib.Path(output_dir) / srcpackage
        )
    )

    source_dirs, workdir = apport_retrace.get_source_dirs(
        report, sandbox=None, extra_packages=["libc6-dbgsym"]
    )
    try:
        assert len(source_dirs) == 2
        get_source_tree_mock.assert_any_call(
            "coreutils", unittest.mock.ANY, "9.4-1", sandbox=None
        )
        get_source_tree_mock.assert_any_call(
            "glibc", unittest.mock.ANY, None, sandbox=None
        )
    finally:
        if workdir:
            workdir.cleanup()


@unittest.mock.patch.object(apport_retrace, "parse_args")
@unittest.mock.patch.object(apport_retrace, "get_crashdb")
@unittest.mock.patch.object(apport_retrace, "load_report")
@unittest.mock.patch.object(apport_retrace, "get_source_dirs")
@unittest.mock.patch("apport.report._get_gdb_path", return_value="/usr/bin/gdb")
@unittest.mock.patch.object(apport_retrace.subprocess, "call")
def test_main_gdb_mode_fetches_sources(
    subprocess_call_mock: MagicMock,
    _get_gdb_path_mock: MagicMock,
    get_source_dirs_mock: MagicMock,
    load_report_mock: MagicMock,
    get_crashdb_mock: MagicMock,
    parse_args_mock: MagicMock,
) -> None:
    """Test interactive gdb mode fetches source dirs and cleans up workdir."""
    parse_args_mock.return_value = argparse.Namespace(
        report="some_binary.crash",
        auth=None,
        core_file=None,
        executable=None,
        procmaps=None,
        rebuild_package_info=False,
        gdb_sandbox=False,
        sandbox=None,
        sandbox_dir=None,
        extra_package=["libc6-dbgsym"],
        cache=None,
        verbose=False,
        timestamps=False,
        dynamic_origins=False,
        gdb=True,
        stacktrace_source=True,
        confirm=False,
        stdout=False,
        remove_core=False,
        output=None,
        duplicate_db=None,
    )
    get_crashdb_mock.return_value = MagicMock()

    report = apport_retrace.Report()
    report["ProblemType"] = "Crash"
    report["CoreDump"] = ("/tmp/core",)
    report["ExecutablePath"] = "/bin/true"
    report["Package"] = "coreutils 1.0"
    report["DistroRelease"] = "Ubuntu 26.04"
    report["Architecture"] = "amd64"
    load_report_mock.return_value = (report, None)

    source_workdir = MagicMock()
    get_source_dirs_mock.return_value = (
        ["/tmp/src-tree1", "/tmp/src-tree2"],
        source_workdir,
    )

    assert apport_retrace.main([]) == 0

    get_source_dirs_mock.assert_called_once_with(report, None, ["libc6-dbgsym"])
    subprocess_call_mock.assert_called_once_with(
        [
            "/usr/bin/gdb",
            "--ex",
            'file "/bin/true"',
            "--directory",
            "/tmp/src-tree1",
            "--directory",
            "/tmp/src-tree2",
            "--ex",
            "core-file /tmp/core",
        ],
        env=unittest.mock.ANY,
    )
    source_workdir.cleanup.assert_called_once_with()


@unittest.mock.patch.object(apport_retrace, "parse_args")
@unittest.mock.patch.object(apport_retrace, "get_crashdb")
@unittest.mock.patch.object(apport_retrace, "load_report")
@unittest.mock.patch.object(apport_retrace, "get_source_dirs")
@unittest.mock.patch.object(apport_retrace, "gen_source_stacktrace")
@unittest.mock.patch.object(apport_retrace, "print_traces")
def test_main_fetches_sources_before_gdb(
    print_traces_mock: MagicMock,
    gen_source_stacktrace_mock: MagicMock,
    get_source_dirs_mock: MagicMock,
    load_report_mock: MagicMock,
    get_crashdb_mock: MagicMock,
    parse_args_mock: MagicMock,
) -> None:
    """Test prefetching sources before gdb and reusing them for source output."""
    parse_args_mock.return_value = argparse.Namespace(
        report="some_binary.crash",
        auth=None,
        core_file=None,
        executable=None,
        procmaps=None,
        rebuild_package_info=False,
        gdb_sandbox=False,
        sandbox=None,
        sandbox_dir=None,
        extra_package=["libc6-dbgsym"],
        cache=None,
        verbose=False,
        timestamps=False,
        dynamic_origins=False,
        gdb=False,
        # source stacktrace, so source tree should be pre-fetched.
        stacktrace_source=True,
        confirm=False,
        stdout=True,
        remove_core=False,
        output=None,
        duplicate_db=None,
    )
    get_crashdb_mock.return_value = MagicMock()

    report = apport_retrace.Report()
    report["ProblemType"] = "Crash"
    report["CoreDump"] = ("/tmp/core",)
    report["ExecutablePath"] = "/bin/true"
    report["Package"] = "coreutils 1.0"
    report["DistroRelease"] = "Ubuntu 26.04"
    report["Architecture"] = "amd64"
    report.add_gdb_info = MagicMock()
    report.add_kernel_crash_info = MagicMock()
    load_report_mock.return_value = (report, None)

    source_workdir = MagicMock()
    get_source_dirs_mock.return_value = (["/tmp/src-tree"], source_workdir)

    assert apport_retrace.main([]) == 0

    get_source_dirs_mock.assert_called_once_with(report, None, ["libc6-dbgsym"])
    report.add_gdb_info.assert_called_once_with(None, None, ["/tmp/src-tree"])
    gen_source_stacktrace_mock.assert_called_once_with(report, None, ["/tmp/src-tree"])
    report.add_kernel_crash_info.assert_called_once_with()
    source_workdir.cleanup.assert_called_once_with()
    print_traces_mock.assert_called_once_with(report)


@unittest.mock.patch.object(apport_retrace, "parse_args")
@unittest.mock.patch.object(apport_retrace, "get_crashdb")
@unittest.mock.patch.object(apport_retrace, "load_report")
@unittest.mock.patch.object(apport_retrace, "get_source_dirs")
@unittest.mock.patch.object(apport_retrace, "gen_source_stacktrace")
@unittest.mock.patch.object(apport_retrace, "print_traces")
def test_main_with_unavailable_source_tree(
    print_traces_mock: MagicMock,
    gen_source_stacktrace_mock: MagicMock,
    get_source_dirs_mock: MagicMock,
    load_report_mock: MagicMock,
    get_crashdb_mock: MagicMock,
    parse_args_mock: MagicMock,
) -> None:
    """Test retracing when source prefetch is enabled but unavailable."""
    parse_args_mock.return_value = argparse.Namespace(
        report="some_binary.crash",
        auth=None,
        core_file=None,
        executable=None,
        procmaps=None,
        rebuild_package_info=False,
        gdb_sandbox=False,
        sandbox=None,
        sandbox_dir=None,
        extra_package=[],
        cache=None,
        verbose=False,
        timestamps=False,
        dynamic_origins=False,
        gdb=False,
        stacktrace_source=True,
        confirm=False,
        stdout=True,
        remove_core=False,
        output=None,
        duplicate_db=None,
    )
    get_crashdb_mock.return_value = MagicMock()

    report = apport_retrace.Report()
    report["ProblemType"] = "Crash"
    report["CoreDump"] = ("/tmp/core",)
    report["ExecutablePath"] = "/bin/true"
    report["Package"] = "coreutils 1.0"
    report["DistroRelease"] = "Ubuntu 24.04"
    report["Architecture"] = "amd64"
    report.add_gdb_info = MagicMock()
    report.add_kernel_crash_info = MagicMock()
    load_report_mock.return_value = (report, None)

    # source retrieval enabled but unavailable
    get_source_dirs_mock.return_value = ([], None)

    assert apport_retrace.main([]) == 0

    get_source_dirs_mock.assert_called_once_with(report, None, [])
    report.add_gdb_info.assert_called_once_with(None, None, [])
    gen_source_stacktrace_mock.assert_called_once_with(report, None, [])
    report.add_kernel_crash_info.assert_called_once_with()
    print_traces_mock.assert_called_once_with(report)


@unittest.mock.patch.object(apport_retrace, "parse_args")
@unittest.mock.patch.object(apport_retrace, "get_crashdb")
@unittest.mock.patch.object(apport_retrace, "load_report")
@unittest.mock.patch.object(apport_retrace, "get_source_dirs")
@unittest.mock.patch.object(apport_retrace, "gen_source_stacktrace")
@unittest.mock.patch.object(apport_retrace, "print_traces")
def test_main_without_stacktrace_source_does_not_prefetch_source(
    print_traces_mock: MagicMock,
    gen_source_stacktrace_mock: MagicMock,
    get_source_dirs_mock: MagicMock,
    load_report_mock: MagicMock,
    get_crashdb_mock: MagicMock,
    parse_args_mock: MagicMock,
) -> None:
    """Test that disabling stacktrace source skips source prefetch entirely."""
    parse_args_mock.return_value = argparse.Namespace(
        report="some_binary.crash",
        auth=None,
        core_file=None,
        executable=None,
        procmaps=None,
        rebuild_package_info=False,
        gdb_sandbox=False,
        sandbox=None,
        sandbox_dir=None,
        extra_package=[],
        cache=None,
        verbose=False,
        timestamps=False,
        dynamic_origins=False,
        gdb=False,
        # No source stacktrace, so source tree should not be pre-fetched.
        stacktrace_source=False,
        confirm=False,
        stdout=True,
        remove_core=False,
        output=None,
        duplicate_db=None,
    )
    get_crashdb_mock.return_value = MagicMock()

    report = apport_retrace.Report()
    report["ProblemType"] = "Crash"
    report["CoreDump"] = ("/tmp/core",)
    report["ExecutablePath"] = "/bin/true"
    report["Package"] = "coreutils 1.0"
    report["DistroRelease"] = "Ubuntu 24.04"
    report["Architecture"] = "amd64"
    report.add_gdb_info = MagicMock()
    report.add_kernel_crash_info = MagicMock()
    load_report_mock.return_value = (report, None)

    assert apport_retrace.main([]) == 0

    get_source_dirs_mock.assert_not_called()
    report.add_gdb_info.assert_called_once_with(None, None, None)
    gen_source_stacktrace_mock.assert_not_called()
    report.add_kernel_crash_info.assert_called_once_with()
    print_traces_mock.assert_called_once_with(report)
