"""Integration tests for crash database implementation for Launchpad."""

# Copyright (C) 2007 - 2009 Canonical Ltd.
# Authors: Martin Pitt <martin.pitt@ubuntu.com>
#          Markus Korn <thekorn@gmx.de>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# pylint: disable=too-many-lines
# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import atexit
import email
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

try:
    from launchpadlib.errors import HTTPError

    IMPORT_ERROR = None
except ImportError as error:
    IMPORT_ERROR = error

from apport.crashdb_impl.launchpad import CrashDatabase
from apport.packaging_impl import impl as packaging
from apport.report import Report

_CACHE = {}


def cache(func):
    """Decorate a function/method to cache the result of its call.

    The cache is ignored if force_fresh is set to True.
    """

    def try_to_get_from_cache(*args, **kwargs):
        if kwargs.get("force_fresh", False):
            return func(*args, **kwargs)
        if func.__name__ not in _CACHE:
            _CACHE[func.__name__] = func(*args, **kwargs)
        return _CACHE[func.__name__]

    return try_to_get_from_cache


@unittest.skipIf(IMPORT_ERROR, f"Python module not available: {IMPORT_ERROR}")
@unittest.skipUnless(
    "TEST_LAUNCHPAD" in os.environ,
    "Need Launchpad access with bug control permission. Set TEST_LAUNCHPAD to run.",
)
class T(unittest.TestCase):
    # pylint: disable=protected-access,too-many-public-methods
    """Integration tests for apport.crashdb_impl.launchpad."""

    # this assumes that a source package 'coreutils' exists and builds a
    # binary package 'coreutils'
    test_package = "coreutils"
    test_srcpackage = "coreutils"

    #
    # Generic tests, should work for all CrashDB implementations
    #

    def setUp(self):
        self.crashdb = self._get_instance()

        # create a local reference report so that we can compare
        # DistroRelease, Architecture, etc.
        self.ref_report = Report()
        self.ref_report.add_os_info()
        self.ref_report.add_user_info()
        self.ref_report["SourcePackage"] = "coreutils"

        # Objects tests rely on.
        self._create_project("langpack-o-matic")

    def _create_bug_from_report(self, name: str, report: Report) -> int:
        """Create a Launchpad bug report from a crash report.

        Return the bug ID.
        """
        bug_target = self._get_bug_target(self.crashdb, report)
        self.assertTrue(bug_target)

        crash_id = self._file_bug(bug_target, report)
        self.assertTrue(crash_id > 0)

        sys.stderr.write(
            f"(Created {name} report: https://{self.hostname}/bugs/{crash_id}) "
        )
        return crash_id

    def _create_project(self, name):
        """Create a project using launchpadlib to be used by tests."""
        project = self.crashdb.launchpad.projects[name]
        if not project:
            self.crashdb.launchpad.projects.new_project(
                description=f"{name}description",
                display_name=name,
                name=name,
                summary=f"{name}summary",
                title=f"{name}title",
            )

    @property
    def hostname(self):
        """Get the Launchpad hostname for the given crashdb."""
        return self.crashdb.get_hostname()

    @cache
    def get_segv_report(self, force_fresh=False):
        # force_fresh used by @cache, pylint: disable=unused-argument
        """Generate SEGV crash report.

        This is only done once, subsequent calls will return the already
        existing ID, unless force_fresh is True.

        Return the ID.
        """
        r = self._generate_sigsegv_report()
        r.add_package_info(self.test_package)
        r.add_os_info()
        r.add_gdb_info()
        r.add_user_info()
        self.assertEqual(r.standard_title(), "crash crashed with SIGSEGV in f()")

        # add some binary gibberish which isn't UTF-8
        r["ShortGibberish"] = ' "]\xb6"\n'
        r["LongGibberish"] = "a\nb\nc\ne\nf\n\xff\xff\xff\n\f"

        return self._create_bug_from_report("SEGV", r)

    @cache
    def get_python_report(self):
        """Generate Python crash report.

        Return the ID.
        """
        r = Report("Crash")
        r["ExecutablePath"] = "/bin/foo"
        r[
            "Traceback"
        ] = """Traceback (most recent call last):
  File "/bin/foo", line 67, in fuzz
    print(weird)
NameError: global name 'weird' is not defined"""
        r["Tags"] = "boogus pybogus"
        r.add_package_info(self.test_package)
        r.add_os_info()
        r.add_user_info()
        self.assertEqual(
            r.standard_title(),
            "foo crashed with NameError in fuzz():"
            " global name 'weird' is not defined",
        )

        return self._create_bug_from_report("Python", r)

    @cache
    def get_uncommon_description_report(self, force_fresh=False):
        # force_fresh used by @cache, pylint: disable=unused-argument
        """File a bug report with an uncommon description.

        This is only done once, subsequent calls will return the already
        existing ID, unless force_fresh is True.

        Example taken from real LP bug 269539. It contains only
        ProblemType/Architecture/DistroRelease in the description, and has
        free-form description text after the Apport data.

        Return the ID.
        """
        desc = """problem

ProblemType: Package
Architecture: amd64
DistroRelease: Ubuntu 8.10

more text

and more
"""
        bug = self.crashdb.launchpad.bugs.createBug(
            title="mixed description bug",
            description=desc,
            target=self.crashdb.lp_distro,
        )
        sys.stderr.write(
            f"(Created uncommon description:"
            f" https://{self.hostname}/bugs/{bug.id}) "
        )

        return bug.id

    def test_1_download(self):
        """download()"""
        r = self.crashdb.download(self.get_segv_report())
        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["Title"], "crash crashed with SIGSEGV in f()")
        self.assertEqual(r["DistroRelease"], self.ref_report["DistroRelease"])
        self.assertEqual(r["Architecture"], self.ref_report["Architecture"])
        self.assertEqual(r["Uname"], self.ref_report["Uname"])
        self.assertEqual(
            r.get("NonfreeKernelModules"), self.ref_report.get("NonfreeKernelModules")
        )
        self.assertEqual(r.get("UserGroups"), self.ref_report.get("UserGroups"))
        self.assertEqual(
            r.get_tags(),
            set(
                [
                    self.crashdb.arch_tag,
                    "apport-crash",
                    packaging.get_system_architecture(),
                ]
            ),
        )

        self.assertEqual(r["Signal"], "11")
        self.assertTrue(r["ExecutablePath"].endswith("/crash"))
        self.assertEqual(r["SourcePackage"], self.test_srcpackage)
        self.assertTrue(r["Package"].startswith(f"{self.test_package} "))
        self.assertIn("f (x=42)", r["Stacktrace"])
        self.assertIn("f (x=42)", r["StacktraceTop"])
        self.assertIn("f (x=42)", r["ThreadStacktrace"])
        self.assertGreater(len(r["CoreDump"]), 1000)
        self.assertIn("Dependencies", r)
        self.assertIn("Disassembly", r)
        self.assertIn("Registers", r)

        # check tags
        r = self.crashdb.download(self.get_python_report())
        self.assertEqual(
            r.get_tags(),
            set(
                [
                    "apport-crash",
                    "boogus",
                    "pybogus",
                    "need-duplicate-check",
                    packaging.get_system_architecture(),
                ]
            ),
        )

    def test_2_update_traces(self):
        # TODO: Split into separate test cases
        # pylint: disable=too-many-statements
        """update_traces()"""
        r = self.crashdb.download(self.get_segv_report())
        self.assertIn("CoreDump", r)
        self.assertIn("Dependencies", r)
        self.assertIn("Disassembly", r)
        self.assertIn("Registers", r)
        self.assertIn("Stacktrace", r)
        self.assertIn("ThreadStacktrace", r)
        self.assertEqual(r["Title"], "crash crashed with SIGSEGV in f()")

        # updating with a useless stack trace retains core dump
        r["StacktraceTop"] = "?? ()"
        r["Stacktrace"] = "long\ntrace"
        r["ThreadStacktrace"] = "thread\neven longer\ntrace"
        r["FooBar"] = "bogus"
        self.crashdb.update_traces(
            self.get_segv_report(), r, "I can has a better retrace?"
        )
        r = self.crashdb.download(self.get_segv_report())
        self.assertIn("CoreDump", r)
        self.assertIn("Dependencies", r)
        self.assertIn("Disassembly", r)
        self.assertIn("Registers", r)
        self.assertIn("Stacktrace", r)  # TODO: ascertain that it's the updated one
        self.assertIn("ThreadStacktrace", r)
        self.assertNotIn("FooBar", r)
        self.assertEqual(r["Title"], "crash crashed with SIGSEGV in f()")

        tags = self.crashdb.launchpad.bugs[self.get_segv_report()].tags
        self.assertIn("apport-crash", tags)
        self.assertNotIn("apport-collected", tags)

        # updating with a useful stack trace removes core dump
        r[
            "StacktraceTop"
        ] = "read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so"
        r["Stacktrace"] = "long\ntrace"
        r["ThreadStacktrace"] = "thread\neven longer\ntrace"
        self.crashdb.update_traces(self.get_segv_report(), r, "good retrace!")
        r = self.crashdb.download(self.get_segv_report())
        self.assertNotIn("CoreDump", r)
        self.assertIn("Dependencies", r)
        self.assertIn("Disassembly", r)
        self.assertIn("Registers", r)
        self.assertIn("Stacktrace", r)
        self.assertIn("ThreadStacktrace", r)
        self.assertNotIn("FooBar", r)

        # as previous title had standard form, the top function gets
        # updated
        self.assertEqual(r["Title"], "crash crashed with SIGSEGV in read()")

        # respects title amendments
        bug = self.crashdb.launchpad.bugs[self.get_segv_report()]
        bug.title = "crash crashed with SIGSEGV in f() on exit"
        try:
            bug.lp_save()
        except HTTPError:
            pass  # LP#336866 workaround
        r[
            "StacktraceTop"
        ] = "read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so"
        self.crashdb.update_traces(
            self.get_segv_report(), r, "good retrace with title amendment"
        )
        r = self.crashdb.download(self.get_segv_report())
        self.assertEqual(r["Title"], "crash crashed with SIGSEGV in read() on exit")

        # does not destroy custom titles
        bug = self.crashdb.launchpad.bugs[self.get_segv_report()]
        bug.title = "crash is crashy"
        try:
            bug.lp_save()
        except HTTPError:
            pass  # LP#336866 workaround

        r[
            "StacktraceTop"
        ] = "read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so"
        self.crashdb.update_traces(
            self.get_segv_report(), r, "good retrace with custom title"
        )
        r = self.crashdb.download(self.get_segv_report())
        self.assertEqual(r["Title"], "crash is crashy")

        # test various situations which caused crashes
        r["Stacktrace"] = ""  # empty file
        r["ThreadStacktrace"] = '"]\xb6"\n'  # not interpretable as UTF-8, LP #353805
        r["StacktraceSource"] = "a\nb\nc\ne\nf\n\xff\xff\xff\n\f"
        self.crashdb.update_traces(self.get_segv_report(), r, "tests")

    def test_get_comment_url(self):
        """get_comment_url() for non-ASCII titles"""
        title = b"1\xc3\xa4\xe2\x99\xa52"

        # distro, UTF-8 bytestring
        r = Report("Bug")
        r["Title"] = title
        url = self.crashdb.get_comment_url(r, 42)
        self.assertTrue(
            url.endswith("/ubuntu/+filebug/42?field.title=1%C3%A4%E2%99%A52")
        )

        # distro, unicode
        r["Title"] = title.decode("UTF-8")
        url = self.crashdb.get_comment_url(r, 42)
        self.assertTrue(
            url.endswith("/ubuntu/+filebug/42?field.title=1%C3%A4%E2%99%A52")
        )

        # package, unicode
        r["SourcePackage"] = "coreutils"
        url = self.crashdb.get_comment_url(r, 42)
        self.assertTrue(
            url.endswith(
                "/ubuntu/+source/coreutils/+filebug/42?field.title=1%C3%A4%E2%99%A52"
            )
        )

    def test_update_description(self):
        """update() with changing description"""
        bug_target = self.crashdb.lp_distro.getSourcePackage(name="bash")
        bug = self.crashdb.launchpad.bugs.createBug(
            description="test description for test bug.",
            target=bug_target,
            title="testbug",
        )
        crash_id = bug.id
        self.assertTrue(crash_id > 0)
        sys.stderr.write(f"(https://{self.hostname}/bugs/{crash_id}) ")

        r = Report("Bug")

        r["OneLiner"] = b"bogus\xe2\x86\x92".decode("UTF-8")
        r["StacktraceTop"] = "f()\ng()\nh(1)"
        r["ShortGoo"] = "lineone\nlinetwo"
        r["DpkgTerminalLog"] = "one\ntwo\nthree\nfour\nfive\nsix"
        r["VarLogDistupgradeBinGoo"] = b"\x01" * 1024

        self.crashdb.update(crash_id, r, "NotMe", change_description=True)

        r = self.crashdb.download(crash_id)

        self.assertEqual(r["OneLiner"], b"bogus\xe2\x86\x92".decode("UTF-8"))
        self.assertEqual(r["ShortGoo"], "lineone\nlinetwo")
        self.assertEqual(r["DpkgTerminalLog"], "one\ntwo\nthree\nfour\nfive\nsix")
        self.assertEqual(r["VarLogDistupgradeBinGoo"], b"\x01" * 1024)

        self.assertEqual(
            self.crashdb.launchpad.bugs[crash_id].tags, ["apport-collected"]
        )

    def test_update_comment(self):
        """update() with appending comment"""
        bug_target = self.crashdb.lp_distro.getSourcePackage(name="bash")
        # we need to fake an apport description separator here, since we
        # want to be lazy and use download() for checking the result
        bug = self.crashdb.launchpad.bugs.createBug(
            description="Pr0blem\n\n--- \nProblemType: Bug",
            target=bug_target,
            title="testbug",
        )
        crash_id = bug.id
        self.assertTrue(crash_id > 0)
        sys.stderr.write(f"(https://{self.hostname}/bugs/{crash_id}) ")

        r = Report("Bug")

        r["OneLiner"] = "bogus→"
        r["StacktraceTop"] = "f()\ng()\nh(1)"
        r["ShortGoo"] = "lineone\nlinetwo"
        r["DpkgTerminalLog"] = "one\ntwo\nthree\nfour\nfive\nsix"
        r["VarLogDistupgradeBinGoo"] = "\x01" * 1024

        self.crashdb.update(crash_id, r, "meow", change_description=False)

        r = self.crashdb.download(crash_id)

        self.assertNotIn("OneLiner", r)
        self.assertNotIn("ShortGoo", r)
        self.assertEqual(r["ProblemType"], "Bug")
        self.assertEqual(r["DpkgTerminalLog"], "one\ntwo\nthree\nfour\nfive\nsix")
        self.assertEqual(r["VarLogDistupgradeBinGoo"], "\x01" * 1024)

        self.assertEqual(
            self.crashdb.launchpad.bugs[crash_id].tags, ["apport-collected"]
        )

    def test_update_filter(self):
        """update() with a key filter"""
        bug_target = self.crashdb.lp_distro.getSourcePackage(name="bash")
        bug = self.crashdb.launchpad.bugs.createBug(
            description="test description for test bug",
            target=bug_target,
            title="testbug",
        )
        crash_id = bug.id
        self.assertTrue(crash_id > 0)
        sys.stderr.write(f"(https://{self.hostname}/bugs/{crash_id}) ")

        r = Report("Bug")

        r["OneLiner"] = "bogus→"
        r["StacktraceTop"] = "f()\ng()\nh(1)"
        r["ShortGoo"] = "lineone\nlinetwo"
        r["DpkgTerminalLog"] = "one\ntwo\nthree\nfour\nfive\nsix"
        r["VarLogDistupgradeBinGoo"] = "\x01" * 1024

        self.crashdb.update(
            crash_id,
            r,
            "NotMe",
            change_description=True,
            key_filter=["ProblemType", "ShortGoo", "DpkgTerminalLog"],
        )

        r = self.crashdb.download(crash_id)

        self.assertNotIn("OneLiner", r)
        self.assertEqual(r["ShortGoo"], "lineone\nlinetwo")
        self.assertEqual(r["ProblemType"], "Bug")
        self.assertEqual(r["DpkgTerminalLog"], "one\ntwo\nthree\nfour\nfive\nsix")
        self.assertNotIn("VarLogDistupgradeBinGoo", r)

        self.assertEqual(self.crashdb.launchpad.bugs[crash_id].tags, [])

    def test_get_distro_release(self):
        """get_distro_release()"""
        self.assertEqual(
            self.crashdb.get_distro_release(self.get_segv_report()),
            self.ref_report["DistroRelease"],
        )

    def test_get_affected_packages(self):
        """get_affected_packages()"""
        self.assertEqual(
            self.crashdb.get_affected_packages(self.get_segv_report()),
            [self.ref_report["SourcePackage"]],
        )

    def test_is_reporter(self):
        """is_reporter()"""
        self.assertTrue(self.crashdb.is_reporter(self.get_segv_report()))
        self.assertFalse(self.crashdb.is_reporter(1))

    def test_can_update(self):
        """can_update()"""
        self.assertTrue(self.crashdb.can_update(self.get_segv_report()))
        self.assertFalse(self.crashdb.can_update(1))

    def test_duplicates(self):
        """Test duplicate handling."""
        # initially we have no dups
        self.assertEqual(self.crashdb.duplicate_of(self.get_segv_report()), None)
        self.assertEqual(self.crashdb.get_fixed_version(self.get_segv_report()), None)

        segv_id = self.get_segv_report()
        known_test_id = self.get_uncommon_description_report()
        known_test_id2 = self.get_uncommon_description_report(force_fresh=True)

        # dupe our segv_report and check that it worked; then undupe it
        r = self.crashdb.download(segv_id)
        self.crashdb.close_duplicate(r, segv_id, known_test_id)
        self.assertEqual(self.crashdb.duplicate_of(segv_id), known_test_id)

        # this should be a no-op
        self.crashdb.close_duplicate(r, segv_id, known_test_id)
        self.assertEqual(self.crashdb.duplicate_of(segv_id), known_test_id)

        self.assertEqual(self.crashdb.get_fixed_version(segv_id), "invalid")
        self.crashdb.close_duplicate(r, segv_id, None)
        self.assertEqual(self.crashdb.duplicate_of(segv_id), None)
        self.assertEqual(self.crashdb.get_fixed_version(segv_id), None)

        # this should have removed attachments; note that Stacktrace is
        # short, and thus inline
        r = self.crashdb.download(self.get_segv_report())
        self.assertNotIn("CoreDump", r)
        self.assertNotIn("Disassembly", r)
        self.assertNotIn("ProcMaps", r)
        self.assertNotIn("ProcStatus", r)
        self.assertNotIn("Registers", r)
        self.assertNotIn("ThreadStacktrace", r)

        # now try duplicating to a duplicate bug; this should automatically
        # transition to the master bug
        self.crashdb.close_duplicate(Report(), known_test_id, known_test_id2)
        self.crashdb.close_duplicate(r, segv_id, known_test_id)
        self.assertEqual(self.crashdb.duplicate_of(segv_id), known_test_id2)

        self.crashdb.close_duplicate(Report(), known_test_id, None)
        self.crashdb.close_duplicate(Report(), known_test_id2, None)
        self.crashdb.close_duplicate(r, segv_id, None)

        # this should be a no-op
        self.crashdb.close_duplicate(Report(), known_test_id, None)
        self.assertEqual(self.crashdb.duplicate_of(known_test_id), None)

        self.crashdb.mark_regression(segv_id, known_test_id)
        self._verify_marked_regression(segv_id)

    def test_marking_segv(self):
        """Test processing status markings for signal crashes."""
        # mark_retraced()
        unretraced_before = self.crashdb.get_unretraced()
        self.assertIn(self.get_segv_report(), unretraced_before)
        self.assertNotIn(self.get_python_report(), unretraced_before)
        self.crashdb.mark_retraced(self.get_segv_report())
        unretraced_after = self.crashdb.get_unretraced()
        self.assertNotIn(self.get_segv_report(), unretraced_after)
        self.assertEqual(
            unretraced_before, unretraced_after.union(set([self.get_segv_report()]))
        )
        self.assertEqual(self.crashdb.get_fixed_version(self.get_segv_report()), None)

        # mark_retrace_failed()
        self._mark_needs_retrace(self.get_segv_report())
        self.crashdb.mark_retraced(self.get_segv_report())
        self.crashdb.mark_retrace_failed(self.get_segv_report())
        unretraced_after = self.crashdb.get_unretraced()
        self.assertNotIn(self.get_segv_report(), unretraced_after)
        self.assertEqual(
            unretraced_before, unretraced_after.union(set([self.get_segv_report()]))
        )
        self.assertEqual(self.crashdb.get_fixed_version(self.get_segv_report()), None)

        # mark_retrace_failed() of invalid bug
        self._mark_needs_retrace(self.get_segv_report())
        self.crashdb.mark_retraced(self.get_segv_report())
        self.crashdb.mark_retrace_failed(self.get_segv_report(), "I don't like you")
        unretraced_after = self.crashdb.get_unretraced()
        self.assertNotIn(self.get_segv_report(), unretraced_after)
        self.assertEqual(
            unretraced_before, unretraced_after.union(set([self.get_segv_report()]))
        )
        self.assertEqual(
            self.crashdb.get_fixed_version(self.get_segv_report()), "invalid"
        )

    def test_marking_project(self):
        """Test processing status markings for a project CrashDB."""
        # create a distro bug
        distro_bug = self.crashdb.launchpad.bugs.createBug(
            description="foo",
            tags=self.crashdb.arch_tag,
            target=self.crashdb.lp_distro,
            title="ubuntu distro retrace bug",
        )

        # create a project crash DB and a bug
        launchpad_instance = os.environ.get("APPORT_LAUNCHPAD_INSTANCE") or "qastaging"

        project_db = CrashDatabase(
            os.environ.get("LP_CREDENTIALS"),
            {"project": "langpack-o-matic", "launchpad_instance": launchpad_instance},
        )
        project_bug = project_db.launchpad.bugs.createBug(
            description="bar",
            tags=project_db.arch_tag,
            target=project_db.lp_distro,
            title="project retrace bug",
        )

        # on project_db, we recognize the project bug and can mark it
        unretraced_before = project_db.get_unretraced()
        self.assertIn(project_bug.id, unretraced_before)
        self.assertNotIn(distro_bug.id, unretraced_before)
        project_db.mark_retraced(project_bug.id)
        unretraced_after = project_db.get_unretraced()
        self.assertNotIn(project_bug.id, unretraced_after)
        self.assertEqual(
            unretraced_before, unretraced_after.union(set([project_bug.id]))
        )
        self.assertEqual(self.crashdb.get_fixed_version(project_bug.id), None)

    def test_marking_foreign_arch(self):
        """Test processing status markings for a project CrashDB."""
        # create a DB for fake arch
        launchpad_instance = os.environ.get("APPORT_LAUNCHPAD_INSTANCE") or "qastaging"
        fakearch_db = CrashDatabase(
            os.environ.get("LP_CREDENTIALS"),
            {
                "distro": "ubuntu",
                "launchpad_instance": launchpad_instance,
                "architecture": "fakearch",
            },
        )

        fakearch_unretraced_before = fakearch_db.get_unretraced()
        systemarch_unretraced_before = self.crashdb.get_unretraced()

        # create a bug with a fake architecture
        bug = self.crashdb.launchpad.bugs.createBug(
            description="foo",
            tags=["need-fakearch-retrace"],
            target=self.crashdb.lp_distro,
            title="ubuntu distro retrace bug for fakearch",
        )
        print(f"fake arch bug: https://staging.launchpad.net/bugs/{bug.id}")

        fakearch_unretraced_after = fakearch_db.get_unretraced()
        systemarch_unretraced_after = self.crashdb.get_unretraced()

        self.assertEqual(systemarch_unretraced_before, systemarch_unretraced_after)
        self.assertEqual(
            fakearch_unretraced_after, fakearch_unretraced_before.union(set([bug.id]))
        )

    def test_marking_python(self):
        """Test processing status markings for interpreter crashes."""
        unchecked_before = self.crashdb.get_dup_unchecked()
        self.assertIn(self.get_python_report(), unchecked_before)
        self.assertNotIn(self.get_segv_report(), unchecked_before)
        self.crashdb._mark_dup_checked(self.get_python_report(), self.ref_report)
        unchecked_after = self.crashdb.get_dup_unchecked()
        self.assertNotIn(self.get_python_report(), unchecked_after)
        self.assertEqual(
            unchecked_before, unchecked_after.union(set([self.get_python_report()]))
        )
        self.assertEqual(self.crashdb.get_fixed_version(self.get_python_report()), None)

    def test_update_traces_invalid(self):
        """Test updating an invalid crash.

        This simulates a race condition where a crash being processed gets
        invalidated by marking it as a duplicate.
        """
        crash_id = self.get_segv_report(force_fresh=True)

        r = self.crashdb.download(crash_id)

        self.crashdb.close_duplicate(r, crash_id, self.get_segv_report())

        # updating with a useful stack trace removes core dump
        r[
            "StacktraceTop"
        ] = "read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so"
        r["Stacktrace"] = "long\ntrace"
        r["ThreadStacktrace"] = "thread\neven longer\ntrace"
        self.crashdb.update_traces(crash_id, r, "good retrace!")

        r = self.crashdb.download(crash_id)
        self.assertNotIn("CoreDump", r)

    @unittest.mock.patch.object(
        CrashDatabase, "_get_source_version", unittest.mock.MagicMock()
    )
    def test_get_fixed_version(self):
        """get_fixed_version() for fixed bugs

        Other cases are already checked in test_marking_segv() (invalid
        bugs) and test_duplicates (duplicate bugs) for efficiency.
        """
        # staging.launchpad.net often does not have Quantal, so mock-patch
        # it to a known value
        CrashDatabase._get_source_version.return_value = "3.14"
        self._mark_report_fixed(self.get_segv_report())
        fixed_ver = self.crashdb.get_fixed_version(self.get_segv_report())
        self.assertEqual(fixed_ver, "3.14")
        self._mark_report_new(self.get_segv_report())
        self.assertEqual(self.crashdb.get_fixed_version(self.get_segv_report()), None)

    #
    # Launchpad specific implementation and tests
    #

    @staticmethod
    @cache
    def _get_instance():
        """Create a CrashDB instance."""
        launchpad_instance = os.environ.get("APPORT_LAUNCHPAD_INSTANCE") or "qastaging"

        return CrashDatabase(
            os.environ.get("LP_CREDENTIALS"),
            {"distro": "ubuntu", "launchpad_instance": launchpad_instance},
        )

    @staticmethod
    def _get_bug_target(db, report):
        """Return the bug_target for this report."""
        project = db.options.get("project")
        if "SourcePackage" in report:
            return db.lp_distro.getSourcePackage(name=report["SourcePackage"])
        if project:
            return db.launchpad.projects[project]
        return None

    def _file_bug(
        self, bug_target: object, report: Report, description: str = "some description"
    ) -> int:
        """File a bug report for a report.

        Return the bug ID.
        """
        # unfortunately staging's +storeblob API hardly ever works, so we
        # must avoid using it. Fake it by manually doing the comments and
        # attachments that +filebug would ordinarily do itself when given a
        # blob handle.
        mime = self.crashdb._generate_upload_blob(report)
        msg = email.message_from_binary_file(mime)
        mime.close()
        msg_iter = msg.walk()

        # first one is the multipart container
        header = next(msg_iter)
        assert header.is_multipart()

        # second part should be an inline text/plain attachments
        # with all short fields
        part = next(msg_iter)
        assert not part.is_multipart()
        assert part.get_content_type() == "text/plain"
        description += "\n\n" + part.get_payload(decode=True).decode("UTF-8", "replace")

        # create the bug from header and description data
        bug = self.crashdb.launchpad.bugs.createBug(
            description=description,
            # temporarily disabled to work around SSLHandshakeError on
            # private attachments
            # private=(header['Private'] == 'yes'),
            tags=header["Tags"].split(),
            target=bug_target,
            title=report.get("Title", report.standard_title()),
        )

        # now add the attachments
        for part in msg_iter:
            assert not part.is_multipart()
            bug.addAttachment(
                comment="",
                description=part.get_filename(),
                content_type=None,
                data=part.get_payload(decode=True),
                filename=part.get_filename(),
                is_patch=False,
            )

        for subscriber in header["Subscribers"].split():
            sub = self.crashdb.launchpad.people[subscriber]
            if sub:
                bug.subscribe(person=sub)

        return bug.id

    def _mark_needs_retrace(self, crash_id):
        """Mark a report ID as needing retrace."""
        bug = self.crashdb.launchpad.bugs[crash_id]
        if self.crashdb.arch_tag not in bug.tags:
            bug.tags = bug.tags + [self.crashdb.arch_tag]
            bug.lp_save()

    def _mark_needs_dupcheck(self, crash_id):
        """Mark a report ID as needing duplicate check."""
        bug = self.crashdb.launchpad.bugs[crash_id]
        if "need-duplicate-check" not in bug.tags:
            bug.tags = bug.tags + ["need-duplicate-check"]
            bug.lp_save()

    def _mark_report_fixed(self, crash_id):
        """Close a report ID as "fixed"."""
        bug = self.crashdb.launchpad.bugs[crash_id]
        tasks = list(bug.bug_tasks)
        assert len(tasks) == 1
        t = tasks[0]
        t.status = "Fix Released"
        t.lp_save()

    def _mark_report_new(self, crash_id):
        """Reopen a report ID as "new"."""
        bug = self.crashdb.launchpad.bugs[crash_id]
        tasks = list(bug.bug_tasks)
        assert len(tasks) == 1
        t = tasks[0]
        t.status = "New"
        t.lp_save()

    def _verify_marked_regression(self, crash_id):
        """Verify that report ID is marked as regression."""
        bug = self.crashdb.launchpad.bugs[crash_id]
        self.assertIn("regression-retracer", bug.tags)

    def test_project(self):
        """Test reporting crashes against a project instead of a distro."""
        launchpad_instance = os.environ.get("APPORT_LAUNCHPAD_INSTANCE") or "qastaging"
        # crash database for langpack-o-matic project (this does not have
        # packages in any distro)
        crashdb = CrashDatabase(
            os.environ.get("LP_CREDENTIALS"),
            {"project": "langpack-o-matic", "launchpad_instance": launchpad_instance},
        )
        self.assertEqual(crashdb.distro, None)

        # create Python crash report
        r = Report("Crash")
        r["ExecutablePath"] = "/bin/foo"
        r[
            "Traceback"
        ] = """Traceback (most recent call last):
  File "/bin/foo", line 67, in fuzz
    print(weird)
NameError: global name 'weird' is not defined"""
        r.add_os_info()
        r.add_user_info()
        self.assertEqual(
            r.standard_title(),
            "foo crashed with NameError in fuzz():"
            " global name 'weird' is not defined",
        )

        # file it
        bug_target = self._get_bug_target(crashdb, r)
        self.assertEqual(bug_target.name, "langpack-o-matic")

        crash_id = self._file_bug(bug_target, r)
        self.assertTrue(crash_id > 0)
        sys.stderr.write(f"(https://{self.hostname}/bugs/{crash_id}) ")

        # update
        r = crashdb.download(crash_id)
        r[
            "StacktraceTop"
        ] = "read () from /lib/libc.6.so\nfoo (i=1) from /usr/lib/libfoo.so"
        r["Stacktrace"] = "long\ntrace"
        r["ThreadStacktrace"] = "thread\neven longer\ntrace"
        crashdb.update_traces(crash_id, r, "good retrace!")
        r = crashdb.download(crash_id)

        # test fixed version
        self.assertEqual(crashdb.get_fixed_version(crash_id), None)
        crashdb.close_duplicate(r, crash_id, self.get_uncommon_description_report())
        self.assertEqual(
            crashdb.duplicate_of(crash_id), self.get_uncommon_description_report()
        )
        self.assertEqual(crashdb.get_fixed_version(crash_id), "invalid")
        crashdb.close_duplicate(r, crash_id, None)
        self.assertEqual(crashdb.duplicate_of(crash_id), None)
        self.assertEqual(crashdb.get_fixed_version(crash_id), None)

    def test_download_robustness(self):
        """download() of uncommon description formats"""
        # only ProblemType/Architecture/DistroRelease in description
        r = self.crashdb.download(self.get_uncommon_description_report())
        self.assertEqual(r["ProblemType"], "Package")
        self.assertEqual(r["Architecture"], "amd64")
        self.assertTrue(r["DistroRelease"].startswith("Ubuntu "))

    def test_escalation(self):
        """Escalating bugs with more than 10 duplicates"""
        launchpad_instance = os.environ.get("APPORT_LAUNCHPAD_INSTANCE") or "qastaging"
        db = CrashDatabase(
            os.environ.get("LP_CREDENTIALS"),
            {
                "distro": "ubuntu",
                "launchpad_instance": launchpad_instance,
                "escalation_tag": "omgkittens",
                "escalation_subscription": "apport-hackers",
            },
        )

        count = 0
        p = db.launchpad.people[db.options["escalation_subscription"]].self_link
        # needs to have 13 consecutive valid bugs without dupes
        first_dup = 10070
        try:
            for b in range(first_dup, first_dup + 13):
                count += 1
                sys.stderr.write(f"{b} ")
                db.close_duplicate(Report(), b, self.get_segv_report())
                b = db.launchpad.bugs[self.get_segv_report()]
                has_escalation_tag = db.options["escalation_tag"] in b.tags
                has_escalation_subscription = any(
                    s.person_link == p for s in b.subscriptions
                )
                if count <= 10:
                    self.assertFalse(has_escalation_tag)
                    self.assertFalse(has_escalation_subscription)
                else:
                    self.assertTrue(has_escalation_tag)
                    self.assertTrue(has_escalation_subscription)
        finally:
            for b in range(first_dup, first_dup + count):
                sys.stderr.write(f"R{b} ")
                db.close_duplicate(Report(), b, None)
        sys.stderr.write("\n")

    def test_marking_python_task_mangle(self):
        """Test source package task fixup for marking interpreter
        scrashes."""
        self._mark_needs_dupcheck(self.get_python_report())
        unchecked_before = self.crashdb.get_dup_unchecked()
        self.assertIn(self.get_python_report(), unchecked_before)

        # add an upstream task, and remove the package name from the
        # package task; _mark_dup_checked is supposed to restore the
        # package name
        b = self.crashdb.launchpad.bugs[self.get_python_report()]
        if b.private:
            b.private = False
            b.lp_save()
        t = b.bug_tasks[0]
        t.target = self.crashdb.launchpad.distributions["ubuntu"]
        t.lp_save()
        b.addTask(target=self.crashdb.launchpad.projects["coreutils"])

        r = self.crashdb.download(self.get_python_report())
        self.crashdb._mark_dup_checked(self.get_python_report(), r)

        unchecked_after = self.crashdb.get_dup_unchecked()
        self.assertNotIn(self.get_python_report(), unchecked_after)
        self.assertEqual(
            unchecked_before, unchecked_after.union(set([self.get_python_report()]))
        )

        # upstream task should be unmodified
        b = self.crashdb.launchpad.bugs[self.get_python_report()]
        self.assertEqual(b.bug_tasks[0].bug_target_name, "coreutils")
        self.assertEqual(b.bug_tasks[0].status, "New")
        self.assertEqual(b.bug_tasks[0].importance, "Undecided")

        # package-less distro task should have package name fixed
        self.assertEqual(b.bug_tasks[1].bug_target_name, "coreutils (Ubuntu)")
        self.assertEqual(b.bug_tasks[1].status, "New")
        self.assertEqual(b.bug_tasks[1].importance, "Medium")

        # should not confuse get_fixed_version()
        self.assertEqual(self.crashdb.get_fixed_version(self.get_python_report()), None)

    @staticmethod
    def _generate_sigsegv_report(signal="11"):
        """Create a test executable which will die with a SIGSEGV, generate
        a core dump for it, create a problem report with those two
        arguments (ExecutablePath and CoreDump) and call add_gdb_info().

        Return the apport.report.Report.
        """
        workdir = None
        orig_cwd = os.getcwd()
        pr = Report()
        try:
            workdir = tempfile.mkdtemp()
            atexit.register(shutil.rmtree, workdir)
            os.chdir(workdir)

            # create a test executable
            with open("crash.c", "w", encoding="utf-8") as fd:
                fd.write(
                    """
int f(x) {
    int* p = 0; *p = x;
    return x+1;
}
int main() { return f(42); }
"""
                )
            assert subprocess.call(["gcc", "-g", "crash.c", "-o", "crash"]) == 0
            assert os.path.exists("crash")

            # call it through gdb and dump core
            subprocess.call(
                [
                    "gdb",
                    "--batch",
                    "--ex",
                    "run",
                    "--ex",
                    "generate-core-file core",
                    "./crash",
                ],
                stdout=subprocess.PIPE,
            )
            assert os.path.exists("core")
            subprocess.check_call(["sync"])
            assert (
                subprocess.call(["readelf", "-n", "core"], stdout=subprocess.PIPE) == 0
            )

            pr["ExecutablePath"] = os.path.join(workdir, "crash")
            pr["CoreDump"] = (os.path.join(workdir, "core"),)
            pr["Signal"] = signal

            pr.add_gdb_info()
        finally:
            os.chdir(orig_cwd)

        return pr
