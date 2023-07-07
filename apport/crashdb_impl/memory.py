"""Simple in-memory CrashDatabase implementation, mainly useful for testing."""

# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import time

import apport.crashdb
import apport.report


class CrashDatabase(apport.crashdb.CrashDatabase):
    """Simple implementation of crash database interface which keeps everything
    in memory.

    This is mainly useful for testing and debugging.
    """

    def __init__(self, auth_file, options):
        """Initialize crash database connection.

        This class does not support bug patterns and authentication.
        """
        apport.crashdb.CrashDatabase.__init__(self, auth_file, options)

        # reports is a list of dictionaries with keys:
        # report, fixed_version, dup_of, comment
        self.reports = []
        self.unretraced = set()
        self.dup_unchecked = set()

        self.upload_delay = 0
        self.upload_msg = None

        if "sample_data" in options:
            self.add_sample_data()

    def upload(self, report, progress_callback=None, user_message_callback=None):
        """Store the report and return a handle number (starting from 0).

        This does not support (nor need) progress callbacks.
        """
        assert self.accepts(report)

        if user_message_callback and self.upload_msg:
            user_message_callback(self.upload_msg[0], self.upload_msg[1])

        self.reports.append(
            {"report": report, "fixed_version": None, "dup_of": None, "comment": ""}
        )
        crash_id = len(self.reports) - 1
        if "Traceback" in report:
            self.dup_unchecked.add(crash_id)
        else:
            self.unretraced.add(crash_id)

        # Simulate uploading some data
        if self.upload_delay:
            if progress_callback:
                progress_callback(0, 100)
            time.sleep(self.upload_delay)
            if progress_callback:
                progress_callback(100, 100)

        return crash_id

    def get_comment_url(self, report, handle):
        """Return http://<sourcepackage>.bugs.example.com/<handle> for package
        bugs or http://bugs.example.com/<handle> for reports without a
        SourcePackage.
        """
        if "SourcePackage" in report:
            return f"http://{report['SourcePackage']}.bugs.example.com/{handle}"
        return f"http://bugs.example.com/{handle}"

    def get_id_url(self, report, crash_id):
        """Return URL for a given report ID.

        The report is passed in case building the URL needs additional
        information from it, such as the SourcePackage name.

        Return None if URL is not available or cannot be determined.
        """
        return self.get_comment_url(report, crash_id)

    def download(self, crash_id):
        """Download the problem report from given ID and return a Report."""
        return self.reports[crash_id]["report"]

    def get_affected_packages(self, crash_id):
        """Return list of affected source packages for given ID."""
        return [self.reports[crash_id]["report"]["SourcePackage"]]

    def is_reporter(self, crash_id):
        """Check whether the user is the reporter of given ID."""
        return True

    def can_update(self, crash_id):
        """Check whether the user is eligible to update a report.

        A user should add additional information to an existing ID if (s)he is
        the reporter or subscribed, the bug is open, not a duplicate, etc. The
        exact policy and checks should be done according to  the particular
        implementation.
        """
        return self.is_reporter(crash_id)

    def update(
        self,
        crash_id,
        report,
        comment,
        change_description=False,
        attachment_comment=None,
        key_filter=None,
    ):  # pylint: disable=too-many-arguments
        """Update the given report ID with all data from report.

        This creates a text comment with the "short" data (see
        ProblemReport.write_mime()), and creates attachments for all the
        bulk/binary data.

        If change_description is True, and the crash db implementation supports
        it, the short data will be put into the description instead (like in a
        new bug).

        comment will be added to the "short" data. If attachment_comment is
        given, it will be added to the attachment uploads.

        If key_filter is a list or set, then only those keys will be added.
        """
        r = self.reports[crash_id]
        r["comment"] = comment

        if key_filter:
            for f in key_filter:
                if f in report:
                    r["report"][f] = report[f]
        else:
            r["report"].update(report)

    def get_distro_release(self, crash_id):
        """Get 'DistroRelease: <release>' from the given report ID and return
        it."""
        return self.reports[crash_id]["report"]["DistroRelease"]

    def get_unfixed(self):
        """Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.

        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably OSError).
        """
        result = set()
        for i, report in enumerate(self.reports):
            if report["dup_of"] is None and report["fixed_version"] is None:
                result.add(i)

        return result

    def get_fixed_version(self, crash_id):
        """Return the package version that fixes a given crash.

        Return None if the crash is not yet fixed, or an empty string if the
        crash is fixed, but it cannot be determined by which version. Return
        'invalid' if the crash report got invalidated, such as closed a
        duplicate or rejected.

        This function should make sure that the returned result is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably OSError).
        """
        try:
            if self.reports[crash_id]["dup_of"] is not None:
                return "invalid"
            return self.reports[crash_id]["fixed_version"]
        except IndexError:
            return "invalid"

    def duplicate_of(self, crash_id):
        """Return master ID for a duplicate bug.

        If the bug is not a duplicate, return None.
        """
        return self.reports[crash_id]["dup_of"]

    def close_duplicate(self, report, crash_id, master_id):
        """Mark a crash id as duplicate of given master ID.

        If master is None, id gets un-duplicated.
        """
        self.reports[crash_id]["dup_of"] = master_id

    def mark_regression(self, crash_id, master):
        """Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').
        """
        assert self.reports[master]["fixed_version"] is not None
        self.reports[crash_id]["comment"] = f"regression, already fixed in #{master}"

    def _mark_dup_checked(self, crash_id, report):
        """Mark crash id as checked for being a duplicate."""
        try:
            self.dup_unchecked.remove(crash_id)
        except KeyError:
            pass  # happens when trying to check for dup twice

    def mark_retraced(self, crash_id):
        """Mark crash id as retraced."""
        self.unretraced.remove(crash_id)

    def mark_retrace_failed(self, crash_id, invalid_msg=None):
        """Mark crash id as 'failed to retrace'.

        This is a no-op since this crash DB is not interested in it.
        """

    def get_unretraced(self):
        """Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture."""
        return self.unretraced

    def get_dup_unchecked(self):
        """Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().
        """
        return self.dup_unchecked

    def latest_id(self):
        """Return the ID of the most recently filed report."""
        return len(self.reports) - 1

    def add_sample_data(self):
        """Add some sample crash reports.

        This is mostly useful for test suites.
        """
        # signal crash with source package and complete stack trace
        r = apport.report.Report()
        r["Package"] = "libfoo1 1.2-3"
        r["SourcePackage"] = "foo"
        r["DistroRelease"] = "FooLinux Pi/2"
        r["Signal"] = "11"
        r["ExecutablePath"] = "/bin/crash"

        r[
            "StacktraceTop"
        ] = """foo_bar (x=1) at crash.c:28
d01 (x=1) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
__frob (x=1) at crash.c:30"""
        self.upload(r)

        # duplicate of above crash (slightly different arguments and
        # package version)
        r = apport.report.Report()
        r["Package"] = "libfoo1 1.2-4"
        r["SourcePackage"] = "foo"
        r["DistroRelease"] = "Testux 1.0"
        r["Signal"] = "11"
        r["ExecutablePath"] = "/bin/crash"

        r[
            "StacktraceTop"
        ] = """foo_bar (x=2) at crash.c:28
d01 (x=3) at crash.c:29
raise () from /lib/libpthread.so.0
<signal handler called>
__frob (x=4) at crash.c:30"""
        self.upload(r)

        # unrelated signal crash
        r = apport.report.Report()
        r["Package"] = "bar 42-4"
        r["SourcePackage"] = "bar"
        r["DistroRelease"] = "Testux 1.0"
        r["Signal"] = "11"
        r["ExecutablePath"] = "/usr/bin/broken"

        r[
            "StacktraceTop"
        ] = """h (p=0x0) at crash.c:25
g (x=1, y=42) at crash.c:26
f (x=1) at crash.c:27
e (x=1) at crash.c:28
d (x=1) at crash.c:29"""
        self.upload(r)

        # Python crash
        r = apport.report.Report()
        r["Package"] = "python-goo 3epsilon1"
        r["SourcePackage"] = "pygoo"
        r["DistroRelease"] = "Testux 2.2"
        r["ExecutablePath"] = "/usr/bin/pygoo"
        r[
            "Traceback"
        ] = """Traceback (most recent call last):
  File "test.py", line 7, in <module>
    print(_f(5))
  File "test.py", line 5, in _f
    return g_foo00(x+1)
  File "test.py", line 2, in g_foo00
    return x/0
ZeroDivisionError: integer division or modulo by zero"""
        self.upload(r)

        # Python crash reoccurs in a later version
        # (used for regression detection)
        r = apport.report.Report()
        r["Package"] = "python-goo 5"
        r["SourcePackage"] = "pygoo"
        r["DistroRelease"] = "Testux 2.2"
        r["ExecutablePath"] = "/usr/bin/pygoo"
        r[
            "Traceback"
        ] = """Traceback (most recent call last):
  File "test.py", line 7, in <module>
    print(_f(5))
  File "test.py", line 5, in _f
    return g_foo00(x+1)
  File "test.py", line 2, in g_foo00
    return x/0
ZeroDivisionError: integer division or modulo by zero"""
        self.upload(r)
