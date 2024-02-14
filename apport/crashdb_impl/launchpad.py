"""Crash database implementation for Launchpad."""

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
# pylint: disable=invalid-name,missing-function-docstring

import atexit
import email
import gzip
import http.client
import io
import os.path
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
import urllib.request

try:
    from httplib2 import FailedToDecompressContent
    from launchpadlib.errors import HTTPError, RestfulError
    from launchpadlib.launchpad import Launchpad
    from launchpadlib.uris import lookup_web_root
except ImportError:
    # if launchpadlib is not available, only client-side reporting will work
    Launchpad = None

import apport.crashdb
import apport.logging
import apport.report
from apport.packaging_impl import impl as packaging

DEFAULT_LAUNCHPAD_INSTANCE = "production"
default_credentials_path = os.path.expanduser("~/.cache/apport/launchpad.credentials")


def filter_filename(attachments):
    for attachment in attachments:
        try:
            f = attachment.data.open()
        except (HTTPError, FailedToDecompressContent):
            apport.logging.error("Broken attachment on bug, ignoring")
            continue
        name = f.filename
        if name.endswith(".txt") or name.endswith(".gz"):
            yield f


def id_set(tasks):
    # same as set(int(i.bug.id) for i in tasks) but faster
    return set(int(i.self_link.split("/").pop()) for i in tasks)


class CrashDatabase(apport.crashdb.CrashDatabase):
    """Launchpad implementation of crash database interface."""

    def __init__(self, auth, options):
        """Initialize Launchpad crash database.

        You need to specify a launchpadlib-style credentials file to
        access launchpad. If you supply None, it will use
        default_credentials_path (~/.cache/apport/launchpad.credentials).

        Recognized options are:
        - distro: Name of the distribution in Launchpad
        - project: Name of the project in Launchpad
          (Note that exactly one of "distro" or "project" must be given.)
        - launchpad_instance: If set, this uses the given launchpad instance
          instead of production (optional). This can be overridden or set by
          $APPORT_LAUNCHPAD_INSTANCE environment. For example: "qastaging" or
          "staging".
        - cache_dir: Path to a permanent cache directory; by default it uses a
          temporary one. (optional). This can be overridden or set by
          $APPORT_LAUNCHPAD_CACHE environment.
        - escalation_subscription: This subscribes the given person or team to
          a bug once it gets the 10th duplicate.
        - escalation_tag: This adds the given tag to a bug once it gets more
          than 10 duplicates.
        - initial_subscriber: The Launchpad user which gets subscribed to newly
          filed bugs (default: "apport"). It should be a bot user which the
          crash-digger instance runs as, as this will get to see all bug
          details immediately.
        - triaging_team: The Launchpad user/team which gets subscribed after
          updating a crash report bug by the retracer (default:
          "ubuntu-crashes-universe")
        - architecture: If set, this sets and watches out for needs-*-retrace
          tags of this architecture. This is useful when being used with
          apport-retrace and crash-digger to process crash reports of foreign
          architectures. Defaults to system architecture.
        """
        if os.getenv("APPORT_LAUNCHPAD_INSTANCE"):
            options["launchpad_instance"] = os.getenv("APPORT_LAUNCHPAD_INSTANCE")
        if not auth:
            lp_instance = options.get("launchpad_instance")
            if lp_instance:
                auth = ".".join(
                    (default_credentials_path, lp_instance.split("://", 1)[-1])
                )
            else:
                auth = default_credentials_path
        apport.crashdb.CrashDatabase.__init__(self, auth, options)

        self.distro = options.get("distro")
        if self.distro:
            assert (
                "project" not in options
            ), 'Must not set both "project" and "distro" option'
        else:
            assert (
                "project" in options
            ), 'Need to have either "project" or "distro" option'

        if "architecture" in options:
            self.arch_tag = f"need-{options['architecture']}-retrace"
        else:
            self.arch_tag = f"need-{packaging.get_system_architecture()}-retrace"
        self.options = options
        self.auth = auth
        assert self.auth

        self.__launchpad = None
        self.__lp_distro = None
        self.__lpcache = os.getenv("APPORT_LAUNCHPAD_CACHE", options.get("cache_dir"))
        if not self.__lpcache:
            # use a temporary dir
            self.__lpcache = tempfile.mkdtemp(prefix="launchpadlib.cache.")
            atexit.register(shutil.rmtree, self.__lpcache, ignore_errors=True)

    @property
    def launchpad(self):
        """Return Launchpad instance."""
        if self.__launchpad:
            return self.__launchpad

        if Launchpad is None:
            sys.stderr.write(
                f"ERROR: The launchpadlib Python {sys.version[0]} module"
                f" is not installed."
                f" Please install the python3-launchpadlib package!\n"
            )
            sys.exit(1)

        if self.options.get("launchpad_instance"):
            launchpad_instance = self.options.get("launchpad_instance")
        else:
            launchpad_instance = DEFAULT_LAUNCHPAD_INSTANCE

        auth_dir = os.path.dirname(self.auth)
        if auth_dir and not os.path.isdir(auth_dir):
            os.makedirs(auth_dir)

        try:
            self.__launchpad = Launchpad.login_with(
                "apport-collect",
                launchpad_instance,
                launchpadlib_dir=self.__lpcache,
                allow_access_levels=["WRITE_PRIVATE"],
                credentials_file=self.auth,
                version="1.0",
            )
        except (RestfulError, OSError, ValueError) as error:
            apport.logging.error(
                "connecting to Launchpad failed: %s\n"
                'You can reset the credentials by removing the file "%s"',
                getattr(error, "content", str(error)),
                self.auth,
            )
            sys.exit(99)  # transient error

        return self.__launchpad

    def _get_distro_tasks(self, tasks):
        if not self.distro:
            return

        for t in tasks:
            if t.bug_target_name.lower() == self.distro or re.match(
                rf"^.+\({self.distro}.*\)$", t.bug_target_name.lower()
            ):
                yield t

    @property
    def lp_distro(self):
        """Return Launchpad distribution (e.g. ubuntu)."""
        if self.__lp_distro is None:
            if self.distro:
                self.__lp_distro = self.launchpad.distributions[self.distro]
            elif "project" in self.options:
                self.__lp_distro = self.launchpad.projects[self.options["project"]]
            else:
                raise SystemError(
                    "distro or project needs to be specified in crashdb options"
                )

        return self.__lp_distro

    def upload(self, report, progress_callback=None, user_message_callback=None):
        """Upload given problem report return a handle for it.

        This should happen noninteractively.

        If the implementation supports it, and a function progress_callback is
        passed, that is called repeatedly with two arguments: the number of
        bytes already sent, and the total number of bytes to send. This can be
        used to provide a proper upload progress indication on frontends.
        """
        assert self.accepts(report)

        blob_file = self._generate_upload_blob(report)
        ticket = upload_blob(blob_file, progress_callback, hostname=self.get_hostname())
        blob_file.close()
        assert ticket
        return ticket

    def get_hostname(self) -> str:
        """Return the hostname for the Launchpad instance."""
        launchpad_instance = self.options.get(
            "launchpad_instance", DEFAULT_LAUNCHPAD_INSTANCE
        )
        url = urllib.parse.urlparse(lookup_web_root(launchpad_instance))
        return url.netloc

    def get_comment_url(self, report, handle):
        """Return an URL that should be opened after report has been uploaded
        and upload() returned handle.

        Should return None if no URL should be opened (anonymous filing without
        user comments); in that case this function should do whichever
        interactive steps it wants to perform.
        """
        args = {}
        title = report.get("Title", report.standard_title())
        if title:
            args["field.title"] = title

        hostname = self.get_hostname()

        if "SnapSource" in report:
            project = report["SnapSource"]
        else:
            project = self.options.get("project")

        if project:
            return (
                f"https://bugs.{hostname}/{project}/+filebug/{handle}"
                f"?{urllib.parse.urlencode(args)}"
            )

        if "SourcePackage" in report:
            return (
                f"https://bugs.{hostname}/{self.distro}/+source"
                f"/{report['SourcePackage']}/+filebug/{handle}"
                f"?{urllib.parse.urlencode(args)}"
            )

        return (
            f"https://bugs.{hostname}/{self.distro}/+filebug/{handle}"
            f"?{urllib.parse.urlencode(args)}"
        )

    def get_id_url(self, report: apport.report.Report, crash_id: int) -> str:
        """Return URL for a given report ID.

        The report is passed in case building the URL needs additional
        information from it, such as the SourcePackage name.

        Return None if URL is not available or cannot be determined.
        """
        return f"https://bugs.{self.get_hostname()}/bugs/{crash_id}"

    def download(self, crash_id):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-statements
        """Download the problem report from given ID and return a Report."""
        report = apport.report.Report()
        b = self.launchpad.bugs[crash_id]

        # parse out fields from summary
        m = re.search(r"(ProblemType:.*)$", b.description, re.S)
        if not m:
            m = re.search(r"^--- \r?$[\r\n]*(.*)", b.description, re.M | re.S)
        assert m, "bug description must contain standard apport format data"

        description = (
            m.group(1)
            .encode("UTF-8")
            .replace(b"\xc2\xa0", b" ")
            .replace(b"\r\n", b"\n")
        )

        if b"\n\n" in description:
            # this often happens, remove all empty lines between top and
            # 'Uname'
            if b"Uname:" in description:
                # this will take care of bugs like LP #315728 where stuff
                # is added after the apport data
                (part1, part2) = description.split(b"Uname:", 1)
                description = (
                    part1.replace(b"\n\n", b"\n")
                    + b"Uname:"
                    + part2.split(b"\n\n", 1)[0]
                )
            else:
                # just parse out the Apport block; e. g. LP #269539
                description = description.split(b"\n\n", 1)[0]

        report.load(io.BytesIO(description))

        if "Date" not in report:
            # We had not submitted this field for a while, claiming it
            # redundant. But it is indeed required for up-to-the-minute
            # comparison with log files, etc. For backwards compatibility with
            # those reported bugs, read the creation date
            try:
                report["Date"] = b.date_created.ctime()
            except AttributeError:
                # support older wadllib API which returned strings
                report["Date"] = b.date_created
        if "ProblemType" not in report:
            if "apport-bug" in b.tags:
                report["ProblemType"] = "Bug"
            elif "apport-crash" in b.tags:
                report["ProblemType"] = "Crash"
            elif "apport-kernelcrash" in b.tags:
                report["ProblemType"] = "KernelCrash"
            elif "apport-package" in b.tags:
                report["ProblemType"] = "Package"
            else:
                raise ValueError(
                    f"cannot determine ProblemType from tags: {str(b.tags)}"
                )

        report.add_tags(b.tags)

        if "Title" in report:
            report["OriginalTitle"] = report["Title"]

        report["Title"] = b.title

        for attachment in filter_filename(b.attachments):
            key, ext = os.path.splitext(attachment.filename)
            # ignore attachments with invalid keys
            try:
                report[key] = ""
            except (AssertionError, TypeError, ValueError):
                continue
            if ext == ".txt":
                report[key] = attachment.read()
                try:
                    report[key] = report[key].decode("UTF-8")
                except UnicodeDecodeError:
                    pass
            elif ext == ".gz":
                try:
                    with gzip.GzipFile(fileobj=attachment) as gz:
                        report[key] = gz.read()
                except OSError as error:
                    # some attachments are only called .gz, but are
                    # uncompressed (LP #574360)
                    if "Not a gzip" not in str(error):
                        raise
                    attachment.seek(0)
                    report[key] = attachment.read()
            else:
                raise NotImplementedError(
                    f"Unknown attachment type: {attachment.filename}"
                )
        return report

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
        bug = self.launchpad.bugs[crash_id]

        # TODO: raise an error if key_filter is not a list or set
        if key_filter:
            skip_keys = set(report.keys()) - set(key_filter)
        else:
            skip_keys = None

        # we want to reuse the knowledge of write_mime() with all its
        # different input types and output formatting; however, we have to
        # dissect the mime ourselves, since we can't just upload it as a blob
        with tempfile.TemporaryFile() as mime:
            report.write_mime(mime, skip_keys=skip_keys)
            mime.flush()
            mime.seek(0)
            msg = email.message_from_binary_file(mime)
            msg_iter = msg.walk()

            # first part is the multipart container
            part = next(msg_iter)
            assert part.is_multipart()

            # second part should be an inline text/plain attachments with
            # all short fields
            part = next(msg_iter)
            assert not part.is_multipart()
            assert part.get_content_type() == "text/plain"

            if not key_filter:
                # when we update a complete report, we are updating
                # an existing bug with apport-collect
                x = bug.tags[:]  # LP#254901 workaround
                x.append("apport-collected")
                # add any tags (like the release) to the bug
                if "Tags" in report:
                    x += self._filter_tag_names(report["Tags"]).split()
                bug.tags = x
                bug.lp_save()
                # fresh bug object, LP#336866 workaround
                bug = self.launchpad.bugs[crash_id]

            # short text data
            text = part.get_payload(decode=True).decode("UTF-8", "replace")
            # text can be empty if you are only adding an attachment to a bug
            if text:
                if change_description:
                    bug.description = f"{bug.description}\n--- \n{text}"
                    bug.lp_save()
                else:
                    if not comment:
                        comment = bug.title
                    bug.newMessage(content=text, subject=comment)

            # other parts are the attachments:
            for part in msg_iter:
                bug.addAttachment(
                    comment=attachment_comment or "",
                    description=part.get_filename(),
                    content_type=None,
                    data=part.get_payload(decode=True),
                    filename=part.get_filename(),
                    is_patch=False,
                )

    def update_traces(self, crash_id, report, comment=""):
        """Update the given report ID for retracing results.

        This updates Stacktrace, ThreadStacktrace, StacktraceTop,
        and StacktraceSource. You can also supply an additional comment.
        """
        apport.crashdb.CrashDatabase.update_traces(self, crash_id, report, comment)

        bug = self.launchpad.bugs[crash_id]
        # ensure it's assigned to a package
        if "SourcePackage" in report:
            for task in bug.bug_tasks:
                if task.target.resource_type_link.endswith("#distribution"):
                    task.target = self.lp_distro.getSourcePackage(
                        name=report["SourcePackage"]
                    )
                    task.lp_save()
                    bug = self.launchpad.bugs[crash_id]
                    break

        # remove core dump if stack trace is usable
        if report.has_useful_stacktrace():
            for a in bug.attachments:
                if a.title == "CoreDump.gz":
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass  # LP#249950 workaround
            try:
                task = self._get_distro_tasks(bug.bug_tasks)
                task = next(task)
                if task.importance == "Undecided":
                    task.importance = "Medium"
                    task.lp_save()
            except StopIteration:
                pass  # no distro tasks

            # update bug title with retraced function name
            fn = report.stacktrace_top_function()
            if fn:
                m = re.match(r"^(.*crashed with SIG.* in )([^( ]+)(\(\).*$)", bug.title)
                if m and m.group(2) != fn:
                    bug.title = m.group(1) + fn + m.group(3)
                    try:
                        bug.lp_save()
                    except HTTPError:
                        pass  # LP#336866 workaround
                    bug = self.launchpad.bugs[crash_id]

        self._subscribe_triaging_team(bug, report)

    def get_distro_release(self, crash_id):
        """Get 'DistroRelease: <release>' from the given report ID and return
        it."""
        bug = self.launchpad.bugs[crash_id]
        m = re.search("DistroRelease: ([-a-zA-Z0-9.+/ ]+)", bug.description)
        if m:
            return m.group(1)
        raise ValueError("URL does not contain DistroRelease: field")

    def get_affected_packages(self, crash_id):
        """Return list of affected source packages for given ID."""
        bug_target_re = re.compile(
            rf"/{self.distro}/(?:(?P<suite>[^/]+)/)?\+source" rf"/(?P<source>[^/]+)$"
        )

        bug = self.launchpad.bugs[crash_id]
        result = []

        for task in bug.bug_tasks:
            match = bug_target_re.search(task.target.self_link)
            if not match:
                continue
            if task.status in {"Invalid", "Won't Fix", "Fix Released"}:
                continue
            result.append(match.group("source"))
        return result

    def is_reporter(self, crash_id):
        """Check whether the user is the reporter of given ID."""
        bug = self.launchpad.bugs[crash_id]
        return bug.owner.name == self.launchpad.me.name

    def can_update(self, crash_id):
        """Check whether the user is eligible to update a report.

        A user should add additional information to an existing ID if (s)he is
        the reporter or subscribed, the bug is open, not a duplicate, etc. The
        exact policy and checks should be done according to the particular
        implementation.
        """
        bug = self.launchpad.bugs[crash_id]
        if bug.duplicate_of:
            return False

        if bug.owner.name == self.launchpad.me.name:
            return True

        # check subscription
        me = self.launchpad.me.self_link
        for sub in bug.subscriptions.entries:
            if sub["person_link"] == me:
                return True

        return False

    def get_unretraced(self):
        """Return an ID set of all crashes which have not been retraced yet and
        which happened on the current host architecture."""
        try:
            bugs = self.lp_distro.searchTasks(
                tags=self.arch_tag, created_since="2011-08-01"
            )
            return id_set(bugs)
        except HTTPError as error:
            apport.logging.error("connecting to Launchpad failed: %s", str(error))
            sys.exit(99)  # transient error

    def get_dup_unchecked(self):
        """Return an ID set of all crashes which have not been checked for
        being a duplicate.

        This is mainly useful for crashes of scripting languages such as
        Python, since they do not need to be retraced. It should not return
        bugs that are covered by get_unretraced().
        """
        try:
            bugs = self.lp_distro.searchTasks(
                tags="need-duplicate-check", created_since="2011-08-01"
            )
            return id_set(bugs)
        except HTTPError as error:
            apport.logging.error("connecting to Launchpad failed: %s", str(error))
            sys.exit(99)  # transient error

    def get_unfixed(self):
        """Return an ID set of all crashes which are not yet fixed.

        The list must not contain bugs which were rejected or duplicate.

        This function should make sure that the returned list is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably OSError).
        """
        bugs = self.lp_distro.searchTasks(tags="apport-crash")
        return id_set(bugs)

    def _get_source_version(self, package):
        """Return the version of given source package in the latest release of
        given distribution.

        If 'distro' is None, we will look for a launchpad project .
        """
        sources = self.lp_distro.main_archive.getPublishedSources(
            exact_match=True,
            source_name=package,
            distro_series=self.lp_distro.current_series,
        )
        # first element is the latest one
        return sources[0].source_package_version

    def get_fixed_version(self, crash_id):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-return-statements
        """Return the package version that fixes a given crash.

        Return None if the crash is not yet fixed, or an empty string if the
        crash is fixed, but it cannot be determined by which version. Return
        'invalid' if the crash report got invalidated, such as closed a
        duplicate or rejected.

        This function should make sure that the returned result is correct. If
        there are any errors with connecting to the crash database, it should
        raise an exception (preferably OSError).
        """
        # do not do version tracking yet; for that, we need to get the current
        # distrorelease and the current package version in that distrorelease
        # (or, of course, proper version tracking in Launchpad itself)

        try:
            b = self.launchpad.bugs[crash_id]
        except KeyError:
            return "invalid"

        if b.duplicate_of:
            return "invalid"

        tasks = list(b.bug_tasks)  # just fetch it once

        if self.distro:
            distro_identifier = f"({self.distro.lower()})"
            fixed_tasks = list(
                filter(
                    lambda task: task.status == "Fix Released"
                    and distro_identifier in task.bug_target_display_name.lower(),
                    tasks,
                )
            )

            if not fixed_tasks:
                fixed_distro = list(
                    filter(
                        lambda task: task.status == "Fix Released"
                        and task.bug_target_name.lower() == self.distro.lower(),
                        tasks,
                    )
                )
                if fixed_distro:
                    # fixed in distro inself (without source package)
                    return ""

            if len(fixed_tasks) > 1:
                apport.logging.warning(
                    "There is more than one task fixed in %s %s,"
                    " using first one to determine fixed version",
                    self.distro,
                    crash_id,
                )
                return ""

            if fixed_tasks:
                task = fixed_tasks.pop()
                try:
                    return self._get_source_version(
                        task.bug_target_display_name.split()[0]
                    )
                except IndexError:
                    # source does not exist any more
                    return "invalid"
            else:
                # check if there only invalid ones
                invalid_tasks = list(
                    filter(
                        lambda task: task.status in {"Invalid", "Won't Fix", "Expired"}
                        and distro_identifier in task.bug_target_display_name.lower(),
                        tasks,
                    )
                )
                if invalid_tasks:
                    non_invalid_tasks = list(
                        filter(
                            lambda task: task.status
                            not in ("Invalid", "Won't Fix", "Expired")
                            and distro_identifier
                            in task.bug_target_display_name.lower(),
                            tasks,
                        )
                    )
                    if not non_invalid_tasks:
                        return "invalid"
        else:
            fixed_tasks = list(
                filter(lambda task: task.status == "Fix Released", tasks)
            )
            if fixed_tasks:
                # TODO: look for current series
                return ""
            # check if there any invalid ones
            if list(filter(lambda task: task.status == "Invalid", tasks)):
                return "invalid"

        return None

    def duplicate_of(self, crash_id):
        """Return master ID for a duplicate bug.

        If the bug is not a duplicate, return None.
        """
        b = self.launchpad.bugs[crash_id].duplicate_of
        if b:
            return b.id
        return None

    def close_duplicate(self, report, crash_id, master_id):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-statements
        """Mark a crash id as duplicate of given master ID.

        If master is None, id gets un-duplicated.
        """
        bug = self.launchpad.bugs[crash_id]

        if master_id:
            assert (
                crash_id != master_id
            ), f"cannot mark bug {str(crash_id)} as a duplicate of itself"

            # check whether the master itself is a dup
            master = self.launchpad.bugs[master_id]
            if master.duplicate_of:
                master = master.duplicate_of
                master_id = master.id
                if master.id == crash_id:
                    # this happens if the bug was manually duped to a newer one
                    apport.logging.warning(
                        "Bug %i was manually marked as a dupe of newer bug %i,"
                        " not closing as duplicate",
                        crash_id,
                        master_id,
                    )
                    return

            for a in bug.attachments:
                if a.title in {
                    "CoreDump.gz",
                    "Stacktrace.txt",
                    "ThreadStacktrace.txt",
                    "ProcMaps.txt",
                    "ProcStatus.txt",
                    "Registers.txt",
                    "Disassembly.txt",
                }:
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass  # LP#249950 workaround

            # fresh bug object, LP#336866 workaround
            bug = self.launchpad.bugs[crash_id]
            bug.newMessage(
                content=f"Thank you for taking the time to report this crash"
                f" and helping to make this software better.  This particular"
                f" crash has already been reported and is a duplicate of bug"
                f" #{master_id}, so is being marked as such.  Please look at"
                f" the other bug report to see if there is any missing"
                f" information that you can provide, or to see if there is a"
                f" workaround for the bug.  Additionally, any further"
                f" discussion regarding the bug should occur in the other"
                f" report.  Please continue to report any other bugs you may"
                f" find.",
                subject="This bug is a duplicate",
            )

            # refresh, LP#336866 workaround
            bug = self.launchpad.bugs[crash_id]
            if bug.private:
                bug.private = False

            # set duplicate last, since we cannot modify already dup'ed bugs
            if not bug.duplicate_of:
                bug.duplicate_of = master

            # cache tags of master bug report instead of performing multiple
            # queries
            master_tags = master.tags

            if len(master.duplicates) == 10:
                if (
                    "escalation_tag" in self.options
                    and self.options["escalation_tag"] not in master_tags
                    and self.options.get("escalated_tag", " invalid ")
                    not in master_tags
                ):
                    master.tags = master_tags + [
                        self.options["escalation_tag"]
                    ]  # LP#254901 workaround
                    master.lp_save()

                if (
                    "escalation_subscription" in self.options
                    and self.options.get("escalated_tag", " invalid ")
                    not in master_tags
                ):
                    p = self.launchpad.people[self.options["escalation_subscription"]]
                    master.subscribe(person=p)

            # requesting updated stack trace?
            if report.has_useful_stacktrace() and (
                "apport-request-retrace" in master_tags
                or "apport-failed-retrace" in master_tags
            ):
                self.update(
                    master_id,
                    report,
                    f"Updated stack trace from duplicate bug {crash_id}",
                    key_filter=[
                        "Stacktrace",
                        "ThreadStacktrace",
                        "Package",
                        "Dependencies",
                        "ProcMaps",
                        "ProcCmdline",
                    ],
                )

                master = self.launchpad.bugs[master_id]
                x = master.tags[:]  # LP#254901 workaround
                try:
                    x.remove("apport-failed-retrace")
                except ValueError:
                    pass
                try:
                    x.remove("apport-request-retrace")
                except ValueError:
                    pass
                master.tags = x
                try:
                    master.lp_save()
                except HTTPError:
                    pass  # LP#336866 workaround

            # allow list of tags to copy from duplicates bugs to the master
            tags_to_copy = ["bugpattern-needed"]
            for series in self.lp_distro.series:
                if series.status not in [
                    "Active Development",
                    "Current Stable Release",
                    "Supported",
                    "Pre-release Freeze",
                ]:
                    continue
                tags_to_copy.append(series.name)
            # copy tags over from the duplicate bug to the master bug
            dupe_tags = set(bug.tags)
            # reload master tags as they may have changed
            master_tags = master.tags
            missing_tags = dupe_tags.difference(master_tags)

            for tag in missing_tags:
                if tag in tags_to_copy:
                    master_tags.append(tag)

            master.tags = master_tags
            master.lp_save()

        elif bug.duplicate_of:
            bug.duplicate_of = None

        # pylint: disable=protected-access
        if bug._dirty_attributes:  # LP#336866 workaround
            bug.lp_save()

    def mark_regression(self, crash_id, master):
        """Mark a crash id as reintroducing an earlier crash which is
        already marked as fixed (having ID 'master').
        """
        bug = self.launchpad.bugs[crash_id]
        bug.newMessage(
            content=f"This crash has the same stack trace characteristics as"
            f" bug #{master}. However, the latter was already fixed in an"
            f" earlier package version than the one in this report. This might"
            f" be a regression or because the problem is in a dependent"
            f" package.",
            subject="Possible regression detected",
        )
        # fresh bug object, LP#336866 workaround
        bug = self.launchpad.bugs[crash_id]
        bug.tags = bug.tags + ["regression-retracer"]  # LP#254901 workaround
        bug.lp_save()

    def mark_retraced(self, crash_id):
        """Mark crash id as retraced."""
        bug = self.launchpad.bugs[crash_id]
        if self.arch_tag in bug.tags:
            x = bug.tags[:]  # LP#254901 workaround
            x.remove(self.arch_tag)
            bug.tags = x
            try:
                bug.lp_save()
            except HTTPError:
                pass  # LP#336866 workaround

    def mark_retrace_failed(self, crash_id, invalid_msg=None):
        """Mark crash id as 'failed to retrace'."""
        bug = self.launchpad.bugs[crash_id]
        if invalid_msg:
            try:
                task = self._get_distro_tasks(bug.bug_tasks)
                task = next(task)
            except StopIteration:
                # no distro task, just use the first one
                task = bug.bug_tasks[0]
            task.status = "Invalid"
            task.lp_save()
            bug.newMessage(
                content=invalid_msg, subject="Crash report cannot be processed"
            )

            for a in bug.attachments:
                if a.title == "CoreDump.gz":
                    try:
                        a.removeFromBug()
                    except HTTPError:
                        pass  # LP#249950 workaround
        elif "apport-failed-retrace" not in bug.tags:
            # LP#254901 workaround
            bug.tags = bug.tags + ["apport-failed-retrace"]
            bug.lp_save()

    def _mark_dup_checked(self, crash_id, report):
        """Mark crash id as checked for being a duplicate."""
        bug = self.launchpad.bugs[crash_id]

        # if we have a distro task without a package, fix it
        if "SourcePackage" in report:
            for task in bug.bug_tasks:
                if task.target.resource_type_link.endswith("#distribution"):
                    task.target = self.lp_distro.getSourcePackage(
                        name=report["SourcePackage"]
                    )
                    try:
                        task.lp_save()
                        bug = self.launchpad.bugs[crash_id]
                    except HTTPError:
                        # might fail if there is already another
                        # Ubuntu package task
                        pass
                    break

        if "need-duplicate-check" in bug.tags:
            x = bug.tags[:]  # LP#254901 workaround
            x.remove("need-duplicate-check")
            bug.tags = x
            bug.lp_save()
            if "Traceback" in report:
                for task in bug.bug_tasks:
                    if "#distribution" in task.target.resource_type_link:
                        if task.importance == "Undecided":
                            task.importance = "Medium"
                            task.lp_save()
        self._subscribe_triaging_team(bug, report)

    def known(self, report):
        """Check if the crash db already knows about the crash signature.

        Check if the report has a DuplicateSignature, crash_signature(), or
        StacktraceAddressSignature, and ask the database whether the problem is
        already known. If so, return an URL where the user can check the status
        or subscribe (if available), or just return True if the report is known
        but there is no public URL. In that case the report will not be
        uploaded (i. e. upload() will not be called).

        Return None if the report does not have any signature or the crash
        database does not support checking for duplicates on the client side.

        The default implementation uses a text file format generated by
        duplicate_db_publish() at an URL specified by the "dupdb_url" option.
        Subclasses are free to override this with a custom implementation, such
        as a real database lookup.
        """
        # we override the method here to check if the user actually has access
        # to the bug, and if the bug requests more retraces; in either case we
        # should file it.
        url = apport.crashdb.CrashDatabase.known(self, report)

        if not url:
            return url

        # record the fact that it is a duplicate, for triagers
        report["DuplicateOf"] = url

        try:
            with urllib.request.urlopen(f"{url}/+text") as f:
                line = f.readline()
                if not line.startswith(b"bug:"):
                    # presumably a 404 etc. page,
                    # which happens for private bugs
                    return True

                # check tags
                for line in f:
                    if line.startswith(b"tags:"):
                        if (
                            b"apport-failed-retrace" in line
                            or b"apport-request-retrace" in line
                        ):
                            return None
                        break

                    # stop at the first task, tags are in the first block
                    if not line.strip():
                        break
        except OSError:
            # if we are offline, or LP is down, upload will fail anyway, so we
            # can just as well avoid the upload
            return url

        return url

    def _subscribe_triaging_team(self, bug, report):
        """Subscribe the right triaging team to the bug."""
        # FIXME: this entire function is an ugly Ubuntu specific hack until LP
        # gets a real crash db; see https://wiki.ubuntu.com/CrashReporting

        if "DistroRelease" in report and report["DistroRelease"].split()[0] != "Ubuntu":
            return  # only Ubuntu bugs are filed private

        # use a url hack here, it is faster
        # pylint: disable=protected-access
        team = self.options.get("triaging_team", "ubuntu-crashes-universe")
        person = f"{self.launchpad._root_uri}~{team}"
        if not person.replace(str(self.launchpad._root_uri), "").strip("~") in [
            str(sub).split("/", maxsplit=1)[-1] for sub in bug.subscriptions
        ]:
            bug.subscribe(person=person)

    def _generate_upload_blob(self, report):
        """Generate a multipart/MIME temporary file for uploading.

        You have to close the returned file object after you are done with it.
        """
        # set reprocessing tags
        hdr = {"Tags": f"apport-{report['ProblemType'].lower()}"}
        a = report.get("PackageArchitecture")
        if not a or a == "all":
            a = report.get("Architecture")
        if a:
            hdr["Tags"] += f" {a}"
        if "Tags" in report:
            hdr["Tags"] += f" {self._filter_tag_names(report['Tags'])}"

        # privacy/retracing for distro reports
        # FIXME: ugly hack until LP has a real crash db
        if "DistroRelease" in report:
            if a and (
                "VmCore" in report
                or "CoreDump" in report
                or "LaunchpadPrivate" in report
            ):
                hdr["Private"] = "yes"
                hdr["Subscribers"] = report.get(
                    "LaunchpadSubscribe",
                    self.options.get("initial_subscriber", "apport"),
                )
                hdr["Tags"] += f" need-{a}-retrace"
            elif "Traceback" in report:
                hdr["Private"] = "yes"
                hdr["Subscribers"] = "apport"
                hdr["Tags"] += " need-duplicate-check"
        if "DuplicateSignature" in report and "need-duplicate-check" not in hdr["Tags"]:
            hdr["Tags"] += " need-duplicate-check"

        # if we have checkbox submission key, link it to the bug; keep text
        # reference until the link is shown in Launchpad's UI
        if "CheckboxSubmission" in report:
            hdr["HWDB-Submission"] = report["CheckboxSubmission"]

        # order in which keys should appear in the temporary file
        order = [
            "ProblemType",
            "DistroRelease",
            "Package",
            "Regression",
            "Reproducible",
            "TestedUpstream",
            "ProcVersionSignature",
            "Uname",
            "NonfreeKernelModules",
        ]

        # write MIME/Multipart version into temporary file
        # temporary file is returned, pylint: disable=consider-using-with
        mime = tempfile.TemporaryFile()
        report.write_mime(
            mime,
            extra_headers=hdr,
            skip_keys=["Tags", "LaunchpadPrivate", "LaunchpadSubscribe"],
            priority_fields=order,
        )
        mime.flush()
        mime.seek(0)

        return mime

    @staticmethod
    def _filter_tag_names(tags):
        """Replace characters from tags which are not palatable to
        Launchpad."""
        res = ""
        for ch in tags.lower().encode("ASCII", errors="ignore"):
            if ch in b"abcdefghijklmnopqrstuvwxyz0123456789 " or (
                len(res) > 0 and ch in b"+-."
            ):
                res += chr(ch)
            else:
                res += "."

        return res


#
# Launchpad storeblob API (should go into launchpadlib, see LP #315358)
#

_https_upload_callback = None


#
# This progress code is based on KodakLoader by Jason Hildebrand
# <jason@opensky.ca>. See http://www.opensky.ca/~jdhildeb/software/kodakloader/
# for details.
class HTTPSProgressConnection(http.client.HTTPSConnection):
    """Implement a HTTPSConnection with an optional callback function for
    upload progress."""

    def send(self, data):
        # if callback has not been set, call the old method
        if not _https_upload_callback:
            http.client.HTTPSConnection.send(self, data)
            return

        sent = 0
        total = len(data)
        chunksize = 1024
        while sent < total:
            _https_upload_callback(sent, total)
            t1 = time.time()
            http.client.HTTPSConnection.send(self, data[sent : (sent + chunksize)])
            sent += chunksize
            t2 = time.time()

            # adjust chunksize so that it takes between .5 and 2
            # seconds to send a chunk
            if chunksize > 1024:
                if t2 - t1 < 0.5:
                    chunksize <<= 1
                elif t2 - t1 > 2:
                    chunksize >>= 1


class HTTPSProgressHandler(urllib.request.HTTPSHandler):
    """Implement a HTTPSHandler with an optional callback function for
    upload progress."""

    def https_open(self, req):
        return self.do_open(HTTPSProgressConnection, req)


def upload_blob(blob, progress_callback=None, hostname="launchpad.net"):
    """Upload blob (file-like object) to Launchpad.

    progress_callback can be set to a function(sent, total) which is regularly
    called with the number of bytes already sent and total number of bytes to
    send. It is called every 0.5 to 2 seconds (dynamically adapted to upload
    bandwidth).

    Return None on error, or the ticket number on success.

    By default this uses the production Launchpad hostname. Set
    hostname to 'launchpad.dev', 'qastaging.launchpad.net', or
    'staging.launchpad.net' to use another instance for testing.
    """
    ticket = None
    url = f"https://{hostname}/+storeblob"

    global _https_upload_callback  # pylint: disable=global-statement
    _https_upload_callback = progress_callback

    # build the form-data multipart/MIME request
    data = email.mime.multipart.MIMEMultipart()

    submit = email.mime.text.MIMEText("1")
    submit.add_header("Content-Disposition", 'form-data; name="FORM_SUBMIT"')
    data.attach(submit)

    form_blob = email.mime.base.MIMEBase("application", "octet-stream")
    form_blob.add_header(
        "Content-Disposition", 'form-data; name="field.blob"; filename="x"'
    )
    form_blob.set_payload(blob.read().decode("ascii"))
    data.attach(form_blob)

    data_flat = io.BytesIO()
    gen = email.generator.BytesGenerator(data_flat, mangle_from_=False)
    gen.flatten(data)

    # do the request; we need to explicitly set the content type here, as it
    # defaults to x-www-form-urlencoded
    req = urllib.request.Request(url, data_flat.getvalue())
    req.add_header(
        "Content-Type", f"multipart/form-data; boundary={data.get_boundary()}"
    )
    opener = urllib.request.build_opener(HTTPSProgressHandler)
    result = opener.open(req)
    ticket = result.info().get("X-Launchpad-Blob-Token")

    assert ticket
    return ticket
