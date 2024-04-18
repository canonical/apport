"""Abstract Apport user interface.

This encapsulates the workflow and common code for any user interface
implementation (like GTK, Qt, or CLI).
"""

# Copyright (C) 2007 - 2011 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

# pylint: disable=too-many-lines
# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import argparse
import ast
import configparser
import dataclasses
import errno
import gettext
import glob
import gzip
import io
import locale
import os.path
import pwd
import queue
import re
import shutil
import signal
import smtplib
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import webbrowser
import zlib
from collections.abc import Sequence
from gettext import gettext as _
from typing import Any

import apport.crashdb
import apport.fileutils
import apport.logging
import apport.REThread
from apport.packaging_impl import impl as packaging
from apport.user_group import get_process_user_and_group

__version__ = "2.28.1"


symptom_script_dir = os.environ.get("APPORT_SYMPTOMS_DIR", "/usr/share/apport/symptoms")
PF_KTHREAD = 0x200000


def get_pid(report):
    """Extract process ID from report."""
    try:
        pid = re.search("Pid:\t(.*)\n", report.get("ProcStatus", "")).group(1)
        return int(pid)
    except (IndexError, AttributeError):
        return None


def _get_env_int(key: str, default: int | None = None) -> int | None:
    """Get an environment variable as integer.

    Return None if it doesn't exist or failed to convert to integer.
    The optional second argument can specify an alternate default.
    """
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default


def _get_newest_process_for_user(name: str, uid: int) -> int | None:
    process = subprocess.run(
        ["pgrep", "-n", "-x", "-u", str(uid), name],
        capture_output=True,
        check=False,
        text=True,
    )
    if process.returncode != 0 or not process.stdout:
        return None
    return int(process.stdout.strip())


def _get_users_environ(uid: int) -> dict[str, str]:
    """Find D-BUS address and XDG_DATA_DIRS for the given user.

    The D-BUS address and XDG_DATA_DIRS is needed for xdg-open. It is
    incredibly hard, or alternatively, unsafe to funnel it through
    pkexec/env/sudo, so grab it from gvfsd.
    """
    gvfsd_pid = _get_newest_process_for_user("gvfsd", uid)
    if gvfsd_pid is None:
        return {}

    gvfsd_pid_fd = os.open(
        f"/proc/{gvfsd_pid}", os.O_RDONLY | os.O_PATH | os.O_DIRECTORY
    )
    try:
        gvfsd_env = apport.fileutils.get_process_environ(gvfsd_pid_fd)
    except OSError:
        return {}
    finally:
        os.close(gvfsd_pid_fd)

    return {
        key: gvfsd_env[key]
        for key in ("DBUS_SESSION_BUS_ADDRESS", "XDG_DATA_DIRS")
        if key in gvfsd_env
    }


def run_as_real_user(
    args: list[str], *, get_user_env: bool = False, **kwargs: Any
) -> None:
    """Call subprocess.run as real user if called via sudo/pkexec.

    If we are called through pkexec/sudo, determine the real user ID and
    run the command with it to get the user's web browser settings.
    If get_user_env is set to True, the D-BUS address and XDG_DATA_DIRS
    is grabbed from a running gvfsd and added to the process environment.
    """
    uid = _get_env_int("SUDO_UID", _get_env_int("PKEXEC_UID"))
    if uid is None or not get_process_user_and_group().is_root():
        subprocess.run(args, check=False, **kwargs)
        return

    pwuid = pwd.getpwuid(uid)

    gid = _get_env_int("SUDO_GID")
    if gid is None:
        gid = pwuid.pw_gid

    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("SUDO_") and k != "PKEXEC_UID"
    }
    if get_user_env:
        env |= _get_users_environ(uid)
    env["HOME"] = pwuid.pw_dir
    # mypy on Ubuntu 22.04 and 22.10 does not know user and groups
    subprocess.run(
        args,
        check=False,
        env=env,
        user=uid,  # type: ignore
        group=gid,
        extra_groups=os.getgrouplist(pwuid.pw_name, gid),
        **kwargs,
    )


def still_running(pid):
    """Check if the process with the given ID is still running."""
    try:
        os.kill(int(pid), 0)
    except OSError as error:
        if error.errno == errno.ESRCH:
            return False
    return True


def thread_collect_info(
    report, reportfile, package, ui, symptom_script=None, ignore_uninstalled=False
):
    # TODO: Split into smaller functions/methods
    # pylint: disable=too-many-branches,too-many-statements
    """Collect information about report.

    Encapsulate calls to add_*_info() and update given report, so that this
    function is suitable for threading.

    ui must be a HookUI instance, it gets passed to add_hooks_info().

    If reportfile is not None, the file is written back with the new data.

    If symptom_script is given, it will be run first (for run_symptom()).
    """
    assert isinstance(ui, HookUI)
    try:
        report.add_gdb_info()
    except OSError:
        # it's okay if gdb is not installed on the client side; we'll get stack
        # traces on retracing.
        pass
    report.add_os_info()

    if symptom_script:
        symb = {}
        try:
            with open(symptom_script, encoding="utf-8") as f:
                # legacy, pylint: disable=exec-used
                exec(compile(f.read(), symptom_script, "exec"), symb)
            package = symb["run"](report, ui)
            if not package:
                apport.logging.error(
                    "symptom script %s did not determine the affected package",
                    symptom_script,
                )
                return
            report["Symptom"] = os.path.splitext(os.path.basename(symptom_script))[0]
        except StopIteration:
            sys.exit(0)
        except Exception:  # pylint: disable=broad-except
            apport.logging.error("symptom script %s crashed:", symptom_script)
            traceback.print_exc()
            sys.exit(0)

    if not package:
        if "ExecutablePath" in report:
            package = apport.fileutils.find_file_package(report["ExecutablePath"])
        else:
            raise KeyError(
                "called without a package, and report does not have ExecutablePath"
            )

    # check if the package name relates to an installed snap
    snap = apport.fileutils.find_snap(package)
    if snap:
        report.add_snap_info(snap)

    try:
        report.add_package_info(package)
    except ValueError:
        # this happens if we are collecting information on an uninstalled
        # package

        # we found no package, but a snap, so lets continue
        if not ignore_uninstalled and "Snap" not in report:
            raise
    except SystemError as error:
        report["UnreportableReason"] = str(error)

    if "UnreportableReason" not in report:
        if report.add_hooks_info(ui):
            sys.exit(0)

        # check package origin; we do that after adding hooks, so that hooks
        # have the chance to set a third-party CrashDB.
        try:
            if (
                "CrashDB" not in report
                and "APPORT_DISABLE_DISTRO_CHECK" not in os.environ
            ):
                if "Package" not in report and "Snap" not in report:
                    report["UnreportableReason"] = _(
                        "This package does not seem to be installed correctly"
                    )
                elif not packaging.is_distro_package(
                    report["Package"].split()[0]
                ) and not packaging.is_native_origin_package(
                    report["Package"].split()[0]
                ):
                    # TRANS: %s is the name of the operating system
                    report["UnreportableReason"] = (
                        _(
                            "This does not seem to be an official %s package."
                            " Please retry after updating the indexes of"
                            " available packages, if that does not work"
                            " then remove related third party packages"
                            " and try again."
                        )
                        % report["DistroRelease"].split()[0]
                    )
        except ValueError:
            # this happens if we are collecting information on an uninstalled
            # package

            # we found no package, but a snap, so lets continue
            if not ignore_uninstalled and "Snap" not in report:
                raise

    # add title
    if "Title" not in report:
        title = report.standard_title()
        if title:
            report["Title"] = title

    # check obsolete packages
    if (
        report.get("ProblemType") == "Crash"
        and "APPORT_IGNORE_OBSOLETE_PACKAGES" not in os.environ
    ):
        old_pkgs = report.obsolete_packages()
        if old_pkgs:
            report["UnreportableReason"] = _(
                "You have some obsolete package versions installed."
                " Please upgrade the following packages"
                " and check if the problem still occurs:\n\n%s"
            ) % ", ".join(old_pkgs)

    if reportfile:
        try:
            with open(reportfile, "ab") as f:
                os.chmod(reportfile, 0)
                report.write(f, only_new=True)
        except OSError as error:
            # this should happen very rarely; presumably a new crash report is
            # being generated by a background apport instance (which will set
            # the file to permissions zero while writing), while the first
            # report is being processed
            apport.logging.error("Cannot update %s: %s", reportfile, error)

        apport.fileutils.mark_report_seen(reportfile)
        os.chmod(reportfile, 0o640)


@dataclasses.dataclass
class Action:
    """Action to take on a problem report.

    Possible actions: examine the crash ('examine'), report the crash
    ('report'), restart the crashed application ('restart'), or ignore further
    crashes ('ignore').
    """

    examine: bool = False
    ignore: bool = False
    remember: bool = False
    report: bool = False
    restart: bool = False


class UserInterface:
    # TODO: Check if some methods can be made private
    # pylint: disable=too-many-public-methods
    """Apport user interface API.

    This provides an abstract base class for encapsulating the workflow and
    common code for any user interface implementation (like GTK, Qt, or CLI).

    A concrete subclass must implement all the abstract ui_* methods.
    """

    def __init__(self, argv: list[str]):
        """Initialize program state and parse command line options."""
        self.gettext_domain = "apport"
        self.report: apport.report.Report | None = None
        self.report_file: str | None = None
        self.cur_package = None
        self.offer_restart = False
        self.specified_a_pkg = False
        self.upload_progress = None

        try:
            self.crashdb = apport.crashdb.get_crashdb(None)
        except ImportError as error:
            # this can happen while upgrading python packages
            apport.logging.fatal(
                "Could not import module, is a package upgrade in progress?"
                " Error: %s",
                str(error),
            )
        except KeyError:
            apport.logging.fatal(
                "/etc/apport/crashdb.conf is damaged: No default database"
            )

        gettext.textdomain(self.gettext_domain)
        self.args = self.parse_argv(argv)

    #
    # main entry points
    #

    def run_crashes(self):
        """Present all currently pending crash reports.

        Ask the user what to do about them, and offer to file bugs for them.

        Crashes that occurred in a different desktop (logind) session than the
        one that is currently running are not processed. This skips crashes
        that happened during logout, which are uninteresting and confusing to
        see at the next login.

        Return True if at least one crash report was processed, False
        otherwise.
        """
        result = False
        # for iterating over /var/crash (as opposed to running on or clicking
        # on a particular .crash file) we offer restarting
        self.offer_restart = True

        if os.geteuid() == 0:
            reports = apport.fileutils.get_new_system_reports()
        else:
            reports = apport.fileutils.get_new_reports()

        for f in reports:
            if not self.load_report(f):
                continue
            assert self.report

            if self.report["ProblemType"] == "Hang":
                self.finish_hang(f)
            else:
                self.run_crash(f)
            result = True

        return result

    def run_crash(self, report_file):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-return-statements
        # pylint: disable=too-many-statements
        """Present and report a particular crash.

        If confirm is True, ask the user what to do about it, and offer to file
        a bug for it.

        If confirm is False, the user will not be asked, and the crash is
        reported right away.
        """
        self.report_file = report_file

        try:
            try:
                apport.fileutils.mark_report_seen(report_file)
            except OSError:
                # not there any more? no problem, then it won't be regarded as
                # "seen" any more anyway
                pass
            if not self.report and not self.load_report(report_file):
                return
            assert self.report

            if "Ignore" in self.report:
                return

            # check for absent CoreDumps (removed if they exceed size limit)
            if (
                self.report.get("ProblemType") == "Crash"
                and "Signal" in self.report
                and "CoreDump" not in self.report
                and "Stacktrace" not in self.report
            ):
                subject = os.path.basename(
                    self.report.get("ExecutablePath", _("unknown program"))
                )
                heading = _('Sorry, the program "%s" closed unexpectedly') % subject
                footer = _(
                    "Your computer does not have enough free "
                    "memory to automatically analyze the problem "
                    "and send a report to the developers."
                )
                self.ui_error_message(
                    _("Problem in %s") % subject, f"{heading}\n\n{footer}"
                )
                return

            allowed_to_report = apport.fileutils.allowed_to_report()
            response = self.ui_present_report_details(allowed_to_report)
            if response.report or response.examine:
                if "_MarkForUpload" not in self.report:
                    self.collect_info()

            if self.report is None:
                # collect() does that on invalid reports
                return

            if response.examine:
                self.examine()
                return
            if response.restart:
                self.restart()
            if response.ignore:
                self.report.mark_ignore()
            try:
                if response.remember:
                    self.remember_send_report(response.report)
            # use try/expect for python2 support. Old reports (generated
            # pre-apport 2.20.10-0ubuntu4) may not have the remember key
            # and can be loaded afterwards (or after dist-upgrade)
            except KeyError:
                pass
            if not response.report:
                return

            # We don't want to send crashes to the crash database for binaries
            # that changed since the crash happened. See LP: #1039220 for
            # details.
            if (
                "_MarkForUpload" in self.report
                and self.report["_MarkForUpload"] != "False"
            ):
                apport.fileutils.mark_report_upload(report_file)
            # We check for duplicates and unreportable crashes here, rather
            # than before we show the dialog, as we want to submit these to the
            # crash database, but not Launchpad.
            if self.crashdb.accepts(self.report):
                # FIXME: This behaviour is not really correct, but necessary as
                # long as we only support a single crashdb and have whoopsie
                # hardcoded. Once we have multiple crash dbs, we need to check
                # accepts() earlier, and not even present the data if none of
                # the DBs wants the report. See LP#957177 for details.
                if self.handle_duplicate():
                    return
                if self.check_unreportable():
                    return
                self.file_report()
        except PermissionError:
            self.ui_error_message(
                _("Invalid problem report"),
                _("You are not allowed to access this problem report."),
            )
            sys.exit(1)
        except OSError as error:
            if error.errno == errno.ENOMEM:
                apport.logging.fatal("Out of memory, aborting")
            elif error.errno == errno.ENOSPC:
                self.ui_error_message(
                    _("Error"),
                    _(
                        "There is not enough disk space"
                        " available to process this report."
                    ),
                )
                sys.exit(1)
            elif error.errno == errno.EIO:
                self.ui_error_message(_("Invalid problem report"), error.strerror)
                sys.exit(1)
            raise

    @staticmethod
    def finish_hang(f):
        """Finish processing a hanging application after the core pipe handler
        has handed the report back.

        This will signal to whoopsie that the report needs to be uploaded.
        """
        apport.fileutils.mark_report_upload(f)
        apport.fileutils.mark_report_seen(f)

    def run_hang(self, pid):
        """Report an application hanging.

        This will first present a dialog containing the information it can
        collect from the running application (everything but the trace) with
        the option of terminating or restarting the application, optionally
        reporting that this error occurred.

        A SIGABRT will then be sent to the process and a series of
        noninteractive processes will collect the remaining information and
        mark the report for uploading.
        """
        self.report = apport.Report("Hang")

        if not self.args.pid:
            self.ui_error_message(
                _("No PID specified"),
                _("You need to specify a PID. See --help for more information."),
            )
            return False

        try:
            self.report.add_proc_info(pid)
        except ValueError as error:
            if str(error) == "invalid process":
                self.ui_error_message(
                    _("Invalid PID"), _("The specified process ID does not exist.")
                )
                sys.exit(1)
            elif str(error) == "not accessible":
                self.ui_error_message(
                    _("Not your PID"),
                    _("The specified process ID does not belong to you."),
                )
                sys.exit(1)
        self.report.add_package_info()
        path = self.report.get("ExecutablePath", "")
        self.cur_package = apport.fileutils.find_file_package(path)
        self.report.add_os_info()
        allowed_to_report = apport.fileutils.allowed_to_report()
        response = self.ui_present_report_details(allowed_to_report, modal_for=int(pid))
        if response.report:
            apport.fileutils.mark_hanging_process(self.report, pid)
            os.kill(int(pid), signal.SIGABRT)
        else:
            os.kill(int(pid), signal.SIGKILL)

        if response.restart:
            self.wait_for_pid(pid)
            self.restart()
        return True

    @staticmethod
    def wait_for_pid(pid):
        """waitpid() does not work for non-child processes. Query the process
        state in a loop, waiting for "no such process."
        """
        while True:
            try:
                os.kill(int(pid), 0)
            except OSError as error:
                if error.errno == errno.ESRCH:
                    break
                raise
            time.sleep(1)

    @staticmethod
    def kill_segv(pid):
        """Kill process with signal SIGSEGV."""
        os.kill(int(pid), signal.SIGSEGV)

    def run_report_bug(self, symptom_script: str | None = None) -> bool:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-return-statements
        # pylint: disable=too-many-statements
        """Report a bug.

        If a pid is given on the command line, the report will contain runtime
        debug information. Either a package or a pid must be specified; if none
        is given, show a list of symptoms.

        If a symptom script is given, this will be run first (used by
        run_symptom()).
        """
        if not self.args.package and not self.args.pid and not symptom_script:
            if self.run_symptoms():
                return True

            self.ui_error_message(
                _("No package specified"),
                _(
                    "You need to specify a package or a PID."
                    " See --help for more information."
                ),
            )
            return False

        self.report = apport.Report("Bug")

        # if PID is given, add info
        if self.args.pid:
            try:
                proc_pid_fd = os.open(
                    f"/proc/{self.args.pid}", os.O_RDONLY | os.O_PATH | os.O_DIRECTORY
                )
                stat_file = os.open("stat", os.O_RDONLY, dir_fd=proc_pid_fd)
                with io.open(stat_file, encoding="utf-8") as f:
                    stat = f.read().split()
                flags = int(stat[8])
                if flags & PF_KTHREAD:
                    # this PID is a kernel thread
                    self.args.package = "linux"
                else:
                    self.report.add_proc_info(
                        pid=self.args.pid, proc_pid_fd=proc_pid_fd
                    )
            except PermissionError:
                self.ui_error_message(
                    _("Permission denied"),
                    _(
                        "The specified process does not belong to you. Please"
                        " run this program as the process owner or as root."
                    ),
                )
                return False
            except (ValueError, OSError) as error:
                if getattr(error, "errno", None) == errno.ENOENT:
                    # silently ignore nonexisting PIDs; the user must not
                    # close the application prematurely
                    return False
                self.ui_error_message(
                    _("Invalid PID"),
                    _("The specified process ID does not belong to a program."),
                )
                return False
        else:
            self.report.add_proc_environ()

        if self.args.package:
            self.args.package = self.args.package.strip()
        # "Do what I mean" for filing against "linux"
        if self.args.package == "linux":
            self.cur_package = packaging.get_kernel_package()
        else:
            self.cur_package = self.args.package

        try:
            self.collect_info(symptom_script)
        except ValueError as error:
            if "package" in str(error) and "does not exist" in str(error):
                if not self.cur_package:
                    self.ui_error_message(
                        _("Invalid problem report"),
                        _("Symptom script %s did not determine an affected package")
                        % symptom_script,
                    )
                else:
                    self.ui_error_message(
                        _("Invalid problem report"),
                        _("Package %s does not exist") % self.cur_package,
                    )
                return False
            raise

        if self.check_unreportable():
            return False

        self.add_extra_tags()

        if self.handle_duplicate():
            return True

        # not useful for bug reports, and has potentially sensitive information
        try:
            del self.report["ProcCmdline"]
        except KeyError:
            pass

        if self.args.save:
            try:
                savefile = os.path.expanduser(self.args.save)
                if savefile.endswith(".gz"):
                    with gzip.open(savefile, "wb") as f:
                        self.report.write(f)
                else:
                    with open(os.path.expanduser(self.args.save), "wb") as f:
                        self.report.write(f)
            except OSError as error:
                self.ui_error_message(_("Cannot create report"), str(error))
        else:
            # show what's being sent
            allowed_to_report = True
            response = self.ui_present_report_details(allowed_to_report)
            if response.report:
                self.file_report()

        return True

    def run_update_report(self) -> bool:
        """Update an existing bug with locally collected information."""
        # avoid irrelevant noise
        if not self.crashdb.can_update(self.args.update_report):
            self.ui_error_message(
                _("Updating problem report"),
                _(
                    "You are not the reporter or subscriber of this "
                    "problem report, or the report is a duplicate or already "
                    'closed.\n\nPlease create a new report using "apport-bug".'
                ),
            )
            return False

        is_reporter = self.crashdb.is_reporter(self.args.update_report)

        if not is_reporter:
            r = self.ui_question_yesno(
                _(
                    "You are not the reporter of this problem report. It is "
                    "much easier to mark a bug as a duplicate of another than "
                    "to move your comments and attachments to a new bug.\n\n"
                    "Subsequently, we recommend that you file a new bug "
                    'report using "apport-bug" and make a comment in this bug '
                    "about the one you file.\n\nDo you really want to proceed?"
                )
            )
            if not r:
                return False

        # list of affected source packages
        self.report = apport.Report("Bug")
        if self.args.package:
            pkgs = [self.args.package.strip()]
        else:
            pkgs = self.crashdb.get_affected_packages(self.args.update_report)

        info_collected = False
        for p in pkgs:
            # print(f"Collecting apport information for source package {p}...")
            self.cur_package = p
            self.report["SourcePackage"] = p
            self.report["Package"] = p  # no way to find this out

            # we either must have the package installed or a source package
            # hook available to collect sensible information
            try:
                packaging.get_version(p)
            except ValueError:
                if not os.path.exists(
                    os.path.join(apport.report.PACKAGE_HOOK_DIR, f"source_{p}.py")
                ):
                    print(f"Package {p} not installed and no hook available, ignoring")
                    continue
            self.collect_info(ignore_uninstalled=True)
            info_collected = True

        if not info_collected:
            self.ui_info_message(
                _("Updating problem report"), _("No additional information collected.")
            )
            return False

        self.report.add_user_info()
        self.report.add_proc_environ()
        self.add_extra_tags()

        # delete the uninteresting keys
        del self.report["Date"]
        try:
            del self.report["SourcePackage"]
        except KeyError:
            pass

        if len(self.report) == 0:
            self.ui_info_message(
                _("Updating problem report"), _("No additional information collected.")
            )
            return False

        # show what's being sent
        allowed_to_report = True
        response = self.ui_present_report_details(allowed_to_report)
        if response.report:
            self.crashdb.update(
                self.args.update_report,
                self.report,
                "apport information",
                change_description=is_reporter,
                attachment_comment="apport information",
            )
            return True

        return False

    def run_symptoms(self):
        """Report a bug from a list of available symptoms.

        Return False if no symptoms are available.
        """
        scripts = glob.glob(os.path.join(symptom_script_dir, "*.py"))

        # symptoms contains a list of (symptom_description, symptom_name)
        symptoms = []
        for script in scripts:
            # scripts with an underscore can be used for private libraries
            if os.path.basename(script).startswith("_"):
                continue
            symb = {}
            try:
                with open(script, encoding="utf-8") as f:
                    # legacy, pylint: disable=exec-used
                    exec(compile(f.read(), script, "exec"), symb)
            except Exception:  # pylint: disable=broad-except
                apport.logging.error("symptom script %s is invalid", script)
                traceback.print_exc()
                continue
            if "run" not in symb:
                apport.logging.error(
                    "symptom script %s does not define run() function", script
                )
                continue
            symptom_name = os.path.splitext(os.path.basename(script))[0]
            symptoms.append((symb.get("description", symptom_name), symptom_name))

        if not symptoms:
            return False

        symptoms.sort()
        symptoms.append(("Other problem", None))

        ch = self.ui_question_choice(
            _("What kind of problem do you want to report?"),
            [description for description, name in symptoms],
            False,
        )

        if ch is not None:
            symptom = symptoms[ch[0]][1]
            if symptom:
                self.run_report_bug(os.path.join(symptom_script_dir, symptom + ".py"))
            else:
                return False

        return True

    def run_symptom(self):
        """Report a bug with a symptom script."""
        script = os.path.join(symptom_script_dir, self.args.symptom + ".py")
        if not os.path.exists(script):
            self.ui_error_message(
                _("Unknown symptom"),
                _('The symptom "%s" is not known.') % self.args.symptom,
            )
            return

        self.run_report_bug(script)

    def run_argv(self):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-return-statements
        """Call appropriate run_* method according to command line arguments.

        Return True if at least one report has been processed, and False
        otherwise.
        """
        if self.args.symptom:
            self.run_symptom()
            return True
        if self.args.hanging:
            self.run_hang(self.args.pid)
            return True
        if self.args.filebug:
            return self.run_report_bug()
        if self.args.update_report is not None:
            return self.run_update_report()
        if self.args.version:
            print(__version__)
            return True
        if self.args.crash_file:
            try:
                self.run_crash(self.args.crash_file)
            except OSError as error:
                self.ui_error_message(_("Invalid problem report"), str(error))
            return True
        if self.args.window:
            if os.getenv("XDG_SESSION_TYPE") == "wayland":
                self.ui_error_message(
                    _("Cannot create report"),
                    _(
                        "The window option cannot be used on "
                        "Wayland.\n\nPlease find the window's "
                        "process ID and then run 'ubuntu-bug "
                        "<process ID>'."
                        "\n\nThe process ID can be found "
                        "by running the System Monitor application. "
                        "In the Processes tab, scroll until you "
                        "find the correct application. The process "
                        "ID is the number listed in the ID column."
                    ),
                )
                return True

            self.ui_info_message(
                "",
                _(
                    "After closing this message please click on an"
                    " application window to report a problem about it."
                ),
            )
            xprop = subprocess.run(
                ["xprop", "_NET_WM_PID"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if xprop.returncode == 0:
                try:
                    self.args.pid = int(xprop.stdout.split()[-1])
                except ValueError:
                    self.ui_error_message(
                        _("Cannot create report"),
                        _("xprop failed to determine process ID of the window"),
                    )
                    return True
                return self.run_report_bug()

            self.ui_error_message(
                _("Cannot create report"),
                _("xprop failed to determine process ID of the window")
                + "\n\n"
                + xprop.stderr.decode(),
            )
            return True

        return self.run_crashes()

    #
    # methods that implement workflow bits
    #

    @staticmethod
    def parse_argv_update(argv: Sequence[str]) -> argparse.Namespace:
        """Parse command line options when being invoked in update mode."""
        parser = argparse.ArgumentParser(usage=_("%(prog)s <report number>"))
        parser.add_argument("-p", "--package", help=_("Specify package name."))
        parser.add_argument(
            "--tag",
            action="append",
            default=[],
            dest="tags",
            help=_("Add an extra tag to the report. Can be specified multiple times."),
        )
        parser.add_argument("update_report", metavar="report_number", type=int)
        args = parser.parse_args(argv[1:])

        args.symptom = None
        args.filebug = False
        args.crash_file = None
        args.version = False
        args.hanging = False
        return args

    def parse_argv(self, argv: list[str]) -> argparse.Namespace:
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-statements
        """Parse command line options.

        If a single argument is given without any options, this tries to "do
        what I mean".
        """
        # invoked in update mode?
        if len(argv) > 0:
            if "APPORT_INVOKED_AS" in os.environ:
                argv[0] = os.path.join(
                    os.path.dirname(argv[0]),
                    os.path.basename(os.environ["APPORT_INVOKED_AS"]),
                )
            cmd = argv[0]
            if cmd.endswith("-update-bug") or cmd.endswith("-collect"):
                return self.parse_argv_update(argv)

        if len(argv) > 0 and cmd.endswith("-bug"):
            suppress = argparse.SUPPRESS
        else:
            suppress = None

        parser = argparse.ArgumentParser(
            usage=_(
                "%(prog)s [options]"
                " [symptom|pid|package|program path|.apport/.crash file]"
            )
        )
        parser.add_argument(
            "-f",
            "--file-bug",
            action="store_true",
            dest="filebug",
            help=suppress
            or _(
                "Start in bug filing mode. Requires --package and an optional"
                " --pid, or just a --pid. If neither is given, display a list"
                " of known symptoms. (Implied if a single argument is given.)"
            ),
        )
        parser.add_argument(
            "-w",
            "--window",
            action="store_true",
            help=_("Click a window as a target for filing a problem report."),
        )
        parser.add_argument(
            "-u",
            "--update-bug",
            type=int,
            dest="update_report",
            help=suppress
            or _("Start in bug updating mode. Can take an optional --package."),
        )
        parser.add_argument(
            "-s",
            "--symptom",
            metavar="SYMPTOM",
            help=suppress
            or _(
                "File a bug report about a symptom. (Implied if symptom name"
                " is given as only argument.)"
            ),
        )
        parser.add_argument(
            "-p",
            "--package",
            help=suppress
            or _(
                "Specify package name in --file-bug mode. This is optional"
                " if a --pid is specified. (Implied if package name"
                " is given as only argument.)"
            ),
        )
        parser.add_argument(
            "-P",
            "--pid",
            type=int,
            help=suppress
            or _(
                "Specify a running program in --file-bug mode. If this is"
                " specified, the bug report will contain more information."
                "  (Implied if pid is given as only argument.)"
            ),
        )
        parser.add_argument(
            "--hanging",
            action="store_true",
            help=_("The provided pid is a hanging application."),
        )
        parser.add_argument(
            "-c",
            "--crash-file",
            metavar="PATH",
            help=suppress
            or _(
                "Report the crash from given .apport or .crash file"
                " instead of the pending ones in %s."
                " (Implied if file is given as only argument.)"
            )
            % apport.fileutils.report_dir,
        )
        parser.add_argument(
            "--save",
            metavar="PATH",
            help=_(
                "In bug filing mode, save the collected information into"
                " a file instead of reporting it. This file can then be"
                " reported later on from a different machine."
            ),
        )
        parser.add_argument(
            "--tag",
            action="append",
            default=[],
            dest="tags",
            help=_("Add an extra tag to the report. Can be specified multiple times."),
        )
        parser.add_argument(
            "-v",
            "--version",
            action="store_true",
            help=_("Print the Apport version number."),
        )
        parser.add_argument("issue", nargs="?", help=argparse.SUPPRESS)

        args = parser.parse_args(argv[1:])
        issue = args.issue
        del args.issue

        # mutually exclusive arguments
        if args.update_report:
            args_only_for_new_reports = [
                args.filebug,
                args.window,
                args.symptom,
                args.pid,
                args.crash_file,
                args.save,
            ]
            if any(args_only_for_new_reports):
                parser.error(
                    "-u/--update-bug option cannot be used together"
                    " with options for a new report"
                )

        # no argument: default to "show pending crashes" except when called in
        # bug mode
        # NOTE: uses argv, since args if empty for all the options,
        # e.g. "-v" or "-u $BUG"
        if len(argv) == 1 and cmd.endswith("-bug"):
            args.filebug = True
            return args

        # one argument: guess "file bug" mode by argument type
        if issue is None:
            return args

        # symptom?
        if os.path.exists(os.path.join(symptom_script_dir, issue + ".py")):
            args.filebug = True
            args.symptom = issue

        # .crash/.apport file?
        elif issue.endswith(".crash") or issue.endswith(".apport"):
            args.crash_file = issue

        # PID?
        elif issue.isdigit():
            args.filebug = True
            args.pid = issue

        # executable?
        elif "/" in issue:
            if issue.startswith("/snap/bin"):
                # see if the snap has the same name as the executable
                snap = apport.fileutils.find_snap(issue.split("/")[-1])
                if not snap:
                    parser.error(
                        f"{issue} is provided by a snap. No contact address"
                        f" has been provided; visit the forum at"
                        f" https://forum.snapcraft.io/ for help."
                    )
                elif snap.get("contact", ""):
                    parser.error(
                        f"{issue} is provided by a snap published by"
                        f" {snap['developer']}. Contact them"
                        f" via {snap['contact']} for help."
                    )
                else:
                    parser.error(
                        f"{issue} is provided by a snap published by"
                        f" {snap['developer']}. No contact address"
                        f" has been provided; visit the forum"
                        f" at https://forum.snapcraft.io/ for help."
                    )
                sys.exit(1)
            else:
                pkg = packaging.get_file_package(issue)
                if not pkg:
                    parser.error(f"{issue} does not belong to a package.")
                    sys.exit(1)
            args.filebug = True
            args.package = pkg

        # otherwise: package name
        else:
            args.filebug = True
            self.specified_a_pkg = True
            args.package = issue

        return args

    @staticmethod
    def format_filesize(size):
        """Format the given integer as humanly readable and i18n'ed file
        size."""
        if size < 1000000:
            return locale.format_string("%.1f KB", size / 1000.0)
        if size < 1000000000:
            return locale.format_string("%.1f MB", size / 1000000.0)
        return locale.format_string("%.1f GB", size / float(1000000000))

    def get_complete_size(self):
        """Return the size of the complete report."""
        assert self.report
        # report wasn't loaded, so count manually
        size = 0
        for k in self.report:
            if self.report[k]:
                try:
                    size += self.report[k].get_on_disk_size()
                except AttributeError:
                    size += len(self.report[k])
        return size

    def get_reduced_size(self):
        """Return the size of the reduced report."""
        assert self.report
        size = 0
        for k in self.report:
            if k != "CoreDump":
                if self.report[k]:
                    try:
                        size += self.report[k].get_on_disk_size()
                    except AttributeError:
                        size += len(self.report[k])

        return size

    def can_examine_locally(self):
        """Check whether to offer the "Examine locally" button.

        This will be true if the report has a core dump, apport-retrace is
        installed and a terminal is available (see ui_has_terminal()).
        """
        if not self.report or "CoreDump" not in self.report:
            return False

        if shutil.which("apport-retrace") is None:
            return False

        return self.ui_has_terminal()

    def restart(self):
        """Reopen the crashed application."""
        assert self.report and "ProcCmdline" in self.report

        if os.fork() == 0:
            os.setsid()
            os.execlp(
                "sh",
                "sh",
                "-c",
                self.report.get("RespawnCommand", self.report["ProcCmdline"]),
            )
            sys.exit(1)

    def examine(self):
        """Locally examine crash report."""
        assert self.report_file
        response = self.ui_question_choice(
            _(
                "This will launch apport-retrace in a terminal window"
                " to examine the crash."
            ),
            [
                _("Run gdb session"),
                _("Run gdb session without downloading debug symbols"),
                # TRANSLATORS: %s contains the crash report file name
                _("Update %s with fully symbolic stack trace") % self.report_file,
            ],
            False,
        )

        if response is None:
            return

        cache_dir = os.path.expanduser("~/.cache/apport/retrace")
        retrace_with_download = f"apport-retrace -S system -C {cache_dir} -v "
        retrace_no_download = "apport-retrace "
        filearg = "'" + self.report_file.replace("'", "'\\''") + "'"

        cmds = {
            0: retrace_with_download + "--gdb " + filearg,
            1: retrace_no_download + "--gdb " + filearg,
            2: retrace_with_download + "--output " + filearg + " " + filearg,
        }

        self.ui_run_terminal(cmds[response[0]])

    def remember_send_report(self, send_report: bool) -> None:
        """Put whoopsie in auto or never mode."""
        try:
            subprocess.check_output(
                [
                    "/usr/bin/gdbus",
                    "call",
                    "-y",
                    "-d",
                    "com.ubuntu.WhoopsiePreferences",
                    "-o",
                    "/com/ubuntu/WhoopsiePreferences",
                    "-m",
                    "com.ubuntu.WhoopsiePreferences.SetReportCrashes",
                    str(send_report).lower(),
                ]
            )
            subprocess.check_output(
                [
                    "/usr/bin/gdbus",
                    "call",
                    "-y",
                    "-d",
                    "com.ubuntu.WhoopsiePreferences",
                    "-o",
                    "/com/ubuntu/WhoopsiePreferences",
                    "-m",
                    "com.ubuntu.WhoopsiePreferences.SetAutomaticallyReportCrashes",
                    "true",
                ]
            )
        except (OSError, subprocess.CalledProcessError) as error:
            msg = _(
                "Saving crash reporting state failed."
                " Can't set auto or never reporting mode."
            )
            self.ui_error_message(
                _("Can't remember send report status settings"),
                f"{msg}\n\n{str(error)}",
            )

    def check_report_crashdb(self):
        """Process reports' CrashDB field, if present."""
        if self.report is None or "CrashDB" not in self.report:
            return True

        # specification?
        if self.report["CrashDB"].lstrip().startswith("{"):
            try:
                spec = ast.literal_eval(self.report["CrashDB"])
                assert isinstance(spec, dict)
                assert "impl" in spec
            except (AssertionError, SyntaxError, ValueError) as error:
                self.report["UnreportableReason"] = (
                    f"A package hook defines an invalid crash database"
                    f" definition:\n{self.report['CrashDB']}\n{error}"
                )
                return False
            try:
                self.crashdb = apport.crashdb.load_crashdb(None, spec)
            except (ImportError, KeyError):
                self.report["UnreportableReason"] = (
                    f"A package hook wants to send this report to the crash"
                    f' database "{self.report["CrashDB"]}"'
                    f" which does not exist."
                )

        else:
            # DB name
            try:
                self.crashdb = apport.crashdb.get_crashdb(None, self.report["CrashDB"])
            except (ImportError, KeyError):
                self.report["UnreportableReason"] = (
                    f"A package hook wants to send this report to the crash"
                    f' database "{self.report["CrashDB"]}"'
                    f" which does not exist."
                )
                return False

        return True

    def collect_info(
        self, symptom_script=None, ignore_uninstalled=False, on_finished=None
    ):
        # TODO: Split into smaller functions/methods
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        """Collect additional information.

        Call all the add_*_info() methods and display a progress dialog during
        this.

        In particular, this adds OS, package and gdb information and checks bug
        patterns.

        If a symptom script is given, this will be run first (used by
        run_symptom()).
        """
        assert self.report
        self.report["_MarkForUpload"] = "True"

        # skip if we already ran (we might load a processed report)
        if (
            self.report.get("ProblemType") == "Crash" and "Stacktrace" in self.report
        ) or (
            self.report.get("ProblemType") != "Crash" and "Dependencies" in self.report
        ):
            if on_finished:
                on_finished()
            return

        # ensure that the crashed program is still installed:
        if self.report.get("ProblemType") == "Crash":
            exe_path = self.report.get("ExecutablePath", "")
            if not os.path.exists(exe_path):
                msg = _(
                    "This problem report applies to a program"
                    " which is not installed any more."
                )
                if exe_path:
                    msg = f"{msg} ({self.report['ExecutablePath']})"
                self.report["UnreportableReason"] = msg
                if on_finished:
                    on_finished()
                return

            if "InterpreterPath" in self.report:
                if not os.path.exists(self.report["InterpreterPath"]):
                    msg = _(
                        "This problem report applies to a program"
                        " which is not installed any more."
                    )
                    self.report["UnreportableReason"] = (
                        f"{msg} ({self.report['InterpreterPath']})"
                    )
                    if on_finished:
                        on_finished()
                    return

        # check if binary changed since the crash happened
        if "ExecutablePath" in self.report and "ExecutableTimestamp" in self.report:
            orig_time = int(self.report["ExecutableTimestamp"])
            del self.report["ExecutableTimestamp"]
            cur_time = int(os.stat(self.report["ExecutablePath"]).st_mtime)

            if orig_time != cur_time:
                self.report["_MarkForUpload"] = "False"
                self.report["UnreportableReason"] = (
                    _(
                        "The problem happened with the program %s"
                        " which changed since the crash occurred."
                    )
                    % self.report["ExecutablePath"]
                )
                return

        if (
            not self.cur_package
            and "ExecutablePath" not in self.report
            and not symptom_script
        ):
            # this happens if we file a bug without specifying a PID or a
            # package
            self.report.add_os_info()
        else:
            # since this might take a while, create separate threads and
            # display a progress dialog.
            self.ui_start_info_collection_progress()
            # only use a UI for asking questions if the crash db will accept
            # the report
            if self.crashdb.accepts(self.report):
                hookui = HookUI(self)
            else:
                hookui = NoninteractiveHookUI()

            if "Stacktrace" not in self.report:
                # save original environment, in case hooks change it
                orig_env = os.environ.copy()
                icthread = apport.REThread.REThread(
                    target=thread_collect_info,
                    name="thread_collect_info",
                    args=(
                        self.report,
                        self.report_file,
                        self.cur_package,
                        hookui,
                        symptom_script,
                        ignore_uninstalled,
                    ),
                )
                icthread.start()
                while icthread.is_alive():
                    self.ui_pulse_info_collection_progress()
                    try:
                        hookui.process_event()
                    except KeyboardInterrupt:
                        sys.exit(1)

                icthread.join()

                # restore original environment
                os.environ.clear()
                os.environ.update(orig_env)

                try:
                    icthread.exc_raise()
                except (OSError, EOFError, zlib.error) as error:
                    # can happen with broken core dumps
                    msg = _("This problem report is damaged and cannot be processed.")
                    self.report["UnreportableReason"] = f"{msg}\n\n{repr(error)}"
                    self.report["_MarkForUpload"] = "False"
                except ValueError:  # package does not exist
                    if "UnreportableReason" not in self.report:
                        self.report["UnreportableReason"] = _(
                            "This report is about a package that is not installed."
                        )
                        self.report["_MarkForUpload"] = "False"
                except Exception as error:  # pylint: disable=broad-except
                    apport.logging.error("%s", repr(error))
                    self.report["UnreportableReason"] = (
                        _(
                            "An error occurred while attempting to "
                            "process this problem report:"
                        )
                        + "\n\n"
                        + str(error)
                    )
                    self.report["_MarkForUpload"] = "False"

            # ask for target, if snap and deb package are installed
            if "Snap" in self.report and "Package" in self.report:
                if "(not installed)" in self.report["Package"]:
                    # choose snap automatically, if deb package
                    # is not installed
                    res = [0]
                else:
                    res = self.ui_question_choice(
                        _(
                            "You have two versions of this application"
                            " installed, which one do you want to report"
                            " a bug against?"
                        ),
                        [
                            _("%s snap") % self.report["Snap"],
                            _("%s deb package") % self.report["Package"],
                        ],
                        False,
                    )
                # bug report is about the snap, clean deb package info
                if res == [0]:
                    del self.report["Package"]
                    if "PackageArchitecture" in self.report:
                        del self.report["PackageArchitecture"]
                    if "SourcePackage" in self.report:
                        del self.report["SourcePackage"]
                # bug report is about the deb package, clean snap info
                elif res == [1]:
                    del self.report["Snap"]
                    if "SnapSource" in self.report:
                        del self.report["SnapSource"]
                    if "SnapTags" in self.report:
                        del self.report["SnapTags"]
                else:
                    self.ui_stop_info_collection_progress()
                    sys.exit(0)

            # append snap tags, if this report is about the snap
            if "Snap" in self.report and "SnapTags" in self.report:
                self.report.add_tags(self.report.pop("SnapTags").split(" "))

            # show a hint if we cannot auto report a snap bug via 'SnapSource'
            if (
                "Snap" in self.report
                and (
                    "SnapSource" not in self.report and "SnapGitName" not in self.report
                )
                and "UnreportableReason" not in self.report
                and self.specified_a_pkg
            ):
                snap = apport.fileutils.find_snap(self.cur_package)
                if snap.get("contact", ""):
                    self.report["UnreportableReason"] = _(
                        "%s is provided by a snap published by %s."
                        " Contact them via %s for help."
                    ) % (snap["name"], snap["developer"], snap["contact"])
                else:
                    self.report["UnreportableReason"] = _(
                        "%s is provided by a snap published by %s. No contact"
                        " address has been provided; visit the forum"
                        " at https://forum.snapcraft.io/ for help."
                    ) % (snap["name"], snap["developer"])
                self.report["_MarkForUpload"] = "False"

            if "UnreportableReason" in self.report or not self.check_report_crashdb():
                self.ui_stop_info_collection_progress()
                if on_finished:
                    on_finished()
                return

            # check bug patterns
            if (
                self.report.get("ProblemType") == "KernelCrash"
                or self.report.get("ProblemType") == "KernelOops"
                or "Package" in self.report
            ):
                bpthread = apport.REThread.REThread(
                    target=self.report.search_bug_patterns,
                    args=(self.crashdb.get_bugpattern_baseurl(),),
                )
                bpthread.start()
                while bpthread.is_alive():
                    self.ui_pulse_info_collection_progress()
                    try:
                        bpthread.join(0.1)
                    except KeyboardInterrupt:
                        sys.exit(1)
                try:
                    bpthread.exc_raise()
                except (OSError, EOFError, zlib.error) as error:
                    # can happen with broken gz values
                    msg = _("This problem report is damaged and cannot be processed.")
                    self.report["UnreportableReason"] = f"{msg}\n\n{repr(error)}"
                if bpthread.return_value():
                    self.report["_KnownReport"] = bpthread.return_value()

            # check crash database if problem is known
            if self.report.get("ProblemType") != "Bug":
                known_thread = apport.REThread.REThread(
                    target=self.crashdb.known, args=(self.report,)
                )
                known_thread.start()
                while known_thread.is_alive():
                    self.ui_pulse_info_collection_progress()
                    try:
                        known_thread.join(0.1)
                    except KeyboardInterrupt:
                        sys.exit(1)
                known_thread.exc_raise()
                val = known_thread.return_value()
                if val is not None:
                    if val is True:
                        self.report["_KnownReport"] = "1"
                    else:
                        self.report["_KnownReport"] = val

            # anonymize; needs to happen after duplicate checking, otherwise we
            # might damage the stack trace
            anonymize_thread = apport.REThread.REThread(target=self.report.anonymize)
            anonymize_thread.start()
            while anonymize_thread.is_alive():
                self.ui_pulse_info_collection_progress()
                try:
                    anonymize_thread.join(0.1)
                except KeyboardInterrupt:
                    sys.exit(1)
            anonymize_thread.exc_raise()

            self.ui_stop_info_collection_progress()

            # check that we were able to determine package names
            if "UnreportableReason" not in self.report:
                if (
                    (
                        "SourcePackage" not in self.report
                        and "Dependencies" not in self.report
                    )
                    or (
                        not self.report.get("ProblemType", "").startswith("Kernel")
                        and "Package" not in self.report
                    )
                ) and not self._is_snap():
                    self.ui_error_message(
                        _("Invalid problem report"),
                        _("Could not determine the package or source package name."),
                    )
                    # TODO This is not called consistently,
                    # is it really needed?
                    self.ui_shutdown()
                    sys.exit(1)

        if on_finished:
            on_finished()

    def _is_snap(self):
        assert self.report
        return "SnapSource" in self.report or "Snap" in self.report

    def open_url(self, url):
        """Open the given URL in a new browser window.

        Display an error dialog if everything fails.
        """
        try:
            try:
                run_as_real_user(["xdg-open", url], get_user_env=True)
                return
            except OSError:
                # fall back to webbrowser
                if webbrowser.open(url, new=1, autoraise=True):
                    return
                error_details = ""
        except Exception as error:  # pylint: disable=broad-except
            error_details = f"\n{error}"

        title = _("Unable to start web browser")
        message = _("Unable to start web browser to open %s.") % url
        self.ui_error_message(title, message + error_details)

    def file_report(self):
        """Upload the current report and guide the user to the reporting
        web page."""
        assert self.report
        # FIXME: This behaviour is not really correct, but necessary as
        # long as we only support a single crashdb and have whoopsie
        # hardcoded. Once we have multiple crash dbs, we need to check
        # accepts() earlier, and not even present the data if none of
        # the DBs wants the report. See LP#957177 for details.
        if not self.crashdb.accepts(self.report):
            return
        # drop PackageArchitecture if equal to Architecture
        if self.report.get("PackageArchitecture") == self.report.get("Architecture"):
            try:
                del self.report["PackageArchitecture"]
            except KeyError:
                pass

        # StacktraceAddressSignature is redundant and does not need to clutter
        # the database
        try:
            del self.report["StacktraceAddressSignature"]
        except KeyError:
            pass

        self.upload_progress = None

        def progress_callback(sent, total):
            self.upload_progress = float(sent) / total

        message_queue = queue.SimpleQueue()

        def message_callback(title, text):
            message_displayed = threading.Event()
            message_queue.put((title, text, message_displayed))
            message_displayed.wait()

        # drop internal/uninteresting keys, that start with "_"
        for k in list(self.report):
            if k.startswith("_"):
                del self.report[k]

        self.ui_start_upload_progress()
        upthread = apport.REThread.REThread(
            target=self.crashdb.upload,
            args=(self.report, progress_callback, message_callback),
        )
        upthread.start()
        try:
            while upthread.is_alive():
                self.ui_set_upload_progress(self.upload_progress)
                try:
                    title, text, msg_displayed = message_queue.get(
                        block=True, timeout=0.1
                    )
                    self.ui_info_message(title, text)
                    msg_displayed.set()
                    upthread.exc_raise()
                except queue.Empty:
                    pass

            upthread.exc_raise()
        except KeyboardInterrupt:
            sys.exit(1)
        except (smtplib.SMTPConnectError, urllib.error.URLError) as error:
            msg = _(
                "Cannot connect to crash database,"
                " please check your Internet connection."
            )
            self.ui_error_message(_("Network problem"), f"{msg}\n\n{str(error)}")
            return

        ticket = upthread.return_value()
        self.ui_stop_upload_progress()

        url = self.crashdb.get_comment_url(self.report, ticket)
        if url:
            self.open_url(url)

    def load_report(self, path):
        """Load report from given path and do some consistency checks.

        This might issue an error message and return False if the report cannot
        be processed, otherwise self.report is initialized and True is
        returned.
        """
        try:
            self.report = apport.Report()
            with open(path, "rb") as f:
                self.report.load(f, binary="compressed")
            if "ProblemType" not in self.report:
                raise ValueError('Report does not contain "ProblemType" field')
        except MemoryError:
            self.report = None
            self.ui_error_message(
                _("Memory exhaustion"),
                _(
                    "Your system does not have enough memory"
                    " to process this crash report."
                ),
            )
            return False
        except OSError as error:
            self.report = None
            self.ui_error_message(_("Invalid problem report"), error.strerror)
            return False
        except (TypeError, ValueError, AssertionError, zlib.error) as error:
            self.report = None
            msg = _("This problem report is damaged and cannot be processed.")
            self.ui_error_message(
                _("Invalid problem report"), f"{msg}\n\n{repr(error)}"
            )
            return False

        if "Package" in self.report:
            self.cur_package = self.report["Package"].split()[0]
        else:
            self.cur_package = apport.fileutils.find_file_package(
                self.report.get("ExecutablePath", "")
            )

        return True

    def check_unreportable(self):
        """Check if the current report is unreportable.

        If so, display an info message and return True.
        """
        assert self.report
        if not self.crashdb.accepts(self.report):
            return False
        if "UnreportableReason" in self.report:
            if isinstance(self.report["UnreportableReason"], bytes):
                self.report["UnreportableReason"] = self.report[
                    "UnreportableReason"
                ].decode("UTF-8")
            if "Package" in self.report:
                title = _("Problem in %s") % self.report["Package"].split()[0]
            else:
                title = ""
            self.ui_info_message(
                title,
                _("The problem cannot be reported:\n\n%s")
                % self.report["UnreportableReason"],
            )
            return True
        return False

    def get_desktop_entry(self):
        """Return a .desktop info dictionary for the current report.

        Return None if report cannot be associated to a .desktop file.
        """
        assert self.report
        if "DesktopFile" in self.report and os.path.exists(self.report["DesktopFile"]):
            desktop_file = self.report["DesktopFile"]
        else:
            try:
                desktop_file = apport.fileutils.find_package_desktopfile(
                    self.cur_package
                )
            except ValueError:
                return None

        if not desktop_file:
            return None

        cp = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            cp.read(desktop_file, encoding="UTF-8")
        except configparser.Error as error:
            sys.stderr.write(f"Warning! {desktop_file} is broken: {str(error)}\n")
            return None
        if not cp.has_section("Desktop Entry"):
            return None
        result = dict(cp.items("Desktop Entry"))
        if "name" not in result:
            return None
        return result

    def handle_duplicate(self):
        """Check if current report matches a bug pattern.

        If so, tell the user about it, open the existing bug in a browser, and
        return True.
        """
        assert self.report
        if not self.crashdb.accepts(self.report):
            return False
        if "_KnownReport" not in self.report:
            return False

        # if we have an URL, open it; otherwise this is just a marker that we
        # know about it
        if self.report["_KnownReport"].startswith("http"):
            self.ui_info_message(
                _("Problem already known"),
                _(
                    "This problem was already reported in the bug report"
                    " displayed in the web browser. Please check"
                    " if you can add any further information"
                    " that might be helpful for the developers."
                ),
            )

            self.open_url(self.report["_KnownReport"])
        else:
            self.ui_info_message(
                _("Problem already known"),
                _("This problem was already reported to developers. Thank you!"),
            )

        return True

    def add_extra_tags(self):
        """Add extra tags to report specified with --tags on CLI."""
        assert self.report
        if self.args.tags:
            self.report.add_tags(self.args.tags)

    #
    # abstract UI methods that must be implemented in derived classes
    #

    def ui_present_report_details(
        self, allowed_to_report: bool = True, modal_for: int | None = None
    ) -> Action:
        """Show details of the bug report.

        Return the action and options as an Action object:

        - Valid attributes are: report the crash ('report'), restart
          the crashed application ('restart'), or ignore further crashes
          ('ignore').
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_info_message(self, title, text):
        """Show an information message box with given title and text."""
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_error_message(self, title, text):
        """Show an error message box with given title and text."""
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_start_info_collection_progress(self):
        """Open a indefinite progress bar for data collection.

        This tells the user to wait while debug information is being
        collected.
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_pulse_info_collection_progress(self):
        """Advance the data collection progress bar.

        This function is called every 100 ms.
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_stop_info_collection_progress(self):
        """Close debug data collection progress window."""
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_start_upload_progress(self):
        """Open progress bar for data upload.

        This tells the user to wait while debug information is being uploaded.
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_set_upload_progress(self, progress: float | None) -> None:
        """Update data upload progress bar.

        Set the progress bar in the debug data upload progress window to the
        given ratio (between 0 and 1, or None for indefinite progress).

        This function is called every 100 ms.
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_stop_upload_progress(self):
        """Close debug data upload progress window."""
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_shutdown(self):
        """Called right before terminating the program.

        This can be used for for cleaning up.
        """

    def ui_has_terminal(self):
        """Check for a terminal window.

        Check if a terminal application is available and can be launched.
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_run_terminal(self, command):
        """Run command in a terminal window.

        Run given command in a terminal window; raise an
        exception if terminal cannot be opened.
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    #
    # Additional UI dialogs; these are not required by Apport itself, but can
    # be used by interactive package hooks
    #

    def ui_question_yesno(self, text):
        """Show a yes/no question.

        Return True if the user selected "Yes", False if selected "No" or
        "None" on cancel/dialog closing.
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_question_choice(self, text, options, multiple):
        """Show an question with predefined choices.

        options is a list of strings to present. If multiple is True, they
        should be check boxes, if multiple is False they should be radio
        buttons.

        Return list of selected option indexes, or None if the user cancelled.
        If multiple == False, the list will always have one element.
        """
        raise NotImplementedError("this function must be overridden by subclasses")

    def ui_question_file(self, text):
        """Show a file selector dialog.

        Return path if the user selected a file, or None if cancelled.
        """
        raise NotImplementedError("this function must be overridden by subclasses")


class HookUI:
    """Interactive functions which can be used in package hooks.

    This provides an interface for package hooks which need to ask interactive
    questions. Directly passing the UserInterface instance to the hooks needs
    to be avoided, since we need to call the UI methods in a different thread,
    and also don't want hooks to be able to poke in the UI.
    """

    def __init__(self, ui):
        """Create a HookUI object.

        ui is the UserInterface instance to wrap.
        """
        self.ui = ui

        # variables for communicating with the UI thread
        self._request_event = threading.Event()
        self._response_event = threading.Event()
        self._request_fn = None
        self._request_args = None
        self._response = None

    #
    # API for hooks
    #

    def information(self, text):
        """Show an information with OK/Cancel buttons.

        This can be used for asking the user to perform a particular action,
        such as plugging in a device which does not work.
        """
        return self._trigger_ui_request("ui_info_message", "", text)

    def yesno(self, text):
        """Show a yes/no question.

        Return True if the user selected "Yes", False if selected "No" or
        "None" on cancel/dialog closing.
        """
        return self._trigger_ui_request("ui_question_yesno", text)

    def choice(self, text, options, multiple=False):
        """Show an question with predefined choices.

        options is a list of strings to present. If multiple is True, they
        should be check boxes, if multiple is False they should be radio
        buttons.

        Return list of selected option indexes, or None if the user cancelled.
        If multiple == False, the list will always have one element.
        """
        return self._trigger_ui_request("ui_question_choice", text, options, multiple)

    def file(self, text):
        """Show a file selector dialog.

        Return path if the user selected a file, or None if cancelled.
        """
        return self._trigger_ui_request("ui_question_file", text)

    #
    # internal API for inter-thread communication
    #

    def _trigger_ui_request(self, fn, *args):
        """Called by HookUi functions in info collection thread."""
        # only one at a time
        assert not self._request_event.is_set()
        assert not self._response_event.is_set()
        assert self._request_fn is None

        self._response = None
        self._request_fn = fn
        self._request_args = args
        self._request_event.set()
        self._response_event.wait()

        self._request_fn = None
        self._response_event.clear()

        return self._response

    def process_event(self):
        """Called by GUI thread to check and process hook UI requests."""
        # sleep for 0.1 seconds to wait for events
        self._request_event.wait(0.1)
        if not self._request_event.is_set():
            return

        assert not self._response_event.is_set()
        self._request_event.clear()
        self._response = getattr(self.ui, self._request_fn)(*self._request_args)
        self._response_event.set()


class NoninteractiveHookUI(HookUI):
    """HookUI variant that does not ask the user any questions."""

    def __init__(self):
        super().__init__(None)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"

    def information(self, text):
        return None

    def yesno(self, text):
        return None

    def choice(self, text, options, multiple=False):
        return None

    def file(self, text):
        return None

    def process_event(self):
        # Give other threads some chance to run
        time.sleep(0.1)
