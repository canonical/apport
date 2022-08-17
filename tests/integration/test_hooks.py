"""Test the various package hooks."""

# Copyright (C) 2007 - 2009 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import datetime
import os
import shutil
import subprocess
import tempfile
import unittest

import apport.fileutils
import apport.report
from tests.paths import get_data_directory, local_test_environment

datadir = get_data_directory()


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = os.environ | local_test_environment()

    def setUp(self):
        self.orig_report_dir = apport.fileutils.report_dir
        apport.fileutils.report_dir = tempfile.mkdtemp()
        self.env["APPORT_REPORT_DIR"] = apport.fileutils.report_dir

        self.workdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(apport.fileutils.report_dir)
        apport.fileutils.report_dir = self.orig_report_dir

        shutil.rmtree(self.workdir)

    def test_package_hook_nologs(self):
        """package_hook without any log files."""

        ph = subprocess.run(
            ["%s/package_hook" % datadir, "-p", "bash"],
            check=False,
            env=self.env,
            input=b"something is wrong",
        )
        self.assertEqual(
            ph.returncode, 0, "package_hook finished successfully"
        )

        reps = apport.fileutils.get_new_reports()
        self.assertEqual(len(reps), 1, "package_hook created a report")

        r = apport.report.Report()
        with open(reps[0], "rb") as f:
            r.load(f)

        self.assertEqual(r["ProblemType"], "Package")
        self.assertEqual(
            r["Package"], "bash " + apport.packaging.get_version("bash")
        )
        self.assertEqual(r["ErrorMessage"], "something is wrong")

    def test_package_hook_uninstalled(self):
        """package_hook on an uninstalled package (might fail to install)."""

        pkg = apport.packaging.get_uninstalled_package()
        ph = subprocess.run(
            ["%s/package_hook" % datadir, "-p", pkg],
            check=False,
            env=self.env,
            input=b"something is wrong",
        )
        self.assertEqual(
            ph.returncode, 0, "package_hook finished successfully"
        )

        reps = apport.fileutils.get_new_reports()
        self.assertEqual(len(reps), 1, "package_hook created a report")

        r = apport.report.Report()
        with open(reps[0], "rb") as f:
            r.load(f)

        self.assertEqual(r["ProblemType"], "Package")
        self.assertEqual(r["Package"], pkg + " (not installed)")
        self.assertEqual(r["ErrorMessage"], "something is wrong")

    def test_package_hook_logs(self):
        """package_hook with a log dir and a log file."""

        with open(
            os.path.join(self.workdir, "log_1.log"), "w", encoding="utf-8"
        ) as f:
            f.write("Log 1\nbla")
        with open(
            os.path.join(self.workdir, "log2"), "w", encoding="utf-8"
        ) as f:
            f.write("Yet\nanother\nlog")
        os.mkdir(os.path.join(self.workdir, "logsub"))
        with open(
            os.path.join(self.workdir, "logsub", "notme.log"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write("not me!")

        ph = subprocess.run(
            [
                "%s/package_hook" % datadir,
                "-p",
                "bash",
                "-l",
                os.path.realpath(__file__),
                "-l",
                self.workdir,
            ],
            check=False,
            env=self.env,
            input=b"something is wrong",
        )
        self.assertEqual(
            ph.returncode, 0, "package_hook finished successfully"
        )

        reps = apport.fileutils.get_new_reports()
        self.assertEqual(len(reps), 1, "package_hook created a report")

        r = apport.report.Report()
        with open(reps[0], "rb") as f:
            r.load(f)

        filekey = None
        log1key = None
        log2key = None
        for k in r.keys():
            if k.endswith("Testhookspy"):
                filekey = k
            elif k.endswith("Log1log"):
                log1key = k
            elif k.endswith("Log2"):
                log2key = k
            elif "sub" in k:
                self.fail("logsub should not go into log files")

        self.assertTrue(filekey)
        self.assertTrue(log1key)
        self.assertTrue(log2key)
        self.assertIn("0234lkjas", r[filekey])
        self.assertEqual(len(r[filekey]), os.path.getsize(__file__))
        self.assertEqual(r[log1key], "Log 1\nbla")
        self.assertEqual(r[log2key], "Yet\nanother\nlog")

    def test_package_hook_tags(self):
        """package_hook with extra tags argument."""
        cmd = [
            "%s/package_hook" % datadir,
            "-p",
            "bash",
            "-t",
            "dist-upgrade, verybad",
        ]
        ph = subprocess.run(
            cmd, check=False, env=self.env, input=b"something is wrong"
        )
        self.assertEqual(
            ph.returncode, 0, "package_hook finished successfully"
        )

        reps = apport.fileutils.get_new_reports()
        self.assertEqual(len(reps), 1, "package_hook created a report")

        r = apport.report.Report()
        with open(reps[0], "rb") as f:
            r.load(f)

        self.assertEqual(r["Tags"], "dist-upgrade verybad")

    def test_kernel_crashdump_kexec(self):
        """kernel_crashdump using kexec-tools."""

        with open(
            os.path.join(apport.fileutils.report_dir, "vmcore"), "wb"
        ) as vmcore:
            vmcore.write(b"\x01" * 100)
        with open(
            os.path.join(apport.fileutils.report_dir, "vmcore.log"),
            "w",
            encoding="utf-8",
        ) as log:
            log.write("vmcore successfully dumped")

        self.assertEqual(
            subprocess.call("%s/kernel_crashdump" % datadir, env=self.env),
            0,
            "kernel_crashdump finished successfully",
        )

        reps = apport.fileutils.get_new_reports()
        self.assertEqual(len(reps), 1, "kernel_crashdump created a report")

        r = apport.report.Report()
        with open(reps[0], "rb") as f:
            r.load(f)

        self.assertEqual(
            set(r.keys()),
            set(
                [
                    "Date",
                    "Package",
                    "ProblemType",
                    "VmCore",
                    "VmCoreLog",
                    "Uname",
                    "Architecture",
                    "DistroRelease",
                ]
            ),
        )
        self.assertEqual(r["ProblemType"], "KernelCrash")
        self.assertEqual(r["VmCoreLog"], "vmcore successfully dumped")
        self.assertEqual(r["VmCore"], b"\x01" * 100)
        self.assertIn("linux", r["Package"])
        self.assertIn(os.uname()[2].split("-")[0], r["Package"])

    def test_kernel_crashdump_kdump(self):
        """kernel_crashdump using kdump-tools."""

        timedir = datetime.datetime.strftime(
            datetime.datetime.now(), "%Y%m%d%H%M"
        )
        vmcore_dir = os.path.join(apport.fileutils.report_dir, timedir)
        os.mkdir(vmcore_dir)

        dmesgfile = os.path.join(vmcore_dir, "dmesg." + timedir)
        with open(dmesgfile, "wt", encoding="utf-8") as dmesg:
            dmesg.write("1" * 100)

        self.assertEqual(
            subprocess.call("%s/kernel_crashdump" % datadir, env=self.env),
            0,
            "kernel_crashdump finished successfully",
        )

        reps = apport.fileutils.get_new_reports()
        self.assertEqual(len(reps), 1, "kernel_crashdump created a report")

        r = apport.report.Report()
        with open(reps[0], "rb") as f:
            r.load(f)

        self.assertEqual(
            set(r.keys()),
            set(
                [
                    "Date",
                    "Package",
                    "ProblemType",
                    "VmCoreDmesg",
                    "Uname",
                    "Architecture",
                    "DistroRelease",
                ]
            ),
        )
        self.assertEqual(r["ProblemType"], "KernelCrash")
        self.assertEqual(r["VmCoreDmesg"], "1" * 100)
        self.assertIn("linux", r["Package"])

        self.assertIn(os.uname()[2].split("-")[0], r["Package"])

        r.add_package_info(r["Package"])
        self.assertIn(os.uname()[2].split("-")[0], r["Package"])

    def test_kernel_crashdump_log_symlink(self):
        """attempted DoS with vmcore.log symlink

        We must only accept plain files, otherwise vmcore.log might be a
        symlink to the .crash file, which would recursively fill itself.
        """
        with open(
            os.path.join(apport.fileutils.report_dir, "vmcore"), "wb"
        ) as vmcore:
            vmcore.write(b"\x01" * 100)
        os.symlink(
            "vmcore", os.path.join(apport.fileutils.report_dir, "vmcore.log")
        )

        self.assertNotEqual(
            subprocess.call(
                "%s/kernel_crashdump" % datadir,
                env=self.env,
                stderr=subprocess.PIPE,
            ),
            0,
            "kernel_crashdump unexpectedly succeeded",
        )

        self.assertEqual(apport.fileutils.get_new_reports(), [])

    def test_kernel_crashdump_kdump_log_symlink(self):
        """attempted DoS with dmesg symlink with kdump-tools"""

        timedir = datetime.datetime.strftime(
            datetime.datetime.now(), "%Y%m%d%H%M"
        )
        vmcore_dir = os.path.join(apport.fileutils.report_dir, timedir)
        os.mkdir(vmcore_dir)

        dmesgfile = os.path.join(vmcore_dir, "dmesg." + timedir)
        os.symlink("../kernel.crash", dmesgfile)

        self.assertNotEqual(
            subprocess.call(
                "%s/kernel_crashdump" % datadir,
                env=self.env,
                stderr=subprocess.PIPE,
            ),
            0,
            "kernel_crashdump unexpectedly succeeded",
        )
        self.assertEqual(apport.fileutils.get_new_reports(), [])

    @unittest.skipIf(os.geteuid() != 0, "this test needs to be run as root")
    def test_kernel_crashdump_kdump_log_dir_symlink(self):
        """attempted DoS with dmesg dir symlink with kdump-tools"""

        timedir = datetime.datetime.strftime(
            datetime.datetime.now(), "%Y%m%d%H%M"
        )
        vmcore_dir = os.path.join(apport.fileutils.report_dir, timedir)
        os.mkdir(vmcore_dir + ".real")
        # pretend that a user tries information disclosure by pre-creating a
        # symlink to another dir
        os.symlink(vmcore_dir + ".real", vmcore_dir)
        os.lchown(vmcore_dir, 65534, 65534)

        dmesgfile = os.path.join(vmcore_dir, "dmesg." + timedir)
        with open(dmesgfile, "wt", encoding="utf-8") as dmesg:
            dmesg.write("1" * 100)

        self.assertNotEqual(
            subprocess.call(
                "%s/kernel_crashdump" % datadir,
                env=self.env,
                stderr=subprocess.PIPE,
            ),
            0,
            "kernel_crashdump unexpectedly succeeded",
        )
        self.assertEqual(apport.fileutils.get_new_reports(), [])

    @staticmethod
    def _gcc_version_path():
        """Determine a valid version and executable path of gcc and return it
        as a tuple."""

        gcc = subprocess.run(
            ["gcc", "--version"], check=True, stdout=subprocess.PIPE, text=True
        )

        ver_fields = gcc.stdout.splitlines()[0].split()[3].split(".")
        # try major/minor first
        gcc_ver = ".".join(ver_fields[:2])
        gcc_path = "/usr/bin/gcc-" + gcc_ver
        if not os.path.exists(gcc_path):
            # fall back to only major
            gcc_ver = ver_fields[0]
            gcc_path = "/usr/bin/gcc-" + gcc_ver

        subprocess.run(
            [gcc_path, "--version"], check=True, stdout=subprocess.PIPE
        )

        return (gcc_ver, gcc_path)

    def test_gcc_ide_hook_file(self):
        """gcc_ice_hook with a temporary file."""

        (gcc_version, gcc_path) = self._gcc_version_path()

        with tempfile.NamedTemporaryFile() as test_source:
            test_source.write(b"int f(int x);")
            test_source.flush()
            test_source.seek(0)

            self.assertEqual(
                subprocess.call(
                    ["%s/gcc_ice_hook" % datadir, gcc_path, test_source.name],
                    env=self.env,
                ),
                0,
                "gcc_ice_hook finished successfully",
            )

            reps = apport.fileutils.get_new_reports()
            self.assertEqual(len(reps), 1, "gcc_ice_hook created a report")

            r = apport.report.Report()
            with open(reps[0], "rb") as f:
                r.load(f)
            self.assertEqual(r["ProblemType"], "Crash")
            self.assertEqual(r["ExecutablePath"], gcc_path)
            self.assertEqual(
                r["PreprocessedSource"], test_source.read().decode()
            )

            r.add_package_info()

        self.assertEqual(r["Package"].split()[0], "gcc-" + gcc_version)
        self.assertNotEqual(r["Package"].split()[1], "")  # has package version
        self.assertIn("libc", r["Dependencies"])

    def test_gcc_ide_hook_file_binary(self):
        """gcc_ice_hook with a temporary file with binary data."""

        gcc_path = self._gcc_version_path()[1]

        with tempfile.NamedTemporaryFile() as test_source:
            test_source.write(b"int f(int x); \xFF\xFF")
            test_source.flush()
            test_source.seek(0)

            self.assertEqual(
                subprocess.call(
                    ["%s/gcc_ice_hook" % datadir, gcc_path, test_source.name],
                    env=self.env,
                ),
                0,
                "gcc_ice_hook finished successfully",
            )

            reps = apport.fileutils.get_new_reports()
            self.assertEqual(len(reps), 1, "gcc_ice_hook created a report")

            r = apport.report.Report()
            with open(reps[0], "rb") as f:
                r.load(f)
            self.assertEqual(r["PreprocessedSource"], test_source.read())

    def test_gcc_ide_hook_pipe(self):
        """gcc_ice_hook with piping."""

        (gcc_version, gcc_path) = self._gcc_version_path()

        test_source = "int f(int x);"

        hook = subprocess.run(
            ["%s/gcc_ice_hook" % datadir, gcc_path, "-"],
            check=False,
            env=self.env,
            input=test_source.encode(),
        )
        self.assertEqual(
            hook.returncode, 0, "gcc_ice_hook finished successfully"
        )

        reps = apport.fileutils.get_new_reports()
        self.assertEqual(len(reps), 1, "gcc_ice_hook created a report")

        r = apport.report.Report()
        with open(reps[0], "rb") as f:
            r.load(f)

        self.assertEqual(r["ProblemType"], "Crash")
        self.assertEqual(r["ExecutablePath"], gcc_path)
        self.assertEqual(r["PreprocessedSource"], test_source)

        r.add_package_info()

        self.assertEqual(r["Package"].split()[0], "gcc-" + gcc_version)

    def test_kernel_oops_hook(self):
        test_source = """------------[ cut here ]------------
kernel BUG at /tmp/oops.c:5!
invalid opcode: 0000 [#1] SMP
Modules linked in: oops cpufreq_stats ext2 i915 drm nf_conntrack_ipv4\
 ipt_REJECT iptable_filter ip_tables nf_conntrack_ipv6 xt_state\
 nf_conntrack xt_tcpudp ip6t_ipv6header ip6t_REJECT ip6table_filter ip6_tables\
 x_tables ipv6 loop dm_multipath rtc_cmos iTCO_wdt iTCO_vendor_support pcspkr\
 i2c_i801 i2c_core battery video ac output power_supply button sg joydev\
 usb_storage dm_snapshot dm_zero dm_mirror dm_mod ahci pata_acpi ata_generic\
 ata_piix libata sd_mod scsi_mod ext3 jbd mbcache uhci_hcd ohci_hcd ehci_hcd
"""
        hook = subprocess.run(
            ["%s/kernel_oops" % datadir],
            check=False,
            env=self.env,
            input=test_source.encode(),
        )
        self.assertEqual(
            hook.returncode, 0, "kernel_oops finished successfully"
        )

        reps = apport.fileutils.get_new_reports()
        self.assertEqual(len(reps), 1, "kernel_oops created a report")

        r = apport.report.Report()
        with open(reps[0], "rb") as f:
            r.load(f)

        self.assertEqual(r["ProblemType"], "KernelOops")
        self.assertEqual(r["OopsText"], test_source)

        self.assertIn("linux", r["Package"])
        self.assertIn(os.uname()[2].split("-")[0], r["Package"])
