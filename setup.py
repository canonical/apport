#!/usr/bin/python3

"""Installer script for Apport."""

# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import glob
import logging
import os.path
import subprocess
import sys

from setuptools_apport.java import register_java_sub_commands

try:
    import DistUtilsExtra.auto
    from DistUtilsExtra.command.build_extra import build_extra
except ImportError:
    sys.stderr.write(
        "To build Apport you need https://launchpad.net/python-distutils-extra\n"
    )
    sys.exit(1)

BASH_COMPLETIONS = "share/bash-completion/completions/"


class clean_java_subdir(DistUtilsExtra.auto.clean_build_tree):
    """Java crash handler clean command."""

    def run(self):
        DistUtilsExtra.auto.clean_build_tree.run(self)
        for root, _, files in os.walk("java"):
            for f in files:
                if f.endswith(".jar") or f.endswith(".class"):
                    os.unlink(os.path.join(root, f))


class install_fix_hashbangs(DistUtilsExtra.auto.install_auto):
    """Fix hashbang lines in scripts in data dir."""

    def _fix_symlinks_in_bash_completion(self):
        log = logging.getLogger(__name__)
        autoinstalled_completion_dir = os.path.join(
            self.install_data, "share", "apport", "bash-completion"
        )
        for completion in glob.glob("data/bash-completion/*"):
            try:
                source = os.readlink(completion)
            except OSError:
                continue
            dest = os.path.join(
                self.install_data, BASH_COMPLETIONS, os.path.basename(completion)
            )
            if not os.path.exists(dest):
                continue

            log.info("Convert %s into a symlink to %s...", dest, source)
            os.remove(dest)
            os.symlink(source, dest)

            autoinstalled = os.path.join(
                autoinstalled_completion_dir, os.path.basename(completion)
            )
            os.remove(autoinstalled)

        # Clean-up left-over bash-completion from auto install
        if os.path.isdir(autoinstalled_completion_dir):
            os.rmdir(autoinstalled_completion_dir)

    def run(self):
        log = logging.getLogger(__name__)
        DistUtilsExtra.auto.install_auto.run(self)
        self._fix_symlinks_in_bash_completion()
        new_hashbang = f"#!{sys.executable.rsplit('.', 1)[0]}\n"

        for d in (
            os.path.join(self.install_data, "share", "apport"),
            os.path.join(self.install_data, "bin"),
        ):
            for path, _, files in os.walk(d):
                for fname in files:
                    f = os.path.join(path, fname)
                    with open(f, encoding="utf-8") as fd:
                        try:
                            lines = fd.readlines()
                        except UnicodeDecodeError:
                            # ignore data files like spinner.gif
                            continue
                    if lines[0].startswith("#!") and "python" in lines[0]:
                        log.info("Updating hashbang of %s", f)
                        lines[0] = new_hashbang
                        with open(f, "w", encoding="utf-8") as fd:
                            for line in lines:
                                fd.write(line)


#
# main
#

from apport.ui import __version__  # noqa: E402, pylint: disable=C0413

# determine systemd unit directory
try:
    systemd_unit_dir = subprocess.check_output(
        ["pkg-config", "--variable=systemdsystemunitdir", "systemd"],
        universal_newlines=True,
    ).strip()
    systemd_tmpfiles_dir = subprocess.check_output(
        ["pkg-config", "--variable=tmpfilesdir", "systemd"], universal_newlines=True
    ).strip()
except (FileNotFoundError, subprocess.CalledProcessError):
    # hardcoded fallback path
    systemd_unit_dir = "/lib/systemd/system"
    systemd_tmpfiles_dir = "/usr/lib/tmpfiles.d"

try:
    udev_dir = subprocess.check_output(
        ["pkg-config", "--variable=udevdir", "udev"], text=True
    ).strip()
except (FileNotFoundError, subprocess.CalledProcessError):
    udev_dir = "/lib/udev"

cmdclass = register_java_sub_commands(build_extra, install_fix_hashbangs)
DistUtilsExtra.auto.setup(
    name="apport",
    author="Martin Pitt",
    author_email="martin.pitt@ubuntu.com",
    url="https://launchpad.net/apport",
    license="gpl",
    description="intercept, process, and report crashes and bug reports",
    packages=[
        "apport",
        "apport.crashdb_impl",
        "apport.packaging_impl",
        "problem_report",
    ],
    package_data={"apport": ["py.typed"], "problem_report": ["py.typed"]},
    version=__version__,
    data_files=[
        ("share/doc/apport/", glob.glob("doc/*.txt")),
        # these are not supposed to be called directly, use apport-bug instead
        ("share/apport", ["gtk/apport-gtk", "kde/apport-kde"]),
        (BASH_COMPLETIONS, glob.glob("data/bash-completion/*")),
        ("lib/pm-utils/sleep.d/", glob.glob("pm-utils/sleep.d/*")),
        (f"{udev_dir}/rules.d", glob.glob("udev/*.rules")),
        (
            systemd_unit_dir,
            glob.glob("data/systemd/*.service") + glob.glob("data/systemd/*.socket"),
        ),
        (
            f"{systemd_unit_dir}/systemd-coredump@.service.d",
            ["data/systemd/systemd-coredump@.service.d/apport-coredump-hook.conf"],
        ),
        (systemd_tmpfiles_dir, glob.glob("data/systemd/*.conf")),
    ],
    cmdclass={
        "build": build_extra,
        "clean": clean_java_subdir,
        "install": install_fix_hashbangs,
    }
    | cmdclass,
)
