#!/usr/bin/python3

# distutils-extra needs porting, pylint: disable=deprecated-module
import distutils.command.build
import distutils.command.clean
import distutils.core
import distutils.version
import glob
import os.path
import subprocess
import sys

try:
    import DistUtilsExtra.auto
except ImportError:
    sys.stderr.write(
        "To build Apport you need"
        " https://launchpad.net/python-distutils-extra\n"
    )
    sys.exit(1)

assert (
    distutils.version.StrictVersion(DistUtilsExtra.auto.__version__) >= "2.24"
), "needs DistUtilsExtra.auto >= 2.24"


class build_java_subdir(distutils.core.Command):
    """Java crash handler build command."""

    description = "Compile java components of Apport"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        oldwd = os.getcwd()
        os.chdir("java")
        release = "7"

        subprocess.check_call(
            ["javac", "-source", release, "-target", release]
            + glob.glob("com/ubuntu/apport/*.java")
        )
        subprocess.check_call(
            ["jar", "cvf", "apport.jar"]
            + glob.glob("com/ubuntu/apport/*.class")
        )
        subprocess.check_call(
            ["javac", "-source", release, "-target", release, "crash.java"]
        )
        subprocess.check_call(["jar", "cvf", "crash.jar", "crash.class"])

        os.chdir(oldwd)


class clean_java_subdir(DistUtilsExtra.auto.clean_build_tree):
    """Java crash handler clean command."""

    def run(self):
        DistUtilsExtra.auto.clean_build_tree.run(self)
        for (root, _, files) in os.walk("java"):
            for f in files:
                if f.endswith(".jar") or f.endswith(".class"):
                    os.unlink(os.path.join(root, f))


class install_fix_hashbangs(DistUtilsExtra.auto.install_auto):
    """Fix hashbang lines in scripts in data dir."""

    def run(self):
        DistUtilsExtra.auto.install_auto.run(self)
        new_hashbang = "#!%s\n" % sys.executable.rsplit(".", 1)[0]

        for d in (
            os.path.join(self.install_data, "share", "apport"),
            os.path.join(self.install_data, "bin"),
        ):
            for (path, _, files) in os.walk(d):
                for fname in files:
                    f = os.path.join(path, fname)
                    with open(f, encoding="utf-8") as fd:
                        try:
                            lines = fd.readlines()
                        except UnicodeDecodeError:
                            # ignore data files like spinner.gif
                            continue
                    if lines[0].startswith("#!") and "python" in lines[0]:
                        distutils.log.info("Updating hashbang of %s", f)
                        lines[0] = new_hashbang
                        with open(f, "w", encoding="utf-8") as fd:
                            for line in lines:
                                fd.write(line)


#
# main
#

optional_data_files = []
cmdclass = {"install": install_fix_hashbangs}

# if we have Java available, build the Java crash handler
try:
    subprocess.check_call(["javac", "-version"], stderr=subprocess.PIPE)

    distutils.command.build.build.sub_commands.append(
        ("build_java_subdir", None)
    )
    optional_data_files.append(("share/java", ["java/apport.jar"]))
    cmdclass["build_java_subdir"] = build_java_subdir
    cmdclass["clean"] = clean_java_subdir
    print("Java support: Enabled")
except (OSError, subprocess.CalledProcessError):
    print("Java support: Java not available, not building Java crash handler")

from apport.ui import __version__  # noqa: E402, pylint: disable=C0413

# determine systemd unit directory
try:
    systemd_unit_dir = subprocess.check_output(
        ["pkg-config", "--variable=systemdsystemunitdir", "systemd"],
        universal_newlines=True,
    ).strip()
    systemd_tmpfiles_dir = subprocess.check_output(
        ["pkg-config", "--variable=tmpfilesdir", "systemd"],
        universal_newlines=True,
    ).strip()
except subprocess.CalledProcessError:
    # hardcoded fallback path
    systemd_unit_dir = "/lib/systemd/system"
    systemd_tmpfiles_dir = "/usr/lib/tmpfiles.d"

DistUtilsExtra.auto.setup(
    name="apport",
    author="Martin Pitt",
    author_email="martin.pitt@ubuntu.com",
    url="https://launchpad.net/apport",
    license="gpl",
    description="intercept, process, and report crashes and bug reports",
    version=__version__,
    data_files=[
        ("share/doc/apport/", glob.glob("doc/*.txt")),
        # these are not supposed to be called directly, use apport-bug instead
        ("share/apport", ["gtk/apport-gtk", "kde/apport-kde"]),
        ("lib/pm-utils/sleep.d/", glob.glob("pm-utils/sleep.d/*")),
        ("/lib/udev/rules.d", glob.glob("udev/*.rules")),
        (systemd_unit_dir, glob.glob("data/systemd/*.s*")),
        (systemd_tmpfiles_dir, glob.glob("data/systemd/*.conf")),
    ]
    + optional_data_files,
    cmdclass=cmdclass,
)
