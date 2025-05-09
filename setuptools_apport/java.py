"""Setuptools extension to build the Java subdirectory."""

import functools
import glob
import logging
import os
import pathlib
import subprocess
import typing

from setuptools import Command, Distribution


# pylint: disable-next=invalid-name
class build_java(Command):
    """Compile Java components of Apport"""

    description = __doc__
    user_options = [("minimum_java_release=", "r", "Specify minimum Java release.")]

    def __init__(self, dist: Distribution, **kwargs: dict[str, typing.Any]) -> None:
        Command.__init__(self, dist, **kwargs)
        self.initialize_options()

    def initialize_options(self) -> None:
        """Set or (reset) all options/attributes/caches to their default values"""
        self.minimum_java_release = "7"

    def finalize_options(self) -> None:
        """Set final values for all options/attributes"""

    def run(self) -> None:
        """Build the Java .class and .jar files."""
        oldwd = os.getcwd()
        os.chdir("java")
        javac = [
            "javac",
            "-source",
            self.minimum_java_release,
            "-target",
            self.minimum_java_release,
        ]
        subprocess.check_call(javac + glob.glob("com/ubuntu/apport/*.java"))
        subprocess.check_call(
            ["jar", "cvf", "apport.jar"] + glob.glob("com/ubuntu/apport/*.class")
        )
        subprocess.check_call(javac + ["testsuite/crash.java"])
        subprocess.check_call(
            ["jar", "cvf", "crash.jar", "crash.class"], cwd="testsuite"
        )

        os.chdir(oldwd)


# pylint: disable-next=invalid-name
class install_java(Command):
    """Install Java components of Apport."""

    def __init__(self, dist: Distribution, **kwargs: dict[str, typing.Any]) -> None:
        super().__init__(dist, **kwargs)
        self.initialize_options()

    def initialize_options(self) -> None:
        """Set default values for all the options that this command supports."""
        self.install_dir: str | None = None

    def finalize_options(self) -> None:
        """Set final values for all the options that this command supports."""
        self.set_undefined_options("install_data", ("install_dir", "install_dir"))

    def _install_data_files(self, dst_path: str, src_files: list[pathlib.Path]) -> None:
        assert self.install_dir
        for src_file in src_files:
            target = pathlib.Path(self.install_dir) / dst_path / src_file.name
            self.mkpath(str(target.parent))
            self.copy_file(str(src_file), str(target), preserve_mode=False)

    def run(self) -> None:
        """Install the Java .jar files."""
        self._install_data_files("share/java", [pathlib.Path("java/apport.jar")])


@functools.cache
def has_java(unused_command: Command) -> bool:
    """Check if the Java compiler is available."""
    try:
        subprocess.run(["javac", "-version"], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        logging.getLogger(__name__).warning(
            "Java support: Java not available, not building Java crash handler"
        )
        return False
    return True


def register_java_sub_commands(
    build: type[Command], install: type[Command]
) -> dict[str, type[Command]]:
    """Plug the Java extension into setuptools.

    Return a dictionary with the added command classes which needs to
    be passed to the `setup` call as `cmdclass` parameter.
    """
    build.sub_commands.append(("build_java_subdir", has_java))
    install.sub_commands.append(("install_java", has_java))
    return {"build_java_subdir": build_java, "install_java": install_java}
