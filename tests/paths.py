import os


def is_local_source_directory() -> bool:
    """Return True if the current working directory is the source directory.

    The local source directory is expected to have a tests directory
    and a setup.py file.
    """
    return os.path.isdir("tests") and os.path.exists("setup.py")
