import importlib
import os

from apport.packaging import PackageInfo, freedesktop_os_release


def determine_packaging_implementation() -> str:
    """Determine the packaging implementation for the host."""
    info = freedesktop_os_release()
    assert info is not None
    ids = set([info["ID"]]) | set(info.get("ID_LIKE", "").split(" "))
    if "debian" in ids:
        return "apt_dpkg"
    if os.path.exists("/usr/bin/rpm"):
        return "rpm"
    raise RuntimeError(
        "Could not determine system package manager."
        " Please file a bug and provide /etc/os-release!"
    )


def load_packaging_implementation() -> PackageInfo:
    """Return the packaging implementation for the host."""
    module = importlib.import_module(
        f"apport.packaging_impl.{determine_packaging_implementation()}"
    )
    return module.impl


impl = load_packaging_implementation()
