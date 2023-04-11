"""Detect if the current session is running under Wayland."""

import os


def add_info(report, unused_ui):
    """Add a tag if current session is running under Wayland."""
    if os.environ.get("WAYLAND_DISPLAY"):
        report.add_tags(["wayland-session"])
