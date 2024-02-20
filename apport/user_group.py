# Copyright (C) 2023 Canonical Ltd.
# Author: Benjamin Drung <benjamin.drung@canonical.com>
# SPDX-License-Identifier: GPL-2.0-or-later

"""Functions around users and groups."""

import dataclasses
import os


@dataclasses.dataclass()
class UserGroupID:
    """Pair of user and group ID."""

    uid: int
    gid: int

    def is_root(self) -> bool:
        """Check if the user or group ID is root."""
        return self.uid == 0 or self.gid == 0

    @classmethod
    def from_systemd_coredump(cls, coredump):
        """Extract user and group from systemd-coredump dictionary."""
        uid = coredump.get("COREDUMP_UID")
        assert isinstance(uid, int)
        gid = coredump.get("COREDUMP_GID")
        assert isinstance(gid, int)
        return cls(uid, gid)


def get_process_user_and_group() -> UserGroupID:
    """Return the current process’s real user and group."""
    return UserGroupID(os.getuid(), os.getgid())
