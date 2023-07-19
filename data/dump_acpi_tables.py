#!/usr/bin/python3

"""Dump ACPI tables."""

# TODO: Address following pylint complaints
# pylint: disable=invalid-name

import os
import stat
import sys


def dump_acpi_table(filename, tablename, out):
    """Dump a single ACPI table."""
    if not os.access(filename, os.R_OK):
        return

    out.write(f"{tablename[0:4]} @ 0x0000000000000000\n")
    n = 0
    with open(filename, "rb") as f:
        hex_str = ""
        try:
            byte = f.read(1)
            while byte != b"":
                val = ord(byte)
                if (n & 15) == 0:
                    if n > 65535:
                        hex_str = f"   {n:04X}: "
                    else:
                        hex_str = f"    {n:04X}: "
                    ascii_str = ""

                hex_str = f"{hex_str}{val:02X} "

                if (val < 32) or (val > 126):
                    ascii_str = f"{ascii_str}."
                else:
                    ascii_str = ascii_str + chr(val)
                n = n + 1
                if (n & 15) == 0:
                    out.write(f"{hex_str} {ascii_str}\n")
                byte = f.read(1)
        finally:
            if (n % 16) != 0:
                hex_str += "   " * (16 - n % 16)
                out.write(f"{hex_str} {ascii_str}\n")

    out.write("\n")


def dump_acpi_tables(path, out):
    """Dump ACPI tables."""
    tables = os.listdir(path)
    for tablename in tables:
        pathname = os.path.join(path, tablename)
        mode = os.stat(pathname).st_mode
        if stat.S_ISDIR(mode):
            dump_acpi_tables(pathname, out)
        else:
            dump_acpi_table(pathname, tablename, out)


if os.path.isdir("/sys/firmware/acpi/tables"):
    dump_acpi_tables("/sys/firmware/acpi/tables", sys.stdout)
