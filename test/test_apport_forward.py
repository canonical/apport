#!/usr/bin/python3

import array
import os
import socket
import sys
import tempfile

path = tempfile.mktemp()

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)

parent_pid = os.getpid()

if os.fork() == 0:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(path)

    blob = tempfile.mktemp()
    with open(blob, "w+") as fd:
        fd.write("blob")

    with open(blob, "r") as fd:
        args = "%s 11 100" % parent_pid
        client.sendmsg([args.encode()], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                          array.array("i", [fd.fileno()]))])
    os.remove(blob)
    sys.exit(0)

conn, addr = server.accept()

os.dup2(conn.fileno(), 3)
child = os.fork()
if child == 0:
    os.environ["LISTEN_PID"] = "%s" % os.getpid()
    os.environ["LISTEN_FDNAMES"] = "connection"
    os.environ["LISTEN_FDS"] = "1"

    os.execl("data/apport", "apport")

os.waitpid(child, 0)
os.remove(path)
