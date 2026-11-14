"""
Processes as /proc shows them: who connected to the broker, and the chain
of parents above it. Linux only; elsewhere every reader answers None.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

PROC = Path("/proc")
#: The name Claude Code runs under. Nix wraps it, and the wrapper's comm is `.claude-wrapped`.
CLAUDE = "claude"


@dataclass(frozen=True, slots=True)
class Process:
    pid: int
    parent: int
    #: Clock ticks after boot. With the pid, it names one process: a pid is reused, the pair is not.
    start: int
    #: The kernel's comm: the executable's name, cut at 15 bytes.
    name: str


def parse_stat(text: str) -> Process:
    "One `/proc/<pid>/stat` line. The comm sits in parentheses and may hold spaces or parentheses."
    head, _, rest = text.rpartition(")")
    pid, _, name = head.partition(" (")
    fields = rest.split()
    # fields[0] is the state (stat field 3), so stat field n is fields[n - 3].
    return Process(pid=int(pid), parent=int(fields[1]), start=int(fields[19]), name=name)


def read(pid: int) -> Process | None:
    try:
        return parse_stat((PROC / str(pid) / "stat").read_text())
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


def ancestry(pid: int, reader: Callable[[int], Process | None] = read) -> list[Process]:
    "The process `pid` and each parent above it, nearest first. Empty when `pid` is gone."
    chain: list[Process] = []
    current = reader(pid)
    while current is not None:
        chain.append(current)
        if current.parent <= 1:
            break
        current = reader(current.parent)
    return chain


def among(pid: int, start: int, chain: list[Process]) -> bool:
    return any(process.pid == pid and process.start == start for process in chain)


def alive(pid: int, start: int, reader: Callable[[int], Process | None] = read) -> bool:
    process = reader(pid)
    return process is not None and process.start == start


def argv0(pid: int) -> str:
    try:
        return (PROC / str(pid) / "cmdline").read_bytes().split(b"\0", 1)[0].decode(errors="replace")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return ""


def cwd(pid: int) -> str:
    try:
        return os.readlink(PROC / str(pid) / "cwd")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return ""


def is_claude(process: Process, argv0: str) -> bool:
    return os.path.basename(argv0) == CLAUDE or process.name in (CLAUDE, ".%s-wrapped" % CLAUDE)


def nearest_claude(pid: int) -> Process | None:
    "The nearest process above `pid` that is Claude Code."
    for process in ancestry(pid)[1:]:
        if is_claude(process, argv0(process.pid)):
            return process
    return None


def peer(connection: socket.socket) -> Process | None:
    """
    The process at the other end of a unix socket, from SO_PEERCRED. The
    kernel records the pid at connect; a process that exits and gives its
    pid away before this reads /proc is mistaken for the new one.
    """
    if sys.platform != "linux" or connection.family != socket.AF_UNIX:
        return None
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, _, _ = struct.unpack("3i", credentials)
    return read(pid) if pid > 0 else None
