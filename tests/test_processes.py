"The process facts a grant rests on, read from /proc."

from __future__ import annotations

import os
import socket
import sys

import pytest

from touchgate import processes
from touchgate.processes import Process, ancestry, is_claude, parse_stat

STAT = "4107 (a (b) c) S 4100 4107 4100 0 -1 4194304 1 0 0 0 0 0 0 0 20 0 1 0 98765 1 1 18446744073709551615"


def test_a_comm_may_hold_spaces_and_parentheses():
    assert parse_stat(STAT) == Process(pid=4107, parent=4100, start=98765, name="a (b) c")


def test_ancestry_walks_up_to_the_first_process():
    table = {9: Process(9, 5, 90, "sh"), 5: Process(5, 2, 50, "claude"), 2: Process(2, 1, 20, "init")}
    assert [process.pid for process in ancestry(9, table.get)] == [9, 5, 2]


def test_ancestry_stops_at_a_gone_parent():
    table = {9: Process(9, 5, 90, "sh")}
    assert ancestry(9, table.get) == [table[9]]
    assert ancestry(4, table.get) == []


def test_claude_by_argv0_or_by_its_nix_wrapper():
    assert is_claude(Process(1, 0, 0, ".claude-wrapped"), "")
    assert is_claude(Process(1, 0, 0, "node"), "/usr/bin/claude")
    assert not is_claude(Process(1, 0, 0, "bash"), "/bin/bash")


@pytest.mark.skipif(sys.platform != "linux", reason="/proc and SO_PEERCRED")
def test_the_peer_of_a_socketpair_is_this_process():
    left, right = socket.socketpair(socket.AF_UNIX)
    with left, right:
        peer = processes.peer(left)
    assert peer is not None and peer.pid == os.getpid()
    assert processes.alive(peer.pid, peer.start)
    assert not processes.alive(peer.pid, peer.start + 1)
    assert ancestry(os.getpid())[0] == peer
