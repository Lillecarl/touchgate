"Grants on their own: what they cover, and each way they end."

from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest

from touchgate.approval import (
    GRANT_NAMESPACE,
    NAMESPACE,
    Anchor,
    ApprovalError,
    ExecMode,
    GrantTerms,
    Request,
    challenge,
    namespace_of,
)
from touchgate.client import describe
from touchgate.grants import Grants, parse_duration
from touchgate.processes import Process

ANCHOR = Process(5, 2, 50, ".claude-wrapped")
SHELL = Process(9, 5, 90, "bash")
CLIENT = Process(12, 9, 120, "touchgate")
CHAIN = [CLIENT, SHELL, ANCHOR]


def _request(argv=("/bin/deploy", "prod"), prefix=None, uses=None, grant=True, **changes) -> Request:
    terms = GrantTerms(seconds=60, uses=uses, prefix=prefix, anchor=Anchor(5, 50, ANCHOR.name, "/srv"))
    request = Request(
        id="r1",
        secret="deploy",
        item_id="item-1",
        argv=argv,
        cwd="/srv",
        requester=None,
        mode=ExecMode.BROKER,
        explicit={},
        sources={"TOKEN": "TOKEN"},
        expires=0,
        deadline=0.0,
        challenge=b"",
        grant=terms if grant else None,
    )
    return replace(request, **changes)


@pytest.fixture
def table():
    "The processes that run, by pid. A test removes one to end it."
    return {process.pid: process for process in CHAIN}


@pytest.fixture
def grants(table):
    return Grants(reader=table.get)


def test_durations():
    assert parse_duration("90s") == 90
    assert parse_duration("8h") == 8 * 3600
    for wrong in ("8", "2d", "0m", "1w"):
        with pytest.raises(ApprovalError):
            parse_duration(wrong)


def test_a_grant_covers_the_same_command_under_its_anchor(grants):
    grant = grants.add(_request())
    later = _request(grant=False)
    assert grants.find(later, CHAIN) is grant
    assert grants.find(later, [Process(30, 2, 300, "evil"), ANCHOR]) is grant
    # Outside the tree, a reused anchor pid, or the anchor itself asking: no.
    assert grants.find(later, [Process(30, 1, 300, "evil")]) is None
    assert grants.find(later, [CLIENT, Process(5, 2, 51, "claude")]) is None
    assert grants.find(later, [ANCHOR]) is None


def test_a_grant_covers_nothing_else(grants):
    grants.add(_request())
    for other in (
        _request(argv=("/bin/deploy", "staging"), grant=False),
        _request(item_id="item-2", grant=False),
        _request(sources={"TOKEN": "password"}, grant=False),
        _request(mode=ExecMode.CLIENT, grant=False),
        _request(),
    ):
        assert grants.find(other, CHAIN) is None


def test_a_prefix_grant_covers_more_arguments(grants):
    grants.add(_request(prefix=1))
    assert grants.find(_request(argv=("/bin/deploy", "staging", "-v"), grant=False), CHAIN) is not None
    assert grants.find(_request(argv=("/bin/other",), grant=False), CHAIN) is None


def test_a_grant_ends_after_its_uses(grants):
    grant = grants.add(_request(uses=2))
    later = _request(grant=False)
    grants.use(grant.id, later, CHAIN)
    grants.use(grant.id, later, CHAIN)
    with pytest.raises(ApprovalError, match="ended"):
        grants.use(grant.id, later, CHAIN)
    assert grants.listed() == []


def test_a_grant_ends_with_its_anchor_and_its_time(grants, table):
    first = grants.add(_request())
    del table[ANCHOR.pid]
    assert grants.find(_request(grant=False), CHAIN) is None
    table[ANCHOR.pid] = ANCHOR
    second = grants.add(_request())
    second.deadline = 0.0
    assert grants.listed() == []
    assert first.id not in grants.held


def test_revoke(grants):
    one, two = grants.add(_request()), grants.add(_request())
    assert grants.revoke(one.id) == [one.id]
    assert grants.revoke(one.id) == []
    assert grants.revoke(None) == [two.id]


def test_a_signer_shows_the_grant_and_signs_it_apart():
    terms = GrantTerms(seconds=8 * 3600, uses=None, prefix=1, anchor=Anchor(5, 50, ANCHOR.name, "/srv"))
    argv = ("/bin/deploy", "prod")
    fields = ("r1", "nonce", int(time.time()) + 60, "deploy", "item-1", argv, "/srv", None, ExecMode.BROKER, {})
    granting, plain = challenge(*fields, grant=terms), challenge(*fields)
    shown = describe(granting)
    assert "any command that starts /bin/deploy" in shown
    assert "process 5 (.claude-wrapped) in /srv" in shown and "8h00m" in shown
    assert "GRANTS" not in describe(plain)
    assert (namespace_of(granting), namespace_of(plain)) == (GRANT_NAMESPACE, NAMESPACE)
    with pytest.raises(ApprovalError, match="cannot show: more"):
        describe(json.dumps({**json.loads(plain), "more": 1}).encode())
