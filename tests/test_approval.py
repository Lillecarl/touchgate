"""
Requests and approvals over the broker's socket: a touch signature from a
key the vault lists releases the values, and nothing else does.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import uuid

import anyio
import pytest

from accounts import Bw, register
from authenticator import SoftKey, plain_signature
from touchgate import config
from touchgate.approval import APPROVERS_ITEM, ApprovalError, ExecMode, approvers
from touchgate.broker import Broker, ask
from touchgate.client import approved_env, request
from touchgate.sshsig import SkFlags
from touchgate.vault import Device, Endpoints, Item, Secret, Vault

DEADLINE = 45
PASSWORD = "approval password"
ARGV = ["/usr/bin/psql", "--host", "db"]


@pytest.fixture(scope="module")
def approver() -> SoftKey:
    return SoftKey()


@pytest.fixture(scope="module")
async def broker(vaultwarden, tmp_path_factory, approver):
    "One account and broker for the module: `bw` and a 600k PBKDF2 login cost seconds each."
    account = await register(vaultwarden, "%s@example.test" % uuid.uuid4().hex[:12], PASSWORD)
    bw = Bw(account, anyio.Path(tmp_path_factory.mktemp("bw")))
    await bw.login()
    await bw.create_login("database", "app", "s3cr3t", fields={"API_TOKEN": "t0ken", "not a name": "skipped"})
    await bw.create_login(APPROVERS_ITEM, "", "", notes="# the YubiKey\n%s\nnot a key\n" % approver.line())
    settings = config.Config(account.email, Endpoints.of(account.server.base_url))
    broker = Broker(settings, Device(str(uuid.uuid4())), transport=account.server.transport())
    await broker.unlock(PASSWORD)
    return broker


@pytest.fixture
async def socket(broker, tmp_path):
    path = tmp_path / "broker.sock"
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            await tasks.start(broker.serve, path)
            yield path
            tasks.cancel_scope.cancel()


def _signer(key: SoftKey, **options):
    async def sign(challenge: bytes) -> str:
        return key.sign(challenge, **options)

    return sign


async def _ask(socket, env=None):
    return await request(socket, "database", ARGV, cwd="/srv", requester="%1", mode=ExecMode.CLIENT, env=env or {})


async def _approve(socket, id, signature):
    return await ask(socket, {"op": "approve", "id": id, "signature": signature})


async def test_a_touch_releases_the_values(socket, approver):
    announced = []
    with anyio.fail_after(DEADLINE):
        values = await approved_env(
            socket,
            "database",
            ARGV,
            _signer(approver),
            cwd="/srv",
            requester="%1",
            env={"PGPASSWORD": "password", "PGUSER": "username"},
            announce=announced.append,
        )
    assert values == {"API_TOKEN": "t0ken", "PGPASSWORD": "s3cr3t", "PGUSER": "app"}
    assert "psql --host db" in announced[0]


async def test_the_challenge_names_the_run_and_carries_no_value(socket):
    with anyio.fail_after(DEADLINE):
        reply = await ask(
            socket,
            {"op": "request", "secret": "database", "argv": ARGV, "cwd": "/srv", "requester": "%1"},
        )
    challenge = json.loads(str(reply["challenge"]))
    assert challenge["argv"] == ARGV and challenge["cwd"] == "/srv" and challenge["requester"] == "%1"
    assert challenge["variables"] == ["API_TOKEN"] and challenge["exec"] == "client"
    assert "s3cr3t" not in json.dumps(reply) and "t0ken" not in json.dumps(reply)


@pytest.mark.parametrize(
    ("signature", "error"),
    [
        (lambda key, c: key.sign(c, flags=SkFlags.USER_VERIFICATION), "without a touch"),
        (lambda key, c: SoftKey().sign(c), "may not approve"),
        (lambda key, c: plain_signature(c), "not a security key"),
        (lambda key, c: key.sign(c, namespace="git"), "not 'touchgate'"),
        (lambda key, c: key.sign(c + b" "), "does not verify"),
    ],
    ids=["no-touch", "other-key", "plain-key", "namespace", "other-bytes"],
)
async def test_refused_and_used_up(socket, approver, signature, error):
    with anyio.fail_after(DEADLINE):
        id, challenge = await _ask(socket)
        refused = await _approve(socket, id, signature(approver, challenge))
        # The attempt used the request: the right signature now finds nothing.
        again = await _approve(socket, id, approver.sign(challenge))
    assert refused["ok"] is False and error in str(refused["error"])
    assert again["ok"] is False and "no request" in str(again["error"])


async def test_a_signature_approves_one_request_once(socket, approver):
    with anyio.fail_after(DEADLINE):
        first, first_challenge = await _ask(socket)
        second, _ = await _ask(socket)
        crossed = await _approve(socket, second, approver.sign(first_challenge))
        approved = await _approve(socket, first, approver.sign(first_challenge))
        replayed = await _approve(socket, first, approver.sign(first_challenge))
    assert crossed["ok"] is False and "does not verify" in str(crossed["error"])
    assert approved["ok"] is True
    assert replayed["ok"] is False


async def test_an_expired_request_is_refused(socket, broker, approver):
    with anyio.fail_after(DEADLINE):
        id, challenge = await _ask(socket)
        broker.requests.pending[id] = dataclasses.replace(broker.requests.pending[id], deadline=0.0)
        answer = await _approve(socket, id, approver.sign(challenge))
    assert answer["ok"] is False and "expired" in str(answer["error"])


async def test_what_a_request_may_not_ask_for(socket):
    with anyio.fail_after(DEADLINE):
        with pytest.raises(ApprovalError, match="not a secret"):
            await request(socket, APPROVERS_ITEM, ARGV, cwd="/", requester=None, mode=ExecMode.CLIENT, env={})
        with pytest.raises(ApprovalError, match="has no nothing"):
            await _ask(socket, env={"X": "nothing"})
        with pytest.raises(ApprovalError, match="not a variable name"):
            await _ask(socket, env={"1X": "password"})
        with pytest.raises(ApprovalError, match="0 items"):
            await request(socket, "missing", ARGV, cwd="/", requester=None, mode=ExecMode.CLIENT, env={})


async def test_locking_drops_the_requests(socket, broker, approver):
    with anyio.fail_after(DEADLINE):
        id, challenge = await _ask(socket)
        await ask(socket, {"op": "lock"})
        try:
            answer = await _approve(socket, id, approver.sign(challenge))
            locked = await ask(socket, {"op": "request", "secret": "database", "argv": ARGV, "cwd": "/"})
        finally:
            await broker.unlock(PASSWORD)
    assert answer["ok"] is False
    assert locked["ok"] is False and "locked" in str(locked["error"])


async def test_no_value_or_signature_reaches_the_log(socket, approver, caplog):
    caplog.set_level(logging.DEBUG)
    with anyio.fail_after(DEADLINE):
        id, challenge = await _ask(socket, env={"PGPASSWORD": "password"})
        signature = approver.sign(challenge)
        await _approve(socket, id, signature)
        id, challenge = await _ask(socket)
        await _approve(socket, id, approver.sign(challenge, flags=0))
    body = signature.splitlines()[1]
    assert "approved" in caplog.text and "without a touch" in caplog.text
    for leaked in ("s3cr3t", "t0ken", body):
        assert leaked not in caplog.text


async def test_touchgate_run_signs_with_ssh_keygen(broker, tmp_path):
    """
    The command line end to end: arguments, the request, ssh-keygen as the
    signer, the approve. A plain key is what ssh-keygen can make here, so
    the broker refuses it, and the command never starts.
    """
    key = tmp_path / "id_ed25519"
    (tmp_path / "touchgate").mkdir()
    (tmp_path / "touchgate" / "config.toml").write_text('email = "a@b.c"\nsigning_key = "%s"\n' % key)
    marker = tmp_path / "ran"
    environment = {**os.environ, "XDG_CONFIG_HOME": str(tmp_path), "XDG_RUNTIME_DIR": str(tmp_path / "run")}
    with anyio.fail_after(DEADLINE):
        await anyio.run_process(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
        async with anyio.create_task_group() as tasks:
            await tasks.start(broker.serve, config.socket_path(environment))
            done = await anyio.run_process(
                ["touchgate", "run", "--env", "PGPASSWORD=password", "database", "--", "touch", str(marker)],
                env=environment,
                check=False,
            )
            tasks.cancel_scope.cancel()
    stderr = done.stderr.decode()
    assert done.returncode == 1, stderr
    assert "touch the key to give database to: " in stderr and str(marker) in stderr
    assert "not a security key" in stderr
    assert not marker.exists()


def test_the_approver_list_skips_what_is_no_security_key(approver):
    notes = "# comment\n\n%s\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== plain\njunk\n" % approver.line()
    item = Item("1", 2, APPROVERS_ITEM, None, None, None, Secret(notes), {})
    assert [key.blob for key in approvers(Vault((item,)))] == [approver.blob]
    assert approvers(Vault(())) == ()
