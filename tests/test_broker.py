"""
The broker over its socket: unlock, status, lock, and requests it refuses.
"""

from __future__ import annotations

import os
import stat
import uuid

import anyio
import pytest

from accounts import Bw, register
from touchgate import config
from touchgate.broker import Broker, ask
from touchgate.vault import Device, Endpoints

DEADLINE = 45


@pytest.fixture
async def account(vaultwarden, tmp_path):
    account = await register(vaultwarden, "%s@example.test" % uuid.uuid4().hex[:12], "broker password")
    bw = Bw(account, anyio.Path(tmp_path / "bw"))
    await bw.login()
    await bw.create_login("database", "app", "s3cr3t")
    return account


def _broker(account) -> Broker:
    settings = config.Config(account.email, Endpoints.of(account.server.base_url))
    return Broker(settings, Device(str(uuid.uuid4())), transport=account.server.transport())


async def test_the_broker_unlocks_and_locks(account, tmp_path):
    socket = tmp_path / "run" / "broker.sock"
    broker = _broker(account)
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            await tasks.start(broker.serve, socket)

            assert await ask(socket, {"op": "status"}) == {"ok": True, "unlocked": False, "items": None}
            assert await ask(socket, {"op": "unlock", "password": "broker password"}) == {"ok": True}
            assert await ask(socket, {"op": "status"}) == {"ok": True, "unlocked": True, "items": 1}
            assert await ask(socket, {"op": "lock"}) == {"ok": True}
            assert broker.vault is None

            tasks.cancel_scope.cancel()

    assert stat.S_IMODE(os.stat(socket.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(socket).st_mode) == 0o600


async def test_a_wrong_password_leaves_it_locked(account, tmp_path):
    socket = tmp_path / "broker.sock"
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            await tasks.start(_broker(account).serve, socket)

            answer = await ask(socket, {"op": "unlock", "password": "not it"})
            status = await ask(socket, {"op": "status"})

            tasks.cancel_scope.cancel()

    assert answer["ok"] is False and "incorrect" in str(answer["error"])
    assert status["unlocked"] is False


async def test_a_request_it_does_not_read_is_refused_without_echo(account, tmp_path):
    "A malformed unlock must not send its password back, or into the log."
    socket = tmp_path / "broker.sock"
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            await tasks.start(_broker(account).serve, socket)

            unknown = await ask(socket, {"op": "give-me-everything"})
            malformed = await ask(socket, {"op": "unlock", "password": 12345678})
            # The listener lives on after both.
            status = await ask(socket, {"op": "status"})

            tasks.cancel_scope.cancel()

    assert unknown["ok"] is False
    assert malformed["ok"] is False and "12345678" not in str(malformed)
    assert status["ok"] is True


def test_the_config_names_a_server(tmp_path):
    assert config.Config.parse({"email": "a@b.c"}).endpoints == config.SERVERS["us"]
    assert config.Config.parse({"email": "a@b.c", "server": "eu"}).endpoints == config.SERVERS["eu"]
    assert config.Config.parse({"email": "a@b.c", "server": "https://vault.example/"}).endpoints == Endpoints(
        "https://vault.example/api", "https://vault.example/identity"
    )
    with pytest.raises(config.ConfigError):
        config.Config.parse({})


def test_the_device_id_stays(tmp_path):
    environ = {"XDG_STATE_HOME": str(tmp_path)}
    assert config.device(environ) == config.device(environ)
