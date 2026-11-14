"""
touchgate opens a vault that the official `bw` CLI wrote, on vaultwarden.
"""

from __future__ import annotations

import logging
import uuid

import anyio
import pytest

from accounts import CHEAP_ARGON2, Account, Bw, register
from touchgate.vault import Device, LoginFailed, Secret, Vault, open_vault

#: Registration, a bw login and a create each cost a node start and a KDF.
DEADLINE = 45

DEVICE = Device(identifier=str(uuid.uuid4()))


def _email() -> str:
    return "%s@example.test" % uuid.uuid4().hex[:12]


async def _open(account: Account, password: str | None = None) -> Vault:
    server = account.server
    return await open_vault(
        server.base_url, account.email, password or account.password, DEVICE, transport=server.transport()
    )


async def test_an_item_bw_wrote_opens(vaultwarden, tmp_path):
    with anyio.fail_after(DEADLINE):
        account = await register(vaultwarden, _email(), "correct horse battery staple")
        bw = Bw(account, anyio.Path(tmp_path))
        await bw.login()
        item_id = await bw.create_login(
            "database", "app", "s3cr3t-pässword", notes="rotated monthly", fields={"API_TOKEN": "tok-123"}
        )

        vault = await _open(account)

    item = vault.find("database")
    assert item.id == item_id
    assert item.username == Secret("app")
    assert item.password == Secret("s3cr3t-pässword")
    assert item.notes == Secret("rotated monthly")
    assert item.fields == {"API_TOKEN": Secret("tok-123")}
    assert vault.find(item_id) is item


async def test_an_argon2id_account_opens(vaultwarden, tmp_path):
    with anyio.fail_after(DEADLINE):
        account = await register(vaultwarden, _email(), "correct horse battery staple", CHEAP_ARGON2)
        bw = Bw(account, anyio.Path(tmp_path))
        await bw.login()
        await bw.create_login("mail", "carl", "hunter2")

        vault = await _open(account)

    assert vault.find("mail").password == Secret("hunter2")


async def test_a_wrong_password_is_refused(vaultwarden):
    with anyio.fail_after(DEADLINE):
        account = await register(vaultwarden, _email(), "correct horse battery staple")
        with pytest.raises(LoginFailed):
            await _open(account, "wrong horse")


async def test_no_secret_reaches_the_log(vaultwarden, tmp_path, caplog):
    "Every logger at DEBUG, httpx2's included."
    caplog.set_level(logging.DEBUG)
    with anyio.fail_after(DEADLINE):
        account = await register(vaultwarden, _email(), "a master password")
        bw = Bw(account, anyio.Path(tmp_path))
        await bw.login()
        await bw.create_login("leaky", "nobody", "do-not-log-me")
        vault = await _open(account)

    item = vault.find("leaky")
    assert "do-not-log-me" not in caplog.text
    assert "a master password" not in caplog.text
    assert "do-not-log-me" not in repr(item)
