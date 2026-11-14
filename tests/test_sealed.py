"""
The master password sealed to a security key's PRF. A software PRF stands
in for the key; the real one (python-fido2 over USB) needs a person.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os
import stat

import anyio
import pytest

from approving import DEADLINE, PASSWORD
from touchgate import config
from touchgate.broker import ask
from touchgate.sealed import Sealed, SealError, seal, unseal, write


class SoftPrf:
    "A security key's PRF in software: one secret per credential, HMAC over the salt."

    def __init__(self) -> None:
        self.credentials: dict[bytes, bytes] = {}
        self.touches = 0

    async def create(self) -> bytes:
        self.touches += 1
        credential_id = os.urandom(16)
        self.credentials[credential_id] = os.urandom(32)
        return credential_id

    async def prf(self, credential_id: bytes, salt: bytes) -> bytes:
        self.touches += 1
        return hmac.digest(self.credentials[credential_id], salt, hashlib.sha256)


async def test_sealed_opens_with_its_key_only(tmp_path):
    key = SoftPrf()
    with anyio.fail_after(DEADLINE):
        sealed = await seal(key, "hunter2 ä")
        path = tmp_path / "touchgate" / "sealed-password.json"
        await write(path, sealed)
        opened = await unseal(key, Sealed.loads(path.read_text()))

        other = SoftPrf()
        other.credentials[sealed.credential_id] = os.urandom(32)
        with pytest.raises(SealError, match="does not open"):
            await unseal(other, sealed)
        flipped = bytes([sealed.ciphertext[0] ^ 1]) + sealed.ciphertext[1:]
        with pytest.raises(SealError, match="does not open"):
            await unseal(key, dataclasses.replace(sealed, ciphertext=flipped))

    assert opened == "hunter2 ä"
    assert "hunter2" not in path.read_text()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # Sealing makes a credential and derives once; each open derives once.
    assert key.touches == 4


def test_a_file_that_is_no_sealed_password_is_refused():
    with pytest.raises(SealError):
        Sealed.loads("{}")
    with pytest.raises(SealError):
        Sealed.loads("not json")


async def test_the_sealed_password_unlocks_the_broker(broker, socket):
    "What `unlock --yubikey` does on the Mac, against the socket SSH would forward."
    key = SoftPrf()
    with anyio.fail_after(DEADLINE):
        sealed = await seal(key, PASSWORD)
        await ask(socket, {"op": "lock"})
        answer = await ask(socket, {"op": "unlock", "password": await unseal(key, sealed)})
        status = await ask(socket, {"op": "status"})
    assert answer == {"ok": True}
    assert status["unlocked"] is True


def test_a_forwarded_socket_takes_the_place_of_the_local_one(tmp_path):
    forwarded = tmp_path / "dynhetz.sock"
    assert config.socket_path({config.SOCKET_VARIABLE: str(forwarded)}) == forwarded
    assert config.socket_path({"XDG_RUNTIME_DIR": "/run/user/1"}) == config.Path("/run/user/1/touchgate/broker.sock")
