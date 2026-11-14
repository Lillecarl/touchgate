"""
The master password, sealed to a FIDO2 security key.

The key's PRF (the hmac-secret extension) turns a salt into the same 32
bytes on every touch, for one credential on one key. Those bytes, put
through HKDF, are the AES-GCM key for the password. The sealed file
holds the credential id, the salt and the ciphertext, and opens only
with that key plugged in and touched.

This runs where the key is plugged in: on the Mac, which then sends the
password to the broker over an SSH-forwarded socket.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

import anyio
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

VERSION = 1
RP_ID = "touchgate"
ORIGIN = "https://touchgate"
#: Binds the ciphertext to its purpose: these bytes never decrypt anything else.
AAD = b"touchgate sealed master password v1"


class SealError(Exception):
    pass


class Authenticator(Protocol):
    async def create(self) -> bytes:
        "Makes a credential with the PRF enabled, and answers its id."
        ...

    async def prf(self, credential_id: bytes, salt: bytes) -> bytes:
        "The credential's PRF output for `salt`: 32 bytes, the same on every touch."
        ...


@dataclass(frozen=True, slots=True)
class Sealed:
    credential_id: bytes
    salt: bytes
    nonce: bytes
    ciphertext: bytes

    def dumps(self) -> str:
        encode = lambda data: base64.b64encode(data).decode()
        return json.dumps(
            {
                "version": VERSION,
                "rp_id": RP_ID,
                "credential_id": encode(self.credential_id),
                "salt": encode(self.salt),
                "nonce": encode(self.nonce),
                "ciphertext": encode(self.ciphertext),
            },
            indent=2,
        )

    @classmethod
    def loads(cls, text: str) -> Sealed:
        try:
            data = json.loads(text)
            if data["version"] != VERSION or data["rp_id"] != RP_ID:
                raise SealError("a sealed password this version does not read")
            return cls(*(base64.b64decode(data[name]) for name in ("credential_id", "salt", "nonce", "ciphertext")))
        except (ValueError, KeyError, TypeError):
            raise SealError("not a sealed password file") from None


def _key(prf_output: bytes) -> AESGCM:
    return AESGCM(HKDF(hashes.SHA256(), 32, salt=None, info=AAD).derive(prf_output))


async def seal(authenticator: Authenticator, password: str) -> Sealed:
    credential_id = await authenticator.create()
    salt = os.urandom(32)
    nonce = os.urandom(12)
    key = _key(await authenticator.prf(credential_id, salt))
    return Sealed(credential_id, salt, nonce, key.encrypt(nonce, password.encode(), AAD))


async def unseal(authenticator: Authenticator, sealed: Sealed) -> str:
    key = _key(await authenticator.prf(sealed.credential_id, sealed.salt))
    try:
        return key.decrypt(sealed.nonce, sealed.ciphertext, AAD).decode()
    except InvalidTag:
        raise SealError("this key does not open the sealed password") from None


async def write(path: Path, sealed: Sealed) -> None:
    "Writes the file readable by its owner only."
    target = anyio.Path(path)
    await target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".new")
    await temporary.write_text(sealed.dumps())
    await temporary.chmod(0o600)
    await temporary.rename(target)


class Fido2Key:
    "The first FIDO2 key on USB, through python-fido2. Its calls block, so they run in a thread."

    def __init__(self, announce: Callable[[str], None]) -> None:
        self.announce = announce

    def _client(self) -> Fido2Client:
        announce = self.announce

        class Prompt(UserInteraction):
            def prompt_up(self) -> None:
                announce("touch the security key")

        device = next(CtapHidDevice.list_devices(), None)
        if device is None:
            raise SealError("no FIDO2 security key on USB")
        return Fido2Client(device, DefaultClientDataCollector(ORIGIN), Prompt())

    def _create(self) -> bytes:
        result = self._client().make_credential(
            PublicKeyCredentialCreationOptions.from_dict(
                {
                    "rp": {"id": RP_ID, "name": "touchgate"},
                    "user": {"id": os.urandom(16), "name": "touchgate"},
                    "challenge": os.urandom(32),
                    "pubKeyCredParams": [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}],
                    "authenticatorSelection": {"userVerification": "discouraged", "residentKey": "discouraged"},
                    "extensions": {"prf": {}},
                }
            )
        )
        prf = result.client_extension_results.prf
        if prf is None or not prf.enabled:
            raise SealError("the security key has no PRF (hmac-secret)")
        credential = result.response.attestation_object.auth_data.credential_data
        if credential is None:
            raise SealError("the security key made no credential")
        return credential.credential_id

    def _prf(self, credential_id: bytes, salt: bytes) -> bytes:
        result = (
            self._client()
            .get_assertion(
                PublicKeyCredentialRequestOptions.from_dict(
                    {
                        "rpId": RP_ID,
                        "challenge": os.urandom(32),
                        "allowCredentials": [{"type": "public-key", "id": credential_id}],
                        "userVerification": "discouraged",
                        "extensions": {"prf": {"eval": {"first": salt}}},
                    }
                )
            )
            .get_response(0)
        )
        prf = result.client_extension_results.prf
        if prf is None or prf.results is None:
            raise SealError("the security key answered no PRF output")
        return prf.results.first

    async def create(self) -> bytes:
        return await anyio.to_thread.run_sync(self._create)

    async def prf(self, credential_id: bytes, salt: bytes) -> bytes:
        return await anyio.to_thread.run_sync(self._prf, credential_id, salt)
