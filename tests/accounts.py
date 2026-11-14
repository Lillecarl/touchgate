"""
Accounts on a test vaultwarden, and items in them written by the official
`bw` CLI, so touchgate never reads a vault it wrote itself.

Registration has to make the account's keys on the client, and `bw`
cannot register, so that part is ours (docs/protocol.md §8).
"""

from __future__ import annotations

import base64
import json
import os
import ssl
from dataclasses import dataclass
from typing import Any

import anyio
import httpx2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sealing import encrypt
from touchgate.crypto import Kdf, KdfType, SymmetricKey, master_key, password_hash, stretch

#: The official clients' floor for PBKDF2. Below it, `bw login` upgrades the KDF at once,
#: which revokes its own token: "Error refreshing access token", invalid_grant.
CHEAP_PBKDF2 = Kdf(KdfType.PBKDF2_SHA256, 600_000)
#: The official clients' floor for Argon2id.
CHEAP_ARGON2 = Kdf(KdfType.ARGON2ID, 2, 16, 1)


@dataclass(frozen=True, slots=True)
class Server:
    "A test vaultwarden behind TLS from a throwaway CA, since `bw` refuses plain HTTP."

    base_url: str
    trust: ssl.SSLContext
    ca_file: str

    def transport(self) -> httpx2.AsyncHTTPTransport:
        return httpx2.AsyncHTTPTransport(verify=self.trust)


@dataclass(frozen=True, slots=True)
class Account:
    server: Server
    email: str
    password: str


async def register(server: Server, email: str, password: str, kdf: Kdf = CHEAP_PBKDF2) -> Account:
    key = master_key(password, email, kdf)
    user_key = os.urandom(64)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_der = private.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    async with httpx2.AsyncClient(base_url=server.base_url, verify=server.trust) as http:
        sent = await http.post(
            "/identity/accounts/register/send-verification-email",
            json={"email": email},
            headers={"Accept": "application/json"},
        )
        sent.raise_for_status()
        finished = await http.post(
            "/identity/accounts/register/finish",
            json={
                "email": email,
                "emailVerificationToken": sent.json(),
                "masterPasswordHash": password_hash(key, password),
                "key": encrypt(user_key, stretch(key)),
                "kdf": int(kdf.type),
                "kdfIterations": kdf.iterations,
                "kdfMemory": kdf.memory,
                "kdfParallelism": kdf.parallelism,
                "userAsymmetricKeys": {
                    "encryptedPrivateKey": encrypt(private_der, SymmetricKey.from_bytes(user_key)),
                    "publicKey": base64.b64encode(public_der).decode(),
                },
            },
        )
        finished.raise_for_status()
    return Account(server, email, password)


class Bw:
    "The official CLI, logged in to one account, with its state in a directory of its own."

    def __init__(self, account: Account, home: anyio.Path) -> None:
        self.account = account
        self.environment = {
            **os.environ,
            "BITWARDENCLI_APPDATA_DIR": str(home),
            "HOME": str(home),
            "NODE_EXTRA_CA_CERTS": account.server.ca_file,
        }
        self.session: str | None = None

    async def run(self, *arguments: str) -> str:
        environment = dict(self.environment)
        if self.session is not None:
            environment["BW_SESSION"] = self.session
        done = await anyio.run_process(["bw", "--nointeraction", *arguments], env=environment, check=False)
        if done.returncode != 0:
            raise RuntimeError("bw %s failed: %s" % (arguments[0], done.stderr.decode(errors="replace").strip()))
        return done.stdout.decode()

    async def login(self) -> None:
        await self.run("config", "server", self.account.server.base_url)
        self.session = (await self.run("login", self.account.email, self.account.password, "--raw")).strip()

    async def create_login(
        self, name: str, username: str, password: str, notes: str | None = None, fields: dict[str, str] | None = None
    ) -> str:
        item: dict[str, Any] = json.loads(await self.run("get", "template", "item"))  # bw's own JSON shape
        item.update(
            type=1,
            name=name,
            notes=notes,
            login={"username": username, "password": password, "uris": [], "totp": None},
            # Type 1 is a hidden field.
            fields=[{"name": key, "value": value, "type": 1} for key, value in (fields or {}).items()],
        )
        encoded = base64.b64encode(json.dumps(item).encode()).decode()
        return json.loads(await self.run("create", "item", encoded))["id"]
