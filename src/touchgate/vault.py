"""
Log in to a Bitwarden server, sync, and open the vault in memory.

Read only: nothing here writes to the server. `docs/protocol.md` is the
specification; sections are named as `protocol.md §N`.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

import httpx2
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from .crypto import (
    BadMac,
    Kdf,
    KdfType,
    SymmetricKey,
    VaultCryptoError,
    decrypt,
    master_key,
    password_hash,
    stretch,
    unwrap_rsa,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "CipherType",
    "Device",
    "Item",
    "LoginFailed",
    "Secret",
    "TwoFactorRequired",
    "Vault",
    "WrongPassword",
    "open_vault",
]

log = logging.getLogger(__name__)

#: vaultwarden hides SSH-key items from a client older than this (protocol.md §5).
CLIENT_VERSION = "2024.12.0"
#: LinuxDesktop, as rbw sends (protocol.md §3).
DEVICE_TYPE = 8


class LoginFailed(Exception):
    "The server refused the login. The message is the server's."


class TwoFactorRequired(LoginFailed):
    "The account has two-factor login, which this client does not do yet."


class WrongPassword(LoginFailed):
    "The master password does not open the account's key."


@dataclass(frozen=True, slots=True)
class Secret:
    "A vault value. Its repr hides it, so a log line or a traceback does not carry it."

    value: str = field(repr=False)

    def __repr__(self) -> str:
        return "Secret(***)"


@dataclass(frozen=True, slots=True)
class Device:
    "How this installation names itself to the server. `identifier` stays the same across runs."

    identifier: str
    name: str = "touchgate"


class CipherType(IntEnum):
    LOGIN = 1
    SECURE_NOTE = 2
    CARD = 3
    IDENTITY = 4
    SSH_KEY = 5


@dataclass(frozen=True, slots=True)
class Item:
    id: str
    type: int
    name: str
    organization_id: str | None
    username: Secret | None
    password: Secret | None
    notes: Secret | None
    #: Custom fields by name. A name that repeats keeps its last value.
    fields: Mapping[str, Secret]


@dataclass(frozen=True, slots=True)
class Vault:
    items: tuple[Item, ...]

    def find(self, name_or_id: str) -> Item:
        "The item with this id, else the one with this name. Two of that name is an error."
        named = [item for item in self.items if item.id == name_or_id]
        if not named:
            named = [item for item in self.items if item.name == name_or_id]
        if len(named) != 1:
            raise KeyError("%d items named %r" % (len(named), name_or_id))
        return named[0]


class _Wire(BaseModel):
    # vaultwarden answers in camelCase, the official server partly in PascalCase.
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


def _alias(camel: str) -> AliasChoices:
    return AliasChoices(camel, camel[0].upper() + camel[1:])


class _Prelogin(_Wire):
    kdf: KdfType = Field(validation_alias=_alias("kdf"))
    kdf_iterations: int = Field(validation_alias=_alias("kdfIterations"))
    kdf_memory: int | None = Field(None, validation_alias=_alias("kdfMemory"))
    kdf_parallelism: int | None = Field(None, validation_alias=_alias("kdfParallelism"))


class _Token(_Wire):
    access_token: str
    key: str = Field(validation_alias=_alias("key"))
    private_key: str | None = Field(None, validation_alias=_alias("privateKey"))


class _Organization(_Wire):
    id: str = Field(validation_alias=_alias("id"))
    key: str | None = Field(None, validation_alias=_alias("key"))


class _Profile(_Wire):
    organizations: list[_Organization] = Field(default_factory=list, validation_alias=_alias("organizations"))


class _Field(_Wire):
    name: str | None = Field(None, validation_alias=_alias("name"))
    value: str | None = Field(None, validation_alias=_alias("value"))


class _Login(_Wire):
    username: str | None = Field(None, validation_alias=_alias("username"))
    password: str | None = Field(None, validation_alias=_alias("password"))


class _Cipher(_Wire):
    id: str = Field(validation_alias=_alias("id"))
    type: int = Field(validation_alias=_alias("type"))
    organization_id: str | None = Field(None, validation_alias=_alias("organizationId"))
    key: str | None = Field(None, validation_alias=_alias("key"))
    name: str = Field(validation_alias=_alias("name"))
    notes: str | None = Field(None, validation_alias=_alias("notes"))
    login: _Login | None = Field(None, validation_alias=_alias("login"))
    fields: list[_Field] | None = Field(None, validation_alias=_alias("fields"))
    deleted_date: str | None = Field(None, validation_alias=_alias("deletedDate"))


class _Sync(_Wire):
    profile: _Profile = Field(validation_alias=_alias("profile"))
    ciphers: list[_Cipher] = Field(default_factory=list, validation_alias=_alias("ciphers"))


def _failure(response: httpx2.Response) -> LoginFailed:
    try:
        body = response.json()
    except ValueError:
        return LoginFailed("HTTP %d from the server" % response.status_code)
    if isinstance(body, dict) and "TwoFactorProviders" in body:
        return TwoFactorRequired("the account asks for a second factor")
    model = body.get("errorModel") if isinstance(body, dict) else None
    message = (model or {}).get("message") or body.get("error_description") or body.get("message") or ""
    return LoginFailed("HTTP %d: %s" % (response.status_code, message or "no reason given"))


async def open_vault(
    base_url: str,
    email: str,
    password: str,
    device: Device,
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> Vault:
    "Log in with the master password, sync, and decrypt every item."
    headers = {
        "Bitwarden-Client-Name": "cli",
        "Bitwarden-Client-Version": CLIENT_VERSION,
        "Device-Type": str(DEVICE_TYPE),
    }
    async with httpx2.AsyncClient(base_url=base_url.rstrip("/"), headers=headers, transport=transport) as http:
        prelogin = await http.post("/identity/accounts/prelogin", json={"email": email})
        prelogin.raise_for_status()
        settings = _Prelogin.model_validate(prelogin.json())
        kdf = Kdf(settings.kdf, settings.kdf_iterations, settings.kdf_memory, settings.kdf_parallelism).checked()

        key = master_key(password, email, kdf)
        response = await http.post(
            "/identity/connect/token",
            data={
                "grant_type": "password",
                "username": email,
                "password": password_hash(key, password),
                "scope": "api offline_access",
                "client_id": "cli",
                "deviceType": str(DEVICE_TYPE),
                "deviceIdentifier": device.identifier,
                "deviceName": device.name,
            },
            # The official server wants it; vaultwarden ignores it (protocol.md §0).
            headers={"Auth-Email": base64.urlsafe_b64encode(email.encode()).decode().rstrip("=")},
        )
        if response.status_code != 200:
            raise _failure(response)
        token = _Token.model_validate(response.json())

        try:
            user_key = SymmetricKey.from_bytes(decrypt(token.key, stretch(key)))
        except BadMac:
            raise WrongPassword("the master password does not open the account key") from None

        sync = await http.get("/api/sync", headers={"Authorization": "Bearer " + token.access_token})
        sync.raise_for_status()
        return _open(_Sync.model_validate(sync.json()), user_key, token.private_key)


def _open(sync: _Sync, user_key: SymmetricKey, private_key: str | None) -> Vault:
    org_keys: dict[str, SymmetricKey] = {}
    if private_key is not None:
        der = decrypt(private_key, user_key)
        for organization in sync.profile.organizations:
            if organization.key is not None:
                org_keys[organization.id] = SymmetricKey.from_bytes(unwrap_rsa(organization.key, der))

    items = []
    for cipher in sync.ciphers:
        if cipher.deleted_date is not None:
            continue
        try:
            items.append(_item(cipher, user_key, org_keys))
        except VaultCryptoError as error:
            # One item that does not open leaves the rest readable. The id names it, never its contents.
            log.warning("item %s does not open: %s", cipher.id, error)
    return Vault(tuple(items))


def _item(cipher: _Cipher, user_key: SymmetricKey, org_keys: Mapping[str, SymmetricKey]) -> Item:
    if cipher.organization_id is None:
        key = user_key
    elif cipher.organization_id in org_keys:
        key = org_keys[cipher.organization_id]
    else:
        raise VaultCryptoError("no key for organisation %s" % cipher.organization_id)
    if cipher.key is not None:
        key = SymmetricKey.from_bytes(decrypt(cipher.key, key))

    def text(value: str | None) -> str | None:
        return None if value is None else decrypt(value, key).decode("utf-8")

    def secret(value: str | None) -> Secret | None:
        opened = text(value)
        return None if opened is None else Secret(opened)

    fields = {}
    for each in cipher.fields or []:
        name, value = text(each.name), secret(each.value)
        if name is not None and value is not None:
            fields[name] = value

    return Item(
        id=cipher.id,
        type=cipher.type,
        name=text(cipher.name) or "",
        organization_id=cipher.organization_id,
        username=secret(cipher.login.username) if cipher.login else None,
        password=secret(cipher.login.password) if cipher.login else None,
        notes=secret(cipher.notes),
        fields=fields,
    )
