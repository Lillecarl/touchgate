"""
OpenSSH signatures (SSHSIG) made with a security key, verified in process.

`ssh-keygen -Y verify` checks the signature and the allowed keys, but
it only logs the security key's flags (`sig_verify` in ssh-keygen.c,
OpenSSH 10.5). A signature made without a touch passes it. So touchgate
reads the flags itself, and does the whole check in one place.

Formats: PROTOCOL.sshsig and PROTOCOL.u2f in the OpenSSH source.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct
from dataclasses import dataclass
from enum import IntFlag, StrEnum
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

if TYPE_CHECKING:
    from collections.abc import Collection

MAGIC = b"SSHSIG"
VERSION = 1
BEGIN = "-----BEGIN SSH SIGNATURE-----"
END = "-----END SSH SIGNATURE-----"
NISTP256 = "nistp256"

HASHES = frozenset({"sha256", "sha512"})


class BadSignature(Exception):
    pass


class KeyType(StrEnum):
    ED25519_SK = "sk-ssh-ed25519@openssh.com"
    ECDSA_SK = "sk-ecdsa-sha2-nistp256@openssh.com"


class SkFlags(IntFlag):
    USER_PRESENCE = 0x01
    USER_VERIFICATION = 0x04


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def take(self, size: int) -> bytes:
        if self.at + size > len(self.data):
            raise BadSignature("a truncated signature")
        chunk = self.data[self.at : self.at + size]
        self.at += size
        return chunk

    def uint32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def byte(self) -> int:
        return self.take(1)[0]

    def string(self) -> bytes:
        return self.take(self.uint32())

    def text(self) -> str:
        try:
            return self.string().decode()
        except UnicodeDecodeError:
            raise BadSignature("a name that is not UTF-8") from None

    def end(self) -> None:
        if self.at != len(self.data):
            raise BadSignature("bytes after the signature")


def wire_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


@dataclass(frozen=True, slots=True)
class SkPublicKey:
    "A security key's public key. `blob` is its wire form, which also names the application."

    type: KeyType
    point: bytes
    application: str
    blob: bytes

    @classmethod
    def from_blob(cls, blob: bytes) -> SkPublicKey:
        reader = _Reader(blob)
        name = reader.text()
        try:
            type = KeyType(name)
        except ValueError:
            raise BadSignature("a %s key, not a security key" % name) from None
        if type is KeyType.ECDSA_SK and reader.text() != NISTP256:
            raise BadSignature("an ECDSA key on a curve other than %s" % NISTP256)
        point = reader.string()
        application = reader.text()
        reader.end()
        return cls(type, point, application, blob)

    @classmethod
    def from_line(cls, line: str) -> SkPublicKey:
        "One line as OpenSSH writes a public key: type, base64, and a comment."
        parts = line.split()
        if len(parts) < 2:
            raise BadSignature("not a public key line")
        try:
            key = cls.from_blob(base64.b64decode(parts[1], validate=True))
        except binascii.Error:
            raise BadSignature("a public key that is not base64") from None
        if key.type != parts[0]:
            raise BadSignature("a public key line whose type does not match its key")
        return key

    def check(self, data: bytes, signature: bytes) -> None:
        "Raises InvalidSignature unless `signature` is this key's over `data`."
        match self.type:
            case KeyType.ED25519_SK:
                Ed25519PublicKey.from_public_bytes(self.point).verify(signature, data)
            case KeyType.ECDSA_SK:
                parts = _Reader(signature)
                r = int.from_bytes(parts.string(), "big", signed=True)
                s = int.from_bytes(parts.string(), "big", signed=True)
                parts.end()
                public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.point)
                public.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))


@dataclass(frozen=True, slots=True)
class Verified:
    key: SkPublicKey
    flags: SkFlags
    counter: int


def signed_data(namespace: str, hash_name: str, message: bytes) -> bytes:
    "What the key signs for `message`, before the security key's own framing."
    return (
        MAGIC
        + wire_string(namespace.encode())
        + wire_string(b"")
        + wire_string(hash_name.encode())
        + wire_string(hashlib.new(hash_name, message).digest())
    )


def sk_framed(application: str, flags: int, counter: int, data: bytes) -> bytes:
    "What a security key signs: PROTOCOL.u2f, with no extensions."
    return (
        hashlib.sha256(application.encode()).digest()
        + bytes([flags])
        + struct.pack(">I", counter)
        + hashlib.sha256(data).digest()
    )


def dearmour(text: str) -> bytes:
    lines = [line.strip() for line in text.strip().splitlines()]
    if len(lines) < 3 or lines[0] != BEGIN or lines[-1] != END:
        raise BadSignature("not an SSH signature")
    try:
        return base64.b64decode("".join(lines[1:-1]), validate=True)
    except binascii.Error:
        raise BadSignature("an SSH signature that is not base64") from None


def verify(armoured: str, message: bytes, namespace: str, allowed: Collection[SkPublicKey]) -> Verified:
    "Checks that a key in `allowed` signed `message` in `namespace`, with a touch."
    reader = _Reader(dearmour(armoured))
    if reader.take(len(MAGIC)) != MAGIC:
        raise BadSignature("not an SSH signature")
    if reader.uint32() != VERSION:
        raise BadSignature("an SSH signature version this does not read")
    key = SkPublicKey.from_blob(reader.string())
    signed_namespace = reader.text()
    reader.string()  # reserved
    hash_name = reader.text()
    signature = reader.string()
    reader.end()

    if signed_namespace != namespace:
        raise BadSignature("a signature for %r, not %r" % (signed_namespace, namespace))
    if hash_name not in HASHES:
        raise BadSignature("a signature over a %s hash" % hash_name)
    if key.blob not in {each.blob for each in allowed}:
        raise BadSignature("a key that may not approve")

    inner = _Reader(signature)
    if inner.text() != key.type:
        raise BadSignature("a signature whose type does not match its key")
    raw = inner.string()
    flags = SkFlags(inner.byte())
    counter = inner.uint32()
    inner.end()

    try:
        key.check(sk_framed(key.application, flags, counter, signed_data(namespace, hash_name, message)), raw)
    except (InvalidSignature, ValueError):
        raise BadSignature("a signature that does not verify") from None
    if SkFlags.USER_PRESENCE not in flags:
        raise BadSignature("a signature made without a touch")
    return Verified(key, flags, counter)
