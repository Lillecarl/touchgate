"""
A security key in software, for tests: it makes `sk-ssh-ed25519`
signatures with whatever flags a test asks for, a missing touch included.
The OpenSSH vectors in test_sshsig.py prove the format matches a real key.
"""

from __future__ import annotations

import base64
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from touchgate.sshsig import BEGIN, END, MAGIC, VERSION, KeyType, SkFlags, signed_data, sk_framed, wire_string

TOUCH = SkFlags.USER_PRESENCE
PLAIN_ED25519 = "ssh-ed25519"


def armour(blob: bytes) -> str:
    text = base64.b64encode(blob).decode()
    return "\n".join([BEGIN, *(text[at : at + 70] for at in range(0, len(text), 70)), END]) + "\n"


def _sshsig(public_blob: bytes, namespace: str, hash_name: str, signature: bytes) -> str:
    return armour(
        MAGIC
        + struct.pack(">I", VERSION)
        + wire_string(public_blob)
        + wire_string(namespace.encode())
        + wire_string(b"")
        + wire_string(hash_name.encode())
        + wire_string(signature)
    )


class SoftKey:
    def __init__(self, application: str = "ssh:") -> None:
        self.private = Ed25519PrivateKey.generate()
        self.application = application
        point = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.blob = wire_string(KeyType.ED25519_SK.encode()) + wire_string(point) + wire_string(application.encode())

    def line(self) -> str:
        return "%s %s soft key" % (KeyType.ED25519_SK, base64.b64encode(self.blob).decode())

    def sign(
        self,
        message: bytes,
        namespace: str = "touchgate",
        *,
        flags: int = TOUCH,
        counter: int = 1,
        hash_name: str = "sha512",
    ) -> str:
        framed = sk_framed(self.application, flags, counter, signed_data(namespace, hash_name, message))
        inner = (
            wire_string(KeyType.ED25519_SK.encode())
            + wire_string(self.private.sign(framed))
            + bytes([flags])
            + struct.pack(">I", counter)
        )
        return _sshsig(self.blob, namespace, hash_name, inner)


def plain_signature(message: bytes, namespace: str = "touchgate") -> str:
    "An ordinary ed25519 signature: valid, and from no security key."
    private = Ed25519PrivateKey.generate()
    point = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    blob = wire_string(PLAIN_ED25519.encode()) + wire_string(point)
    inner = wire_string(PLAIN_ED25519.encode()) + wire_string(private.sign(signed_data(namespace, "sha512", message)))
    return _sshsig(blob, namespace, "sha512", inner)
