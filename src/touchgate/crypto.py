"""
The vault cryptography of a Bitwarden account, read side only.

`docs/protocol.md` is the specification, with a source citation for
every rule here. Sections are named as `protocol.md §N`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Self

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

__all__ = [
    "BadMac",
    "EncType",
    "Kdf",
    "KdfType",
    "SymmetricKey",
    "Unsupported",
    "VaultCryptoError",
    "WeakKdf",
    "decrypt",
    "master_key",
    "normalised_email",
    "password_hash",
    "stretch",
    "unwrap_rsa",
]

KEY_LENGTH = 32
IV_LENGTH = 16


class VaultCryptoError(Exception):
    "A vault value that does not open. The message never holds key or plaintext material."


class BadMac(VaultCryptoError):
    "The MAC does not match: a wrong key, or a value someone changed. On the user key it means a wrong password."


class Unsupported(VaultCryptoError):
    "An encryption type this client refuses to read."


class WeakKdf(VaultCryptoError):
    "KDF settings below what the official clients accept: a server that asks for them may be downgrading the account."


class KdfType(IntEnum):
    PBKDF2_SHA256 = 0
    ARGON2ID = 1


@dataclass(frozen=True, slots=True)
class Kdf:
    """
    How the master key is derived. For Argon2id, `iterations` is the
    time cost and `memory` is in MiB, as on the wire.
    """

    type: KdfType
    iterations: int
    memory: int | None = None
    parallelism: int | None = None

    def checked(self) -> Self:
        "The official clients' floors (protocol.md §1). Applied before deriving anything."
        if self.type is KdfType.PBKDF2_SHA256:
            if self.iterations < 5000:
                raise WeakKdf("PBKDF2 with %d iterations, below 5000" % self.iterations)
        elif self.memory is None or self.parallelism is None:
            raise WeakKdf("Argon2id without memory or parallelism")
        elif self.iterations < 2 or self.memory < 16 or self.parallelism < 1:
            raise WeakKdf(
                "Argon2id with t=%d m=%d p=%d, below t=2 m=16 p=1" % (self.iterations, self.memory, self.parallelism)
            )
        return self


@dataclass(frozen=True, slots=True)
class SymmetricKey:
    "A 64-byte vault key: AES-256 key, then HMAC-SHA256 key."

    enc: bytes = field(repr=False)
    mac: bytes = field(repr=False)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        if len(data) != 2 * KEY_LENGTH:
            raise VaultCryptoError("a vault key is 64 bytes, not %d" % len(data))
        return cls(data[:KEY_LENGTH], data[KEY_LENGTH:])


class EncType(IntEnum):
    AES_CBC_256_HMAC_SHA256 = 2
    RSA_2048_OAEP_SHA1 = 4


def normalised_email(email: str) -> str:
    "The salt's spelling of an email (protocol.md §2, §9.1)."
    return email.strip().lower()


def master_key(password: str, email: str, kdf: Kdf) -> bytes:
    "protocol.md §2.1. The caller checks `kdf` first."
    secret = password.encode("utf-8")
    salt = normalised_email(email).encode("utf-8")
    if kdf.type is KdfType.PBKDF2_SHA256:
        return hashlib.pbkdf2_hmac("sha256", secret, salt, kdf.iterations, KEY_LENGTH)
    if kdf.memory is None or kdf.parallelism is None:
        raise WeakKdf("Argon2id without memory or parallelism")
    return hash_secret_raw(
        secret,
        # A hash of the email, not the email.
        hashlib.sha256(salt).digest(),
        time_cost=kdf.iterations,
        memory_cost=kdf.memory * 1024,
        parallelism=kdf.parallelism,
        hash_len=KEY_LENGTH,
        type=Type.ID,
        version=19,
    )


def password_hash(key: bytes, password: str) -> str:
    """
    What the server sees in place of the password (protocol.md §2.2).
    The master key is PBKDF2's password and the master password its salt.
    The server compares the text, so the padded spelling matters.
    """
    return base64.b64encode(hashlib.pbkdf2_hmac("sha256", key, password.encode("utf-8"), 1, KEY_LENGTH)).decode()


def stretch(key: bytes) -> SymmetricKey:
    "HKDF-Expand only, with no extract step (protocol.md §2.3)."

    def expand(info: bytes) -> bytes:
        return HKDFExpand(hashes.SHA256(), KEY_LENGTH, info).derive(key)

    return SymmetricKey(expand(b"enc"), expand(b"mac"))


def _parts(text: str, expected: EncType, count: int) -> list[bytes]:
    head, dot, body = text.partition(".")
    if not dot or not head.isdigit():
        # A string with no type is type 0, which carries no MAC.
        raise Unsupported("an encrypted value with no type")
    found = int(head)
    if found != expected:
        raise Unsupported("encryption type %d where %d (%s) was expected" % (found, expected, expected.name))
    pieces = body.split("|")
    if len(pieces) != count:
        # rbw reads a two-part type 2 and skips its MAC. Not here.
        raise Unsupported("type %d with %d parts, not %d" % (found, len(pieces), count))
    try:
        return [base64.b64decode(piece, validate=True) for piece in pieces]
    except ValueError:
        raise VaultCryptoError("an encrypted value that is not base64") from None


def decrypt(text: str, key: SymmetricKey) -> bytes:
    "A type 2 value: the MAC first, in constant time, then AES-256-CBC (protocol.md §6)."
    iv, ciphertext, mac = _parts(text, EncType.AES_CBC_256_HMAC_SHA256, 3)
    if len(iv) != IV_LENGTH:
        raise VaultCryptoError("an IV of %d bytes" % len(iv))
    expected = hmac.new(key.mac, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise BadMac("the MAC does not match")
    decryptor = Cipher(algorithms.AES(key.enc), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise VaultCryptoError("bad padding after a good MAC") from None


def unwrap_rsa(text: str, private_key_der: bytes) -> bytes:
    "A type 4 value, as an organisation key is: RSA-OAEP with SHA-1 (protocol.md §6)."
    (ciphertext,) = _parts(text, EncType.RSA_2048_OAEP_SHA1, 1)
    private_key = serialization.load_der_private_key(private_key_der, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise VaultCryptoError("the account's private key is not RSA")
    try:
        return private_key.decrypt(ciphertext, OAEP(mgf=MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
    except ValueError:
        raise VaultCryptoError("RSA decryption failed") from None
