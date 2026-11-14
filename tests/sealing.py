"""
The write side of the vault cryptography, which only the tests need: an
account's keys at registration, and values to tamper with.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from touchgate.crypto import SymmetricKey


def encrypt(plaintext: bytes, key: SymmetricKey, iv: bytes | None = None) -> str:
    "A type 2 value (docs/protocol.md §6)."
    iv = os.urandom(16) if iv is None else iv
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key.enc), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(key.mac, iv + ciphertext, hashlib.sha256).digest()
    return "2." + "|".join(base64.b64encode(part).decode() for part in (iv, ciphertext, mac))
