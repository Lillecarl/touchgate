"""
The cryptography against vectors from Bitwarden's own client tests, which
touchgate did not write. docs/protocol.md §10 says where each comes from.
"""

from __future__ import annotations

import base64
import hashlib
import os

import pytest
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from sealing import encrypt
from touchgate.crypto import (
    BadMac,
    Kdf,
    KdfType,
    SymmetricKey,
    Unsupported,
    WeakKdf,
    decrypt,
    master_key,
    password_hash,
    stretch,
    unwrap_rsa,
)

# libs/legacy-crypto/src/node/node-crypto-function.service.spec.ts:19-37 of bitwarden/clients.
RSA_PRIVATE_KEY = (
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXRVrCX+2hfOQS8Hz"
    "YUS2oc/jGVTZpv+/Ryuoh9d8ihYX9dd0cYh2tl6KWdFc88lPUH11Oxqy20Rk2e5r/RF6T9yM0Me3NPnaKt+hlhLtfoc0h86L"
    "nhD56A9FDUfuI0dVnPcrwNv0YJIo94LwxtbqBULNvXl6wJ7WAbODrCQy5ZgMVg+iH+gGpwiqsZqHt+KuoHWcN53MSPDfaF4/"
    "YMB99U3TziJMOOJask1TEEnakMPln11PczNDazT17DXIxYrbPfutPdh6sLs6AQOajdZijfEvepgnOe7cQ7aeatiOJFrjTApK"
    "PGxOVRzEMX4XS4xbyhH0QxQeB6l16l8C0uxIBAgMBAAECggEASaWfeVDA3cVzOPFSpvJm20OTE+R6uGOU+7vh36TX/POq92q"
    "Buwbd0h0oMD32FxsXywd2IxtBDUSiFM9699qufTVuM0Q3tZw6lHDTOVG08+tPdr8qSbMtw7PGFxN79fHLBxejjO4IrM9lapj"
    "WpxEF+11x7r+wM+0xRZQ8sNFYG46aPfIaty4BGbL0I2DQ2y8I57iBCAy69eht59NLMm27fRWGJIWCuBIjlpfzET1j2HLXUIh"
    "5bTBNzqaN039WH49HczGE3mQKVEJZc/efk3HaVd0a1Sjzyn0QY+N1jtZN3jTRbuDWA1AknkX1LX/0tUhuS3/7C3ejHxjw4Dk"
    "1ZLo5/QKBgQDIWvqFn0+IKRSu6Ua2hDsufIHHUNLelbfLUMmFthxabcUn4zlvIscJO00Tq/ezopSRRvbGiqnxjv/mYxucvOU"
    "BeZtlus0Q9RTACBtw9TGoNTmQbEunJ2FOSlqbQxkBBAjgGEppRPt30iGj/VjAhCATq2MYOa/X4dVR51BqQAFIEwKBgQDBSIf"
    "TFKC/hDk6FKZlgwvupWYJyU9RkyfstPErZFmzoKhPkQ3YORo2oeAYmVUbS9I2iIYpYpYQJHX8jMuCbCz4ONxTCuSIXYQYUcU"
    "q4PglCKp31xBAE6TN8SvhfME9/MvuDssnQinAHuF0GDAhF646T3LLS1not6Vszv7brwSoGwKBgQC88v/8cGfi80ssQZeMnVv"
    "q1UTXIeQcQnoY5lGHJl3K8mbS3TnXE6c9j417Fdz+rj8KWzBzwWXQB5pSPflWcdZO886Xu/mVGmy9RWgLuVFhXwCwsVEPjNX"
    "5ramRb0/vY0yzenUCninBsIxFSbIfrPtLUYCc4hpxr+sr2Mg/y6jpvQKBgBezMRRs3xkcuXepuI2R+BCXL1/b02IJTUf1F+1"
    "eLLGd7YV0H+J3fgNc7gGWK51hOrF9JBZHBGeOUPlaukmPwiPdtQZpu4QNE3l37VlIpKTF30E6mb+BqR+nht3rUjarnMXgAoE"
    "Z18y6/KIjpSMpqC92Nnk/EBM9EYe6Cf4eA9ApAoGAeqEUg46UTlJySkBKURGpIs3v1kkf5I0X8DnOhwb+HPxNaiEdmO7ckm8"
    "+tPVgppLcG0+tMdLjigFQiDUQk2y3WjyxP5ZvXu7U96jaJRI8PFMoE06WeVYcdIzrID2HvqH+w0UQJFrLJ/0Mn4stFAEzXKZ"
    "BokBGnjFnTnKcs7nv/O8="
)
# The same file, :169-173.
RSA_CIPHERTEXT = (
    "A1/p8BQzN9UrbdYxUY2Va5+kPLyfZXF9JsZrjeEXcaclsnHurdxVAJcnbEqYMP3UXV"
    "4YAS/mpf+Rxe6/X0WS1boQdA0MAHSgx95hIlAraZYpiMLLiJRKeo2u8YivCdTM9V5vuAEJwf9Tof/qFsFci3sApdbATkorCT"
    "zFOIEPF2S1zgperEP23M01mr4dWVdYN18B32YF67xdJHMbFhp5dkQwv9CmscoWq7OE5HIfOb+JAh7BEZb+CmKhM3yWJvoR/D"
    "/5jcercUtK2o+XrzNrL4UQ7yLZcFz6Bfwb/j6ICYvqd/YJwXNE6dwlL57OfwJyCdw2rRYf0/qI00t9u8Iitw=="
)

PBKDF2_5000 = Kdf(KdfType.PBKDF2_SHA256, 5000)


def _b64(text: str) -> bytes:
    return base64.b64decode(text)


@pytest.mark.parametrize(
    ("password", "email", "expected"),
    [
        # :45-47 and :198-239. The salt is already the normalised email, so these are master keys.
        ("password", "user@example.com", "pj9prw/OHPleXI6bRdmlaD+saJS4awrMiQsQiDjeu2I="),
        ("😀password🙏", "user@example.com", "ZdeOata6xoRpB4DLp8zHhXz5kLmkWtX5pd+TdRH8w8w="),
        # The email is trimmed and lowercased before it salts anything.
        ("password", "  User@Example.COM ", "pj9prw/OHPleXI6bRdmlaD+saJS4awrMiQsQiDjeu2I="),
    ],
)
def test_a_pbkdf2_master_key_matches_bitwarden(password, email, expected):
    assert master_key(password, email, PBKDF2_5000) == _b64(expected)


def test_hkdf_expand_matches_bitwarden():
    "The primitive under the stretch: expand only. :76-90."
    prk = _b64("F5h4KdYQnIVH4rKH0P9CZb1GrR4n16/sJrS0PsQEn0Y=")
    assert HKDFExpand(hashes.SHA256(), 32, b"info").derive(prk) == _b64("BnIqJlfnHm0e/2iB/15cbHyR19ARPIcWRp4oNS22CD8=")


def test_the_stretch_expands_enc_and_mac():
    key = _b64("pj9prw/OHPleXI6bRdmlaD+saJS4awrMiQsQiDjeu2I=")
    stretched = stretch(key)
    assert stretched.enc == HKDFExpand(hashes.SHA256(), 32, b"enc").derive(key)
    assert stretched.mac == HKDFExpand(hashes.SHA256(), 32, b"mac").derive(key)


def test_an_organisation_key_unwraps_with_rsa_oaep_sha1():
    "The type of an organisation key. :165-177."
    assert unwrap_rsa("4." + RSA_CIPHERTEXT, _b64(RSA_PRIVATE_KEY)) == b"EncryptMe!"


def test_the_password_hash_is_padded_base64():
    "The server compares it as text (docs/protocol.md §2.2)."
    hashed = password_hash(_b64("pj9prw/OHPleXI6bRdmlaD+saJS4awrMiQsQiDjeu2I="), "password")
    assert len(hashed) == 44 and hashed.endswith("=")


def _key() -> SymmetricKey:
    return SymmetricKey.from_bytes(os.urandom(64))


def test_a_value_opens_with_its_key():
    key = _key()
    assert decrypt(encrypt(b"hunter2", key), key) == b"hunter2"


def test_a_changed_ciphertext_fails_the_mac():
    key = _key()
    kind, rest = encrypt(b"hunter2", key).split(".")
    iv, ciphertext, mac = rest.split("|")
    flipped = bytearray(_b64(ciphertext))
    flipped[0] ^= 1
    with pytest.raises(BadMac):
        decrypt("%s.%s|%s|%s" % (kind, iv, base64.b64encode(flipped).decode(), mac), key)


def test_a_value_opens_with_no_other_key():
    with pytest.raises(BadMac):
        decrypt(encrypt(b"hunter2", _key()), _key())


def test_a_type_2_without_its_mac_is_refused():
    "rbw reads this and skips the MAC check."
    iv, ciphertext, _mac = encrypt(b"hunter2", _key())[2:].split("|")
    with pytest.raises(Unsupported):
        decrypt("2.%s|%s" % (iv, ciphertext), _key())


@pytest.mark.parametrize("kind", ["0", "1", "3", "5", "6", "7", ""])
def test_other_types_are_refused(kind):
    body = encrypt(b"hunter2", _key())[2:]
    with pytest.raises(Unsupported):
        decrypt(("%s.%s" % (kind, body)) if kind else body, _key())


@pytest.mark.parametrize(
    "kdf",
    [
        Kdf(KdfType.PBKDF2_SHA256, 4999),
        Kdf(KdfType.ARGON2ID, 1, 64, 4),
        Kdf(KdfType.ARGON2ID, 3, 15, 4),
        Kdf(KdfType.ARGON2ID, 3, 64, 0),
        Kdf(KdfType.ARGON2ID, 3),
    ],
)
def test_weak_kdf_settings_are_refused(kdf):
    "A server that asks for these may be downgrading the account."
    with pytest.raises(WeakKdf):
        kdf.checked()


def test_an_argon2id_master_key_is_salted_by_the_email_hash():
    "No published vector; argon2-cffi computes the same thing from the documented inputs."
    kdf = Kdf(KdfType.ARGON2ID, 2, 16, 1)
    expected = hash_secret_raw(
        b"password",
        hashlib.sha256(b"user@example.com").digest(),
        time_cost=2,
        memory_cost=16 * 1024,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
    assert master_key("password", "User@example.com", kdf) == expected
