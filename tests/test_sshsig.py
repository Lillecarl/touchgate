"""
Security key signatures: OpenSSH's own vectors, and every way to be refused.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from authenticator import SoftKey, plain_signature
from touchgate.sshsig import BadSignature, SkFlags, SkPublicKey, verify

pytestmark = pytest.mark.timeout(10)

MESSAGE = b"approve: run db -- psql"


@pytest.fixture
def vectors() -> Path:
    "regress/unittests/sshsig/testdata from the OpenSSH source, made by OpenSSH with its test key."
    return Path(os.environ["TOUCHGATE_SSHSIG_VECTORS"])


@pytest.mark.parametrize("name", ["ed25519_sk", "ecdsa_sk"])
def test_openssh_signs_what_this_verifies(vectors, name):
    key = SkPublicKey.from_line((vectors / ("%s.pub" % name)).read_text())
    namespace = (vectors / "namespace").read_text().strip()
    data = (vectors / "signed-data").read_bytes()

    verified = verify((vectors / ("%s.sig" % name)).read_text(), data, namespace, [key])

    assert verified.key == key
    assert SkFlags.USER_PRESENCE in verified.flags
    with pytest.raises(BadSignature, match="does not verify"):
        verify((vectors / ("%s.sig" % name)).read_text(), data + b"!", namespace, [key])


def test_openssh_signatures_that_are_no_plain_security_key_signature_are_refused(vectors):
    namespace = (vectors / "namespace").read_text().strip()
    data = (vectors / "signed-data").read_bytes()
    with pytest.raises(BadSignature, match="not a security key"):
        SkPublicKey.from_line((vectors / "ed25519.pub").read_text())
    # A WebAuthn signature frames the data in a browser's JSON, which this does not read.
    webauthn = SkPublicKey.from_line((vectors / "ecdsa_sk_webauthn.pub").read_text())
    with pytest.raises(BadSignature, match="does not match its key"):
        verify((vectors / "ecdsa_sk_webauthn.sig").read_text(), data, namespace, [webauthn])


def test_a_touch_signature_verifies():
    key = SoftKey()
    allowed = [SkPublicKey.from_line(key.line())]
    assert verify(key.sign(MESSAGE), MESSAGE, "touchgate", allowed).counter == 1
    assert verify(key.sign(MESSAGE, hash_name="sha256"), MESSAGE, "touchgate", allowed).key == allowed[0]


def test_no_touch_is_refused():
    key = SoftKey()
    allowed = [SkPublicKey.from_line(key.line())]
    with pytest.raises(BadSignature, match="without a touch"):
        verify(key.sign(MESSAGE, flags=SkFlags.USER_VERIFICATION), MESSAGE, "touchgate", allowed)


def test_refusals():
    key = SoftKey()
    allowed = [SkPublicKey.from_line(key.line())]
    with pytest.raises(BadSignature, match="may not approve"):
        verify(SoftKey().sign(MESSAGE), MESSAGE, "touchgate", allowed)
    with pytest.raises(BadSignature, match="may not approve"):
        # The same point under another application is another key.
        verify(SoftKey(application="ssh:other").sign(MESSAGE), MESSAGE, "touchgate", allowed)
    with pytest.raises(BadSignature, match="not 'touchgate'"):
        verify(key.sign(MESSAGE, namespace="git"), MESSAGE, "touchgate", allowed)
    with pytest.raises(BadSignature, match="does not verify"):
        verify(key.sign(MESSAGE), MESSAGE + b" and more", "touchgate", allowed)
    with pytest.raises(BadSignature, match="sha1"):
        verify(key.sign(MESSAGE, hash_name="sha1"), MESSAGE, "touchgate", allowed)
    with pytest.raises(BadSignature, match="not a security key"):
        verify(plain_signature(MESSAGE), MESSAGE, "touchgate", allowed)
    with pytest.raises(BadSignature, match="not an SSH signature"):
        verify("hello", MESSAGE, "touchgate", allowed)
