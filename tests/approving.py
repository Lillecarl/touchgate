"""
What the approval tests share: the request they make and a signer for it.
The broker and socket fixtures live in conftest.py.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authenticator import SoftKey

DEADLINE = 45
PASSWORD = "approval password"
ARGV = ["/usr/bin/psql", "--host", "db"]


def signer(key: SoftKey, **options):
    async def sign(challenge: bytes) -> str:
        return key.sign(challenge, **options)

    return sign
