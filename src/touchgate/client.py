"""
`touchgate run`: ask the broker, get the challenge signed by the security
key, and hand back what the broker releases.
"""

from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

import anyio

from .approval import NAMESPACE, ApprovalError, ExecMode
from .broker import ask

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping
    from pathlib import Path

#: Signs challenge bytes and answers an armoured SSH signature.
type Signer = Callable[[bytes], Awaitable[str]]


async def ssh_sign(key: Path, challenge: bytes) -> str:
    "Signs with `ssh-keygen`. A `.pub` key means the private half is in the agent."
    command = ["ssh-keygen", "-Y", "sign", "-n", NAMESPACE, "-f", str(key)]
    if key.suffix == ".pub":
        command.append("-U")
    # stderr stays on the terminal: ssh-keygen asks for the touch there.
    done = await anyio.run_process(command, input=challenge, stderr=None, check=False)
    if done.returncode != 0:
        raise ApprovalError("ssh-keygen could not sign (exit %d)" % done.returncode)
    return done.stdout.decode()


async def request(
    socket: Path,
    secret: str,
    argv: list[str],
    *,
    cwd: str,
    requester: str | None,
    mode: ExecMode,
    env: Mapping[str, str],
) -> tuple[str, bytes]:
    "Asks for `secret` for `argv`, and answers the request id and its challenge."
    reply = await ask(
        socket,
        {
            "op": "request",
            "secret": secret,
            "argv": argv,
            "cwd": cwd,
            "requester": requester,
            "exec": mode,
            "env": dict(env),
        },
    )
    if not reply.get("ok"):
        raise ApprovalError(str(reply.get("error")))
    return str(reply["id"]), str(reply["challenge"]).encode()


async def approved_env(
    socket: Path,
    secret: str,
    argv: list[str],
    sign: Signer,
    *,
    cwd: str,
    requester: str | None,
    env: Mapping[str, str],
    announce: Callable[[str], None],
) -> dict[str, str]:
    "The values for `argv`, once the key signs. The client starts the command itself."
    id, challenge = await request(socket, secret, argv, cwd=cwd, requester=requester, mode=ExecMode.CLIENT, env=env)
    announce("touch the key to give %s to: %s (request %s)" % (secret, shlex.join(argv), id))
    answer = await ask(socket, {"op": "approve", "id": id, "signature": await sign(challenge)})
    if not answer.get("ok"):
        raise ApprovalError(str(answer.get("error")))
    values = answer["env"]
    if not isinstance(values, dict):
        raise ApprovalError("the broker answered no values")
    return {str(name): str(value) for name, value in values.items()}
