"""
`touchgate run`: ask the broker, get the challenge signed by the security
key, and hand back what the broker releases.
"""

from __future__ import annotations

import json
import shlex
import time
from typing import TYPE_CHECKING

import anyio

from .approval import NAMESPACE, ApprovalError, ExecMode
from .broker import MAX_REQUEST, RELAYED, Lines, ask

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
    announce(describe(challenge))
    answer = await ask(socket, {"op": "approve", "id": id, "signature": await sign(challenge)})
    if not answer.get("ok"):
        raise ApprovalError(str(answer.get("error")))
    values = answer["env"]
    if not isinstance(values, dict):
        raise ApprovalError("the broker answered no values")
    return {str(name): str(value) for name, value in values.items()}


async def run_in_broker(
    socket: Path,
    secret: str,
    argv: list[str],
    sign: Signer,
    *,
    cwd: str,
    requester: str | None,
    env: Mapping[str, str],
    environ: Mapping[str, str],
    announce: Callable[[str], None],
    stdio: tuple[int, int, int] = (0, 1, 2),
) -> int:
    """
    Once the key signs, the broker runs `argv` on this process's stdio,
    so the values reach only the approved command. Answers its exit code.
    """
    # The approve carries the environment. Too large, and the broker would refuse it after the touch.
    if len(json.dumps(dict(environ))) > MAX_REQUEST // 2:
        raise ApprovalError("the environment is over %d bytes, too large to pass to the broker" % (MAX_REQUEST // 2))
    id, challenge = await request(socket, secret, argv, cwd=cwd, requester=requester, mode=ExecMode.BROKER, env=env)
    announce(describe(challenge))
    approve = {"op": "approve", "id": id, "signature": await sign(challenge), "environ": dict(environ)}
    async with await anyio.connect_unix(socket) as stream:
        await stream.send_fds(json.dumps(approve).encode() + b"\n", stdio)
        async with anyio.create_task_group() as tasks:

            async def relay() -> None:
                with anyio.open_signal_receiver(*RELAYED) as signals:
                    async for number in signals:
                        await stream.send(json.dumps({"signal": int(number)}).encode() + b"\n")

            tasks.start_soon(relay)
            answer = json.loads(await Lines(stream).next())
            tasks.cancel_scope.cancel()
    if not answer.get("ok"):
        raise ApprovalError(str(answer.get("error")))
    code = int(answer["exit"])
    # A command a signal ended exits as a shell reports it.
    return 128 - code if code < 0 else code


def describe(challenge: bytes) -> str:
    "Everything the challenge holds, for the person about to sign it."
    fields = json.loads(challenge)
    variables = ", ".join("%s from %s" % pair for pair in fields["variables"].items()) or "none"
    starter = "the broker" if fields["exec"] == ExecMode.BROKER else "this client, which gets the values"
    return "\n".join(
        [
            "touch the key to approve request %s:" % fields["id"],
            "  secret     %s (item %s)" % (fields["secret"], fields["item"]),
            "  command    %s" % shlex.join(fields["argv"]),
            "  directory  %s" % fields["cwd"],
            "  started by %s" % starter,
            "  variables  %s" % variables,
            "  requester  %s" % (fields["requester"] or "not in pymux"),
            "  expires    in %d seconds" % max(0, fields["expires"] - int(time.time())),
        ]
    )
