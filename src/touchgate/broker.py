"""
The broker: a user service that holds the unlocked vault in memory and
answers on a unix socket, one JSON request per connection.

The socket's directory is private to the user. Every process of the user
can still connect, agents included, so nothing the socket answers may
give a secret away without an approval the broker verifies itself.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import logging
import os
import signal
import sys
from typing import TYPE_CHECKING, Annotated, Literal

import anyio
import anyio.abc
from anyio.abc import UNIXSocketStream
from pydantic import BaseModel, Field, TypeAdapter, ValidationError

from .approval import NAMESPACE, ApprovalError, ExecMode, Requests, approvers, variables
from .sshsig import BadSignature, SkPublicKey, verify
from .vault import LoginFailed, Vault, open_vault

if TYPE_CHECKING:
    from pathlib import Path

    import httpx2

    from .config import Config
    from .vault import Device

log = logging.getLogger(__name__)

#: One request is small; a client that sends more is not a client.
MAX_REQUEST = 64 * 1024
#: A connection that says nothing for this long is closed.
IDLE = 10

PR_SET_DUMPABLE = 4

#: stdin, stdout and stderr, which a broker run receives from its client.
STDIO = 3
#: The signals a client passes on to the command the broker runs for it.
RELAYED = frozenset({signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGWINCH})
#: Variables that load code into the command. The client's environment is its own claim,
#: and these would let it run its code inside the approved command.
LOADER_PREFIXES = ("LD_", "DYLD_")


class Unlock(BaseModel):
    op: Literal["unlock"]
    password: str = Field(repr=False)


class Status(BaseModel):
    op: Literal["status"]


class Lock(BaseModel):
    op: Literal["lock"]


class Ask(BaseModel):
    "Asks for a secret. The answer is a challenge to sign, never a value."

    op: Literal["request"]
    secret: str
    argv: list[str] = Field(min_length=1)
    cwd: str
    requester: str | None = None
    exec: ExecMode = ExecMode.BROKER
    env: dict[str, str] = {}


class Approve(BaseModel):
    op: Literal["approve"]
    id: str
    signature: str = Field(repr=False)
    #: A broker run's base environment, from the client. The fds come with the message.
    environ: dict[str, str] = Field({}, repr=False)


class Relay(BaseModel):
    "Sent during a broker run: a signal for the command."

    signal: int


Request = Annotated[Unlock | Status | Lock | Ask | Approve, Field(discriminator="op")]
REQUEST: TypeAdapter[Request] = TypeAdapter(Request)


def not_dumpable() -> None:
    """
    Agents run as the same user, and ptrace would read the vault out of
    this process. A process that is not dumpable cannot be attached by
    an unprivileged process of the same user.
    """
    if sys.platform != "linux":
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")


class Broker:
    def __init__(self, config: Config, device: Device, transport: httpx2.AsyncBaseTransport | None = None) -> None:
        self.config = config
        self.device = device
        self.transport = transport
        self.vault: Vault | None = None
        self.approvers: tuple[SkPublicKey, ...] = ()
        self.requests = Requests()
        self._unlocking = anyio.Lock()

    async def unlock(self, password: str) -> None:
        async with self._unlocking:
            self.vault = await open_vault(
                self.config.endpoints, self.config.email, password, self.device, transport=self.transport
            )
            self.approvers = approvers(self.vault)
        log.info("unlocked: %d items, %d approver keys", len(self.vault.items), len(self.approvers))

    def lock(self) -> None:
        self.vault = None
        self.approvers = ()
        self.requests.clear()

    def ask(self, request: Ask) -> dict[str, object]:
        if self.vault is None:
            raise ApprovalError("the broker is locked")
        pending = self.requests.add(
            self.vault, request.secret, tuple(request.argv), request.cwd, request.requester, request.exec, request.env
        )
        log.info("request %s: %s for %s", pending.id, pending.secret, pending.argv[0])
        return {"ok": True, "id": pending.id, "challenge": pending.challenge.decode(), "expires": pending.expires}

    async def approve(self, request: Approve, lines: Lines, fds: list[int]) -> dict[str, object]:
        pending = self.requests.take(request.id)
        if self.vault is None:
            raise ApprovalError("the broker is locked")
        if pending.mode is ExecMode.BROKER and len(fds) != STDIO:
            raise ApprovalError("a broker run passes stdin, stdout and stderr with its approve")
        try:
            verify(request.signature, pending.challenge, NAMESPACE, self.approvers)
        except BadSignature as refused:
            log.warning("request %s refused: %s", pending.id, refused)
            raise ApprovalError("refused: %s" % refused) from None
        try:
            item = self.vault.find(pending.item_id)
        except KeyError:
            raise ApprovalError("%r left the vault" % pending.secret) from None
        values = {name: value.value for name, value in variables(item, pending.explicit).items()}
        log.info("request %s approved", pending.id)
        match pending.mode:
            case ExecMode.CLIENT:
                return {"ok": True, "env": values}
            case ExecMode.BROKER:
                environment = {
                    name: value for name, value in request.environ.items() if not name.startswith(LOADER_PREFIXES)
                }
                code = await _run(pending.argv, pending.cwd, environment | values, fds, lines)
                log.info("request %s: the command exited %d", pending.id, code)
                return {"ok": True, "exit": code}

    async def answer(self, request: Request, lines: Lines, fds: list[int]) -> dict[str, object]:
        match request:
            case Unlock(password=password):
                try:
                    await self.unlock(password)
                except LoginFailed as refused:
                    return {"ok": False, "error": str(refused)}
                return {"ok": True}
            case Status():
                items = None if self.vault is None else len(self.vault.items)
                return {"ok": True, "unlocked": self.vault is not None, "items": items}
            case Lock():
                self.lock()
                return {"ok": True}
            case Ask():
                return self.ask(request)
            case Approve():
                return await self.approve(request, lines, fds)

    async def serve_one(self, stream: anyio.abc.ByteStream) -> None:
        fds: list[int] = []
        async with stream:
            try:
                with anyio.fail_after(IDLE):
                    first = b""
                    if isinstance(stream, UNIXSocketStream):
                        first, fds = await stream.receive_fds(MAX_REQUEST, STDIO)
                    lines = Lines(stream, first)
                    data = await lines.next()
                reply = await self.answer(REQUEST.validate_json(data), lines, fds)
            except (TimeoutError, anyio.EndOfStream, anyio.BrokenResourceError):
                return
            except ValidationError as error:
                # The error names fields, never their values: `input` is dropped.
                reply = {"ok": False, "error": "a request this broker does not read: %s" % _fields(error)}
            except (ApprovalError, ValueError) as error:
                reply = {"ok": False, "error": str(error)}
            except Exception:
                # An exception here would end the listener, and every later client with it.
                log.exception("a request failed")
                reply = {"ok": False, "error": "the broker failed; its log says why"}
            finally:
                for fd in fds:
                    os.close(fd)
            with contextlib.suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
                await stream.send(json.dumps(reply).encode() + b"\n")

    async def serve(self, path: Path, *, task_status: anyio.abc.TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        path.unlink(missing_ok=True)
        listener = await anyio.create_unix_listener(path)
        os.chmod(path, 0o600)
        async with listener:
            task_status.started()
            await listener.serve(self.serve_one)


def _fields(error: ValidationError) -> str:
    return ", ".join(".".join(str(part) for part in each["loc"]) or "(the request)" for each in error.errors())


class Lines:
    "Newline-ended messages from a stream. A line over MAX_REQUEST is an error."

    def __init__(self, stream: anyio.abc.ByteReceiveStream, buffered: bytes = b"") -> None:
        self.stream = stream
        self.buffer = buffered

    async def next(self) -> bytes:
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_REQUEST:
                raise ValueError("a request over %d bytes" % MAX_REQUEST)
            self.buffer += await self.stream.receive()
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line


async def _run(argv: tuple[str, ...], cwd: str, environment: dict[str, str], fds: list[int], lines: Lines) -> int:
    """
    Runs the approved command on the client's stdio, and relays the
    client's signals to it. A client that goes away ends the command.
    The child execs, so it shares none of the broker's memory.
    """
    async with await anyio.open_process(
        list(argv), stdin=fds[0], stdout=fds[1], stderr=fds[2], cwd=cwd, env=environment
    ) as process:

        def end() -> None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()

        async def relay() -> None:
            try:
                while True:
                    number = Relay.model_validate_json(await lines.next()).signal
                    if number in RELAYED:
                        with contextlib.suppress(ProcessLookupError):
                            process.send_signal(signal.Signals(number))
            except (anyio.EndOfStream, anyio.BrokenResourceError, ValidationError, ValueError):
                end()

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(relay)
            code = await process.wait()
            tasks.cancel_scope.cancel()
    return code


async def ask(path: Path, request: dict[str, object]) -> dict[str, object]:
    "One request to the broker at `path`, and its answer."
    async with await anyio.connect_unix(path) as stream:
        await stream.send(json.dumps(request).encode() + b"\n")
        return json.loads(await Lines(stream).next())
