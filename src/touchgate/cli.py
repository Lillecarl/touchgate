"""
`touchgate broker` runs the service. `unlock`, `lock` and `status` talk
to it over its socket. `run` asks it for a secret and runs a command
with it, once a security key signs the request; `run --grant` asks for
more runs with no touch, and `grants` and `revoke` show and end them.
`enroll` seals the master password to a security key, which
`unlock --yubikey` then opens.
"""

from __future__ import annotations

import argparse
import functools
import getpass
import json
import logging
import os
import shutil
import signal
import sys

import anyio

from . import config, processes
from .approval import ApprovalError, Outcome
from .broker import Broker, Lines, ask, not_dumpable
from .client import approved_env, describe, run_in_broker, ssh_sign
from .display import show
from .grants import parse_duration
from .sealed import Fido2Key, Sealed, SealError, seal, unseal, write


async def _broker() -> int:
    not_dumpable()
    settings = config.load()
    broker = Broker(settings, config.device())
    credential = config.credential()
    if credential is not None:
        # systemd decrypted it for this service only. A trailing newline is the file's, not the password's.
        await broker.unlock((await anyio.Path(credential).read_text()).rstrip("\n"))
    await broker.serve(config.socket_path())
    return 0


async def _unlock(yubikey: bool) -> int:
    if yubikey:
        try:
            sealed = Sealed.loads(await anyio.Path(config.sealed_file()).read_text())
        except FileNotFoundError:
            raise config.ConfigError("no sealed password at %s; run touchgate enroll" % config.sealed_file()) from None
        password = await unseal(Fido2Key(_announce), sealed)
    else:
        password = await anyio.to_thread.run_sync(getpass.getpass, "Master password: ")
    return _report(await ask(config.socket_path(), {"op": "unlock", "password": password}))


async def _show(id: str) -> int:
    outcome = await show(config.socket_path(), id, functools.partial(print, flush=True))
    if outcome is None:
        return 1
    # The pymux popup closes when this ends: the person gets a moment to read the outcome.
    await anyio.sleep(2)
    return 0 if outcome is Outcome.APPROVED else 1


async def _enroll() -> int:
    password = await anyio.to_thread.run_sync(getpass.getpass, "Master password: ")
    if password != await anyio.to_thread.run_sync(getpass.getpass, "Again: "):
        raise SealError("the two passwords differ")
    # Two touches: one makes the credential, one derives the key from it.
    path = config.sealed_file()
    await write(path, await seal(Fido2Key(_announce), password))
    print(path)
    return 0


async def _popup(path: str) -> int:
    """
    On the machine with the key, in the popup the pymux plugin opens: read
    what a linked server asks, show it, and answer it with a touch.
    """
    async with await anyio.connect_unix(path) as stream:
        lines = Lines(stream)
        asked = json.loads(await lines.next())
        peer = str(asked.get("peer"))
        try:
            answer = await _answer_linked(peer, asked)
        except (config.ConfigError, ApprovalError, SealError, OSError) as error:
            print("touchgate: %s" % error, flush=True)
            answer = {"error": str(error)}
        await stream.send(json.dumps(answer).encode() + b"\n")
    if "error" in answer:
        await anyio.sleep(3)
    return 0 if "error" not in answer else 1


async def _answer_linked(peer: str, asked: dict[str, object]) -> dict[str, object]:
    match asked.get("op"):
        case "sign":
            challenge = str(asked.get("challenge")).encode()
            print("%s asks:\n%s" % (peer, describe(challenge)), flush=True)
            settings = config.load()
            if settings.signing_key is None:
                raise config.ConfigError("the configuration here names no `signing_key` to sign with")
            return {"signature": await ssh_sign(settings.signing_key, challenge)}
        case "unlock":
            print("%s asks for the master password, to unlock its touchgate broker." % peer, flush=True)
            try:
                sealed = Sealed.loads(await anyio.Path(config.sealed_file()).read_text())
            except FileNotFoundError:
                raise config.ConfigError("no sealed password here; run touchgate enroll") from None
            return {"password": await unseal(Fido2Key(_announce), sealed)}
        case op:
            raise ApprovalError("a linked server asks for %r, which touchgate does not do" % op)


def _announce(line: str) -> None:
    print("touchgate: %s" % line, file=sys.stderr, flush=True)


def _grant(args: argparse.Namespace) -> dict[str, object] | None:
    "The grant terms `run` asks for. The broker reads the anchor's facts from /proc itself."
    if args.grant is None:
        return None
    if args.client_exec:
        raise ApprovalError("a grant runs its commands in the broker, so it takes no --client-exec")
    anchor = args.grant_to
    if anchor is None:
        claude = processes.nearest_claude(os.getpid())
        if claude is None:
            raise ApprovalError("no Claude Code process runs above this one; name the anchor with --grant-to PID")
        anchor = claude.pid
    return {
        "seconds": parse_duration(args.grant),
        "uses": args.grant_uses,
        "prefix": args.grant_prefix,
        "anchor": anchor,
    }


async def _run(
    secret: str, command: list[str], env: dict[str, str], client_exec: bool, grant: dict[str, object] | None
) -> int:
    settings = config.load()
    path = shutil.which(command[0])
    if path is None:
        raise config.ConfigError("no command %r on PATH" % command[0])
    argv = [os.path.abspath(path), *command[1:]]
    # With no key here, the pymux plugin asks the linked machine that holds one.
    sign = None if settings.signing_key is None else functools.partial(ssh_sign, settings.signing_key)
    requester = os.environ.get("PYMUX")
    if not client_exec:
        return await run_in_broker(
            config.socket_path(),
            secret,
            argv,
            sign,
            cwd=os.getcwd(),
            requester=requester,
            env=env,
            environ=os.environ,
            announce=_announce,
            grant=grant,
        )
    values = await approved_env(
        config.socket_path(), secret, argv, sign, cwd=os.getcwd(), requester=requester, env=env, announce=_announce
    )
    # Python ignores SIGPIPE, and an exec keeps an ignored signal ignored.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    os.execve(argv[0], argv, os.environ | values)


def _pair(text: str) -> tuple[str, str]:
    name, separator, source = text.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError("%r is not NAME=SOURCE" % text)
    return name, source


async def _simple(op: str) -> int:
    return _report(await ask(config.socket_path(), {"op": op}))


async def _grants() -> int:
    answer = await ask(config.socket_path(), {"op": "grants"})
    if answer.get("ok"):
        print(json.dumps(answer["grants"], indent=2))
    return _report(answer)


async def _revoke(id: str | None) -> int:
    answer = await ask(config.socket_path(), {"op": "revoke", "id": id})
    if answer.get("ok"):
        print(json.dumps(answer["revoked"]))
    return _report(answer)


def _report(answer: dict[str, object]) -> int:
    if not answer.get("ok"):
        print("touchgate: %s" % answer.get("error"), file=sys.stderr)
        return 1
    if "unlocked" in answer:
        print("unlocked, %s items" % answer["items"] if answer["unlocked"] else "locked")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="touchgate", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("broker", help="Run the broker, which holds the vault.")
    unlock = commands.add_parser("unlock", help="Give the broker the master password.")
    unlock.add_argument("--yubikey", action="store_true", help="Open the password sealed by `enroll` with a touch.")
    commands.add_parser("enroll", help="Seal the master password to the security key plugged in here.")
    show_parser = commands.add_parser("show", help="Show a waiting request as the broker holds it, until it ends.")
    show_parser.add_argument("id", help="The request id.")
    popup = commands.add_parser("popup", help="Answer a linked server's request, in the pymux plugin's popup.")
    popup.add_argument("socket", help="The plugin's socket for this one request.")
    commands.add_parser("lock", help="Make the broker forget the vault.")
    commands.add_parser("status", help="Say whether the broker holds the vault.")
    commands.add_parser("grants", help="List the grants that hold, as JSON.")
    revoke = commands.add_parser("revoke", help="End a grant, or every grant.")
    which = revoke.add_mutually_exclusive_group(required=True)
    which.add_argument("id", nargs="?", help="The grant id, from `touchgate grants`.")
    which.add_argument("--all", action="store_true", help="End every grant.")
    run = commands.add_parser("run", help="Run a command with a secret, once a security key approves.")
    run.add_argument(
        "--env",
        action="append",
        type=_pair,
        default=[],
        metavar="NAME=SOURCE",
        help="Also set NAME from the item's username, password, notes or a field.",
    )
    run.add_argument(
        "--client-exec",
        action="store_true",
        help="Receive the values and start the command here. The broker then cannot hold you to the command.",
    )
    run.add_argument(
        "--grant",
        metavar="DURATION",
        help="Also approve later runs of this command, such as 8h or 30m, under one process tree, with no touch.",
    )
    run.add_argument(
        "--grant-to",
        type=int,
        metavar="PID",
        help="The process the grant holds under. Default: the nearest Claude Code process above this one.",
    )
    run.add_argument("--grant-uses", type=int, metavar="N", help="End the grant after N runs.")
    run.add_argument(
        "--grant-prefix",
        type=int,
        metavar="N",
        help="Grant any command whose first N words match this one. Default: the exact command.",
    )
    run.add_argument("secret", help="The vault item, by name or id.")
    run.add_argument("program", nargs=argparse.REMAINDER, help="-- and the command to run.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="touchgate: %(message)s")
    try:
        match args.command:
            case "broker":
                return anyio.run(_broker)
            case "unlock":
                return anyio.run(_unlock, bool(args.yubikey))
            case "enroll":
                return anyio.run(_enroll)
            case "show":
                return anyio.run(_show, str(args.id))
            case "popup":
                return anyio.run(_popup, str(args.socket))
            case "run":
                program: list[str] = args.program[1:] if args.program[:1] == ["--"] else args.program
                if not program:
                    parser.error("run needs a command after --")
                grant = _grant(args)
                return anyio.run(_run, str(args.secret), program, dict(args.env), bool(args.client_exec), grant)
            case "grants":
                return anyio.run(_grants)
            case "revoke":
                return anyio.run(_revoke, None if args.all else str(args.id))
            case command:
                return anyio.run(_simple, command)
    except (config.ConfigError, ApprovalError, SealError, OSError) as error:
        print("touchgate: %s" % error, file=sys.stderr)
        return 1
