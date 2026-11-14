"""
`touchgate broker` runs the service. `unlock`, `lock` and `status` talk
to it over its socket. `run` asks it for a secret and runs a command
with it, once a security key signs the request. `enroll` seals the
master password to a security key, which `unlock --yubikey` then opens.
"""

from __future__ import annotations

import argparse
import functools
import getpass
import logging
import os
import shutil
import signal
import sys

import anyio

from . import config
from .approval import ApprovalError, Outcome
from .broker import Broker, ask, not_dumpable
from .client import approved_env, run_in_broker, ssh_sign
from .display import show
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


def _announce(line: str) -> None:
    print("touchgate: %s" % line, file=sys.stderr, flush=True)


async def _run(secret: str, command: list[str], env: dict[str, str], client_exec: bool) -> int:
    settings = config.load()
    if settings.signing_key is None:
        raise config.ConfigError("the configuration names no `signing_key` to approve with")
    path = shutil.which(command[0])
    if path is None:
        raise config.ConfigError("no command %r on PATH" % command[0])
    argv = [os.path.abspath(path), *command[1:]]
    sign = functools.partial(ssh_sign, settings.signing_key)
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
    commands.add_parser("lock", help="Make the broker forget the vault.")
    commands.add_parser("status", help="Say whether the broker holds the vault.")
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
            case "run":
                program: list[str] = args.program[1:] if args.program[:1] == ["--"] else args.program
                if not program:
                    parser.error("run needs a command after --")
                return anyio.run(_run, str(args.secret), program, dict(args.env), bool(args.client_exec))
            case command:
                return anyio.run(_simple, command)
    except (config.ConfigError, ApprovalError, SealError, OSError) as error:
        print("touchgate: %s" % error, file=sys.stderr)
        return 1
