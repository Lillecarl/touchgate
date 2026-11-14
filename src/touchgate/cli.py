"""
`touchgate broker` runs the service. `unlock`, `lock` and `status` talk
to it over its socket.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys

import anyio

from . import config
from .broker import Broker, ask, not_dumpable


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


async def _unlock() -> int:
    password = await anyio.to_thread.run_sync(getpass.getpass, "Master password: ")
    return _report(await ask(config.socket_path(), {"op": "unlock", "password": password}))


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
    commands.add_parser("unlock", help="Give the broker the master password.")
    commands.add_parser("lock", help="Make the broker forget the vault.")
    commands.add_parser("status", help="Say whether the broker holds the vault.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="touchgate: %(message)s")
    try:
        match args.command:
            case "broker":
                return anyio.run(_broker)
            case "unlock":
                return anyio.run(_unlock)
            case command:
                return anyio.run(_simple, command)
    except (config.ConfigError, OSError) as error:
        print("touchgate: %s" % error, file=sys.stderr)
        return 1
