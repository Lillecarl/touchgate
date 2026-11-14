"""
Where things live: the configuration file, this installation's device id,
the broker's socket, and the systemd credential that can unlock it.
"""

from __future__ import annotations

import os
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .vault import BITWARDEN_EU, BITWARDEN_US, Device, Endpoints

if TYPE_CHECKING:
    from collections.abc import Mapping

#: The systemd credential name (`LoadCredentialEncrypted=touchgate-password:...`).
CREDENTIAL = "touchgate-password"

SERVERS = {"us": BITWARDEN_US, "eu": BITWARDEN_EU}


class ConfigError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Config:
    email: str
    endpoints: Endpoints

    @classmethod
    def parse(cls, data: Mapping[str, object]) -> Config:
        email = data.get("email")
        if not isinstance(email, str) or not email:
            raise ConfigError("the configuration names no `email`")
        server = data.get("server", "us")
        if not isinstance(server, str):
            raise ConfigError("`server` is `us`, `eu` or a URL")
        endpoints = SERVERS.get(server) or Endpoints.of(server)
        return cls(email, endpoints)


def _home(variable: str, fallback: str, environ: Mapping[str, str]) -> Path:
    value = environ.get(variable)
    return Path(value) if value else Path(environ.get("HOME", "~")).expanduser() / fallback


def config_file(environ: Mapping[str, str] = os.environ) -> Path:
    return _home("XDG_CONFIG_HOME", ".config", environ) / "touchgate" / "config.toml"


def load(environ: Mapping[str, str] = os.environ) -> Config:
    path = config_file(environ)
    try:
        return Config.parse(tomllib.loads(path.read_text()))
    except FileNotFoundError:
        raise ConfigError("no configuration at %s" % path) from None


def socket_path(environ: Mapping[str, str] = os.environ) -> Path:
    runtime = environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        raise ConfigError("XDG_RUNTIME_DIR is not set, so the broker has nowhere private to listen")
    return Path(runtime) / "touchgate" / "broker.sock"


def device(environ: Mapping[str, str] = os.environ) -> Device:
    "The same identifier on every run, so the server sees one device and not a new one per start."
    path = _home("XDG_STATE_HOME", ".local/state", environ) / "touchgate" / "device-id"
    try:
        return Device(path.read_text().strip())
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True)
        identifier = str(uuid.uuid4())
        path.write_text(identifier + "\n")
        return Device(identifier)


def credential(environ: Mapping[str, str] = os.environ) -> Path | None:
    "The master password systemd decrypted for this service, if it was given one."
    directory = environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        return None
    path = Path(directory) / CREDENTIAL
    return path if path.exists() else None
