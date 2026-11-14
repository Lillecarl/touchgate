from __future__ import annotations

import os
import socket as net
import ssl
import uuid
from collections.abc import AsyncIterator

import anyio
import httpx2
import pytest
import trustme

from accounts import Bw, Server, register
from approving import DEADLINE, PASSWORD
from authenticator import SoftKey
from touchgate import config
from touchgate.approval import APPROVERS_ITEM
from touchgate.broker import Broker
from touchgate.vault import Device, Endpoints

#: How long vaultwarden gets to start answering.
STARTUP = 20


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


def _free_port() -> int:
    with net.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="session")
async def vaultwarden(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[Server]:
    "One server for the session. Each test registers its own account in it."
    directory = tmp_path_factory.mktemp("vaultwarden")
    ca = trustme.CA()
    issued = ca.issue_cert("127.0.0.1", "localhost")
    certs, key, ca_file = directory / "chain.pem", directory / "key.pem", directory / "ca.pem"
    issued.private_key_pem.write_to_path(str(key))
    with certs.open("wb") as chain:
        for blob in issued.cert_chain_pems:
            chain.write(blob.bytes())
    ca.cert_pem.write_to_path(str(ca_file))
    trust = ssl.create_default_context()
    ca.configure_trust(trust)

    port = _free_port()
    environment = {
        **os.environ,
        "DATA_FOLDER": str(directory),
        "ROCKET_ADDRESS": "127.0.0.1",
        "ROCKET_PORT": str(port),
        "ROCKET_TLS": '{certs="%s",key="%s"}' % (certs, key),
        "WEB_VAULT_ENABLED": "false",
        "I_REALLY_WANT_VOLATILE_STORAGE": "true",
        # The default login bucket is 10, and a suite logs in more often than that.
        "LOGIN_RATELIMIT_MAX_BURST": "1000",
        "LOGIN_RATELIMIT_SECONDS": "1",
        # Registration counts here, and its default bucket of 50 is a few test modules.
        "UNAUTHENTICATED_RATELIMIT_MAX_BURST": "1000",
        "UNAUTHENTICATED_RATELIMIT_SECONDS": "1",
    }
    server = Server("https://localhost:%d" % port, trust, str(ca_file))
    async with await anyio.open_process(["vaultwarden"], env=environment) as process:
        try:
            with anyio.fail_after(STARTUP):
                async with httpx2.AsyncClient(base_url=server.base_url, verify=trust) as http:
                    # vaultwarden says nothing when it is ready except by answering, so this asks.
                    while True:
                        try:
                            if (await http.get("/alive")).status_code == 200:
                                break
                        except httpx2.TransportError:
                            pass
                        await anyio.sleep(0.1)
            yield server
        finally:
            process.terminate()


@pytest.fixture(scope="module")
def approver() -> SoftKey:
    return SoftKey()


@pytest.fixture(scope="module")
async def broker(vaultwarden, tmp_path_factory, approver):
    "One account and broker for the module: `bw` and a 600k PBKDF2 login cost seconds each."
    account = await register(vaultwarden, "%s@example.test" % uuid.uuid4().hex[:12], PASSWORD)
    bw = Bw(account, anyio.Path(tmp_path_factory.mktemp("bw")))
    await bw.login()
    await bw.create_login("database", "app", "s3cr3t", fields={"API_TOKEN": "t0ken", "not a name": "skipped"})
    await bw.create_login(APPROVERS_ITEM, "", "", notes="# the YubiKey\n%s\nnot a key\n" % approver.line())
    settings = config.Config(account.email, Endpoints.of(account.server.base_url))
    broker = Broker(settings, Device(str(uuid.uuid4())), transport=account.server.transport())
    await broker.unlock(PASSWORD)
    return broker


@pytest.fixture
async def socket(broker, tmp_path):
    path = tmp_path / "broker.sock"
    with anyio.fail_after(DEADLINE):
        async with anyio.create_task_group() as tasks:
            await tasks.start(broker.serve, path)
            yield path
            tasks.cancel_scope.cancel()
