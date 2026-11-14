from __future__ import annotations

import os
import socket
import ssl
from collections.abc import AsyncIterator

import anyio
import httpx2
import pytest
import trustme

from accounts import Server

#: How long vaultwarden gets to start answering.
STARTUP = 20


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


def _free_port() -> int:
    with socket.socket() as probe:
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
