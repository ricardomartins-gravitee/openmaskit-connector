"""Disposable synthetic host -> relay container -> OpenMaskit -> Presidio acceptance."""

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from openmaskit_connector.connector import channel
from openmaskit_connector.state import write_json

ROOT = Path(__file__).resolve().parents[1]


def ports():
    sockets = [socket.socket() for _ in range(3)]
    try:
        for item in sockets:
            item.bind(("127.0.0.1", 0))
        return [item.getsockname()[1] for item in sockets]
    finally:
        for item in sockets:
            item.close()


async def main(image):
    docker = shutil.which("docker") or str(Path.home() / ".docker/bin/docker")
    runtime = ROOT / ".runtime"
    runtime.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="acceptance-", dir=runtime) as directory:
        root = Path(directory)
        root.chmod(0o700)
        web, mcp, relay = ports()
        template = (ROOT / "tests/fixtures/compose.yaml").read_text()
        template = template.replace("9493", str(web)).replace("9494", str(mcp))
        template = template.replace(
            '"127.0.0.1:9495:9495"', f'"127.0.0.1:{relay}:9495"'
        )
        (root / "compose.yaml").write_text(template)
        release = json.loads((ROOT / "tests/fixtures/release.json").read_text())
        environment = {
            **os.environ,
            "OPENMASKIT_IMAGE": release["openmaskit_image"],
            "CONNECTOR_IMAGE": image,
            "LOCAL_UID": str(os.getuid() if hasattr(os, "getuid") else 10001),
            "LOCAL_GID": str(os.getgid() if hasattr(os, "getgid") else 10001),
        }
        settings = {
            "admin_token": secrets.token_urlsafe(32),
            "proxy_token": secrets.token_urlsafe(32),
            "connectors": {},
        }
        write_json(root / "relay/relay.json", settings)
        command = [
            docker,
            "compose",
            "--project-name",
            "connector-acceptance-" + secrets.token_hex(4),
            "--project-directory",
            str(root),
            "--file",
            str(root / "compose.yaml"),
        ]

        async def stack(*args):
            result = await asyncio.to_thread(
                subprocess.run,
                [*command, *args],
                env=environment,
                text=True,
                capture_output=True,
                timeout=360,
            )
            if result.returncode:
                # Only this disposable synthetic project may be logged.
                print(result.stderr[-8000:], file=sys.stderr)
                raise RuntimeError("Disposable Compose action failed")
            return result.stdout

        connector = None
        base = f"http://127.0.0.1:{web}"
        try:
            await stack("up", "--detach", "--wait", "--wait-timeout", "300")
            info = [
                json.loads(line)
                for line in (await stack("ps", "--format", "json")).splitlines()
                if line
            ]
            assert len(info) == 3 and all(row["Health"] == "healthy" for row in info)
            host = root / "host"
            async with httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{relay}", trust_env=False
            ) as api:
                code = (
                    await api.post(
                        "/admin/pairings",
                        headers={"Authorization": "Bearer " + settings["admin_token"]},
                        json={},
                    )
                ).json()["code"]
                paired = (await api.post("/pair", json={"code": code})).json()
                assert (await api.post("/pair", json={"code": code})).status_code == 401
                assert (await api.get("/admin/connectors")).status_code == 401
            write_json(
                host / "connection.json",
                {
                    "endpoint": f"http://127.0.0.1:{relay}",
                    "id": paired["id"],
                    "token": paired["token"],
                },
            )
            write_json(
                host / "profiles.json",
                {
                    "fixture": {
                        "name": "Synthetic MCP",
                        "command": sys.executable,
                        "args": [str(ROOT / "tests/fixture_mcp.py")],
                    }
                },
            )
            ready = asyncio.Event()
            connector = asyncio.create_task(channel(host, connected=ready))
            async with asyncio.timeout(15):
                while not ready.is_set():
                    if connector.done():
                        await connector
                    await asyncio.sleep(0.05)

            async with httpx.AsyncClient(
                base_url=base, trust_env=False, timeout=30
            ) as api:
                token = (await api.get("/api/csrf")).json()["token"]
                api.headers.update({"Origin": base, "X-CSRF-Token": token})

                async def post(path, body):
                    response = await api.post(path, json=body)
                    response.raise_for_status()
                    return response.json()

                created = await post(
                    "/api/targets/custom",
                    {
                        "name": "fixture",
                        "transport": "http",
                        "url": f"http://connector-relay:9495/mcp/{paired['id']}/fixture",
                        "headers": {
                            "Authorization": {
                                "type": "secret",
                                "value": "Bearer " + settings["proxy_token"],
                            }
                        },
                    },
                )
                assert created["connected"], (
                    "Container could not initialize the host MCP"
                )
                provider = await post(
                    "/api/privacy/providers/create",
                    {"name": "Presidio", "endpoint": "http://presidio-analyzer:3000"},
                )
                check = await post(
                    "/api/privacy/checks/create",
                    {
                        "name": "Names",
                        "provider_id": provider["id"],
                        "entities": ["PERSON"],
                    },
                )
                await post(
                    "/api/targets/fixture/privacy/assignments/create",
                    {"check_id": check["id"]},
                )

            async def call(tool, arguments):
                async with streamable_http_client(
                    f"http://127.0.0.1:{mcp}/fixture/mcp"
                ) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        return await session.call_tool(tool, arguments)

            result = await call("greet", {"name": "Sarah Johnson"})
            assert (
                "Sarah Johnson" not in result.model_dump_json()
                and "person_1" in result.model_dump_json()
            )
            result = await call("digest", {"text": "person_1"})
            assert (
                result.content[0].text == hashlib.sha256(b"Sarah Johnson").hexdigest()
            )
            await stack("stop", "presidio-analyzer")
            result = await call("greet", {"name": "Sarah Johnson"})
            assert result.isError and "Sarah Johnson" not in result.model_dump_json()
            await stack(
                "up", "--detach", "--wait", "--wait-timeout", "300", "presidio-analyzer"
            )
            result = await call("greet", {"name": "Sarah Johnson"})
            assert not result.isError and "person_1" in result.model_dump_json()
            print(
                "PASS: real host MCP, authenticated outbound bridge, OpenMaskit masking/alias reversal,"
            )
            print(
                "private Presidio and required-check outage withholding; existing installations untouched."
            )
        except BaseException:
            print(
                (await stack("logs", "--no-color", "--tail", "60"))[-12000:],
                file=sys.stderr,
            )
            raise
        finally:
            if connector:
                connector.cancel()
                await asyncio.gather(connector, return_exceptions=True)
            # This exact unique project contains disposable synthetic data only.
            await stack("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="openmaskit-connector:candidate")
    asyncio.run(main(parser.parse_args().image))
