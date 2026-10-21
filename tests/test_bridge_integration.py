import asyncio
import hashlib
import os
import secrets
import socket
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import ListRootsResult, Root

from openmaskit_connector.connector import channel
from openmaskit_connector.relay import create_app
from openmaskit_connector.state import write_json

FIXTURE = Path(__file__).parent / "fixture_mcp.py"


@asynccontextmanager
async def running_relay(path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(path),
            access_log=False,
            log_level="critical",
            ws_max_size=1_048_576,
        )
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 15)
        sock.close()


@asynccontextmanager
async def paired_connector(tmp_path):
    settings = {
        "admin_token": secrets.token_urlsafe(32),
        "proxy_token": secrets.token_urlsafe(32),
        "connectors": {},
    }
    relay_state = tmp_path / "relay/relay.json"
    write_json(relay_state, settings)
    home = tmp_path / "host"
    async with running_relay(relay_state) as base:
        async with httpx.AsyncClient(base_url=base, trust_env=False) as api:
            code = (
                await api.post(
                    "/admin/pairings",
                    headers={"Authorization": "Bearer " + settings["admin_token"]},
                    json={},
                )
            ).json()["code"]
            config = (await api.post("/pair", json={"code": code})).json()
        write_json(
            home / "connection.json",
            {"endpoint": base, "id": config["id"], "token": config["token"]},
        )
        write_json(
            home / "profiles.json",
            {
                "fixture": {
                    "name": "Synthetic MCP",
                    "command": sys.executable,
                    "args": [str(FIXTURE)],
                    "env": {"SYNTHETIC_PID_FILE": str(home / "child.pid")},
                }
            },
        )
        ready = asyncio.Event()

        async def bundled_channel():
            process = await asyncio.create_subprocess_exec(
                os.environ["CONNECTOR_BINARY"],
                "--home",
                str(home),
                "connect",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                async with httpx.AsyncClient(base_url=base, trust_env=False) as api:
                    while process.returncode is None:
                        status = (
                            await api.get(
                                "/admin/connectors",
                                headers={
                                    "Authorization": "Bearer " + settings["admin_token"]
                                },
                            )
                        ).json()
                        if status["connectors"][0]["connected"]:
                            ready.set()
                            break
                        await asyncio.sleep(0.05)
                await process.wait()
            finally:
                if process.returncode is None:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), 10)

        task = asyncio.create_task(
            bundled_channel()
            if os.environ.get("CONNECTOR_BINARY")
            else channel(home, connected=ready)
        )
        try:
            async with asyncio.timeout(10):
                while not ready.is_set():
                    if task.done():
                        await task
                    await asyncio.sleep(0.01)
            yield base, config, settings, task, home
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@asynccontextmanager
async def mcp_session(base, config, settings, **kwargs):
    async with httpx.AsyncClient(
        headers={"Authorization": "Bearer " + settings["proxy_token"]}, trust_env=False
    ) as http:
        async with streamable_http_client(
            base + f"/mcp/{config['id']}/fixture", http_client=http
        ) as (read, write, _):
            async with ClientSession(
                read, write, read_timeout_seconds=timedelta(seconds=10), **kwargs
            ) as session:
                await session.initialize()
                yield session


async def test_complete_bidirectional_mcp_and_process_cleanup(tmp_path):
    async with paired_connector(tmp_path) as (base, config, settings, task, home):

        async def roots(_context):
            return ListRootsResult(
                roots=[Root(uri="file:///synthetic", name="Synthetic root")]
            )

        progress = []

        async def on_progress(current, total, message):
            progress.append((current, total))

        async with mcp_session(
            base, config, settings, list_roots_callback=roots
        ) as session:
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == {
                "greet",
                "digest",
                "client_roots",
                "wait_for_disconnect",
            }
            result = await session.call_tool(
                "greet", {"name": "Sarah Synthetic"}, progress_callback=on_progress
            )
            assert result.content[0].text == "Hello Sarah Synthetic"
            result = await session.call_tool("digest", {"text": "Sarah Synthetic"})
            assert (
                result.content[0].text == hashlib.sha256(b"Sarah Synthetic").hexdigest()
            )
            result = await session.call_tool("client_roots")
            assert result.content[0].text.rstrip("/") == "file:///synthetic"
            assert (
                str((await session.list_resources()).resources[0].uri)
                == "synthetic://status"
            )
            assert (await session.list_prompts()).prompts[0].name == "synthetic_prompt"
            assert progress == [(1, 1)]
            pid = int((home / "child.pid").read_text())
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if os.name != "nt":
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)


async def test_disconnect_fails_pending_call_and_never_replays(tmp_path):
    async with paired_connector(tmp_path) as (base, config, settings, task, home):
        try:
            async with mcp_session(base, config, settings) as session:
                pending = asyncio.create_task(session.call_tool("wait_for_disconnect"))
                await asyncio.sleep(0.1)
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                async with asyncio.timeout(5):
                    try:
                        result = await pending
                    except Exception as exc:
                        assert not isinstance(exc, TimeoutError), (
                            "Disconnect must fail promptly"
                        )
                    else:
                        assert result.isError, (
                            "Interrupted operation unexpectedly succeeded"
                        )
        except BaseExceptionGroup as group:

            def leaves(error):
                if isinstance(error, BaseExceptionGroup):
                    return [
                        item for child in error.exceptions for item in leaves(child)
                    ]
                return [error]

            assert not any(
                isinstance(error, (AssertionError, TimeoutError))
                for error in leaves(group)
            )


async def test_multiple_http_sessions_are_isolated(tmp_path):
    async with paired_connector(tmp_path) as (base, config, settings, task, home):

        async def one(name):
            async with mcp_session(base, config, settings) as session:
                result = await session.call_tool("greet", {"name": name})
                return result.content[0].text

        assert await asyncio.gather(one("First"), one("Second")) == [
            "Hello First",
            "Hello Second",
        ]
