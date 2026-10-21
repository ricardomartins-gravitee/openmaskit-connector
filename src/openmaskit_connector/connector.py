"""Host-only connector. The remote peer can name approved profiles, never commands."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import signal
from pathlib import Path

from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

from .relay import MAX_BYTES, PROTOCOL
from .state import Profile, identifier, local_endpoint, read_json, write_json


def profiles(home: Path) -> dict[str, Profile]:
    data = read_json(home / "profiles.json")
    if len(data) > 32:
        raise ValueError("Approve at most 32 local MCP profiles")
    return {
        identifier(key): Profile.model_validate(value) for key, value in data.items()
    }


async def channel(home: Path, *, connected: asyncio.Event | None = None):
    config = read_json(home / "connection.json")
    endpoint = local_endpoint(config["endpoint"])
    approved = profiles(home)
    key = identifier(config["id"])
    url = "ws" + endpoint[4:] + "/connect/" + key
    tasks: dict[str, asyncio.Task] = {}
    lock = asyncio.Lock()
    async with connect(
        url,
        additional_headers={"Authorization": "Bearer " + config["token"]},
        proxy=None,
        max_size=MAX_BYTES,
        max_queue=16,
        ping_interval=20,
        ping_timeout=20,
        close_timeout=5,
    ) as ws:

        async def send(frame):
            raw = json.dumps(frame, separators=(",", ":"))
            if len(raw.encode()) > MAX_BYTES:
                raise ValueError("Message too large")
            async with lock:
                await asyncio.wait_for(ws.send(raw), 10)

        await send(
            {
                "type": "hello",
                "protocol": PROTOCOL,
                "profiles": [
                    {"id": key, "name": p.name} for key, p in approved.items()
                ],
            }
        )
        ready = json.loads(await asyncio.wait_for(ws.recv(), 10))
        if ready != {"type": "ready", "protocol": PROTOCOL}:
            raise ValueError("Incompatible relay")
        write_json(
            home / "connector-status.json",
            {"connected": True, "pid": os.getpid(), "profiles": len(approved)},
        )
        if connected:
            connected.set()
        queues: dict[str, asyncio.Queue] = {}

        async def serve(session, profile):
            pumps = []
            queue = queues[session]
            try:
                params = StdioServerParameters(
                    **approved[profile].model_dump(exclude={"name"})
                )
                # Subprocess stderr can contain credentials or personal data.
                with open(os.devnull, "w") as errors:
                    async with stdio_client(params, errlog=errors) as (read, write):

                        async def from_process():
                            async for message in read:
                                if isinstance(message, Exception):
                                    break
                                await send(
                                    {
                                        "type": "message",
                                        "session": session,
                                        "message": message.message.model_dump(
                                            mode="json",
                                            by_alias=True,
                                            exclude_none=True,
                                        ),
                                    }
                                )

                        async def to_process():
                            while (message := await queue.get()) is not None:
                                await write.send(
                                    SessionMessage(
                                        JSONRPCMessage.model_validate(message)
                                    )
                                )

                        pumps = [
                            asyncio.create_task(from_process()),
                            asyncio.create_task(to_process()),
                        ]
                        try:
                            await asyncio.wait(
                                pumps, return_when=asyncio.FIRST_COMPLETED
                            )
                        finally:
                            # Exit the SDK's anyio context in the same task that entered it.
                            for pump in pumps:
                                pump.cancel()
                            await asyncio.gather(*pumps, return_exceptions=True)
            # Keep private subprocess and transport error text out of logs.
            except Exception:  # nosec B110
                pass
            finally:
                queues.pop(session, None)
                tasks.pop(session, None)
                try:
                    await send({"type": "closed", "session": session})
                # A closed notification is best effort after disconnect.
                except Exception:  # nosec B110
                    pass

        try:
            async for raw in ws:
                frame = json.loads(raw)
                session = frame.get("session")
                if not isinstance(session, str) or len(session) != 32:
                    raise ValueError("Invalid session")
                kind = frame.get("type")
                if kind == "open":
                    if (
                        set(frame) != {"type", "session", "profile"}
                        or frame["profile"] not in approved
                        or session in tasks
                        or len(tasks) >= 4
                    ):
                        raise ValueError("Unapproved local launch")
                    queues[session] = asyncio.Queue(maxsize=32)
                    tasks[session] = asyncio.create_task(
                        serve(session, frame["profile"])
                    )
                elif kind == "message":
                    if set(frame) != {"type", "session", "message"}:
                        raise ValueError("Invalid relay message")
                    message = JSONRPCMessage.model_validate(frame["message"])
                    if session in queues:
                        await asyncio.wait_for(
                            queues[session].put(
                                message.model_dump(
                                    mode="json", by_alias=True, exclude_none=True
                                )
                            ),
                            10,
                        )
                elif kind == "close" and set(frame) == {"type", "session"}:
                    if task := tasks.get(session):
                        task.cancel()
                else:
                    raise ValueError("Unknown relay frame")
        finally:
            running = list(tasks.values())
            for task in running:
                task.cancel()
            await asyncio.gather(*running, return_exceptions=True)
            write_json(home / "connector-status.json", {"connected": False})


async def run(home: Path):
    if os.name != "nt":
        task = asyncio.current_task()
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    delay = 1
    while True:
        try:
            await channel(home)
            delay = 1
        except InvalidStatus as exc:
            if exc.response.status_code in {401, 403}:
                write_json(
                    home / "connector-status.json",
                    {"connected": False, "error": "Pair this computer again"},
                )
                return
        except (OSError, ValueError, TimeoutError):
            write_json(
                home / "connector-status.json",
                {"connected": False, "error": "Relay unavailable"},
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            write_json(
                home / "connector-status.json",
                {"connected": False, "error": "Connection interrupted"},
            )
        # Only the empty connection is retried. No MCP messages survive reconnect.
        await asyncio.sleep(delay + secrets.randbelow(1000) / 1000)
        delay = min(delay * 2, 30)
