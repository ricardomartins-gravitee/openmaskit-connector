"""Authenticated reverse relay. Commands and environment variables never enter it.

The Python MCP SDK owns Streamable HTTP sessions; we forward the complete
JSON-RPC stream to a locally approved stdio subprocess over an outbound channel.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from .state import identifier, read_json, write_json

MAX_BYTES = 1_048_576
PROTOCOL = 1


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def authorized(headers, token: str) -> bool:
    return not headers.get("origin") and secrets.compare_digest(
        headers.get("authorization", ""), "Bearer " + token
    )


class Peer:
    def __init__(self, websocket, profiles):
        self.websocket = websocket
        self.profiles = profiles
        self.sessions: dict[str, asyncio.Queue] = {}
        self.lock = asyncio.Lock()

    async def send(self, frame):
        encoded = json.dumps(frame, separators=(",", ":"))
        if len(encoded.encode()) > MAX_BYTES:
            raise ValueError("Message too large")
        async with self.lock:
            await asyncio.wait_for(self.websocket.send_text(encoded), 10)

    def close_sessions(self):
        for queue in self.sessions.values():
            # Never leave a request waiting behind a full queue after disconnect.
            while not queue.empty():
                queue.get_nowait()
            queue.put_nowait(None)


class Forwarder:
    def __init__(self, hub, connector, profile):
        self.hub, self.connector, self.profile = hub, connector, profile

    def create_initialization_options(self):
        return None  # The actual upstream supplies initialization and capabilities.

    async def run(self, read, write, _options, **_kwargs):
        peer = self.hub.peers.get(self.connector)
        if peer is None or self.profile not in peer.profiles or len(peer.sessions) >= 4:
            return
        session = secrets.token_hex(16)
        queue = peer.sessions[session] = asyncio.Queue(maxsize=32)
        tasks = []
        try:
            await peer.send(
                {"type": "open", "session": session, "profile": self.profile}
            )

            async def outbound():
                async for message in read:
                    if isinstance(message, Exception):
                        break
                    await peer.send(
                        {
                            "type": "message",
                            "session": session,
                            "message": message.message.model_dump(
                                mode="json", by_alias=True, exclude_none=True
                            ),
                        }
                    )

            async def inbound():
                while (message := await queue.get()) is not None:
                    await write.send(
                        SessionMessage(JSONRPCMessage.model_validate(message))
                    )

            tasks = [asyncio.create_task(outbound()), asyncio.create_task(inbound())]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            peer.sessions.pop(session, None)
            try:
                await peer.send({"type": "close", "session": session})
            # A close notification is best effort after disconnect.
            except Exception:  # nosec B110
                pass


class Hub:
    def __init__(self, state: Path):
        self.path = state
        self.settings = read_json(state)
        for key in ("admin_token", "proxy_token"):
            if len(self.settings.get(key, "")) < 32:
                raise ValueError("Relay requires provisioned private credentials")
        self.peers: dict[str, Peer] = {}
        self.channels: dict[str, WebSocket] = {}
        self.pairings: dict[str, tuple[float, str]] = {}
        self.attempts: list[float] = []
        self.managers: dict[tuple[str, str], StreamableHTTPSessionManager] = {}
        self.tasks: list[asyncio.Task] = []
        self.manager_lock = asyncio.Lock()

    def save(self):
        write_json(self.path, self.settings)

    async def manager(self, connector, profile):
        key = (connector, profile)
        async with self.manager_lock:
            if key not in self.managers:
                if len(self.managers) >= 64:
                    raise ValueError(
                        "Relay profile capacity reached; restart to clear inactive profiles"
                    )
                manager = StreamableHTTPSessionManager(
                    Forwarder(self, connector, profile),
                    json_response=True,
                    session_idle_timeout=300,
                    security_settings=TransportSecuritySettings(
                        allowed_hosts=[
                            "connector-relay:9495",
                            "127.0.0.1:*",
                            "localhost:*",
                            "[::1]:*",
                        ],
                        allowed_origins=[],
                    ),
                )
                ready = asyncio.Event()

                async def supervise():
                    async with manager.run():
                        ready.set()
                        await asyncio.Event().wait()

                task = asyncio.create_task(supervise())
                self.tasks.append(task)
                await asyncio.wait_for(ready.wait(), 5)
                self.managers[key] = manager
            return self.managers[key]


class LimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > MAX_BYTES:
                return await JSONResponse(
                    {"error": "Request too large"}, status_code=413
                )(scope, receive, send)
            chunks.append(message)
            if not message.get("more_body"):
                break
        iterator = iter(chunks)

        async def replay():
            return next(iterator, None) or await receive()

        await self.app(scope, replay, send)


def create_app(state_path: Path):
    hub = Hub(state_path)

    @asynccontextmanager
    async def lifespan(_app):
        try:
            yield
        finally:
            for peer in list(hub.peers.values()):
                peer.close_sessions()
            for task in hub.tasks:
                task.cancel()
            await asyncio.gather(*hub.tasks, return_exceptions=True)

    async def health(_request):
        return JSONResponse({"status": "healthy", "protocol": PROTOCOL})

    async def admin(request: Request):
        if not authorized(request.headers, hub.settings["admin_token"]):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        if request.method == "GET":
            return JSONResponse(
                {
                    "connectors": [
                        {
                            "id": key,
                            "name": row["name"],
                            "connected": key in hub.peers,
                            "profiles": hub.peers[key].profiles
                            if key in hub.peers
                            else [],
                        }
                        for key, row in hub.settings.get("connectors", {}).items()
                    ]
                }
            )
        try:
            body = await request.json()
            if request.url.path == "/admin/revoke":
                key = identifier(body["id"])
                hub.settings.setdefault("connectors", {}).pop(key, None)
                hub.save()
                if peer := hub.peers.get(key):
                    peer.close_sessions()
                if socket := hub.channels.get(key):
                    await socket.close(code=4401)
                return JSONResponse({"revoked": key})
            name = str(body.get("name", "My computer")).strip()
            if not 1 <= len(name) <= 100:
                raise ValueError("Invalid connector name")
            if len(hub.settings.get("connectors", {})) >= 16:
                raise ValueError("Connector limit reached")
            now = time.monotonic()
            hub.pairings = {k: v for k, v in hub.pairings.items() if v[0] > now}
            if len(hub.pairings) >= 8:
                raise ValueError("Too many pending pairings")
            code = secrets.token_urlsafe(18)
            hub.pairings[digest(code)] = (now + 120, name)
            return JSONResponse({"code": code, "expires_in": 120})
        except (ValueError, KeyError, TypeError):
            return JSONResponse(
                {"error": "Invalid administrative request"}, status_code=400
            )

    async def pair(request: Request):
        if request.headers.get("origin"):
            return JSONResponse(
                {"error": "Browser pairing is not allowed"}, status_code=403
            )
        now = time.monotonic()
        hub.attempts = [t for t in hub.attempts if now - t < 60]
        if len(hub.attempts) >= 10:
            return JSONResponse({"error": "Try pairing again later"}, status_code=429)
        hub.attempts.append(now)
        try:
            body = await request.json()
            expiry, name = hub.pairings.pop(digest(body["code"]))
            if expiry < now or len(hub.settings.get("connectors", {})) >= 16:
                raise ValueError("Pairing expired")
        except (ValueError, KeyError, TypeError):
            return JSONResponse(
                {"error": "Invalid or expired pairing"}, status_code=401
            )
        token, key = secrets.token_urlsafe(32), "computer-" + secrets.token_hex(6)
        hub.settings.setdefault("connectors", {})[key] = {
            "name": name,
            "token_hash": digest(token),
        }
        hub.save()
        return JSONResponse({"id": key, "token": token, "protocol": PROTOCOL})

    async def channel(websocket: WebSocket):
        key = websocket.path_params["connector"]
        row = hub.settings.get("connectors", {}).get(key)
        raw = websocket.headers.get("authorization", "")
        valid = (
            not websocket.headers.get("origin")
            and row
            and raw.startswith("Bearer ")
            and secrets.compare_digest(digest(raw[7:]), row["token_hash"])
        )
        if not valid or key in hub.channels:
            await websocket.close(code=4401)
            return
        hub.channels[key] = websocket
        peer = None
        try:
            await websocket.accept()
            hello = json.loads(await asyncio.wait_for(websocket.receive_text(), 10))
            if (
                hello.get("type") != "hello"
                or hello.get("protocol") != PROTOCOL
                or set(hello) != {"type", "protocol", "profiles"}
            ):
                raise ValueError("Invalid handshake")
            profiles = hello["profiles"]
            if not isinstance(profiles, list) or len(profiles) > 32:
                raise ValueError("Invalid profile list")
            for profile in profiles:
                if (
                    set(profile) != {"id", "name"}
                    or not isinstance(profile["name"], str)
                    or len(profile["name"]) > 100
                ):
                    raise ValueError("Invalid profile")
                identifier(profile["id"])
            if len({p["id"] for p in profiles}) != len(profiles):
                raise ValueError("Duplicate profile")
            if key not in hub.settings.get("connectors", {}):
                raise ValueError("Connector revoked")
            peer = Peer(websocket, {p["id"]: p["name"] for p in profiles})
            hub.peers[key] = peer
            await peer.send({"type": "ready", "protocol": PROTOCOL})
            while True:
                raw = await websocket.receive_text()
                if len(raw.encode()) > MAX_BYTES:
                    raise ValueError("Message too large")
                frame = json.loads(raw)
                session = frame.get("session")
                if session not in peer.sessions:
                    continue  # A late frame from a closed session is never replayed.
                if frame.get("type") == "message" and set(frame) == {
                    "type",
                    "session",
                    "message",
                }:
                    message = JSONRPCMessage.model_validate(frame["message"])
                    await asyncio.wait_for(
                        peer.sessions[session].put(
                            message.model_dump(
                                mode="json", by_alias=True, exclude_none=True
                            )
                        ),
                        10,
                    )
                elif frame.get("type") == "closed" and set(frame) == {
                    "type",
                    "session",
                }:
                    await asyncio.wait_for(peer.sessions[session].put(None), 10)
                else:
                    raise ValueError("Invalid relay frame")
        except (ValueError, TypeError, KeyError, WebSocketDisconnect, TimeoutError):
            pass
        finally:
            if hub.channels.get(key) is websocket:
                hub.channels.pop(key, None)
            if peer:
                peer.close_sessions()
                if hub.peers.get(key) is peer:
                    hub.peers.pop(key, None)
            try:
                await websocket.close(code=1000)
            except RuntimeError:
                pass

    async def mcp(scope, receive, send):
        request = Request(scope, receive)
        if not authorized(request.headers, hub.settings["proxy_token"]):
            return await JSONResponse({"error": "Unauthorized"}, status_code=401)(
                scope, receive, send
            )
        connector, profile = (
            scope["path_params"]["connector"],
            scope["path_params"]["profile"],
        )
        peer = hub.peers.get(connector)
        if peer is None or profile not in peer.profiles:
            return await JSONResponse(
                {"error": "Local connector unavailable"}, status_code=503
            )(scope, receive, send)
        if not request.headers.get("mcp-session-id") and len(peer.sessions) >= 4:
            return await JSONResponse(
                {"error": "Session limit reached"}, status_code=429
            )(scope, receive, send)
        manager = await hub.manager(connector, profile)
        await manager.handle_request(scope, receive, send)

    class MCPEndpoint:
        async def __call__(self, scope, receive, send):
            await mcp(scope, receive, send)

    app = Starlette(
        routes=[
            Route("/health", health),
            Route("/admin/connectors", admin),
            Route("/admin/pairings", admin, methods=["POST"]),
            Route("/admin/revoke", admin, methods=["POST"]),
            Route("/pair", pair, methods=["POST"]),
            WebSocketRoute("/connect/{connector}", channel),
            Route(
                "/mcp/{connector}/{profile}",
                MCPEndpoint(),
                methods=["GET", "POST", "DELETE"],
            ),
        ],
        lifespan=lifespan,
    )
    app.add_middleware(LimitMiddleware)
    app.state.hub = hub
    return app


def app_factory():
    return create_app(Path(os.environ["COMPANION_RELAY_STATE"]))
