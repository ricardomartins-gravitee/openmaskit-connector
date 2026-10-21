import time

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from openmaskit_connector.relay import digest


def paired(client, settings):
    code = client.post(
        "/admin/pairings",
        headers={"Authorization": "Bearer " + settings["admin_token"]},
        json={"name": "Synthetic computer"},
    ).json()["code"]
    response = client.post("/pair", json={"code": code})
    assert response.status_code == 200
    return response.json(), code


def test_pairing_single_use_and_token_redaction(relay):
    app, settings = relay
    with TestClient(app) as client:
        config, code = paired(client, settings)
        assert client.post("/pair", json={"code": code}).status_code == 401
        rows = client.get(
            "/admin/connectors",
            headers={"Authorization": "Bearer " + settings["admin_token"]},
        )
        assert config["token"] not in rows.text
        assert settings["admin_token"] not in rows.text
        assert app.state.hub.settings["connectors"][config["id"]][
            "token_hash"
        ] == digest(config["token"])
        assert config["token"] not in app.state.hub.path.read_text()


def test_expired_code_and_rate_limit(relay):
    app, settings = relay
    with TestClient(app) as client:
        response = client.post(
            "/admin/pairings",
            headers={"Authorization": "Bearer " + settings["admin_token"]},
            json={},
        )
        code = response.json()["code"]
        app.state.hub.pairings[digest(code)] = (time.monotonic() - 1, "Expired")
        assert client.post("/pair", json={"code": code}).status_code == 401
        for _ in range(9):
            assert client.post("/pair", json={"code": "bad"}).status_code == 401
        assert client.post("/pair", json={"code": code}).status_code == 429


@pytest.mark.parametrize(
    "path,method",
    [
        ("/admin/connectors", "get"),
        ("/admin/pairings", "post"),
        ("/admin/revoke", "post"),
        ("/mcp/computer/test", "post"),
    ],
)
def test_admin_and_proxy_require_separate_credentials(relay, path, method):
    app, settings = relay
    with TestClient(app) as client:
        assert getattr(client, method)(path).status_code == 401
        token = (
            settings["proxy_token"]
            if path.startswith("/admin")
            else settings["admin_token"]
        )
        assert (
            getattr(client, method)(
                path, headers={"Authorization": "Bearer " + token}
            ).status_code
            == 401
        )


def test_browser_origin_rejected_even_with_credentials(relay):
    app, settings = relay
    with TestClient(app) as client:
        headers = {
            "Authorization": "Bearer " + settings["admin_token"],
            "Origin": "http://localhost:9493",
        }
        assert (
            client.post("/admin/pairings", headers=headers, json={}).status_code == 401
        )
        assert (
            client.post(
                "/pair", headers={"Origin": "https://evil.test"}, json={"code": "x"}
            ).status_code
            == 403
        )
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/connect/computer", headers=headers):
                pass


def test_connector_profiles_and_immediate_revocation(relay):
    app, settings = relay
    with TestClient(app) as client:
        config, _ = paired(client, settings)
        with client.websocket_connect(
            "/connect/" + config["id"],
            headers={"Authorization": "Bearer " + config["token"]},
        ) as ws:
            ws.send_json(
                {
                    "type": "hello",
                    "protocol": 1,
                    "profiles": [{"id": "fixture", "name": "Synthetic"}],
                }
            )
            assert ws.receive_json() == {"type": "ready", "protocol": 1}
            status = client.get(
                "/admin/connectors",
                headers={"Authorization": "Bearer " + settings["admin_token"]},
            ).json()
            assert status["connectors"][0]["connected"] is True
            response = client.post(
                "/admin/revoke",
                json={"id": config["id"]},
                headers={"Authorization": "Bearer " + settings["admin_token"]},
            )
            assert response.status_code == 200
            with pytest.raises(WebSocketDisconnect):
                ws.receive_json()
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/connect/" + config["id"],
                headers={"Authorization": "Bearer " + config["token"]},
            ):
                pass


def test_no_launch_commands_in_handshake(relay):
    app, settings = relay
    with TestClient(app) as client:
        config, _ = paired(client, settings)
        with client.websocket_connect(
            "/connect/" + config["id"],
            headers={"Authorization": "Bearer " + config["token"]},
        ) as ws:
            ws.send_json(
                {
                    "type": "hello",
                    "protocol": 1,
                    "profiles": [
                        {"id": "fixture", "name": "Test", "command": "/bin/sh"}
                    ],
                }
            )
            with pytest.raises(WebSocketDisconnect):
                ws.receive_json()


@pytest.mark.parametrize(
    "hello",
    [
        {"type": "hello", "protocol": 2, "profiles": []},
        {
            "type": "hello",
            "protocol": 1,
            "profiles": [
                {"id": "fixture", "name": "One"},
                {"id": "fixture", "name": "Two"},
            ],
        },
    ],
)
def test_handshake_rejects_protocol_mismatch_and_duplicate_profiles(relay, hello):
    app, settings = relay
    with TestClient(app) as client:
        config, _ = paired(client, settings)
        headers = {"Authorization": "Bearer " + config["token"]}
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/connect/" + config["id"], headers=headers
            ) as ws:
                ws.send_json(hello)
                ws.receive_json()


def test_websocket_origin_is_rejected_with_valid_connector_token(relay):
    app, settings = relay
    with TestClient(app) as client:
        config, _ = paired(client, settings)
        headers = {
            "Authorization": "Bearer " + config["token"],
            "Origin": "https://evil.test",
        }
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/connect/" + config["id"], headers=headers):
                pass


def test_oversized_websocket_frame_is_closed(relay):
    app, settings = relay
    with TestClient(app) as client:
        config, _ = paired(client, settings)
        headers = {"Authorization": "Bearer " + config["token"]}
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/connect/" + config["id"], headers=headers
            ) as ws:
                ws.send_json({"type": "hello", "protocol": 1, "profiles": []})
                assert ws.receive_json() == {"type": "ready", "protocol": 1}
                ws.send_text("x" * 1_048_577)
                ws.receive_json()


def test_duplicate_connection_is_denied_during_handshake(relay):
    app, settings = relay
    with TestClient(app) as client:
        config, _ = paired(client, settings)
        headers = {"Authorization": "Bearer " + config["token"]}
        with client.websocket_connect(
            "/connect/" + config["id"], headers=headers
        ) as first:
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect(
                    "/connect/" + config["id"], headers=headers
                ):
                    pass
            first.send_json({"type": "hello", "protocol": 1, "profiles": []})
            assert first.receive_json()["type"] == "ready"


def test_bounded_http_and_offline_fail_closed(relay):
    app, settings = relay
    with TestClient(app) as client:
        assert client.post("/pair", content="x" * 1_048_577).status_code == 413
        assert (
            client.post(
                "/mcp/computer/test",
                headers={"Authorization": "Bearer " + settings["proxy_token"]},
                json={},
            ).status_code
            == 503
        )
