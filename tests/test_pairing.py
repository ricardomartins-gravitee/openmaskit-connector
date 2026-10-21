import json
import sys

import pytest
import respx

from openmaskit_connector import cli
from openmaskit_connector.pairing import pair
from openmaskit_connector.state import read_json, write_json


@respx.mock
def test_pairing_persists_compatible_credentials_privately(tmp_path):
    endpoint = "http://127.0.0.1:9495"
    token = "synthetic-connector-credential-long-enough"
    request = respx.post(endpoint + "/pair").respond(
        200, json={"protocol": 1, "id": "computer-test", "token": token}
    )
    assert pair(tmp_path, endpoint, "synthetic-code") == {
        "paired": True,
        "id": "computer-test",
    }
    assert json.loads(request.calls[0].request.content) == {"code": "synthetic-code"}
    assert read_json(tmp_path / "connection.json") == {
        "endpoint": endpoint,
        "id": "computer-test",
        "token": token,
    }


@pytest.mark.parametrize(
    "response",
    [
        {"protocol": 2, "id": "computer-test", "token": "x" * 40},
        {"protocol": 1, "id": "computer-test", "token": "short"},
        {"protocol": 1, "id": "computer-test", "token": 123},
    ],
)
@respx.mock
def test_incompatible_pairing_never_overwrites_existing_state(tmp_path, response):
    path = tmp_path / "connection.json"
    write_json(path, {"existing": True})
    respx.post("http://127.0.0.1:9495/pair").respond(200, json=response)
    with pytest.raises(ValueError, match="Incompatible"):
        pair(tmp_path, "http://127.0.0.1:9495", "synthetic-code")
    assert read_json(path) == {"existing": True}


def test_status_is_redacted_and_uses_standalone_home(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    home = tmp_path / ".openmaskit-connector"
    write_json(home / "connection.json", {"token": "synthetic-private-token"})
    write_json(
        home / "profiles.json",
        {"fixture": {"name": "Fixture", "command": sys.executable}},
    )
    cli.main(["status"])
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "paired": True,
        "protocol": 1,
        "profiles": [{"id": "fixture", "name": "Fixture"}],
    }
    assert "synthetic-private-token" not in output
    assert not (tmp_path / ".openmaskit-companion").exists()


@pytest.mark.parametrize("action", ["setup", "start", "stop", "register"])
def test_connector_has_no_desktop_manager_commands(action):
    with pytest.raises(SystemExit):
        cli.parser().parse_args([action])
