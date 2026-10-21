import json
import sys
from io import StringIO

import pytest

from openmaskit_connector import cli
from openmaskit_connector.state import read_json, write_json


def invoke(home, *args):
    cli.main(["--home", str(home), *args])


def test_approve_requires_explicit_confirmation_and_saves_profile(
    tmp_path, monkeypatch, capsys
):
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(
        json.dumps({"command": sys.executable, "args": ["synthetic"]})
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "approve")
    invoke(
        tmp_path / "home",
        "approve",
        "fixture",
        "--name",
        "Synthetic",
        "--profile",
        str(profile_path),
    )
    assert json.loads(capsys.readouterr().out) == {
        "approved": "fixture",
        "restart_connector": True,
    }
    saved = read_json(tmp_path / "home/profiles.json")["fixture"]
    assert saved["command"] == sys.executable
    assert saved["args"] == ["synthetic"]
    assert saved["name"] == "Synthetic"


def test_approve_cancel_does_not_write_profile(tmp_path, monkeypatch, capsys):
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps({"command": "/usr/bin/env"}))
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    with pytest.raises(SystemExit) as error:
        invoke(
            tmp_path / "home",
            "approve",
            "fixture",
            "--name",
            "Synthetic",
            "--profile",
            str(profile_path),
        )
    assert error.value.code == 1
    assert not (tmp_path / "home/profiles.json").exists()
    captured = capsys.readouterr()
    error_line = captured.err.strip().splitlines()[-1]
    assert json.loads(error_line)["error"]
    assert "synthetic" not in captured.err


def test_approve_rejects_invalid_profile_without_saving(tmp_path, capsys):
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps({"command": "relative-command"}))
    with pytest.raises(SystemExit) as error:
        invoke(
            tmp_path / "home",
            "approve",
            "fixture",
            "--yes",
            "--name",
            "Synthetic",
            "--profile",
            str(profile_path),
        )
    assert error.value.code == 1
    assert not (tmp_path / "home/profiles.json").exists()
    assert json.loads(capsys.readouterr().err)["error"]


@pytest.mark.parametrize("profile_id", ["../escape", "UPPER", "bad id", "a" * 49])
def test_cli_validates_profile_identifiers_before_dispatch(profile_id):
    with pytest.raises(SystemExit) as error:
        cli.parser().parse_args(["forget", profile_id])
    assert error.value.code == 2


def test_forget_and_profiles_operate_on_private_approved_state(tmp_path, capsys):
    write_json(
        tmp_path / "profiles.json",
        {
            "keep": {
                "name": "Keep",
                "command": sys.executable,
                "args": [],
                "env": {},
                "cwd": None,
            },
            "remove": {
                "name": "Remove",
                "command": sys.executable,
                "args": [],
                "env": {},
                "cwd": None,
            },
        },
    )
    invoke(tmp_path, "profiles")
    assert json.loads(capsys.readouterr().out) == {
        "profiles": [{"id": "keep", "name": "Keep"}, {"id": "remove", "name": "Remove"}]
    }
    invoke(tmp_path, "forget", "remove")
    assert json.loads(capsys.readouterr().out) == {
        "removed": "remove",
        "restart_connector": True,
    }
    assert list(read_json(tmp_path / "profiles.json")) == ["keep"]


def test_pair_reads_code_from_stdin_without_echoing_it(tmp_path, monkeypatch, capsys):
    code = "synthetic-pairing-code"
    monkeypatch.setattr("sys.stdin", StringIO(code + "\n"))
    monkeypatch.setattr(
        cli,
        "pair_connector",
        lambda _home, endpoint, supplied: {
            "paired": supplied == code,
            "id": "computer-test",
            "endpoint": endpoint,
        },
    )
    invoke(tmp_path, "pair", "--endpoint", "http://127.0.0.1:9495", "--code-stdin")
    output = capsys.readouterr().out
    assert json.loads(output)["paired"] is True
    assert code not in output
