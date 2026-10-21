import asyncio
import json

import pytest
from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus
from websockets.http11 import Response

from openmaskit_connector import connector


def state(home, profiles=None):
    home.mkdir(parents=True, exist_ok=True)
    (home / "connection.json").write_text(
        json.dumps(
            {"endpoint": "http://127.0.0.1:9495", "id": "connector", "token": "secret"}
        )
    )
    (home / "connection.json").chmod(0o600)
    (home / "profiles.json").write_text(json.dumps(profiles or {}))
    (home / "profiles.json").chmod(0o600)


def auth_error(status):
    return InvalidStatus(Response(status, "Unauthorized", Headers()))


async def stop_signals(monkeypatch):
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "add_signal_handler", lambda *_args: None)


@pytest.mark.parametrize("status", [401, 403])
async def test_auth_failure_stops_and_sanitizes_status(tmp_path, monkeypatch, status):
    await stop_signals(monkeypatch)
    home = tmp_path / "home"
    state(home)
    calls = 0

    async def fail(_home):
        nonlocal calls
        calls += 1
        raise auth_error(status)

    async def unexpected_sleep(_delay):
        pytest.fail("authentication failures must not retry")

    monkeypatch.setattr(connector, "channel", fail)
    monkeypatch.setattr(connector.asyncio, "sleep", unexpected_sleep)

    await connector.run(home)

    assert calls == 1
    assert json.loads((home / "connector-status.json").read_text()) == {
        "connected": False,
        "error": "Pair this computer again",
    }


async def test_backoff_is_bounded_and_resets_after_success(tmp_path, monkeypatch):
    await stop_signals(monkeypatch)
    home = tmp_path / "home"
    state(home)
    outcomes = [OSError("private detail"), None, OSError("private detail")]
    delays = []

    async def channel(_home):
        outcome = outcomes.pop(0)
        if outcome:
            raise outcome

    async def sleep(delay):
        delays.append(delay)
        if len(delays) == 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(connector, "channel", channel)
    monkeypatch.setattr(connector.asyncio, "sleep", sleep)
    monkeypatch.setattr(connector.secrets, "randbelow", lambda _limit: 250)

    with pytest.raises(asyncio.CancelledError):
        await connector.run(home)

    assert delays == [1.25, 1.25, 2.25]
    assert json.loads((home / "connector-status.json").read_text()) == {
        "connected": False,
        "error": "Relay unavailable",
    }


async def test_backoff_caps_at_thirty_seconds(tmp_path, monkeypatch):
    await stop_signals(monkeypatch)
    home = tmp_path / "home"
    state(home)
    delays = []

    async def channel(_home):
        raise OSError("private detail")

    async def sleep(delay):
        delays.append(delay)
        if len(delays) == 8:
            raise asyncio.CancelledError

    monkeypatch.setattr(connector, "channel", channel)
    monkeypatch.setattr(connector.asyncio, "sleep", sleep)
    monkeypatch.setattr(connector.secrets, "randbelow", lambda _limit: 0)

    with pytest.raises(asyncio.CancelledError):
        await connector.run(home)

    assert delays == [1, 2, 4, 8, 16, 30, 30, 30]


async def test_unexpected_error_is_sanitized_and_cancellation_propagates(
    tmp_path, monkeypatch
):
    await stop_signals(monkeypatch)
    home = tmp_path / "home"
    state(home)

    async def fail(_home):
        raise RuntimeError("private token and payload")

    async def stop(_delay):
        raise asyncio.CancelledError

    monkeypatch.setattr(connector, "channel", fail)
    monkeypatch.setattr(connector.asyncio, "sleep", stop)
    monkeypatch.setattr(connector.secrets, "randbelow", lambda _limit: 0)

    with pytest.raises(asyncio.CancelledError):
        await connector.run(home)

    assert json.loads((home / "connector-status.json").read_text()) == {
        "connected": False,
        "error": "Connection interrupted",
    }
    assert "private" not in (home / "connector-status.json").read_text()

    async def cancel(_home):
        raise asyncio.CancelledError

    monkeypatch.setattr(connector, "channel", cancel)
    with pytest.raises(asyncio.CancelledError):
        await connector.run(home)


def test_profiles_limit_and_invalid_profile_are_rejected(tmp_path):
    home = tmp_path / "home"
    state(home, {f"profile-{i}": {} for i in range(33)})
    with pytest.raises(ValueError, match="at most 32"):
        connector.profiles(home)

    state(home, {"fixture": {"name": "Synthetic", "command": "relative"}})
    with pytest.raises(ValueError, match="absolute executable"):
        connector.profiles(home)
