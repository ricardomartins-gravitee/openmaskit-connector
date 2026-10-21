"""Pair a locally approved connector with a loopback relay."""

from pathlib import Path

import httpx

from .state import local_endpoint, write_json

RELAY = "http://127.0.0.1:9495"


def pair(home: Path, endpoint: str, code: str):
    endpoint = local_endpoint(endpoint)
    with httpx.Client(trust_env=False, timeout=10) as api:
        response = api.post(endpoint + "/pair", json={"code": code})
        response.raise_for_status()
        data = response.json()
    if (
        data.get("protocol") != 1
        or not isinstance(data.get("token"), str)
        or len(data["token"]) < 32
    ):
        raise ValueError("Incompatible pairing response")
    write_json(
        home / "connection.json",
        {"endpoint": endpoint, "id": data["id"], "token": data["token"]},
    )
    return {"paired": True, "id": data["id"]}
