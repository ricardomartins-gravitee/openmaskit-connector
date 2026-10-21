"""Pair a locally approved connector with a loopback relay."""

from pathlib import Path

import httpx

from .state import local_endpoint, write_json
from .tls import client_context

RELAY = "http://127.0.0.1:9495"


def pair(home: Path, endpoint: str, code: str, *, ca_file: Path | None = None):
    endpoint = local_endpoint(endpoint)
    context = client_context(endpoint, ca_file)
    with httpx.Client(trust_env=False, timeout=10, verify=context or True) as api:
        response = api.post(endpoint + "/pair", json={"code": code})
        response.raise_for_status()
        data = response.json()
    if (
        data.get("protocol") != 1
        or not isinstance(data.get("token"), str)
        or len(data["token"]) < 32
    ):
        raise ValueError("Incompatible pairing response")
    trust = {"ca_file": str(ca_file.resolve())} if ca_file is not None else {}
    write_json(
        home / "connection.json",
        {"endpoint": endpoint, "id": data["id"], "token": data["token"], **trust},
    )
    return {"paired": True, "id": data["id"]}
