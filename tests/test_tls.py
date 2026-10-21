import asyncio
import secrets
import ssl
import sys
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from unittest.mock import patch

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from test_bridge_integration import FIXTURE, running_relay

from openmaskit_connector import cli
from openmaskit_connector.connector import channel
from openmaskit_connector.pairing import pair
from openmaskit_connector.state import local_endpoint, read_json, write_json
from openmaskit_connector.tls import client_context


def certificate(folder, *, hostname=True, expired=False):
    folder.mkdir()
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic relay")])
    now = datetime.now(timezone.utc)
    names = [x509.DNSName("wrong.invalid")]
    if hostname:
        names = [
            x509.IPAddress(ip_address("127.0.0.1")),
            x509.DNSName("connector-relay"),
        ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 2))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = folder / "relay.pem", folder / "relay.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_file.chmod(0o600)
    return cert_file, {"ssl_certfile": str(cert_file), "ssl_keyfile": str(key_file)}


def state(folder):
    settings = {
        "admin_token": secrets.token_urlsafe(32),
        "proxy_token": secrets.token_urlsafe(32),
        "connectors": {},
    }
    path = folder / "relay/relay.json"
    write_json(path, settings)
    return path, settings


def test_https_loopback_normalization_and_verification_cannot_be_disabled(tmp_path):
    assert local_endpoint("https://localhost:9495/") == "https://127.0.0.1:9495"
    context = client_context("https://127.0.0.1:9495")
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    with pytest.raises(ValueError):
        client_context("http://127.0.0.1:9495", tmp_path / "ca.pem")
    with pytest.raises(ValueError):
        client_context("https://127.0.0.1:9495", tmp_path / "missing.pem")


@pytest.mark.asyncio
async def test_verified_https_pairing_and_wss_forward_complete_synthetic_mcp(tmp_path):
    ca_file, tls = certificate(tmp_path / "pki")
    relay_state, settings = state(tmp_path)
    home = tmp_path / "host"
    context = client_context("https://127.0.0.1:9495", ca_file)
    async with running_relay(relay_state, tls=tls) as base:
        async with httpx.AsyncClient(
            base_url=base, verify=context, trust_env=False
        ) as api:
            code = (
                await api.post(
                    "/admin/pairings",
                    headers={"Authorization": "Bearer " + settings["admin_token"]},
                    json={},
                )
            ).json()["code"]
        await asyncio.to_thread(pair, home, base, code, ca_file=ca_file)
        assert read_json(home / "connection.json")["ca_file"] == str(ca_file.resolve())
        write_json(
            home / "profiles.json",
            {
                "fixture": {
                    "name": "Synthetic MCP",
                    "command": sys.executable,
                    "args": [str(FIXTURE)],
                }
            },
        )
        ready = asyncio.Event()
        connector = asyncio.create_task(channel(home, connected=ready))
        try:
            await asyncio.wait_for(ready.wait(), 5)
            config = read_json(home / "connection.json")
            async with httpx.AsyncClient(
                verify=context,
                trust_env=False,
                headers={"Authorization": "Bearer " + settings["proxy_token"]},
            ) as client:
                async with streamable_http_client(
                    base + "/mcp/" + config["id"] + "/fixture", http_client=client
                ) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        result = await session.call_tool(
                            "greet", {"name": "TLS fixture"}
                        )
                        assert result.content[0].text == "Hello TLS fixture"
        finally:
            connector.cancel()
            await asyncio.gather(connector, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("problem", ["untrusted", "hostname", "expired"])
async def test_tls_failure_never_pairs_or_falls_back_to_plaintext(tmp_path, problem):
    ca_file, tls = certificate(
        tmp_path / "pki", hostname=problem != "hostname", expired=problem == "expired"
    )
    relay_state, _ = state(tmp_path)
    home = tmp_path / "host"
    write_json(home / "connection.json", {"existing": "preserved"})
    before = (home / "connection.json").read_bytes()
    trust = None if problem == "untrusted" else ca_file
    async with running_relay(relay_state, tls=tls) as base:
        with pytest.raises(httpx.ConnectError):
            await asyncio.to_thread(pair, home, base, "synthetic", ca_file=trust)
    assert (home / "connection.json").read_bytes() == before


@pytest.mark.asyncio
async def test_wss_rejects_untrusted_ca_before_credentials_are_sent(tmp_path):
    _, tls = certificate(tmp_path / "server")
    wrong_ca, _ = certificate(tmp_path / "unrelated")
    relay_state, _ = state(tmp_path)
    home = tmp_path / "host"
    async with running_relay(relay_state, tls=tls) as base:
        write_json(
            home / "connection.json",
            {
                "endpoint": base,
                "id": "computer-fixture",
                "token": "synthetic" * 5,
                "ca_file": str(wrong_ca),
            },
        )
        write_json(home / "profiles.json", {})
        with pytest.raises(ssl.SSLCertVerificationError):
            await asyncio.wait_for(channel(home), 5)


def test_relay_cli_requires_both_tls_files_and_passes_them_to_uvicorn(tmp_path):
    path, _ = state(tmp_path)
    ca_file, tls = certificate(tmp_path / "pki")
    with patch("uvicorn.run") as run:
        cli.main(
            [
                "relay",
                "--state",
                str(path),
                "--tls-cert",
                str(ca_file),
                "--tls-key",
                tls["ssl_keyfile"],
            ]
        )
        assert run.call_args.kwargs["ssl_certfile"] == str(ca_file)
        assert run.call_args.kwargs["ssl_keyfile"] == tls["ssl_keyfile"]
    with patch("uvicorn.run") as run, pytest.raises(SystemExit):
        cli.main(["relay", "--state", str(path), "--tls-cert", str(ca_file)])
    run.assert_not_called()
