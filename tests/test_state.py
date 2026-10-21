import os

import pytest
from pydantic import ValidationError

from openmaskit_connector.state import (
    Profile,
    identifier,
    local_endpoint,
    read_json,
    write_json,
)


@pytest.mark.parametrize(
    "value", ["../escape", "UPPER", "space name", "", "a" * 49, ";touch"]
)
def test_identifiers(value):
    with pytest.raises(ValueError):
        identifier(value)


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.test:9495",
        "https://127.0.0.1:9495",
        "http://user@localhost:9",
        "http://localhost:9/path",
        "http://localhost:9?secret=1",
        "http://localhost",
        "http://localhost:0",
        "http://localhost:9#fragment",
        "http://127.0.0.1.evil.test:9",
        "http://localhost:9\n",
    ],
)
def test_endpoints_are_loopback_only(url):
    with pytest.raises(ValueError):
        local_endpoint(url)


def test_private_atomic_files(tmp_path):
    path = tmp_path / "state/config.json"
    write_json(path, {"secret": "synthetic"})
    assert read_json(path) == {"secret": "synthetic"}
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
        path.chmod(0o644)
        with pytest.raises(ValueError):
            read_json(path)


def test_local_profile_rejects_remote_command_and_extra_fields():
    with pytest.raises(ValidationError):
        Profile(name="Test", command="python")
    with pytest.raises(ValidationError):
        Profile(name="Test", command="/bin/echo", shell=True)
