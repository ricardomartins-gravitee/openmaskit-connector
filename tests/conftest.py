import secrets

import pytest

from openmaskit_connector.relay import create_app
from openmaskit_connector.state import write_json


@pytest.fixture
def relay(tmp_path):
    settings = {
        "admin_token": secrets.token_urlsafe(32),
        "proxy_token": secrets.token_urlsafe(32),
        "connectors": {},
    }
    path = tmp_path / "relay.json"
    write_json(path, settings)
    return create_app(path), settings
