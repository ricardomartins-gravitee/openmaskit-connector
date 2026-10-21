"""Private, atomic local state. Launch approval lives exclusively on the host."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")


def identifier(value: str) -> str:
    if not ID.fullmatch(value):
        raise ValueError(
            "Use a lowercase name starting with a letter, up to 48 characters"
        )
    return value


def local_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid service port") from None
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port is None
        or port == 0
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
    ):
        raise ValueError("Choose an explicit HTTP or HTTPS loopback address and port")
    host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
    if host == "::1":
        host = "[::1]"
    return f"{parsed.scheme}://{host}:{port}"


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    command: str = Field(min_length=1)
    args: list[str] = Field(default_factory=list, max_length=128)
    env: dict[str, str] = Field(default_factory=dict, max_length=128)
    cwd: str | None = None

    @field_validator("command")
    @classmethod
    def absolute_command(cls, value):
        if not Path(value).is_absolute():
            raise ValueError("Approve an absolute executable path")
        return value

    @field_validator("cwd")
    @classmethod
    def absolute_cwd(cls, value):
        if value is not None and not Path(value).is_absolute():
            raise ValueError("Working directory must be absolute")
        return value


def default_home() -> Path:
    return Path.home() / ".openmaskit-connector"


def private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("State directory cannot be a symbolic link")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def write_json(path: Path, data: dict) -> None:
    private_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(data, out, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_json(path: Path) -> dict:
    if path.is_symlink():
        raise ValueError("State files cannot be symbolic links")
    if not path.exists():
        return {}
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError("Private state file permissions must be 0600")
    return json.loads(path.read_text())
