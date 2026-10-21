"""Verified TLS for explicitly selected local relay endpoints."""

import ssl
from pathlib import Path
from urllib.parse import urlsplit


def client_context(endpoint: str, ca_file: Path | None = None):
    if urlsplit(endpoint).scheme != "https":
        if ca_file is not None:
            raise ValueError("A trusted certificate requires an HTTPS relay")
        return None
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_file is not None:
        if (
            ca_file.is_symlink()
            or not ca_file.is_file()
            or ca_file.stat().st_size > 1_048_576
        ):
            raise ValueError("Choose a local relay CA certificate")
        context.load_verify_locations(cadata=ca_file.read_text())
    return context
