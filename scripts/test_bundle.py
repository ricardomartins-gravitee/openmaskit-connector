"""Run the real MCP bridge tests with the packaged executable as connector."""

import os
import platform
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

root = Path(__file__).resolve().parents[1]
binary = (
    root
    / "dist/openmaskit-connector"
    / (
        "openmaskit-connector.exe"
        if platform.system() == "Windows"
        else "openmaskit-connector"
    )
)
reported_version = subprocess.run(
    [str(binary), "--version"], check=True, capture_output=True, text=True
).stdout.strip()
assert reported_version == version("openmaskit-connector")
subprocess.run(
    [sys.executable, "-m", "pytest", "tests/test_bridge_integration.py", "-q"],
    cwd=root,
    env={**os.environ, "CONNECTOR_BINARY": str(binary)},
    check=True,
)
