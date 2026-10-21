"""Run the real MCP bridge tests with the packaged executable as connector."""

import os
import platform
import subprocess
import sys
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
subprocess.run([str(binary), "--version"], check=True)
subprocess.run(
    [sys.executable, "-m", "pytest", "tests/test_bridge_integration.py", "-q"],
    cwd=root,
    env={**os.environ, "CONNECTOR_BINARY": str(binary)},
    check=True,
)
