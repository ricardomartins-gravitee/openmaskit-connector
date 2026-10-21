"""Build a standalone, portable OpenMaskit connector executable."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    entry = ROOT / ".runtime/bundle-entry.py"
    entry.parent.mkdir(exist_ok=True)
    entry.write_text("from openmaskit_connector.cli import main\nmain()\n")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir",
            "--name",
            "openmaskit-connector",
            "--collect-all",
            "openmaskit_connector",
            "--copy-metadata",
            "openmaskit-connector",
            "--collect-submodules",
            "uvicorn",
            str(entry),
        ],
        cwd=ROOT,
        check=True,
    )


if __name__ == "__main__":
    main()
