"""Create portable connector downloads and SHA-256 checksums."""

import hashlib
import platform
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    downloads = ROOT / "dist/downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    label = platform.system().lower() + "-" + platform.machine().lower()
    shutil.make_archive(
        str(downloads / ("openmaskit-connector-" + label)),
        "zip",
        ROOT / "dist",
        "openmaskit-connector",
    )
    checksums = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in downloads.glob("*.zip")
    }
    (downloads / "SHA256SUMS.txt").write_text(
        "".join(f"{value}  {key}\n" for key, value in sorted(checksums.items()))
    )


if __name__ == "__main__":
    main()
