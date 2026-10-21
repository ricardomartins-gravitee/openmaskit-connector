"""Build input/output verification for the same-run Intel cryptography artifact.

Compilation is an explicit CI build operation. This helper never executes source
or invokes a compiler, and consumers never install an sdist.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "ricardomartins-gravitee/openmaskit-connector"
BOOTSTRAP_REPOSITORY = "ricardomartins-gravitee/openmaskit-companion"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024


def build_key():
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    project = next(p for p in lock["package"] if p["name"] == "openmaskit-connector")
    pending = [p["name"] for p in project["dev-dependencies"]["intel-build"]]
    selected = {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        package = next(p for p in lock["package"] if p["name"] == name)
        selected[name] = package
        pending.extend(p["name"] for p in package.get("dependencies", []))
    version, source = locked_source()
    inputs = {
        "schema": 1,
        "target": "cpython-3.12-macos-14-x86_64",
        "uv": "0.13.1",
        "cryptography": {"version": version, "source": source},
        "openssl": locked_openssl(),
        "build_tools": selected,
        "recipe": (ROOT / "scripts/build_intel_dependencies.sh").read_text(),
    }
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def locked_source(lock=None):
    lock = lock or ROOT / "uv.lock"
    packages = tomllib.loads(lock.read_text())["package"]
    package = next(p for p in packages if p["name"] == "cryptography")
    source = package["sdist"]
    url = urllib.parse.urlsplit(source["url"])
    if (
        url.scheme != "https"
        or url.netloc != "files.pythonhosted.org"
        or url.query
        or url.fragment
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", source["hash"])
        or not re.fullmatch(r"\d+\.\d+\.\d+", package["version"])
    ):
        raise ValueError("Invalid locked cryptography source")
    return package["version"], source


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def locked_openssl():
    source = json.loads((ROOT / "dependencies/openssl.json").read_text())
    version = source["version"]
    if (
        not re.fullmatch(r"\d+\.\d+\.\d+", version)
        or source["url"]
        != (
            "https://github.com/openssl/openssl/releases/download/"
            f"openssl-{version}/openssl-{version}.tar.gz"
        )
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", source["hash"])
    ):
        raise ValueError("Invalid locked OpenSSL source")
    return source


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Source download redirects are forbidden")


class GitHubReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != "https" or url.netloc not in {
            "github.com",
            "release-assets.githubusercontent.com",
        }:
            raise ValueError("OpenSSL download redirected outside GitHub HTTPS assets")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_openssl(directory):
    source = locked_openssl()
    directory.mkdir(parents=True, exist_ok=False)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), GitHubReleaseRedirect()
    )
    with opener.open(source["url"], timeout=60) as response:
        content = response.read(64 * 1024 * 1024 + 1)
    if len(content) != source["size"]:
        raise ValueError("OpenSSL source size does not match lockfile")
    if "sha256:" + hashlib.sha256(content).hexdigest() != source["hash"]:
        raise ValueError("OpenSSL source checksum does not match lockfile")
    archive = directory / "source.tar.gz"
    archive.write_bytes(content)
    with tarfile.open(archive) as package:
        package.extractall(directory / "source", filter="data")
    upstream = directory / "source" / f"openssl-{source['version']}"
    upstream.rename(directory / "upstream")


def fetch(directory):
    version, source = locked_source()
    directory.mkdir(parents=True, exist_ok=False)
    archive = directory / "source.tar.gz"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(source["url"], timeout=60) as response:
        content = response.read(16 * 1024 * 1024 + 1)
    if len(content) != source["size"]:
        raise ValueError("Source size does not match lockfile")
    if "sha256:" + hashlib.sha256(content).hexdigest() != source["hash"]:
        raise ValueError("Source checksum does not match lockfile")
    archive.write_bytes(content)
    with tarfile.open(archive) as package:
        # Python 3.12's data filter rejects traversal, devices and escaping links.
        package.extractall(directory / "source", filter="data")
    upstream = directory / "source" / f"cryptography-{version}"
    config = tomllib.loads((upstream / "pyproject.toml").read_text())
    if config["tool"]["maturin"].get("locked") is not True:
        raise ValueError("Upstream build must enforce Cargo.lock")
    if not (upstream / "Cargo.lock").is_file():
        raise ValueError("Locked Rust dependencies are required")


def wheel_details(directory):
    from packaging.utils import parse_wheel_filename

    version, _ = locked_source()
    wheels = list(directory.glob("*.whl"))
    if len(wheels) != 1 or wheels[0].is_symlink():
        raise ValueError("Exactly one regular wheel is required")
    wheel = wheels[0]
    name, built_version, _, tags = parse_wheel_filename(wheel.name)
    if name != "cryptography" or str(built_version) != version:
        raise ValueError("Wheel does not match locked cryptography version")
    if not tags or any(
        not re.fullmatch(r"macosx_\d+_\d+_x86_64", tag.platform) for tag in tags
    ):
        raise ValueError("Wheel must target Intel macOS only")
    with zipfile.ZipFile(wheel) as package:
        metadata = package.read(f"cryptography-{version}.dist-info/METADATA")
    parsed = BytesParser().parsebytes(metadata)
    if parsed["Name"] != "cryptography" or parsed["Version"] != version:
        raise ValueError("Wheel metadata does not match lockfile")
    return wheel


def manifest(directory, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("A full source commit is required")
    version, source = locked_source()
    wheel = wheel_details(directory)
    return {
        "commit": commit,
        "version": version,
        "source_sha256": source["hash"].removeprefix("sha256:"),
        "wheel": wheel.name,
        "wheel_sha256": digest(wheel),
        "build_key": build_key(),
        "openssl_version": locked_openssl()["version"],
        "openssl_source_sha256": locked_openssl()["hash"].removeprefix("sha256:"),
    }


def seal(directory, commit):
    data = manifest(directory, commit)
    (directory / "manifest.json").write_text(json.dumps(data, indent=2) + "\n")


def prepare(directory):
    recorded = json.loads((directory / "manifest.json").read_text())
    expected = manifest(directory, recorded["commit"])
    if recorded != expected:
        raise ValueError(
            "Wheel artifact does not match its source, checksum and build inputs"
        )
    wheel = directory / expected["wheel"]
    (directory / "install.txt").write_text(
        f"{wheel.resolve().as_uri()} --hash=sha256:{expected['wheel_sha256']}\n"
    )


def archive_bundle(directory):
    prepare(directory)
    wheel = wheel_details(directory)
    destination = directory.parent / "intel-native-library.zip"
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in (
            wheel,
            *(
                directory / name
                for name in ("manifest.json", "sbom.json", "toolchain.txt")
            ),
        ):
            bundle.write(path, path.name)
    return destination


def unpack_bundle(archive, directory):
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        wheels = [name for name in names if name.endswith(".whl")]
        if (
            len(names) != 4
            or len(wheels) != 1
            or set(names) != {"manifest.json", "sbom.json", "toolchain.txt", *wheels}
        ):
            raise ValueError("Invalid stored native library members")
        for member in bundle.infolist():
            if (
                Path(member.filename).name != member.filename
                or (member.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise ValueError("Stored native library contains an unsafe path")
        if sum(member.file_size for member in bundle.infolist()) > MAX_BUNDLE_BYTES:
            raise ValueError("Stored native library exceeds size limit")
        directory.mkdir(parents=True, exist_ok=False)
        for name in names:
            (directory / name).write_bytes(bundle.read(name))
    prepare(directory)


def github_json(path, *, repository=REPOSITORY):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "openmaskit-connector-ci",
    }
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/{path}",
        headers=headers,
    )
    api = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with api.open(request, timeout=60) as response:
        return json.loads(response.read(1024 * 1024))


def restore_bootstrap(directory):
    """One reviewed existing build seeds the durable release without recompiling."""
    directory = directory.resolve()
    path = ROOT / "dependencies/intel-bootstrap.json"
    if not path.exists():
        return False
    pin = json.loads(path.read_text())
    if pin["input_fingerprint"] != build_key():
        return False
    job = github_json(
        f"actions/jobs/{int(pin['job_id'])}", repository=BOOTSTRAP_REPOSITORY
    )
    if (
        job.get("run_id") != pin["run_id"]
        or job.get("head_sha") != pin["head_sha"]
        or job.get("conclusion") != "success"
        or job.get("name") != "intel-wheel / Build and verify Intel dependency"
    ):
        raise ValueError("Bootstrap library producer does not match its reviewed pin")
    artifacts = github_json(
        f"actions/runs/{int(pin['run_id'])}/artifacts",
        repository=BOOTSTRAP_REPOSITORY,
    )["artifacts"]
    matching = [
        a
        for a in artifacts
        if a["name"] == "intel-cryptography-wheel" and not a["expired"]
    ]
    if not matching:
        return False
    if len(matching) != 1:
        raise ValueError("Ambiguous bootstrap library artifact")
    subprocess.run(
        [
            "gh",
            "run",
            "download",
            str(int(pin["run_id"])),
            "--repo",
            BOOTSTRAP_REPOSITORY,
            "--name",
            "intel-cryptography-wheel",
            "--dir=" + str(directory),
        ],
        check=True,
        timeout=180,
    )
    recorded = json.loads((directory / "manifest.json").read_text())
    expected = manifest(directory, pin["commit"])
    expected.pop("build_key")
    if recorded != expected or expected["wheel_sha256"] != pin["wheel_sha256"]:
        raise ValueError(
            "Bootstrap library source or checksum does not match its reviewed pin"
        )
    seal(directory, pin["commit"])
    prepare(directory)
    return True


def restore(directory, *, bootstrap_allowed=True):
    """Only a missing library permits compilation; verification errors fail closed."""
    directory = directory.resolve()
    tag = "native-intel-" + build_key()
    try:
        release = github_json(f"releases/tags/{tag}")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return restore_bootstrap(directory) if bootstrap_allowed else False
        raise
    if release.get("draft") or release.get("tag_name") != tag:
        raise ValueError("Invalid stored native library release")
    assets = [a for a in release["assets"] if a["name"] == "intel-native-library.zip"]
    if len(assets) != 1 or not 0 < assets[0]["size"] <= MAX_BUNDLE_BYTES:
        raise ValueError("Missing or invalid native library release asset")
    url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/intel-native-library.zip"
    if assets[0]["browser_download_url"] != url:
        raise ValueError("Unexpected native library asset URL")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), GitHubReleaseRedirect()
    )
    with opener.open(url, timeout=60) as response:
        content = response.read(MAX_BUNDLE_BYTES + 1)
    if (
        len(content) != assets[0]["size"]
        or assets[0].get("digest") != "sha256:" + hashlib.sha256(content).hexdigest()
    ):
        raise ValueError("Stored native library checksum mismatch")
    archive = directory.parent / "intel-native-library.zip"
    archive.write_bytes(content)
    subprocess.run(
        [
            "gh",
            "attestation",
            "verify",
            str(archive),
            "--repo",
            REPOSITORY,
            "--source-ref",
            "refs/heads/main",
            "--signer-workflow",
            f"{REPOSITORY}/.github/workflows/validate.yml",
            "--deny-self-hosted-runners",
        ],
        check=True,
        timeout=180,
    )
    unpack_bundle(archive, directory)
    return True


def sbom(directory):
    from cryptography.hazmat.backends.openssl.backend import backend

    version, _ = locked_source()
    text = backend.openssl_version_text()
    match = re.fullmatch(r"OpenSSL (\d+\.\d+\.\d+[a-z]?) .+", text)
    if not match:
        raise ValueError("Cannot identify embedded OpenSSL for vulnerability scan")
    if match[1] != locked_openssl()["version"]:
        raise ValueError("Native wheel did not link the pinned OpenSSL release")
    components = [
        {
            "type": "library",
            "name": "cryptography",
            "version": version,
            "purl": f"pkg:pypi/cryptography@{version}",
        },
        {
            "type": "library",
            "name": "openssl",
            "version": match[1],
            "purl": f"pkg:generic/openssl@{match[1]}",
            "cpe": f"cpe:2.3:a:openssl:openssl:{match[1]}:*:*:*:*:*:*:*",
        },
    ]
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components,
    }
    (directory / "sbom.json").write_text(json.dumps(data, indent=2) + "\n")
    print(f"Embedded OpenSSL: {text}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        choices=(
            "key",
            "restore",
            "restore-release",
            "archive",
            "fetch",
            "fetch-openssl",
            "seal",
            "prepare",
            "sbom",
        ),
    )
    parser.add_argument("directory", type=Path, nargs="?")
    args = parser.parse_args()
    if args.operation == "key":
        print(build_key())
        return
    if args.directory is None:
        parser.error("directory is required")
    # These are CI operations, with destinations fixed by the workflow contract.
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    name = {
        "fetch": "crypto-build",
        "fetch-openssl": "openssl-build",
        "restore-release": "existing-native-library",
    }.get(args.operation, "intel-wheel")
    directory = root / name
    if args.directory.resolve() != directory or directory.is_symlink():
        raise ValueError("Only the fixed CI destination is accepted")
    if args.operation == "seal":
        seal(
            directory,
            os.environ.get("SOURCE_REVISION") or os.environ.get("GITHUB_SHA", ""),
        )
    elif args.operation in ("restore", "restore-release"):
        result = restore(directory, bootstrap_allowed=args.operation == "restore")
        value = "true" if result else "false"
        print(f"Reused stored native library: {value}")
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"reused={value}\nbuild-key={build_key()}\n")
    else:
        {
            "fetch": fetch,
            "fetch-openssl": fetch_openssl,
            "sbom": sbom,
            "prepare": prepare,
            "archive": archive_bundle,
        }[args.operation](directory)


if __name__ == "__main__":
    main()
