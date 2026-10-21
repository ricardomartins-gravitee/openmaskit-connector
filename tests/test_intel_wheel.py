import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "intel_wheel", Path(__file__).resolve().parents[1] / "scripts/intel_wheel.py"
)
wheel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wheel)
COMMIT = "a" * 40
VERSION, SOURCE = wheel.locked_source()


def make_wheel(directory, *, name=None, metadata=None):
    directory.mkdir(exist_ok=True)
    path = directory / (
        name or f"cryptography-{VERSION}-cp311-abi3-macosx_14_0_x86_64.whl"
    )
    with zipfile.ZipFile(path, "w") as package:
        package.writestr(
            f"cryptography-{VERSION}.dist-info/METADATA",
            metadata or f"Name: cryptography\nVersion: {VERSION}\n",
        )
    return path


def test_verified_wheel_generates_hash_required_direct_file_requirement(tmp_path):
    path = make_wheel(tmp_path)
    wheel.seal(tmp_path, COMMIT)
    wheel.prepare(tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["source_sha256"] == SOURCE["hash"].removeprefix("sha256:")
    assert manifest["wheel_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert (tmp_path / "install.txt").read_text() == (
        f"{path.as_uri()} --hash=sha256:{manifest['wheel_sha256']}\n"
    )


@pytest.mark.parametrize(
    "change",
    [
        "commit",
        "version",
        "source_sha256",
        "wheel_sha256",
        "openssl_version",
        "openssl_source_sha256",
    ],
)
def test_rejects_wheel_from_other_commit_lockfile_or_checksum(tmp_path, change):
    make_wheel(tmp_path)
    wheel.seal(tmp_path, COMMIT)
    path = tmp_path / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest[change] = "untrusted"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        wheel.prepare(tmp_path)
    assert not (tmp_path / "install.txt").exists()


def test_modified_wheel_is_rejected(tmp_path):
    path = make_wheel(tmp_path)
    wheel.seal(tmp_path, COMMIT)
    with path.open("ab") as target:
        target.write(b"modified")
    with pytest.raises(ValueError, match="does not match"):
        wheel.prepare(tmp_path)


@pytest.mark.parametrize(
    "name",
    [
        f"cryptography-{VERSION}-cp311-abi3-macosx_11_0_arm64.whl",
        f"cryptography-{VERSION}-cp311-abi3-macosx_11_0_universal2.whl",
        f"cryptography-{VERSION}-py3-none-any.whl",
        "cryptography-1.0.0-cp311-abi3-macosx_14_0_x86_64.whl",
        f"other-{VERSION}-cp311-abi3-macosx_14_0_x86_64.whl",
    ],
)
def test_rejects_wrong_package_version_or_architecture(tmp_path, name):
    make_wheel(tmp_path, name=name)
    with pytest.raises(ValueError):
        wheel.seal(tmp_path, COMMIT)


def test_rejects_wrong_embedded_metadata(tmp_path):
    make_wheel(tmp_path, metadata="Name: other\nVersion: 1\n")
    with pytest.raises(ValueError, match="metadata"):
        wheel.seal(tmp_path, COMMIT)


def test_requires_one_wheel_full_commit_and_manifest(tmp_path):
    with pytest.raises(ValueError):
        wheel.seal(tmp_path, COMMIT)
    make_wheel(tmp_path)
    with pytest.raises(ValueError, match="full source commit"):
        wheel.seal(tmp_path, "short")
    with pytest.raises(FileNotFoundError):
        wheel.prepare(tmp_path)
    make_wheel(
        tmp_path, name=f"cryptography-{VERSION}-cp312-abi3-macosx_14_0_x86_64.whl"
    )
    with pytest.raises(ValueError, match="Exactly one"):
        wheel.seal(tmp_path, COMMIT)


def fake_source(monkeypatch, content, *, size=None, checksum=None):
    source = {
        **SOURCE,
        "size": len(content) if size is None else size,
        "hash": checksum or "sha256:" + hashlib.sha256(content).hexdigest(),
    }
    monkeypatch.setattr(wheel, "locked_source", lambda: (VERSION, source))

    class Opener:
        def open(self, url, timeout):
            assert url == SOURCE["url"] and timeout == 60
            return io.BytesIO(content)

    monkeypatch.setattr(wheel.urllib.request, "build_opener", lambda *args: Opener())


@pytest.mark.parametrize("failure", ["size", "checksum"])
def test_source_mismatch_fails_before_extracting_or_executing(
    tmp_path, monkeypatch, failure
):
    args = {"size": 42} if failure == "size" else {"checksum": "sha256:" + "0" * 64}
    fake_source(monkeypatch, b"untrusted source", **args)
    with pytest.raises(ValueError, match="does not match lockfile"):
        wheel.fetch(tmp_path / "build")
    assert not (tmp_path / "build/source").exists()


def source_archive(files):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w:gz") as package:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            package.addfile(member, io.BytesIO(data))
    return content.getvalue()


def test_verified_source_preserves_cargo_lock(tmp_path, monkeypatch):
    prefix = f"cryptography-{VERSION}/"
    fake_source(
        monkeypatch,
        source_archive(
            {
                prefix + "pyproject.toml": b"[tool.maturin]\nlocked = true\n",
                prefix + "Cargo.lock": b"locked-rust-inputs",
            }
        ),
    )
    directory = tmp_path / "build"
    wheel.fetch(directory)
    assert (
        directory / "source" / prefix / "Cargo.lock"
    ).read_bytes() == b"locked-rust-inputs"


def test_source_traversal_is_rejected(tmp_path, monkeypatch):
    fake_source(monkeypatch, source_archive({"../../escaped": b"bad"}))
    with pytest.raises(tarfile.FilterError):
        wheel.fetch(tmp_path / "build")
    assert not (tmp_path / "escaped").exists()


def test_source_build_must_enforce_cargo_lock(tmp_path, monkeypatch):
    fake_source(
        monkeypatch,
        source_archive(
            {
                f"cryptography-{VERSION}/pyproject.toml": b"[tool.maturin]\nlocked = false\n",
            }
        ),
    )
    with pytest.raises(ValueError, match="enforce Cargo.lock"):
        wheel.fetch(tmp_path / "build")


def test_source_redirects_are_rejected():
    with pytest.raises(ValueError, match="redirects are forbidden"):
        wheel.NoRedirect().redirect_request(None, None, 302, "", {}, "http://other")


@pytest.mark.parametrize(
    "url",
    [
        "http://release-assets.githubusercontent.com/file",
        "file:///tmp/source",
        "https://github.com.example.org/file",
        "https://other.example/file",
        "https://user@github.com/file",
    ],
)
def test_openssl_redirects_are_limited_to_github_https_assets(url):
    with pytest.raises(ValueError, match="outside GitHub HTTPS"):
        wheel.GitHubReleaseRedirect().redirect_request(None, None, 302, "", {}, url)


def test_github_release_asset_redirect_is_allowed():
    request = wheel.urllib.request.Request("https://github.com/openssl/openssl/file")
    result = wheel.GitHubReleaseRedirect().redirect_request(
        request, None, 302, "", {}, "https://release-assets.githubusercontent.com/file"
    )
    assert result.full_url == "https://release-assets.githubusercontent.com/file"


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", "../bad"),
        ("url", "http://github.com/file"),
        ("hash", "sha256:invalid"),
    ],
)
def test_invalid_openssl_lock_is_rejected(tmp_path, monkeypatch, field, value):
    source = wheel.locked_openssl()
    source[field] = value
    (tmp_path / "dependencies").mkdir()
    (tmp_path / "dependencies/openssl.json").write_text(json.dumps(source))
    monkeypatch.setattr(wheel, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="Invalid locked OpenSSL"):
        wheel.locked_openssl()


@pytest.mark.parametrize("failure", [None, "size", "checksum"])
def test_openssl_source_verification_precedes_extraction(
    tmp_path, monkeypatch, failure
):
    source = wheel.locked_openssl()
    content = source_archive(
        {f"openssl-{source['version']}/Configure": b"upstream input"}
    )
    source["size"] = len(content) + (1 if failure == "size" else 0)
    source["hash"] = "sha256:" + (
        "0" * 64 if failure == "checksum" else hashlib.sha256(content).hexdigest()
    )
    monkeypatch.setattr(wheel, "locked_openssl", lambda: source)

    class Opener:
        def open(self, url, timeout):
            assert url == source["url"] and timeout == 60
            return io.BytesIO(content)

    monkeypatch.setattr(wheel.urllib.request, "build_opener", lambda *args: Opener())
    directory = tmp_path / "build"
    if failure:
        with pytest.raises(ValueError, match="does not match lockfile"):
            wheel.fetch_openssl(directory)
        assert not (directory / "upstream").exists()
    else:
        wheel.fetch_openssl(directory)
        assert (directory / "upstream/Configure").read_bytes() == b"upstream input"


def test_sbom_uses_exact_native_openssl_version_and_cpe(tmp_path, monkeypatch):
    from cryptography.hazmat.backends.openssl.backend import backend

    version = wheel.locked_openssl()["version"]
    monkeypatch.setattr(
        backend, "openssl_version_text", lambda: f"OpenSSL {version} date"
    )
    wheel.sbom(tmp_path)
    data = json.loads((tmp_path / "sbom.json").read_text())
    openssl = next(c for c in data["components"] if c["name"] == "openssl")
    assert openssl["version"] == version
    assert openssl["cpe"] == f"cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    "version", ["LibreSSL 1.2.3", "OpenSSL 3.6.3 old runner library"]
)
def test_sbom_rejects_wrong_or_unrecognized_native_openssl(
    tmp_path, monkeypatch, version
):
    from cryptography.hazmat.backends.openssl.backend import backend

    monkeypatch.setattr(backend, "openssl_version_text", lambda: version)
    with pytest.raises(ValueError):
        wheel.sbom(tmp_path)


def test_seal_cli_prefers_explicit_source_revision_to_caller_revision(
    tmp_path, monkeypatch
):
    directory = tmp_path / "intel-wheel"
    directory.mkdir()
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("SOURCE_REVISION", COMMIT)
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    monkeypatch.setattr(sys, "argv", ["intel_wheel.py", "seal", str(directory)])
    recorded = []
    monkeypatch.setattr(
        wheel, "seal", lambda path, revision: recorded.append((path, revision))
    )

    wheel.main()

    assert recorded == [(directory, COMMIT)]
