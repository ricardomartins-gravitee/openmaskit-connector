import hashlib
import io
import json
import shutil
import subprocess
import sys
import urllib.error
import zipfile
from pathlib import Path

import pytest
from test_intel_wheel import COMMIT, SOURCE, make_wheel, wheel


def isolated_root(tmp_path, monkeypatch):
    root = tmp_path / "source"
    for name in (
        "uv.lock",
        "dependencies/openssl.json",
        "scripts/build_intel_dependencies.sh",
    ):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(wheel.ROOT / name, destination)
    monkeypatch.setattr(wheel, "ROOT", root)
    return root


@pytest.mark.parametrize(
    "change", ["app", "ruff", "recipe", "openssl", "cryptography", "build-tool"]
)
def test_key_tracks_library_inputs_only(tmp_path, monkeypatch, change):
    root = isolated_root(tmp_path, monkeypatch)
    before = wheel.build_key()
    if change == "app":
        (root / "application.py").write_text("updated application")
    elif change == "recipe":
        path = root / "scripts/build_intel_dependencies.sh"
        path.write_text(path.read_text() + "\n# updated recipe\n")
    elif change == "openssl":
        path = root / "dependencies/openssl.json"
        data = json.loads(path.read_text())
        data["hash"] = "sha256:" + "0" * 64
        path.write_text(json.dumps(data))
    else:
        path = root / "uv.lock"
        old = path.read_text()
        replacements = {
            "cryptography": (SOURCE["hash"], "sha256:" + "0" * 64),
            "build-tool": (
                'name = "maturin"\nversion = "1.15.0"',
                'name = "maturin"\nversion = "1.15.1"',
            ),
            "ruff": (
                'name = "ruff"\nversion = "0.17.1"',
                'name = "ruff"\nversion = "0.17.2"',
            ),
        }
        changed = old.replace(*replacements[change])
        assert changed != old
        path.write_text(changed)
    assert (wheel.build_key() == before) == (change in ("app", "ruff"))


def make_bundle(directory):
    make_wheel(directory)
    wheel.seal(directory, COMMIT)
    (directory / "sbom.json").write_text("{}")
    (directory / "toolchain.txt").write_text("synthetic inventory")
    return wheel.archive_bundle(directory)


def test_bundle_roundtrip_preserves_origin_across_application_revisions(tmp_path):
    archive = make_bundle(tmp_path / "built")
    target = tmp_path / "restored"
    wheel.unpack_bundle(archive, target)
    assert json.loads((target / "manifest.json").read_text())["commit"] == COMMIT
    assert (target / "install.txt").exists()


@pytest.mark.parametrize("member", ["../escaped", "/absolute", "extra.txt"])
def test_archive_rejects_unexpected_members(tmp_path, member):
    archive = make_bundle(tmp_path / "built")
    with zipfile.ZipFile(archive, "a") as bundle:
        bundle.writestr(member, b"bad")
    with pytest.raises(ValueError):
        wheel.unpack_bundle(archive, tmp_path / "restored")
    assert not (tmp_path / "escaped").exists()


def test_archive_size_is_bounded(tmp_path, monkeypatch):
    archive = make_bundle(tmp_path / "built")
    monkeypatch.setattr(wheel, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        wheel.unpack_bundle(archive, tmp_path / "restored")


def mock_release(tmp_path, monkeypatch):
    content = make_bundle(tmp_path / "built").read_bytes()
    tag = "native-intel-" + wheel.build_key()
    url = f"https://github.com/{wheel.REPOSITORY}/releases/download/{tag}/intel-native-library.zip"
    release = {
        "draft": False,
        "tag_name": tag,
        "assets": [
            {
                "name": "intel-native-library.zip",
                "size": len(content),
                "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                "browser_download_url": url,
            }
        ],
    }
    monkeypatch.setattr(wheel, "github_json", lambda path, **kwargs: release)

    class Opener:
        def open(self, actual, timeout):
            assert actual == url
            return io.BytesIO(content)

    monkeypatch.setattr(wheel.urllib.request, "build_opener", lambda *args: Opener())
    return release


def test_release_reuse_requires_main_workflow_and_hosted_provenance(
    tmp_path, monkeypatch
):
    assert wheel.REPOSITORY == "ricardomartins-gravitee/openmaskit-connector"
    assert wheel.BOOTSTRAP_REPOSITORY == "ricardomartins-gravitee/openmaskit-companion"
    mock_release(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(
        wheel.subprocess, "run", lambda args, **kw: calls.append((args, kw))
    )
    assert wheel.restore(tmp_path / "restored", bootstrap_allowed=False)
    args, options = calls[0]
    assert args[:3] == ["gh", "attestation", "verify"]
    assert args[args.index("--repo") + 1] == wheel.REPOSITORY
    assert args[args.index("--source-ref") + 1] == "refs/heads/main"
    assert (
        args[args.index("--signer-workflow") + 1]
        == f"{wheel.REPOSITORY}/.github/workflows/validate.yml"
    )
    assert "--deny-self-hosted-runners" in args
    assert options["check"] and options["timeout"] == 180


def test_bad_provenance_is_rejected_before_extraction(tmp_path, monkeypatch):
    mock_release(tmp_path, monkeypatch)

    def reject(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])

    monkeypatch.setattr(wheel.subprocess, "run", reject)
    with pytest.raises(subprocess.CalledProcessError):
        wheel.restore(tmp_path / "restored", bootstrap_allowed=False)
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize("failure", ["checksum", "url", "missing", "draft"])
def test_bad_release_never_falls_back_to_compiling(tmp_path, monkeypatch, failure):
    release = mock_release(tmp_path, monkeypatch)
    if failure == "checksum":
        release["assets"][0]["digest"] = "sha256:" + "0" * 64
    elif failure == "url":
        release["assets"][0]["browser_download_url"] = "https://other.example/lib.zip"
    elif failure == "missing":
        release["assets"] = []
    else:
        release["draft"] = True
    with pytest.raises(ValueError):
        wheel.restore(tmp_path / "restored", bootstrap_allowed=False)


@pytest.mark.parametrize("code", [401, 403, 404, 500])
def test_only_not_found_permits_source_build(tmp_path, monkeypatch, code):
    def unavailable(path):
        raise urllib.error.HTTPError("https://api.github.com/", code, "test", {}, None)

    monkeypatch.setattr(wheel, "github_json", unavailable)
    if code == 404:
        assert not wheel.restore(tmp_path / "restored", bootstrap_allowed=False)
    else:
        with pytest.raises(urllib.error.HTTPError):
            wheel.restore(tmp_path / "restored", bootstrap_allowed=False)


def mock_bootstrap(tmp_path, monkeypatch):
    root = isolated_root(tmp_path, monkeypatch)
    original = tmp_path / "original"
    make_wheel(original)
    wheel.seal(original, COMMIT)
    metadata = json.loads((original / "manifest.json").read_text())
    metadata.pop("build_key")
    (original / "manifest.json").write_text(json.dumps(metadata))
    pin = {
        "input_fingerprint": wheel.build_key(),
        "job_id": 123,
        "run_id": 456,
        "head_sha": "b" * 40,
        "commit": COMMIT,
        "wheel_sha256": metadata["wheel_sha256"],
    }
    (root / "dependencies/intel-bootstrap.json").write_text(json.dumps(pin))
    producer = {
        "run_id": 456,
        "head_sha": "b" * 40,
        "conclusion": "success",
        "name": "intel-wheel / Build and verify Intel dependency",
    }
    requests = []

    def github_json(path, *, repository=wheel.REPOSITORY):
        requests.append((path, repository))
        return (
            producer
            if "/jobs/" in path
            else {"artifacts": [{"name": "intel-cryptography-wheel", "expired": False}]}
        )

    monkeypatch.setattr(wheel, "github_json", github_json)

    def download(args, **kwargs):
        assert args[:4] == ["gh", "run", "download", "456"]
        assert args[args.index("--repo") + 1] == wheel.BOOTSTRAP_REPOSITORY
        destination = next(
            a.removeprefix("--dir=") for a in args if a.startswith("--dir=")
        )
        assert Path(destination).is_absolute()
        shutil.copytree(original, Path(destination))

    monkeypatch.setattr(wheel.subprocess, "run", download)
    return pin, producer, requests


def test_exact_successful_bootstrap_build_is_reused(tmp_path, monkeypatch):
    _, _, requests = mock_bootstrap(tmp_path, monkeypatch)
    directory = tmp_path / "restored"
    assert wheel.restore_bootstrap(directory)
    assert requests == [
        ("actions/jobs/123", wheel.BOOTSTRAP_REPOSITORY),
        ("actions/runs/456/artifacts", wheel.BOOTSTRAP_REPOSITORY),
    ]
    assert (
        json.loads((directory / "manifest.json").read_text())["build_key"]
        == wheel.build_key()
    )


@pytest.mark.parametrize(
    "field,value", [("head_sha", "wrong"), ("run_id", 789), ("conclusion", "failure")]
)
def test_bootstrap_rejects_wrong_or_failed_producer(
    tmp_path, monkeypatch, field, value
):
    _, producer, _ = mock_bootstrap(tmp_path, monkeypatch)
    producer[field] = value
    with pytest.raises(ValueError, match="producer"):
        wheel.restore_bootstrap(tmp_path / "restored")


def test_bootstrap_rejects_unpinned_bytes(tmp_path, monkeypatch):
    pin, _, _ = mock_bootstrap(tmp_path, monkeypatch)
    pin["wheel_sha256"] = "0" * 64
    (wheel.ROOT / "dependencies/intel-bootstrap.json").write_text(json.dumps(pin))
    with pytest.raises(ValueError, match="checksum"):
        wheel.restore_bootstrap(tmp_path / "restored")


def test_expired_seed_permits_a_source_build(tmp_path, monkeypatch):
    _, producer, _ = mock_bootstrap(tmp_path, monkeypatch)
    monkeypatch.setattr(
        wheel,
        "github_json",
        lambda path, **kwargs: producer if "/jobs/" in path else {"artifacts": []},
    )
    assert not wheel.restore_bootstrap(tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_changed_library_inputs_never_use_the_old_seed(tmp_path, monkeypatch):
    pin, _, _ = mock_bootstrap(tmp_path, monkeypatch)
    pin["input_fingerprint"] = "0" * 64
    (wheel.ROOT / "dependencies/intel-bootstrap.json").write_text(json.dumps(pin))
    assert not wheel.restore_bootstrap(tmp_path / "restored")


def test_archive_rejects_symlink_even_with_allowed_name(tmp_path):
    good = make_bundle(tmp_path / "built")
    bad = tmp_path / "symlink.zip"
    with zipfile.ZipFile(good) as original, zipfile.ZipFile(bad, "w") as result:
        for name in original.namelist():
            info = zipfile.ZipInfo(name)
            if name == "manifest.json":
                info.external_attr = 0o120777 << 16
            result.writestr(info, original.read(name))
    with pytest.raises(ValueError, match="unsafe path"):
        wheel.unpack_bundle(bad, tmp_path / "restored")


def test_cli_rejects_destinations_outside_fixed_ci_contract(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(
        sys, "argv", ["intel_wheel.py", "restore", str(tmp_path / "other")]
    )
    with pytest.raises(ValueError, match="fixed CI destination"):
        wheel.main()


def test_cli_passes_canonical_fixed_destination_to_restore(tmp_path, monkeypatch):
    output = tmp_path / "output.txt"
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(
        sys, "argv", ["intel_wheel.py", "restore", str(tmp_path / "intel-wheel")]
    )
    calls = []
    monkeypatch.setattr(
        wheel, "restore", lambda path, **kwargs: calls.append(path) or False
    )
    wheel.main()
    assert calls == [tmp_path.resolve() / "intel-wheel"]
    assert "reused=false" in output.read_text()
