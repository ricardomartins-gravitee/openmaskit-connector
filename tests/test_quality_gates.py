import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.load(
        (ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader
    )


def test_security_and_quality_are_required_before_publishing():
    jobs = workflow("validate.yml")["jobs"]
    assert set(jobs["image"]["needs"]) == {"quality", "security"}
    assert set(jobs["publish"]["needs"]) == {
        "test",
        "image",
        "quality",
        "security",
        "intel-wheel",
        "native-release",
    }
    assert set(jobs["release"]["needs"]) == {
        "test",
        "image",
        "quality",
        "security",
        "intel-wheel",
        "native-release",
        "publish",
    }
    for name in ("quality", "security"):
        assert jobs[name]["uses"] == f"./.github/workflows/{name}.yml"
        assert "workflow_call" in workflow(f"{name}.yml")["on"]


def test_workflows_pin_external_actions_and_do_not_ignore_failures():
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        data = workflow(path.name)
        assert "pull_request_target" not in data["on"]
        for job in data["jobs"].values():
            assert job.get("continue-on-error", "false") == "false"
            for step in job.get("steps", []):
                assert step.get("continue-on-error", "false") == "false"
                if "uses" in step:
                    assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])


def test_coverage_gate_includes_all_production_code_and_branches():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["coverage"]
    assert config["run"]["branch"] is True
    assert config["run"]["source"] == ["src/openmaskit_connector"]
    assert config["report"]["fail_under"] >= 80
    assert "omit" not in config["run"]


def test_ci_disallows_dependency_source_builds_and_implicit_resynchronization():
    for name in ("validate.yml", "quality.yml", "intel-wheel.yml"):
        for job in workflow(name)["jobs"].values():
            for step in job.get("steps", []):
                for command in re.findall(
                    r"\buv (?:sync|run)\b[^\n]*", step.get("run", "")
                ):
                    assert "--frozen" in command
                    assert "--no-build" in command
                    if command.startswith("uv run"):
                        assert "--no-sync" in command
                        assert "--no-build" in command
    assert "uv sync --frozen --no-build" in (ROOT / "Dockerfile").read_text()


def test_intel_compilation_is_explicit_isolated_scanned_and_reused_in_same_run():
    jobs = workflow("validate.yml")["jobs"]
    assert set(jobs["intel-wheel"]["needs"]) == {"quality", "security"}
    assert jobs["intel-wheel"]["uses"] == "./.github/workflows/intel-wheel.yml"
    assert jobs["test"]["needs"] == "intel-wheel"
    test_commands = "\n".join(s.get("run", "") for s in jobs["test"]["steps"])
    assert "scripts/bundle.py" in test_commands
    assert "scripts/test_bundle.py" in test_commands
    assert "desktop/macos" not in test_commands
    assert "manager_acceptance.py" not in test_commands
    builder = workflow("intel-wheel.yml")["jobs"]["wheel"]
    assert builder["runs-on"] == "macos-15-intel"
    assert builder["env"]["OPENSSL_STATIC"] == "1"
    steps = builder["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "--only-group intel-build" in commands
    recipe = (ROOT / "scripts/build_intel_dependencies.sh").read_text()
    assert "uv build" in recipe and "--no-build-isolation" in recipe
    assert "scripts/intel_wheel.py fetch" in commands
    assert "scripts/intel_wheel.py fetch-openssl" in commands
    assert "./Configure darwin64-x86_64-cc no-shared no-module" in recipe
    assert "HARNESS_JOBS=3 make test" in recipe
    assert "brew" not in commands
    assert "scripts/intel_wheel.py seal" in commands
    assert "scripts/test_crypto.py" in commands
    assert "scripts/intel_wheel.py sbom" in commands
    assert "--fail-on high" in commands
    assert "grype-report.json" in commands
    builds = [
        step
        for step in steps
        if step.get("run") == "bash scripts/build_intel_dependencies.sh"
    ]
    assert len(builds) == 1
    assert builds[0]["if"] == "steps.restore.outputs.reused != 'true'"
    for step in steps:
        if (
            "trivy-action@" in step.get("uses", "")
            or "scripts/test_crypto.py" in step.get("run", "")
            or "--fail-on high" in step.get("run", "")
        ):
            assert "if" not in step
    scans = [step["with"] for step in steps if "trivy-action@" in step.get("uses", "")]
    assert {scan["scan-type"] for scan in scans} == {"fs", "sbom"}
    for scan in scans:
        assert scan["scanners"] == "vuln"
        assert scan["exit-code"] == "1"
        assert scan["ignore-unfixed"] == "false"
        assert scan["severity"] == "HIGH,CRITICAL"
    steps = jobs["test"]["steps"]
    downloads = [s for s in steps if "download-artifact@" in s.get("uses", "")]
    assert len(downloads) == 1
    assert downloads[0]["if"] == "matrix.os == 'macos-15-intel'"
    assert downloads[0]["with"]["name"] == "intel-cryptography-wheel"
    assert "run-id" not in downloads[0]["with"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "--no-install-package cryptography" in commands
    assert "scripts/intel_wheel.py prepare" in commands
    assert "scripts/test_crypto.py" in commands
    for job in [builder, jobs["test"]]:
        for step in job["steps"]:
            for command in re.findall(r"\buv pip install\b[^\n]*", step.get("run", "")):
                assert "--no-build" in command
                assert "--no-deps" in command
                assert "--require-hashes" in command


def test_reusable_intel_workflow_checks_out_and_seals_the_requested_connector_revision():
    data = workflow("intel-wheel.yml")
    call = data["on"]["workflow_call"]
    assert call["inputs"]["source-ref"]["type"] == "string"
    assert call["inputs"]["source-ref"]["required"] == "false"
    assert call["inputs"]["source-ref"]["default"] == ""
    steps = data["jobs"]["wheel"]["steps"]
    checkout = next(
        step for step in steps if step.get("uses", "").startswith("actions/checkout@")
    )
    assert (
        checkout["with"]["repository"] == "ricardomartins-gravitee/openmaskit-connector"
    )
    assert checkout["with"]["ref"] == "${{ inputs.source-ref || github.sha }}"
    seal = next(
        step
        for step in steps
        if step.get("name") == "Seal wheel against this commit and lockfile"
    )
    assert seal["env"]["SOURCE_REVISION"] == "${{ inputs.source-ref || github.sha }}"


def test_scanner_downloads_enforce_https_across_redirects():
    for name in ("quality.yml", "security.yml", "intel-wheel.yml"):
        for job in workflow(name)["jobs"].values():
            for step in job.get("steps", []):
                command = step.get("run", "")
                if "curl " in command:
                    assert "--proto '=https'" in command
                    assert "--proto-redir '=https'" in command
                    assert "--insecure" not in command


def test_durable_library_publication_is_main_only_and_requires_all_acceptance():
    jobs = workflow("validate.yml")["jobs"]
    assert workflow("validate.yml")["permissions"] == {"contents": "read"}
    assert jobs["intel-wheel"]["permissions"] == {
        "contents": "read",
        "actions": "read",
        "attestations": "read",
    }
    publisher = jobs["native-release"]
    assert "github.ref == 'refs/heads/main'" in publisher["if"]
    assert "github.event_name != 'pull_request'" in publisher["if"]
    assert set(publisher["needs"]) == {
        "test",
        "image",
        "quality",
        "security",
        "intel-wheel",
    }
    assert publisher["permissions"]["contents"] == "write"
    assert publisher["permissions"]["attestations"] == "write"
    assert set(jobs["release"]["needs"]) == {
        "test",
        "image",
        "quality",
        "security",
        "intel-wheel",
        "native-release",
        "publish",
    }
    builder = workflow("intel-wheel.yml")
    assert builder["permissions"]["contents"] == "read"
    assert builder["permissions"]["attestations"] == "read"
    assert builder["permissions"]["actions"] == "read"
    steps = publisher["steps"]
    commands = "\n".join(s.get("run", "") for s in steps)
    assert "restore-release" in commands
    assert "gh release create" in commands
    assert "--clobber" not in commands
    assert '--target "$GITHUB_SHA"' in commands
    assert any("attest-build-provenance@" in s.get("uses", "") for s in steps)


def test_connector_artifacts_are_packaged_on_all_platforms_and_released_after_gates():
    jobs = workflow("validate.yml")["jobs"]
    test = jobs["test"]
    assert set(test["strategy"]["matrix"]["os"]) == {
        "ubuntu-24.04",
        "macos-26",
        "macos-15-intel",
        "windows-2025",
    }
    commands = "\n".join(step.get("run", "") for step in test["steps"])
    assert "scripts/bundle.py" in commands
    assert "scripts/test_bundle.py" in commands
    assert "scripts/archive.py" in commands
    assert "manager_acceptance.py" not in commands
    assert "swift test" not in commands
    release = jobs["release"]
    assert "refs/heads/main" in release["if"]
    assert "event_name != 'pull_request'" in release["if"]
    release_commands = "\n".join(step.get("run", "") for step in release["steps"])
    assert "uv build --no-build-isolation --no-sources" in release_commands
    assert "--only-group release-build" in release_commands
    assert "gh release create" in release_commands
    assert "SHA256SUMS.txt" in release_commands
    assert "ricardomartins-gravitee/openmaskit-connector" in release_commands
    assert "git ls-remote" in release_commands
    assert "Bump the project version" in release_commands
    assert "connector-v$version" in release_commands
    attest = next(
        step
        for step in test["steps"]
        if "attest-build-provenance@" in step.get("uses", "")
    )
    assert "refs/heads/main" in attest["if"]
    upload = next(
        step for step in test["steps"] if "upload-artifact@" in step.get("uses", "")
    )
    assert upload["with"]["path"] == "dist/downloads/*.zip"
    assert "if" not in upload
    download = next(
        step
        for step in release["steps"]
        if "download-artifact@" in step.get("uses", "")
    )
    assert download["with"]["merge-multiple"] == "true"


def test_connector_release_metadata_records_published_image_and_is_attested(tmp_path):
    release = workflow("validate.yml")["jobs"]["release"]
    steps = release["steps"]
    metadata_step = next(
        step
        for step in steps
        if step.get("name") == "Record the attested relay image for companion consumers"
    )
    assert metadata_step["env"] == {
        "RELAY_IMAGE": "${{ needs.publish.outputs.image }}",
        "SOURCE_COMMIT": "${{ github.sha }}",
    }
    match = re.search(r"python3 - <<'PY'\n(.*?)\nPY", metadata_step["run"], re.S)
    assert match

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0.1.0a1"\n'
    )
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    environment = {
        **os.environ,
        "SOURCE_COMMIT": "a" * 40,
        "RELAY_IMAGE": "ghcr.io/ricardomartins-gravitee/openmaskit-connector@sha256:"
        + "b" * 64,
    }
    subprocess.run(
        [sys.executable, "-c", match.group(1)],
        cwd=tmp_path,
        env=environment,
        check=True,
        timeout=10,
    )
    metadata_path = downloads / "connector-release.json"
    assert json.loads(metadata_path.read_text()) == {
        "schema": 1,
        "protocol": 1,
        "version": "0.1.0a1",
        "commit": "a" * 40,
        "relay_image": "ghcr.io/ricardomartins-gravitee/openmaskit-connector@sha256:"
        + "b" * 64,
    }

    (downloads / "connector-linux-amd64.zip").write_bytes(b"archive")
    (tmp_path / "dist/python").mkdir(parents=True)
    (tmp_path / "dist/python/openmaskit_connector.whl").write_bytes(b"wheel")
    checksum_step = next(
        step
        for step in steps
        if step.get("name") == "Create checksums for Python and executable releases"
    )
    checksum_match = re.search(
        r"python3 - <<'PY'\n(.*?)\nPY", checksum_step["run"], re.S
    )
    assert checksum_match
    subprocess.run(
        [sys.executable, "-c", checksum_match.group(1)],
        cwd=tmp_path,
        check=True,
        timeout=10,
    )
    checksums = (downloads / "SHA256SUMS.txt").read_text()
    assert "connector-release.json" in checksums
    assert "connector-linux-amd64.zip" in checksums
    assert "openmaskit_connector.whl" in checksums

    attestation = next(
        step for step in steps if "attest-build-provenance@" in step.get("uses", "")
    )
    assert "downloads/connector-release.json" in attestation["with"]["subject-path"]
    assert "downloads/SHA256SUMS.txt" in attestation["with"]["subject-path"]
    publish = next(
        step
        for step in steps
        if step.get("name") == "Publish immutable versioned connector release"
    )
    assert "downloads/connector-release.json" in publish["run"]


def report_summary(path, *, root=None, remove_root=False):
    environment = {**os.environ, "RUNNER_TEMP": str(root or path.parent)}
    if remove_root:
        environment.pop("RUNNER_TEMP")
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/security_report.py"), str(path)],
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )


def test_security_summary_withholds_secrets_source_and_untrusted_identifiers(tmp_path):
    private = "synthetic-private-value-must-not-be-printed"
    report = tmp_path / "trivy-report.json"
    report.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": private,
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-12345",
                                "Description": private,
                            },
                            {"VulnerabilityID": private},
                        ],
                        "Misconfigurations": [{"ID": private, "Message": private}],
                        "Secrets": [{"Match": private, "Code": {"Lines": [private]}}],
                    }
                ]
            }
        )
    )
    result = report_summary(report)
    assert result.returncode == 0
    assert "2 vulnerability, 1 misconfiguration, 1 secret" in result.stdout
    assert "CVE-2026-12345" in result.stdout
    assert private not in result.stdout + result.stderr


@pytest.mark.parametrize("content", ["not-json", "[]", '{"Results":[null]}'])
def test_security_summary_fails_closed_without_dumping_malformed_reports(
    tmp_path, content
):
    report = tmp_path / "trivy-report.json"
    report.write_text(content)
    result = report_summary(report)
    assert result.returncode == 1
    assert (
        result.stdout == "Scanner report unavailable or invalid; contents withheld.\n"
    )
    assert result.stderr == ""


def test_security_summary_missing_report_is_not_success(tmp_path):
    result = report_summary(tmp_path / "trivy-image.json")
    assert result.returncode == 1
    assert result.stderr == ""


def test_grype_summary_withholds_component_details(tmp_path):
    private = "synthetic-private-component-details"
    path = tmp_path / "grype-report.json"
    path.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2026-12345",
                            "description": private,
                        },
                        "artifact": {"locations": [private]},
                    },
                    {"vulnerability": {"id": private}},
                ]
            }
        )
    )
    result = report_summary(path)
    assert result.returncode == 0
    assert "2 vulnerability" in result.stdout
    assert "CVE-2026-12345" in result.stdout
    assert private not in result.stdout + result.stderr


@pytest.mark.parametrize("report", [{}, {"matches": None}, {"matches": [None]}])
def test_grype_summary_fails_closed(tmp_path, report):
    path = tmp_path / "grype-report.json"
    path.write_text(json.dumps(report))
    assert report_summary(path).returncode == 1


def test_security_summary_rejects_paths_outside_runner_temp(tmp_path):
    root = tmp_path / "runner"
    root.mkdir()
    outside = tmp_path / "trivy-report.json"
    outside.write_text('{"Results":[]}')
    assert report_summary(outside, root=root).returncode == 1


def test_security_summary_rejects_unapproved_report_names(tmp_path):
    path = tmp_path / "other.json"
    path.write_text('{"Results":[]}')
    assert report_summary(path).returncode == 1


def test_security_summary_requires_runner_temp(tmp_path):
    path = tmp_path / "trivy-report.json"
    path.write_text('{"Results":[]}')
    assert report_summary(path, remove_root=True).returncode == 1


def test_security_summary_rejects_symbolic_links(tmp_path):
    target = tmp_path / "target.json"
    target.write_text('{"Results":[]}')
    path = tmp_path / "trivy-report.json"
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("Symbolic links are unavailable for this Windows account")
    assert report_summary(path).returncode == 1


def test_security_summary_rejects_oversized_reports(tmp_path):
    path = tmp_path / "trivy-report.json"
    with path.open("wb") as report:
        report.truncate(16 * 1024 * 1024 + 1)
    assert report_summary(path).returncode == 1
