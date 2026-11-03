from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCAN_ACTION = ROOT / ".github" / "actions" / "run-scanners" / "action.yml"


def _workflow(name: str) -> dict[str, Any]:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _steps(workflow: dict[str, Any], job: str) -> list[dict[str, Any]]:
    return workflow["jobs"][job]["steps"]


def _run_text(workflow: dict[str, Any], job: str) -> str:
    return "\n".join(str(step.get("run", "")) for step in _steps(workflow, job))


def test_every_workflow_defaults_to_read_only_permissions() -> None:
    for path in sorted(WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert document["permissions"] == {"contents": "read"}, path.name


def test_ci_check_runs_lint_tests_and_vault_lint_without_scanners() -> None:
    workflow = _workflow("ci.yml")
    text = _run_text(workflow, "ci")

    for command in ("ruff check", "ruff format --check", "pytest", "wiki_tool lint"):
        assert command in text
    assert "--redact" not in text
    assert "capture" not in text


def test_only_main_captures_and_only_the_capture_job_can_write() -> None:
    workflow = _workflow("scan-capture.yml")
    dry_run = workflow["jobs"]["dry-run"]
    capture = workflow["jobs"]["capture"]

    assert dry_run["if"] == "github.event_name == 'pull_request'"
    assert "permissions" not in dry_run
    assert capture["permissions"] == {"contents": "write"}
    assert "refs/heads/main" in capture["if"]
    assert "pull_request" in capture["if"]


def test_commits_touch_raw_evidence_and_logs_only() -> None:
    text = _run_text(_workflow("scan-capture.yml"), "capture")

    assert "git add vault/raw vault/logs" in text
    for line in text.splitlines():
        if "git add" in line:
            assert "vault/wiki" not in line


def test_maintenance_is_report_only() -> None:
    workflow = _workflow("maintenance.yml")
    text = _run_text(workflow, "report")

    assert "wiki_tool report" in text
    for forbidden in ("manifest", "capture", "index", "git commit", "git push"):
        assert forbidden not in text, forbidden


def test_scanner_archives_are_pinned_by_sha256() -> None:
    action = yaml.safe_load(SCAN_ACTION.read_text(encoding="utf-8"))
    env = action["runs"]["steps"][0]["env"]

    for name in ("TRIVY_SHA256", "GITLEAKS_SHA256"):
        assert re.fullmatch(r"[0-9a-f]{64}", env[name]), name
    assert env["TRIVY_VERSION"] == "0.74.0"
    assert env["GITLEAKS_VERSION"] == "8.30.1"
    assert env["CHECKOV_VERSION"] == "3.3.20"


def test_gitleaks_reports_are_not_redacted_before_hashing() -> None:
    commands = [
        line
        for line in SCAN_ACTION.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]

    assert any("gitleaks dir" in line for line in commands)
    assert not any("--redact" in line for line in commands)
