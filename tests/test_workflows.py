from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCAN_ACTION = ROOT / ".github" / "actions" / "run-scanners" / "action.yml"
ACTIONS_DIR = ROOT / ".github" / "actions"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
# Every workflow and composite action whose steps can run third-party code.
ACTION_FILES = sorted(WORKFLOWS.glob("*.yml")) + sorted(ACTIONS_DIR.glob("*/action.yml"))
PINNED_REF = re.compile(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}")
VERSIONED_PIN = re.compile(r"uses: [\w./-]+@[0-9a-f]{40}\s+# v\d+\.\d+\.\d+\s*$")


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


def _uses_values(document: dict[str, Any]) -> list[str]:
    steps: list[dict[str, Any]] = []
    for job in (document.get("jobs") or {}).values():
        steps.extend(job.get("steps", []))
    steps.extend((document.get("runs") or {}).get("steps", []))
    return [str(step["uses"]) for step in steps if "uses" in step]


def test_third_party_actions_are_pinned_to_commit_shas() -> None:
    external = 0
    for path in ACTION_FILES:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for uses in _uses_values(document):
            if uses.startswith("./"):
                continue
            assert PINNED_REF.fullmatch(uses), f"{path.name}: {uses}"
            external += 1
    assert external > 0


def test_pinned_actions_keep_their_release_in_a_comment() -> None:
    for path in ACTION_FILES:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "uses: " in line and "uses: ./" not in line:
                assert VERSIONED_PIN.search(line), f"{path.name}: {line.strip()}"


def test_dependabot_keeps_action_pins_current() -> None:
    config = yaml.safe_load(DEPENDABOT.read_text(encoding="utf-8"))
    ecosystems = {update["package-ecosystem"] for update in config["updates"]}
    assert "github-actions" in ecosystems
