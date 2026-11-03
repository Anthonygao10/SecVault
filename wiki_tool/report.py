"""Read-only maintenance report for CI job summaries and local review.

The report never writes to the vault. It gathers lint status, raw-source coverage,
catalog freshness, and capture lifecycle state so the scheduled workflow can
publish a summary and fail when integrity checks fail.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .capture import CaptureError, load_state
from .operations import collect_catalog, find_uncovered_sources, lint_vault, vault_path

UNCOVERED_LIMIT = 50


def build_report(vault: str | Path) -> dict[str, Any]:
    """Collect maintenance facts without writing to the vault."""
    root = vault_path(vault)
    lint = lint_vault(root).as_dict()

    state_error: str | None = None
    try:
        tracked = load_state(root)["findings"]
    except CaptureError as exc:
        tracked, state_error = {}, str(exc)

    candidates = [
        {
            "id": finding_id,
            "scanner": entry.get("scanner"),
            "rule_id": entry.get("rule_id"),
            "path": entry.get("path"),
            "note": entry.get("note"),
        }
        for finding_id, entry in sorted(tracked.items())
        if isinstance(entry, dict) and entry.get("status") == "candidate_fixed"
    ]
    open_findings = sum(
        1 for entry in tracked.values() if isinstance(entry, dict) and entry.get("status") == "open"
    )

    return {
        "ok": bool(lint["ok"]) and state_error is None,
        "lint": lint,
        "state_error": state_error,
        "uncovered_sources": find_uncovered_sources(root),
        "catalog_current": _catalog_is_current(root),
        "open_findings": open_findings,
        "candidate_fixed": candidates,
    }


def _catalog_is_current(root: Path) -> bool:
    path = root / "logs" / "catalog.json"
    if not path.exists():
        return False
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return stored == collect_catalog(root)


def render_markdown(report: dict[str, Any]) -> str:
    """Render the report as Markdown for `$GITHUB_STEP_SUMMARY` or a terminal."""
    lint = report["lint"]
    lines = ["# SecVault maintenance report", "", "## Integrity", ""]
    if lint["ok"]:
        lines.append(f"PASS: checked {lint['checked_notes']} notes; raw hashes match the manifest.")
    else:
        lines.append(f"FAIL: {len(lint['errors'])} problem(s) found.")
        lines.extend(f"- {error}" for error in lint["errors"])
    if report["state_error"]:
        lines.append(f"- capture state: {report['state_error']}")

    uncovered = report["uncovered_sources"]
    lines += ["", "## Coverage", "", f"Raw sources without wiki coverage: {len(uncovered)}"]
    lines.extend(f"- `{path}`" for path in uncovered[:UNCOVERED_LIMIT])
    if len(uncovered) > UNCOVERED_LIMIT:
        lines.append(f"- ... and {len(uncovered) - UNCOVERED_LIMIT} more")

    lines += ["", "## Catalog", ""]
    if report["catalog_current"]:
        lines.append("Catalog is current.")
    else:
        lines.append("Catalog is stale. Run `python -m wiki_tool index` and commit the result.")

    candidates = report["candidate_fixed"]
    lines += [
        "",
        "## Captured findings",
        "",
        f"Open findings: {report['open_findings']}",
        f"Candidates for fixed: {len(candidates)}",
    ]
    if candidates:
        lines.append("")
        lines.append("A human confirms each `fixed` status before it is recorded.")
        lines.extend(
            f"- `{item['id']}` {item['scanner']} `{item['rule_id']}` in `{item['path']}`"
            for item in candidates
        )
    return "\n".join(lines) + "\n"
