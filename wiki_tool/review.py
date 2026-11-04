"""Human review of proposed drafts: listing, review packets, approval, and rejection.

Agents may list drafts and print review packets. Approval and rejection are human
decisions, recorded in `logs/review-state.json`. Nothing in this module moves a draft
into wiki/. `apply` does that, and it refuses any draft without a current approval.
"""

from __future__ import annotations

import difflib
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .hashing import sha256_file
from .operations import (
    DraftError,
    DraftRef,
    draft_target,
    errors_for,
    extract_wikilinks,
    lint_vault,
    load_json,
    relative_path,
    resolve_draft,
    resolve_link,
    source_links,
    vault_path,
)
from .review_state import (
    draft_status,
    load_review_state,
    record_decision,
    save_review_state,
    short_fingerprint,
)
from .safe_text import terminal_safe

REVIEWER_LIMIT = 80
NOTE_LIMIT = 280


def clean_single_line(value: str, label: str, limit: int, *, required: bool) -> str:
    """Collapse a typed value to one line and refuse control or formatting characters."""
    text = " ".join(value.split())
    if required and not text:
        raise DraftError(f"{label} must not be empty")
    if len(text) > limit:
        raise DraftError(f"{label} must be at most {limit} characters")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in text):
        raise DraftError(f"{label} must not contain control or formatting characters")
    return text


def _draft_paths(root: Path) -> list[Path]:
    proposed = root / "proposed"
    if not proposed.is_dir():
        return []
    return sorted(path for path in proposed.rglob("*.md") if path.name != "README.md")


def _display_name(root: Path, path: Path) -> str:
    try:
        return relative_path(root, path)
    except ValueError:
        return f"proposed/{path.name}"


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n")


def list_drafts(vault: str | Path) -> list[dict[str, Any]]:
    """Summarize every draft in proposed/: its target, lint problems, and approval state."""
    root = vault_path(vault).resolve()
    state = load_review_state(root)
    lint_errors = lint_vault(root).errors
    entries: list[dict[str, Any]] = []
    for path in _draft_paths(root):
        try:
            ref = resolve_draft(root, path)
        except DraftError as exc:
            entries.append(
                {
                    "draft": _display_name(root, path),
                    "type": None,
                    "title": None,
                    "target": None,
                    "target_exists": False,
                    "sources": [],
                    "approval": "invalid",
                    "sha256": None,
                    "problems": [str(exc)],
                }
            )
            continue
        metadata = ref.note.metadata
        status, _record = draft_status(state, ref.name, ref.fingerprint)
        target = draft_target(metadata.get("type"), ref.name)
        entries.append(
            {
                "draft": ref.relative,
                "type": metadata.get("type"),
                "title": metadata.get("title"),
                "target": target,
                "target_exists": target is not None and (root / target).exists(),
                "sources": source_links(metadata),
                "approval": status,
                "sha256": short_fingerprint(ref.fingerprint),
                "problems": errors_for(ref.relative, lint_errors),
            }
        )
    return entries


def _source_details(root: Path, metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    manifest = load_json(root / "raw" / "manifest.json", {"files": {}})
    records = manifest.get("files", {}) if isinstance(manifest, dict) else {}
    raw_root = (root / "raw" / "sources").resolve()
    details: list[dict[str, Any]] = []
    for link in source_links(metadata):
        resolved = resolve_link(root, link)
        if resolved is None or not resolved.is_relative_to(raw_root):
            details.append(
                {
                    "link": link,
                    "path": None,
                    "manifest_sha256": None,
                    "current_sha256": None,
                    "matches_manifest": False,
                }
            )
            continue
        path = relative_path(root, resolved)
        record = records.get(path) if isinstance(records, dict) else None
        recorded = record.get("sha256") if isinstance(record, dict) else None
        current = sha256_file(resolved)
        details.append(
            {
                "link": link,
                "path": path,
                "manifest_sha256": recorded,
                "current_sha256": current,
                "matches_manifest": recorded == current,
            }
        )
    return details


def _warnings(root: Path, ref: DraftRef) -> list[str]:
    warnings: list[str] = []
    metadata = ref.note.metadata
    proposed_root = (root / "proposed").resolve()
    for link in extract_wikilinks(ref.note.body):
        resolved = resolve_link(root, link)
        if resolved is not None and resolved.is_relative_to(proposed_root):
            warnings.append(f"links into proposed/: [[{link}]]")
    history = metadata.get("status_history")
    entries = history if isinstance(history, list) else []
    if metadata.get("status") == "fixed" and not any(
        isinstance(entry, Mapping) and entry.get("status") == "fixed" for entry in entries
    ):
        warnings.append("status is fixed but status_history has no fixed entry")
    if metadata.get("type") == "vulnerability" and not metadata.get("finding_id"):
        warnings.append("vulnerability has no finding_id")
    return warnings


def review_packet(vault: str | Path, draft: str | Path) -> dict[str, Any]:
    """Collect what a human needs to decide on one draft. Nothing is written."""
    root = vault_path(vault).resolve()
    ref = resolve_draft(root, draft)
    metadata = ref.note.metadata
    state = load_review_state(root)
    status, record = draft_status(state, ref.name, ref.fingerprint)
    target = draft_target(metadata.get("type"), ref.name)
    target_exists = target is not None and (root / target).is_file()
    diff: str | None = None
    if target is not None and target_exists:
        existing = _text((root / target).read_bytes())
        diff = "\n".join(
            difflib.unified_diff(
                existing.splitlines(),
                _text(ref.data).splitlines(),
                fromfile=target,
                tofile=ref.relative,
                lineterm="",
            )
        )
    history = metadata.get("status_history")
    return {
        "draft": ref.relative,
        "type": metadata.get("type"),
        "title": metadata.get("title"),
        "severity": metadata.get("severity"),
        "status": metadata.get("status"),
        "status_history": history if isinstance(history, list) else [],
        "finding_id": metadata.get("finding_id"),
        "sources": _source_details(root, metadata),
        "sha256": ref.fingerprint,
        "short_sha256": short_fingerprint(ref.fingerprint),
        "approval": {
            "state": status,
            "recorded_decision": record["decision"] if record else None,
            "reviewer": record["reviewer"] if record else None,
            "decided_at": record["decided_at"] if record else None,
            "note": record["note"] if record else None,
        },
        "problems": errors_for(ref.relative, lint_vault(root).errors),
        "warnings": _warnings(root, ref),
        "target": target,
        "target_exists": target_exists,
        "diff": diff,
    }


def _one_line(value: object) -> str:
    return " ".join(str(value).split())


def _approval_line(approval: Mapping[str, Any]) -> str:
    state = approval["state"]
    reviewer = _one_line(approval["reviewer"])
    when = _one_line(approval["decided_at"])
    note = _one_line(approval["note"] or "")
    suffix = f" ({note})" if note else ""
    if state == "approved":
        return f"approved by {reviewer} at {when}{suffix}"
    if state == "stale":
        return (
            f"stale: approved by {reviewer} at {when}, but the draft changed since; "
            "approve it again"
        )
    if state == "rejected":
        return f"rejected by {reviewer} at {when}{suffix}; apply will refuse it"
    if approval["recorded_decision"] == "rejected":
        return f"pending: previously rejected by {reviewer}, and the draft changed since"
    return "pending: no decision recorded"


def render_packet(packet: Mapping[str, Any]) -> str:
    """Render a review packet as plain text. Control and bidi characters are escaped."""
    lines = [
        f"Review packet: {packet['draft']}",
        f"Type: {_one_line(packet['type'])}   Severity: "
        f"{_one_line(packet['severity'] or 'not set')}   "
        f"Status: {_one_line(packet['status'] or 'not set')}",
        f"Title: {_one_line(packet['title'])}",
        f"Finding: {_one_line(packet['finding_id'] or 'none')}",
    ]
    target = packet["target"] or "none (this type is not applicable)"
    if packet["target_exists"]:
        target += " (exists; applying it needs --overwrite)"
    lines += [
        f"Target: {_one_line(target)}",
        f"Approval: {_approval_line(packet['approval'])}",
        f"SHA-256: {packet['sha256']}",
        f"Confirm by typing the first 12 characters: {packet['short_sha256']}",
        "Lint: " + ("PASS" if not packet["problems"] else "FAIL"),
    ]
    lines += [f"  - {_one_line(problem)}" for problem in packet["problems"]]
    lines.append("Status history:")
    for entry in packet["status_history"]:
        if isinstance(entry, Mapping):
            text = f"{entry.get('status')} {entry.get('date')} ref={entry.get('ref')}: "
            text += str(entry.get("note"))
        else:
            text = str(entry)
        lines.append(f"  - {_one_line(text)}")
    if not packet["status_history"]:
        lines.append("  - none")
    lines.append("Sources:")
    for source in packet["sources"]:
        if source["path"] is None:
            lines.append(f"  - {_one_line(source['link'])}: not a raw source in this vault")
        elif source["matches_manifest"]:
            lines.append(f"  - {source['path']}: matches the manifest hash")
        else:
            lines.append(
                f"  - {source['path']}: MISMATCH (manifest {source['manifest_sha256']}, "
                f"current {source['current_sha256']})"
            )
    if not packet["sources"]:
        lines.append("  - none")
    lines.append("Warnings:")
    lines += [f"  - {_one_line(warning)}" for warning in packet["warnings"]]
    if not packet["warnings"]:
        lines.append("  - none")
    if packet["diff"] is not None:
        lines.append("Diff against the existing note:")
        lines.append(packet["diff"] or "(no differences)")
    return terminal_safe("\n".join(lines)) + "\n"


def approve_draft(
    vault: str | Path,
    draft: str | Path,
    *,
    reviewer: str,
    note: str = "",
    confirmation: str,
) -> dict[str, Any]:
    """Record a human approval bound to the draft's current hash.

    `confirmation` must equal the first twelve hex characters of that hash. The CLI
    shows the review packet and asks a human to type it. A draft that changed after
    the packet was shown no longer matches, so the approval is refused.
    """
    root = vault_path(vault).resolve()
    reviewer = clean_single_line(reviewer, "reviewer", REVIEWER_LIMIT, required=True)
    note = clean_single_line(note, "note", NOTE_LIMIT, required=False)
    ref = resolve_draft(root, draft)
    problems = errors_for(ref.relative, lint_vault(root).errors)
    if problems:
        raise DraftError("fix these problems before approving: " + "; ".join(problems))
    if confirmation.strip().lower() != short_fingerprint(ref.fingerprint):
        raise DraftError(
            f"the typed hash does not match {ref.name}; review the current draft again"
        )
    state = load_review_state(root)
    record_decision(
        state,
        ref.name,
        decision="approved",
        fingerprint=ref.fingerprint,
        reviewer=reviewer,
        note=note,
    )
    save_review_state(root, state)
    return {
        "draft": ref.relative,
        "decision": "approved",
        "reviewer": reviewer,
        "sha256": ref.fingerprint,
        "note": note,
    }


def reject_draft(
    vault: str | Path,
    draft: str | Path,
    *,
    reviewer: str,
    reason: str,
) -> dict[str, Any]:
    """Record a rejection. The draft stays in proposed/, and `apply` refuses it."""
    root = vault_path(vault).resolve()
    reviewer = clean_single_line(reviewer, "reviewer", REVIEWER_LIMIT, required=True)
    reason = clean_single_line(reason, "reason", NOTE_LIMIT, required=True)
    ref = resolve_draft(root, draft)
    state = load_review_state(root)
    record_decision(
        state,
        ref.name,
        decision="rejected",
        fingerprint=ref.fingerprint,
        reviewer=reviewer,
        note=reason,
    )
    save_review_state(root, state)
    return {
        "draft": ref.relative,
        "decision": "rejected",
        "reviewer": reviewer,
        "sha256": ref.fingerprint,
        "reason": reason,
    }
