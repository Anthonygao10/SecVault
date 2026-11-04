"""Capture scanner findings as redacted, idempotent raw evidence.

Every finding gets a stable identifier built from the scanner, rule, repository
path, and resource (for gitleaks, a digest of the secret). Line numbers are left
out on purpose, so moving code keeps its identity. Raw notes are never rewritten:
a re-run skips identifiers that already exist and only refreshes the capture
state that records when each finding was last seen.

Scanner input is treated as untrusted data. Only fixed fields are read, free text
is redacted, and the rendered note is checked again for secrets before it is
written. Anything that still looks secret-like stops the capture.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from .operations import (
    VaultError,
    append_log,
    build_catalog,
    lint_vault,
    parse_markdown,
    relative_path,
    update_manifest,
    vault_path,
)
from .redact import REDACTED, contains_secret, redact_text
from .safe_text import inline_text

SCANNER_LABELS = {"trivy": "Trivy", "checkov": "Checkov", "gitleaks": "gitleaks"}
SCANNER_TAGS = {
    "trivy": "infrastructure-as-code",
    "checkov": "infrastructure-as-code",
    "gitleaks": "secrets-management",
}
FINDING_ID_LENGTH = 12
STATE_RELATIVE_PATH = "logs/capture-state.json"
REVISION_PATTERN = re.compile(r"[0-9A-Za-z._-]{1,64}")
PREFIX_PATTERN = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
GITLEAKS_REMEDIATION = "Rotate the exposed credential and remove it from the code history."
# A raw note counts as capture evidence only if capture itself would have named it this way.
CAPTURED_NAME_PATTERN = re.compile(
    r"source-\d{4}-\d{2}-\d{2}-(?:trivy|checkov|gitleaks)-[a-z0-9-]+-(?P<id>[0-9a-f]{12})\.md"
)
_LEADING_MARKUP = re.compile(r"^([#>*+\-=|~`<!\[\]])")
_ORDERED_MARKER = re.compile(r"^(\d+)([.)])(?=\s|$)")


class CaptureError(VaultError):
    """Raised when scanner input cannot be captured safely."""


@dataclass(frozen=True)
class Finding:
    """One scanner result reduced to fields that are safe to persist."""

    scanner: str
    rule_id: str
    path: str
    subject: str
    title: str
    severity: str
    line: int | None
    description: str
    remediation: str
    reference: str

    @property
    def finding_id(self) -> str:
        return stable_finding_id(self.scanner, self.rule_id, self.path, self.subject)


def stable_finding_id(scanner: str, rule_id: str, path: str, subject: str) -> str:
    """Return the stable identifier for a finding.

    `subject` is the resource address for IaC scanners. For gitleaks it is a SHA-256
    digest of the secret, which lets the identifier be computed without storing the
    value. Line numbers are excluded so that moving code keeps its identity.
    """
    key = "|".join((scanner, rule_id, path, subject))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:FINDING_ID_LENGTH]


# --- Reading scanner reports -------------------------------------------------


def read_report(path: Path) -> Any:
    """Load a JSON report, accepting UTF-8 with or without BOM and UTF-16 output."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CaptureError(f"cannot read scanner report: {path.name}") from exc
    try:
        return json.loads(_decode(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError(f"scanner report is not valid JSON: {path.name}") from exc


def _decode(raw: bytes) -> str:
    if raw.startswith(codecs.BOM_UTF8):
        return raw[len(codecs.BOM_UTF8) :].decode("utf-8")
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16")
    if raw[:1] == b"\x00":
        return raw.decode("utf-16-be")
    if raw[1:2] == b"\x00":
        return raw.decode("utf-16-le")
    return raw.decode("utf-8")


def _identifier(value: object) -> str:
    """Normalize a rule, path, or resource identifier without rewriting its content.

    The result feeds the stable finding identifier, so it must not change. Display
    code flattens these values with `inline_text` before writing them into notes.
    """
    return "" if value is None else str(value).strip()


def _markdown_safe(text: str) -> str:
    """Stop scanner prose from starting a heading, list, quote, table, or HTML block."""
    text = text.replace("%%", "% %").replace("<!--", "&lt;!--")
    text = _LEADING_MARKUP.sub(lambda match: "\\" + match.group(1), text)
    return _ORDERED_MARKER.sub(lambda match: f"{match.group(1)}\\{match.group(2)}", text)


def _prose(value: object) -> str:
    """Normalize free text: redact secrets first, then flatten it to one safe line."""
    if value is None:
        return ""
    return _markdown_safe(inline_text(redact_text(str(value))))


def _line(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _records(value: object, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise CaptureError(f"unexpected `{label}` in scanner report")
    return value


def _mapping(value: object, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise CaptureError(f"unexpected `{label}` in scanner report")
    return value


def normalize_path(value: object, prefix: str | None = None) -> str:
    """Return a repository-relative POSIX path with the scan prefix applied once."""
    text = _identifier(value).replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", text) or text.startswith("//"):
        raise CaptureError(
            "scanner reported an absolute path; run scanners on repository-relative paths"
        )
    while text.startswith("./"):
        text = text[2:]
    text = text.lstrip("/")
    if text == ".":
        text = ""
    if prefix is None:
        return text
    if not text:
        return prefix
    if text == prefix or text.startswith(f"{prefix}/"):
        return text
    return f"{prefix}/{text}"


def parse_trivy(report: Any, prefix: str | None) -> list[Finding]:
    """Read failing misconfigurations from `trivy config --format json`."""
    if not isinstance(report, dict) or "Results" not in report:
        raise CaptureError("input is not a Trivy JSON report")
    findings: list[Finding] = []
    for result in _records(report["Results"], "Results"):
        target = result.get("Target")
        for item in _records(result.get("Misconfigurations"), "Misconfigurations"):
            if item.get("Status", "FAIL") != "FAIL":
                continue
            cause = _mapping(item.get("CauseMetadata"), "CauseMetadata")
            rule_id = _identifier(item.get("ID") or item.get("AVDID")) or "unknown"
            findings.append(
                Finding(
                    scanner="trivy",
                    rule_id=rule_id,
                    path=normalize_path(target, prefix),
                    subject=_identifier(cause.get("Resource")),
                    title=_prose(item.get("Title")) or rule_id,
                    severity=_identifier(item.get("Severity")),
                    line=_line(cause.get("StartLine")),
                    description=_prose(item.get("Message") or item.get("Description")),
                    remediation=_prose(item.get("Resolution")),
                    reference=_prose(item.get("PrimaryURL")),
                )
            )
    return findings


def parse_checkov(report: Any, prefix: str | None) -> list[Finding]:
    """Read failed checks from `checkov -o json` (one report, or a list per framework)."""
    blocks = report if isinstance(report, list) else [report]
    findings: list[Finding] = []
    for block in blocks:
        if not isinstance(block, dict) or ("results" not in block and "check_type" not in block):
            raise CaptureError("input is not a Checkov JSON report")
        results = _mapping(block.get("results"), "results")
        for check in _records(results.get("failed_checks"), "failed_checks"):
            line_range = check.get("file_line_range")
            line = _line(line_range[0]) if isinstance(line_range, list) and line_range else None
            rule_id = _identifier(check.get("check_id")) or "unknown"
            findings.append(
                Finding(
                    scanner="checkov",
                    rule_id=rule_id,
                    path=normalize_path(check.get("file_path"), prefix),
                    subject=_identifier(check.get("resource")),
                    title=_prose(check.get("check_name")) or rule_id,
                    severity=_identifier(check.get("severity")),
                    line=line,
                    description=_prose(check.get("short_description") or check.get("description")),
                    remediation="",
                    reference=_prose(check.get("guideline")),
                )
            )
    return findings


def parse_gitleaks(report: Any, prefix: str | None) -> list[Finding]:
    """Read leaks from `gitleaks dir --report-format json`.

    The secret is read only to derive the identifier. It is never stored, and the
    line-bearing `Fingerprint` field is ignored so moved code keeps its identity.
    """
    findings: list[Finding] = []
    for leak in _records(report, "gitleaks findings"):
        rule_id = _identifier(leak.get("RuleID")) or "unknown"
        secret = str(leak.get("Secret") or leak.get("Match") or "")
        findings.append(
            Finding(
                scanner="gitleaks",
                rule_id=rule_id,
                path=normalize_path(leak.get("File"), prefix),
                subject=hashlib.sha256(secret.encode("utf-8")).hexdigest() if secret else "",
                title=_prose(leak.get("Description")) or rule_id,
                severity="",
                line=_line(leak.get("StartLine")),
                description=_prose(leak.get("Description")),
                remediation=GITLEAKS_REMEDIATION,
                reference="",
            )
        )
    return findings


PARSERS: dict[str, Callable[[Any, str | None], list[Finding]]] = {
    "trivy": parse_trivy,
    "checkov": parse_checkov,
    "gitleaks": parse_gitleaks,
}


# --- Rendering raw notes -----------------------------------------------------


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:40].strip("-")
    return slug or "finding"


def note_name(finding: Finding, captured: date) -> str:
    """Return the raw note file name: source-YYYY-MM-DD-<scanner>-<rule>-<id>.md."""
    return (
        f"source-{captured.isoformat()}-{finding.scanner}-"
        f"{_slug(finding.rule_id)}-{finding.finding_id}.md"
    )


def _location(path: str, lines: list[int]) -> str:
    shown = inline_text(path)
    if not lines:
        return f"`{shown}` (line not reported)"
    ordered = sorted(lines)
    noun = "line" if len(ordered) == 1 else "lines"
    return f"`{shown}` {noun} {', '.join(str(number) for number in ordered)}"


def _front_matter(finding: Finding, title: str, captured: date) -> str:
    day = captured.isoformat()
    return (
        "\n".join(
            [
                "---",
                "type: source",
                f"title: {json.dumps(title, ensure_ascii=False)}",
                "tags:",
                "  - source",
                f"  - {SCANNER_TAGS[finding.scanner]}",
                f"created: {day}",
                f"updated: {day}",
                "sources: []",
                f'finding_id: "{finding.finding_id}"',
                f"scanner: {finding.scanner}",
                f"captured: {day}",
                "processed: false",
                "---",
            ]
        )
        + "\n"
    )


def render_note(
    finding: Finding,
    lines: list[int],
    *,
    captured: date,
    revision: str | None = None,
) -> str:
    """Render one raw source note from the fixed finding fields."""
    label = SCANNER_LABELS[finding.scanner]
    if finding.scanner == "gitleaks":
        title = _prose(f"{label} {finding.rule_id} in {finding.path}")
    else:
        title = _prose(f"{label} {finding.rule_id}: {finding.title}")

    body = [
        f"# {title}",
        "",
        f"Capture mode: normalized and redacted {label} output, written by `wiki_tool capture`.",
        "Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.",
        "",
        "## Finding",
        "",
        f"- Scanner: {label}",
        f"- Rule: `{inline_text(finding.rule_id)}`",
        f"- Severity: {inline_text(finding.severity) or 'not reported'}",
        f"- Location: {_location(finding.path, lines)}",
    ]
    if finding.scanner == "gitleaks":
        body.append(f"- Secret value: `{REDACTED}` (omitted by design)")
    elif finding.subject:
        body.append(f"- Resource: `{inline_text(finding.subject)}`")
    if revision:
        body.append(f"- Revision: `{revision}`")
    for heading, text in (
        ("Description", finding.description),
        ("Recommended action", finding.remediation),
        ("Reference", finding.reference),
    ):
        if text:
            body.extend(["", f"## {heading}", "", text])

    return _front_matter(finding, title, captured) + "\n" + "\n".join(body) + "\n"


# --- Capture state and lifecycle ---------------------------------------------


def load_state(root: Path) -> dict[str, Any]:
    """Load the per-finding lifecycle state, or an empty state for a new vault."""
    path = root / STATE_RELATIVE_PATH
    if not path.exists():
        return {"version": 1, "findings": {}}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CaptureError(f"invalid capture state: {STATE_RELATIVE_PATH}") from exc
    findings = state.get("findings") if isinstance(state, dict) else None
    if not isinstance(findings, dict) or not all(
        isinstance(entry, dict) for entry in findings.values()
    ):
        raise CaptureError(f"capture state is malformed: {STATE_RELATIVE_PATH}")
    return state


def save_state(root: Path, state: dict[str, Any]) -> None:
    path = root / STATE_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(state, indent=2, sort_keys=True) + "\n")


def _captured_note_ids(root: Path) -> set[str]:
    """Identifiers of raw notes that capture itself wrote.

    A note counts only when its file name has the shape capture uses and its front
    matter agrees with that name. Any other raw note, however it declares a
    finding_id, cannot suppress capture of a real finding.
    """
    directory = root / "raw" / "sources"
    if not directory.exists():
        return set()
    identifiers: set[str] = set()
    for path in sorted(directory.rglob("*.md")):
        match = CAPTURED_NAME_PATTERN.fullmatch(path.name)
        if match is None:
            continue
        if parse_markdown(path).metadata.get("finding_id") == match.group("id"):
            identifiers.add(match.group("id"))
    return identifiers


def _in_scope(entry: dict[str, Any], scanner: str, prefix: str | None) -> bool:
    """A finding can only be marked fixed by a scan that would have covered it."""
    if entry.get("scanner") != scanner:
        return False
    if prefix is None:
        return True
    path = str(entry.get("path") or "")
    return path == prefix or path.startswith(f"{prefix}/")


def _normalize_prefix(value: str | None) -> str | None:
    if value is None:
        return None
    prefix = value.replace("\\", "/").strip("/")
    if prefix in ("", "."):
        return None
    if not PREFIX_PATTERN.fullmatch(prefix) or ".." in prefix.split("/"):
        raise CaptureError("path prefix must be a relative path without spaces or '..'")
    return prefix


def _group(findings: list[Finding]) -> dict[str, tuple[Finding, list[int]]]:
    grouped: dict[str, tuple[Finding, list[int]]] = {}
    for finding in findings:
        _, lines = grouped.setdefault(finding.finding_id, (finding, []))
        if finding.line is not None and finding.line not in lines:
            lines.append(finding.line)
    return grouped


def capture_findings(
    vault: str | Path,
    scanner: str,
    report_path: str | Path,
    *,
    path_prefix: str | None = None,
    captured_on: date | None = None,
    revision: str | None = None,
) -> dict[str, Any]:
    """Capture one scanner report as raw evidence and report what changed.

    The vault must lint cleanly before capture starts. New findings become raw
    notes, existing ones are skipped, and the manifest, catalog, and capture state
    are refreshed. Raw notes are written before the state file, so an interrupted
    run is retried on the next pass rather than being recorded as captured.
    """
    if scanner not in PARSERS:
        raise CaptureError(f"unsupported scanner: {scanner}")
    if revision is not None and not REVISION_PATTERN.fullmatch(revision):
        raise CaptureError("revision may contain only letters, digits, '.', '_' or '-'")

    root = vault_path(vault)
    precheck = lint_vault(root)
    if not precheck.ok:
        raise CaptureError(
            "vault does not lint cleanly; fix these before capturing: " + "; ".join(precheck.errors)
        )

    captured = captured_on or datetime.now(UTC).date()
    day = captured.isoformat()
    prefix = _normalize_prefix(path_prefix)
    report = Path(report_path)
    findings = _group(PARSERS[scanner](read_report(report), prefix))

    state = load_state(root)
    tracked: dict[str, dict[str, Any]] = state["findings"]
    known = set(tracked) | _captured_note_ids(root)

    pending: list[tuple[str, Path, str]] = []
    for finding_id, (finding, lines) in findings.items():
        if finding_id in known:
            continue
        note_path = root / "raw" / "sources" / note_name(finding, captured)
        text = render_note(finding, lines, captured=captured, revision=revision)
        if contains_secret(text):
            raise CaptureError(
                f"refusing to write {note_path.name}: a secret-like value survived redaction"
            )
        pending.append((finding_id, note_path, text))

    created: dict[str, str] = {}
    if pending:
        (root / "raw" / "sources").mkdir(parents=True, exist_ok=True)
    for finding_id, note_path, text in pending:
        try:
            with note_path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
        except FileExistsError as exc:
            raise CaptureError(f"refusing to overwrite raw evidence: {note_path.name}") from exc
        created[finding_id] = relative_path(root, note_path)

    reopened: list[str] = []
    for finding_id, (finding, _lines) in findings.items():
        entry = tracked.get(finding_id)
        if entry is None:
            entry = {
                "scanner": finding.scanner,
                "rule_id": finding.rule_id,
                "path": finding.path,
                "note": created.get(finding_id),
                "first_seen": day,
                "last_seen": day,
                "status": "open",
            }
            tracked[finding_id] = entry
        elif entry.get("status") == "candidate_fixed":
            entry["status"] = "open"
            reopened.append(finding_id)
        entry["last_seen"] = day

    candidate_fixed: list[str] = []
    for finding_id in sorted(tracked):
        entry = tracked[finding_id]
        if finding_id in findings or entry.get("status") != "open":
            continue
        if _in_scope(entry, scanner, prefix):
            entry["status"] = "candidate_fixed"
            candidate_fixed.append(finding_id)

    save_state(root, state)
    update_manifest(root)
    build_catalog(root)
    if created or reopened or candidate_fixed:
        append_log(
            root,
            f"capture {scanner}; created={len(created)}; reopened={len(reopened)}; "
            f"candidate_fixed={len(candidate_fixed)}",
        )

    return {
        "scanner": scanner,
        "report": report.name,
        "path_prefix": prefix,
        "captured_on": day,
        "findings": len(findings),
        "created": sorted(created.values()),
        "known": sum(1 for finding_id in findings if finding_id in known),
        "reopened": reopened,
        "candidate_fixed": candidate_fixed,
        "lint": lint_vault(root).as_dict(),
    }
