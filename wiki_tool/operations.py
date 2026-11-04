"""Filesystem operations for the SecVault vault.

The functions in this module are deterministic and do not call Obsidian or an
LLM. Agents use them through the CLI and the repository-local workflow skills.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from .hashing import normalized_digest, sha256_file
from .redact import contains_secret
from .review_state import (
    ReviewStateError,
    draft_status,
    load_review_state,
    record_applied,
    require_approval,
    save_review_state,
)

COMMON_FIELDS = ("type", "title", "tags", "created", "updated", "sources")
SOURCE_FIELDS = COMMON_FIELDS + (
    "finding_id",
    "scanner",
    "captured",
    "processed",
)
VULNERABILITY_FIELDS = COMMON_FIELDS + (
    "severity",
    "cwe",
    "owasp",
    "component",
    "status",
    "status_history",
    "finding_id",
    "fix_commit",
)
LOG_FIELDS = COMMON_FIELDS + ("event", "actor")
WIKI_TYPES = {"vulnerability", "postmortem", "concept", "entity"}
TYPE_DIRECTORIES = {
    "vulnerability": "vulnerabilities",
    "postmortem": "postmortems",
    "concept": "concepts",
    "entity": "entities",
}
GENERATED_PATHS = {"logs/catalog.json", "raw/manifest.json"}
WIKILINK_PATTERN = re.compile(r"\[\[([^\]]+)\]\]")
DATE_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")
LINK_UNSAFE_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
DRAFT_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)
DRAFT_UNSAFE_NAME_PATTERN = re.compile(r'[\x00-\x1f\x7f/\\:*?"<>|]')


class VaultError(RuntimeError):
    """Base error for expected vault operation failures."""


class DraftError(VaultError):
    """Raised when a proposed draft is unsafe to list, review, or decide on."""


class DraftApplyError(DraftError):
    """Raised when a proposed draft cannot be safely applied to the wiki."""


@dataclass(frozen=True)
class ParsedNote:
    """A Markdown note and its parsed front matter."""

    path: Path
    metadata: dict[str, Any]
    body: str
    error: str | None = None


@dataclass
class LintResult:
    """Structured result from vault validation."""

    errors: list[str]
    checked_notes: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checked_notes": self.checked_notes,
            "errors": self.errors,
        }


def vault_path(value: str | Path) -> Path:
    """Return a normalized vault path without requiring it to exist."""
    return Path(value).expanduser()


def relative_path(root: Path, path: Path) -> str:
    """Return a vault-relative POSIX path."""
    return path.resolve().relative_to(root.resolve()).as_posix()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, default=_json_default)
        + "\n",
        encoding="utf-8",
    )


def _json_default(value: Any) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def _normalize_value(value: Any) -> Any:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _normalize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    return value


def parse_markdown(path: Path) -> ParsedNote:
    """Parse YAML front matter and body from a Markdown file."""
    return parse_note_text(path, _read_text(path))


def parse_note_text(path: Path, text: str) -> ParsedNote:
    """Parse YAML front matter and body from Markdown text that is already in memory."""
    if not text.startswith("---"):
        return ParsedNote(path, {}, text, "missing YAML front matter")

    lines = text.splitlines(keepends=True)
    closing_index = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if closing_index is None:
        return ParsedNote(path, {}, text, "unterminated YAML front matter")

    front_matter = "".join(lines[1:closing_index])
    body = "".join(lines[closing_index + 1 :])
    try:
        loaded = yaml.safe_load(front_matter) or {}
    except yaml.YAMLError as exc:
        return ParsedNote(path, {}, body, f"invalid YAML front matter: {exc}")
    if not isinstance(loaded, dict):
        return ParsedNote(path, {}, body, "front matter must be a YAML mapping")
    return ParsedNote(path, dict(loaded), body)


def _iter_files(directory: Path, suffix: str | None = None) -> Iterable[Path]:
    if not directory.exists():
        return ()
    paths = (path for path in directory.rglob("*") if path.is_file())
    if suffix is not None:
        paths = (path for path in paths if path.suffix.lower() == suffix)
    return sorted(paths)


def iter_note_files(vault: Path) -> list[Path]:
    """Return Markdown files that participate in schema validation/indexing."""
    paths: list[Path] = []
    paths.extend(_iter_files(vault / "raw" / "sources", ".md"))
    paths.extend(_iter_files(vault / "wiki", ".md"))
    paths.extend(
        path for path in _iter_files(vault / "proposed", ".md") if path.name != "README.md"
    )
    paths.extend(path for path in _iter_files(vault / "logs", ".md") if path.name != "wiki-log.md")
    return sorted(paths)


def _flatten_values(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _flatten_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten_values(child)
    elif isinstance(value, str):
        yield value


def allowed_tags(vault: Path) -> set[str]:
    """Load and flatten the versioned allowed-tag vocabulary."""
    schema_path = vault / "schema" / "tags.yaml"
    if not schema_path.exists():
        raise VaultError(f"missing tag schema: {relative_path(vault, schema_path)}")
    try:
        loaded = yaml.safe_load(_read_text(schema_path)) or {}
    except yaml.YAMLError as exc:
        raise VaultError(f"invalid tag schema: {exc}") from exc
    return set(_flatten_values(loaded.get("tags", {})))


def _metadata_links(metadata: Mapping[str, Any]) -> list[str]:
    links: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, str):
            links.extend(match.group(1) for match in WIKILINK_PATTERN.finditer(value))
        elif isinstance(value, Mapping):
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(metadata)
    return links


def extract_wikilinks(text: str) -> list[str]:
    """Extract raw Obsidian link targets from Markdown text."""
    return [match.group(1) for match in WIKILINK_PATTERN.finditer(text)]


def _clean_link_target(target: str) -> str:
    if target.strip().startswith("[[") and target.strip().endswith("]]"):
        target = target.strip()[2:-2]
    target = target.split("|", 1)[0].split("#", 1)[0].strip()
    return target.replace("\\", "/").removeprefix("./")


def resolve_link(vault: Path, target: str) -> Path | None:
    """Resolve a vault-relative or basename-style Obsidian link.

    Targets that are rooted, contain a colon (drive letters and alternate streams),
    carry control characters, or climb with `..` never resolve. A resolved file must
    also stay inside the vault, which catches symbolic links that point outside.
    """
    cleaned = _clean_link_target(target)
    if not cleaned or cleaned.startswith(("http://", "https://")):
        return None
    if cleaned.startswith("/") or ":" in cleaned or LINK_UNSAFE_PATTERN.search(cleaned):
        return None
    if ".." in cleaned.split("/"):
        return None

    root = vault.resolve()
    candidate = vault / cleaned
    candidates = [candidate]
    if candidate.suffix.lower() != ".md":
        candidates.append(candidate.with_suffix(".md"))
    for possible in candidates:
        if possible.is_file():
            resolved = possible.resolve()
            return resolved if resolved.is_relative_to(root) else None

    if "/" not in cleaned:
        basename = Path(cleaned).stem
        matches = sorted(path.resolve() for path in vault.rglob("*.md") if path.stem == basename)
        # A single match counts only if it stays inside the vault. Ambiguous names never resolve.
        if len(matches) == 1 and matches[0].is_relative_to(root):
            return matches[0]
    return None


def _link_target_is_raw_source(vault: Path, target: str) -> bool:
    resolved = resolve_link(vault, target)
    if resolved is None:
        return False
    try:
        return resolved.is_relative_to((vault / "raw" / "sources").resolve())
    except AttributeError:
        return str(resolved).startswith(str((vault / "raw" / "sources").resolve()))


def source_links(metadata: Mapping[str, Any]) -> list[str]:
    sources = metadata.get("sources")
    if not isinstance(sources, list):
        return []
    return [source for source in sources if isinstance(source, str)]


def _is_date(value: Any) -> bool:
    if isinstance(value, datetime):
        return False
    if isinstance(value, date):
        return True
    if not isinstance(value, str) or not DATE_PATTERN.fullmatch(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _type_for_path(vault: Path, path: Path) -> str | None:
    relative = Path(relative_path(vault, path))
    parts = relative.parts
    if len(parts) >= 3 and parts[:2] == ("raw", "sources"):
        return "source"
    if len(parts) >= 2 and parts[0] == "wiki":
        for note_type, directory in TYPE_DIRECTORIES.items():
            if len(parts) >= 2 and parts[1] == directory:
                return note_type
    if parts and parts[0] == "proposed":
        return None
    if parts and parts[0] == "logs":
        return "log"
    return None


def _expected_fields(note_type: str) -> tuple[str, ...]:
    if note_type == "source":
        return SOURCE_FIELDS
    if note_type == "vulnerability":
        return VULNERABILITY_FIELDS
    if note_type == "log":
        return LOG_FIELDS
    return COMMON_FIELDS


def name_matches(path: Path, note_type: str, vault: Path) -> bool:
    relative = Path(relative_path(vault, path))
    filename = relative.name
    if note_type == "source":
        return bool(
            re.fullmatch(
                r"source-\d{4}-\d{2}-\d{2}-[a-z0-9]+(?:-[a-z0-9]+)*\.md",
                filename,
            )
        )
    if note_type == "vulnerability":
        return bool(re.fullmatch(r"vuln-[a-z0-9]+(?:-[a-z0-9]+)*\.md", filename))
    if note_type == "postmortem":
        return bool(re.fullmatch(r"postmortem-[a-z0-9]+(?:-[a-z0-9]+)*\.md", filename))
    if note_type == "concept":
        return bool(re.fullmatch(r"concept-[a-z0-9]+(?:-[a-z0-9]+)*\.md", filename))
    if note_type == "entity":
        return bool(re.fullmatch(r"entity-[a-z0-9]+(?:-[a-z0-9]+)*\.md", filename))
    if note_type == "log":
        return bool(re.fullmatch(r"log-\d{4}-\d{2}-\d{2}-[a-z0-9]+(?:-[a-z0-9]+)*\.md", filename))
    return False


def _secret_matches(text: str) -> bool:
    return contains_secret(text)


def build_catalog(vault: str | Path) -> dict[str, Any]:
    """Build the searchable catalog and write it to `logs/catalog.json`."""
    root = vault_path(vault)
    catalog = collect_catalog(root)
    _write_json(root / "logs" / "catalog.json", catalog)
    return catalog


def collect_catalog(vault: str | Path) -> dict[str, Any]:
    """Build the searchable catalog in memory without writing it."""
    root = vault_path(vault)
    entries: list[dict[str, Any]] = []
    for path in iter_note_files(root):
        note = parse_markdown(path)
        metadata = _normalize_value(note.metadata)
        title = metadata.get("title") or path.stem
        links = extract_wikilinks(note.body) + _metadata_links(note.metadata)
        entries.append(
            {
                "path": relative_path(root, path),
                "title": title,
                "type": metadata.get("type"),
                "tags": metadata.get("tags", []),
                "severity": metadata.get("severity"),
                "status": metadata.get("status"),
                "sources": metadata.get("sources", []),
                "front_matter": metadata,
                "links": sorted(set(links)),
                "body": note.body.strip(),
                "parse_error": note.error,
            }
        )

    return {"version": 1, "notes": entries}


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        raise VaultError(f"invalid JSON: {relative_path(path.parent.parent, path)}") from exc


def update_manifest(vault: str | Path) -> dict[str, Any]:
    """Hash raw files and write the raw-source manifest."""
    root = vault_path(vault)
    manifest_path = root / "raw" / "manifest.json"
    previous = load_json(manifest_path, {"files": {}})
    previous_files = previous.get("files", {}) if isinstance(previous, dict) else {}
    files: dict[str, Any] = {}
    cited_sources = _cited_raw_sources(root)

    changed: list[str] = []
    for path in _iter_files(root / "raw"):
        relative = relative_path(root, path)
        if relative == "raw/manifest.json" or path.name == ".gitkeep":
            continue
        digest = sha256_file(path)
        previous_record = previous_files.get(relative)
        if previous_record is not None and previous_record.get("sha256") not in (None, digest):
            # Raw evidence is immutable: never re-bless a modified file. Keep the
            # recorded hash and size so `lint` keeps failing until the change is reverted.
            changed.append(relative)
            record = dict(previous_record)
        else:
            record = {"sha256": digest, "size": path.stat().st_size}
        record["processed"] = path.resolve() in cited_sources
        files[relative] = record

    changed.sort()
    removed = sorted(set(previous_files) - set(files))
    for relative in removed:
        # Keep the record of a deleted file so `lint` reports the missing evidence.
        files[relative] = previous_files[relative]
    manifest = {
        "version": 1,
        "files": files,
        "changed": changed,
        "removed": removed,
    }
    _write_json(manifest_path, manifest)
    return manifest


def _cited_raw_sources(root: Path) -> set[Path]:
    cited: set[Path] = set()
    for path in _iter_files(root / "wiki", ".md"):
        note = parse_markdown(path)
        for target in source_links(note.metadata):
            resolved = resolve_link(root, target)
            if resolved is not None:
                try:
                    if resolved.is_relative_to((root / "raw" / "sources").resolve()):
                        cited.add(resolved)
                except AttributeError:
                    if str(resolved).startswith(str((root / "raw" / "sources").resolve())):
                        cited.add(resolved)
    return cited


def find_uncovered_sources(vault: str | Path) -> list[str]:
    """Return raw source paths not cited by an authoritative wiki note."""
    root = vault_path(vault)
    cited = _cited_raw_sources(root)

    uncovered = []
    for path in _iter_files(root / "raw" / "sources", ".md"):
        if path.resolve() not in cited:
            uncovered.append(relative_path(root, path))
    return uncovered


def _manifest_errors(root: Path) -> list[str]:
    manifest_path = root / "raw" / "manifest.json"
    raw_files = [
        path
        for path in _iter_files(root / "raw")
        if path.name != ".gitkeep" and relative_path(root, path) != "raw/manifest.json"
    ]
    if not manifest_path.exists():
        if not raw_files:
            return []
        return ["raw manifest is missing; run `wiki_tool manifest`"]

    manifest = load_json(manifest_path, {})
    records = manifest.get("files", {}) if isinstance(manifest, dict) else {}
    errors: list[str] = []
    current_paths = set()
    for path in raw_files:
        relative = relative_path(root, path)
        current_paths.add(relative)
        record = records.get(relative)
        if record is None:
            errors.append(f"{relative}: missing from raw manifest")
            continue
        actual = sha256_file(path)
        if actual != record.get("sha256"):
            errors.append(f"{relative}: raw content hash does not match manifest")
    for relative in sorted(set(records) - current_paths):
        errors.append(f"{relative}: manifest records a missing raw file")
    return errors


def lint_vault(vault: str | Path) -> LintResult:
    """Validate note structure, links, tags, source traceability, and integrity."""
    root = vault_path(vault)
    errors: list[str] = []
    try:
        tags = allowed_tags(root)
    except VaultError as exc:
        tags = set()
        errors.append(str(exc))

    notes = iter_note_files(root)
    for path in notes:
        relative = relative_path(root, path)
        if relative.startswith("proposed/") and relative.count("/") > 1:
            errors.append(f"{relative}: drafts must sit directly in proposed/")
        note = parse_markdown(path)
        if note.error:
            errors.append(f"{relative}: {note.error}")
            continue

        metadata = note.metadata
        note_type = metadata.get("type")
        if not isinstance(note_type, str):
            errors.append(f"{relative}: missing or invalid `type`")
            continue

        expected_type = _type_for_path(root, path)
        if relative.startswith("proposed/"):
            expected_type = note_type
        if expected_type is not None and note_type != expected_type:
            errors.append(f"{relative}: type `{note_type}` does not match its directory")

        for field in _expected_fields(note_type):
            if field not in metadata:
                errors.append(f"{relative}: missing required field `{field}`")

        title = metadata.get("title")
        if not isinstance(title, str) or not title.strip():
            errors.append(f"{relative}: title must be a non-empty string")

        note_tags = metadata.get("tags")
        if not isinstance(note_tags, list) or not all(isinstance(tag, str) for tag in note_tags):
            errors.append(f"{relative}: tags must be a list of strings")
        else:
            for tag in note_tags:
                if tag not in tags:
                    errors.append(f"{relative}: unknown tag `{tag}`")

        for field in ("created", "updated"):
            if field in metadata and not _is_date(metadata[field]):
                errors.append(f"{relative}: `{field}` must use YYYY-MM-DD")
        if note_type == "source" and "captured" in metadata and not _is_date(metadata["captured"]):
            errors.append(f"{relative}: `captured` must use YYYY-MM-DD")

        if note_type == "source" and not isinstance(metadata.get("processed"), bool):
            errors.append(f"{relative}: `processed` must be boolean")

        if note_type == "vulnerability":
            if metadata.get("status") not in {"open", "fixed", "accepted"}:
                errors.append(f"{relative}: status must be open, fixed, or accepted")
            history = metadata.get("status_history")
            if not isinstance(history, list) or not history:
                errors.append(f"{relative}: status_history must be a non-empty list")
            else:
                for index, entry in enumerate(history):
                    if not isinstance(entry, Mapping):
                        errors.append(f"{relative}: status_history[{index}] must be a mapping")
                        continue
                    for field in ("status", "date", "ref", "note"):
                        if field not in entry:
                            errors.append(f"{relative}: status_history[{index}] missing `{field}`")
                    if "date" in entry and not _is_date(entry["date"]):
                        errors.append(f"{relative}: status_history[{index}] date is invalid")

        if not name_matches(path, note_type, root):
            errors.append(f"{relative}: file name does not follow schema/naming.md")

        links = extract_wikilinks(note.body) + _metadata_links(metadata)
        for target in links:
            if resolve_link(root, target) is None:
                errors.append(f"{relative}: broken wiki link `[[{target}]]`")

        if relative.startswith(("wiki/", "proposed/")):
            cited = source_links(metadata)
            if not cited:
                errors.append(f"{relative}: wiki note must cite at least one raw source")
            for source in cited:
                if not _link_target_is_raw_source(root, source):
                    errors.append(
                        f"{relative}: source citation does not resolve to raw/sources: {source}"
                    )

    errors.extend(_manifest_errors(root))
    try:
        load_review_state(root)
    except ReviewStateError as exc:
        errors.append(str(exc))
    for path in _iter_files(root):
        relative = relative_path(root, path)
        if path.name == ".gitkeep" or relative.startswith(".obsidian/"):
            continue
        if _secret_matches(_read_text(path)):
            errors.append(f"{relative}: secret-like value detected")

    return LintResult(sorted(set(errors)), len(notes))


def _load_catalog(root: Path) -> dict[str, Any]:
    catalog_path = root / "logs" / "catalog.json"
    if not catalog_path.exists():
        return build_catalog(root)
    loaded = load_json(catalog_path, {"notes": []})
    if not isinstance(loaded, dict) or not isinstance(loaded.get("notes"), list):
        raise VaultError("catalog must contain a `notes` list")
    return loaded


def _tokens(value: str) -> list[str]:
    return re.findall(r"[a-z0-9][a-z0-9_-]*", value.lower())


def _snippet(body: str, tokens: Sequence[str], fallback: str) -> str:
    lowered = body.lower()
    positions = [lowered.find(token) for token in tokens if lowered.find(token) >= 0]
    if not positions:
        return fallback[:240]
    position = min(positions)
    start = max(0, position - 80)
    return body[start : start + 240].replace("\n", " ").strip()


def query_catalog(
    vault: str | Path,
    terms: str | Sequence[str],
    *,
    note_type: str | None = None,
    tag: str | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Search titles, tags/front matter, and body text with weighted scoring."""
    root = vault_path(vault)
    query_text = terms if isinstance(terms, str) else " ".join(terms)
    query_tokens = _tokens(query_text)
    if not query_tokens:
        return []
    catalog = _load_catalog(root)
    results: list[dict[str, Any]] = []
    for entry in catalog["notes"]:
        if note_type and entry.get("type") != note_type:
            continue
        entry_tags = entry.get("tags", [])
        if tag and tag not in entry_tags:
            continue

        title = str(entry.get("title") or "")
        tags_text = " ".join(str(item) for item in entry_tags)
        front_text = json.dumps(entry.get("front_matter", {}), default=_json_default)
        body = str(entry.get("body") or "")
        score = 0
        for token in query_tokens:
            if token in title.lower():
                score += 8
            if token in tags_text.lower() or token in front_text.lower():
                score += 3
            if token in body.lower():
                score += 1
        if query_text.lower() in title.lower():
            score += 8
        if query_text.lower() in body.lower():
            score += 2
        if score == 0:
            continue

        results.append(
            {
                "score": score,
                "path": entry.get("path"),
                "title": title,
                "type": entry.get("type"),
                "severity": entry.get("severity"),
                "status": entry.get("status"),
                "sources": entry.get("sources", []),
                "snippet": _snippet(body, query_tokens, title),
            }
        )

    results.sort(key=lambda item: (-int(item["score"]), str(item["path"])))
    return results[: max(0, limit)]


def append_log(root: Path, message: str) -> None:
    """Append one timestamped entry to the maintenance log."""
    log_path = root / "logs" / "wiki-log.md"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.write_text("# SecVault Wiki Log\n\n", encoding="utf-8")
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat()
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(f"- `{timestamp}` — {message}\n")


def audit_vault(vault: str | Path) -> dict[str, Any]:
    """Run deterministic maintenance checks and append an audit log entry."""
    root = vault_path(vault)
    catalog = build_catalog(root)
    manifest = update_manifest(root)
    uncovered = find_uncovered_sources(root)
    lint = lint_vault(root)
    regression = {
        term: len(query_catalog(root, term, limit=5)) for term in ("vulnerability", "security")
    }
    status = "passed" if lint.ok else "failed"
    append_log(
        root,
        f"audit {status}; notes={len(catalog['notes'])}; "
        f"uncovered_sources={len(uncovered)}; errors={len(lint.errors)}",
    )
    return {
        "status": status,
        "catalog_count": len(catalog["notes"]),
        "manifest_count": len(manifest.get("files", {})),
        "uncovered_sources": uncovered,
        "lint": lint.as_dict(),
        "regression_queries": regression,
    }


@dataclass(frozen=True)
class DraftRef:
    """A draft that passed the location and name checks, read once for hashing and parsing."""

    path: Path
    relative: str
    name: str
    data: bytes
    fingerprint: str
    note: ParsedNote


@dataclass(frozen=True)
class _ApplyPlan:
    """One approved draft that is cleared to move into the wiki."""

    draft: DraftRef
    target: Path
    backup: bytes | None
    reviewer: str


def draft_name_problem(name: str) -> str | None:
    """Return why a draft file name is unsafe, or None when the name is acceptable."""
    if not name or name.startswith("."):
        return "draft name must not be empty or hidden"
    if DRAFT_UNSAFE_NAME_PATTERN.search(name):
        return "draft name contains a character that is unsafe in paths or on Windows"
    if name != name.strip() or name.endswith("."):
        return "draft name must not end with a space or a dot"
    if not name.endswith(".md"):
        return "draft name must end with .md"
    if name.split(".", 1)[0].upper() in DRAFT_RESERVED_NAMES:
        return "draft name uses a reserved Windows device name"
    return None


def errors_for(relative: str, errors: Iterable[str]) -> list[str]:
    """Return the lint errors that belong to one vault-relative file."""
    prefix = f"{relative}:"
    return [error for error in errors if error.startswith(prefix)]


def draft_target(note_type: object, name: str) -> str | None:
    """Return the vault-relative wiki path a draft of this type would occupy."""
    if not isinstance(note_type, str) or note_type not in TYPE_DIRECTORIES:
        return None
    return f"wiki/{TYPE_DIRECTORIES[note_type]}/{name}"


def resolve_draft(vault: str | Path, draft: str | Path) -> DraftRef:
    """Locate one draft that sits directly in vault/proposed/ and read it once.

    Symbolic links, `..` escapes, and unsafe names are refused before any content is
    read. A relative path is tried from the current directory first, then from the
    vault root.
    """
    root = vault_path(vault).resolve()
    proposed = (root / "proposed").resolve()
    supplied = Path(draft).expanduser()
    if not supplied.is_absolute():
        from_cwd = Path.cwd() / supplied
        supplied = from_cwd if from_cwd.exists() else root / supplied
    lexical = Path(os.path.abspath(supplied))
    if os.path.normcase(str(lexical.parent.resolve())) != os.path.normcase(str(proposed)):
        raise DraftError("draft must be a file directly inside vault/proposed/")
    if supplied.is_symlink() or lexical.is_symlink():
        raise DraftError("draft must not be a symbolic link")
    problem = draft_name_problem(lexical.name)
    if problem is not None:
        raise DraftError(problem)
    if not lexical.is_file():
        raise DraftError(f"draft does not exist: proposed/{lexical.name}")
    data = lexical.read_bytes()
    note = parse_note_text(lexical, data.decode("utf-8", errors="replace"))
    return DraftRef(
        path=lexical,
        relative=f"proposed/{lexical.name}",
        name=lexical.name,
        data=data,
        fingerprint=normalized_digest(data),
        note=note,
    )


def _approval_record(root: Path, ref: DraftRef) -> dict[str, Any]:
    try:
        return require_approval(load_review_state(root), ref.name, ref.fingerprint)
    except ReviewStateError as exc:
        raise DraftApplyError(str(exc)) from exc


def _require_history_extends(existing: ParsedNote, replacement: ParsedNote) -> None:
    """An overwrite may add history entries but may not rewrite or drop existing ones."""
    old = _normalize_value(existing.metadata.get("status_history") or [])
    new = _normalize_value(replacement.metadata.get("status_history") or [])
    if not isinstance(old, list) or not isinstance(new, list):
        raise DraftApplyError("status_history must be a list in both the draft and the note")
    if new[: len(old)] != old:
        raise DraftApplyError(
            "overwrite refused: the draft's status_history must extend the existing "
            "history as a prefix"
        )


def _plan_apply(
    root: Path,
    ref: DraftRef,
    *,
    overwrite: bool,
    problems: Sequence[str],
) -> _ApplyPlan:
    """Check what must hold before a draft may move. Nothing is changed here."""
    if problems:
        raise DraftApplyError("cannot apply invalid draft: " + "; ".join(problems))
    note_type = ref.note.metadata.get("type")
    relative_target = draft_target(note_type, ref.name)
    if relative_target is None:
        raise DraftApplyError(f"draft type is not an applicable wiki type: {note_type}")
    record = _approval_record(root, ref)
    target = root / relative_target
    backup: bytes | None = None
    if target.exists() or target.is_symlink():
        if not overwrite:
            raise DraftApplyError(f"refusing to overwrite existing note: {relative_target}")
        if not target.is_file() or target.is_symlink():
            raise DraftApplyError(f"refusing to overwrite a non-file: {relative_target}")
        _require_history_extends(parse_markdown(target), ref.note)
        backup = target.read_bytes()
    return _ApplyPlan(draft=ref, target=target, backup=backup, reviewer=str(record["reviewer"]))


def _roll_back(moved: Sequence[_ApplyPlan]) -> list[str]:
    """Undo completed moves in reverse order. Returns the names that could not be restored."""
    incomplete: list[str] = []
    for plan in reversed(moved):
        try:
            if plan.backup is None:
                plan.target.unlink(missing_ok=True)
            else:
                plan.target.write_bytes(plan.backup)
            if not plan.draft.path.exists():
                plan.draft.path.write_bytes(plan.draft.data)
        except OSError:
            incomplete.append(plan.draft.name)
    return incomplete


def _apply_plans(root: Path, plans: Sequence[_ApplyPlan]) -> None:
    """Move drafts into the wiki as one unit: lint once, and undo every move on failure."""
    moved: list[_ApplyPlan] = []
    try:
        for plan in plans:
            plan.target.parent.mkdir(parents=True, exist_ok=True)
            if plan.backup is None:
                try:
                    stream = plan.target.open("xb")
                except FileExistsError as exc:
                    relative_target = plan.target.relative_to(root).as_posix()
                    raise DraftApplyError(
                        f"refusing to overwrite existing note: {relative_target}"
                    ) from exc
                moved.append(plan)
                with stream:
                    stream.write(plan.draft.data)
            else:
                moved.append(plan)
                plan.target.write_bytes(plan.draft.data)
            plan.draft.path.unlink()
        lint = lint_vault(root)
        if not lint.ok:
            raise DraftApplyError("draft failed lint after apply: " + "; ".join(lint.errors))
    except Exception as exc:
        incomplete = _roll_back(moved)
        if incomplete:
            raise DraftApplyError(
                "apply failed and the rollback was incomplete; restore from git: "
                + ", ".join(incomplete)
            ) from exc
        raise


def _record_applied(root: Path, plans: Sequence[_ApplyPlan]) -> list[str]:
    """Retire each applied decision, keep it in the event trail, and log the change."""
    state = load_review_state(root)
    targets: list[str] = []
    for plan in plans:
        target = plan.target.relative_to(root).as_posix()
        record_applied(
            state,
            plan.draft.name,
            fingerprint=plan.draft.fingerprint,
            target=target,
            approved_by=plan.reviewer,
        )
        targets.append(target)
    save_review_state(root, state)
    for plan, target in zip(plans, targets, strict=True):
        append_log(
            root,
            f"applied {plan.draft.name} to {target}; approved_by={plan.reviewer}; "
            f"sha256={plan.draft.fingerprint[:12]}",
        )
    return targets


def apply_draft(
    vault: str | Path,
    draft: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Move one approved proposed note into its authoritative wiki directory.

    The draft must sit directly in vault/proposed/, lint cleanly, and carry an approval
    for its exact current bytes. Overwriting also needs a status_history that extends
    the existing one. The vault is linted after the move, and a failure restores the
    draft and the previous note.
    """
    root = vault_path(vault).resolve()
    ref = resolve_draft(root, draft)
    problems = errors_for(ref.relative, lint_vault(root).errors)
    plan = _plan_apply(root, ref, overwrite=overwrite, problems=problems)
    _apply_plans(root, [plan])
    applied = _record_applied(root, [plan])
    return {
        "applied": applied[0],
        "audit": audit_vault(root),
    }


def apply_approved(vault: str | Path) -> dict[str, Any]:
    """Apply every approved draft in one batch with one lint pass.

    A draft that cannot be read safely, or that has a problem, stops the batch before
    anything moves; this fails closed for unapproved drafts too. Batch apply never
    overwrites an existing note; overwrites are applied one at a time with `--overwrite`.
    If the lint pass fails, every move is rolled back.
    """
    root = vault_path(vault).resolve()
    try:
        state = load_review_state(root)
    except ReviewStateError as exc:
        raise DraftApplyError(str(exc)) from exc
    proposed = root / "proposed"
    approved: list[DraftRef] = []
    if proposed.is_dir():
        for path in sorted(proposed.glob("*.md")):
            if path.name == "README.md":
                continue
            ref = resolve_draft(root, path)
            if draft_status(state, ref.name, ref.fingerprint)[0] == "approved":
                approved.append(ref)
    if not approved:
        return {"applied": [], "audit": None}
    lint_errors = lint_vault(root).errors
    plans = [
        _plan_apply(root, ref, overwrite=False, problems=errors_for(ref.relative, lint_errors))
        for ref in approved
    ]
    _apply_plans(root, plans)
    applied = _record_applied(root, plans)
    return {
        "applied": applied,
        "audit": audit_vault(root),
    }
