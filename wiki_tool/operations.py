"""Filesystem operations for the SecVault vault.

The functions in this module are deterministic and do not call Obsidian or an
LLM. Agents use them through the CLI and the repository-local workflow skills.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

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
SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}\b"),
)


class VaultError(RuntimeError):
    """Base error for expected vault operation failures."""


class DraftApplyError(VaultError):
    """Raised when a proposed draft cannot be safely applied."""


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
    text = _read_text(path)
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
    return target.replace("\\", "/").removeprefix("./").removeprefix("/")


def resolve_link(vault: Path, target: str) -> Path | None:
    """Resolve a vault-relative or basename-style Obsidian link."""
    cleaned = _clean_link_target(target)
    if not cleaned or cleaned.startswith(("http://", "https://")):
        return None

    candidate = vault / cleaned
    candidates = [candidate]
    if candidate.suffix.lower() != ".md":
        candidates.append(candidate.with_suffix(".md"))
    for possible in candidates:
        if possible.is_file():
            return possible.resolve()

    if "/" not in cleaned:
        basename = Path(cleaned).stem
        matches = sorted(path.resolve() for path in vault.rglob("*.md") if path.stem == basename)
        if len(matches) == 1:
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


def _source_links(metadata: Mapping[str, Any]) -> list[str]:
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


def _name_matches(path: Path, note_type: str, vault: Path) -> bool:
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
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def build_catalog(vault: str | Path) -> dict[str, Any]:
    """Build and write the searchable catalog."""
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

    catalog = {"version": 1, "notes": entries}
    _write_json(root / "logs" / "catalog.json", catalog)
    return catalog


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, default: Any) -> Any:
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
    previous = _load_json(manifest_path, {"files": {}})
    previous_files = previous.get("files", {}) if isinstance(previous, dict) else {}
    files: dict[str, Any] = {}

    for path in _iter_files(root / "raw"):
        relative = relative_path(root, path)
        if relative == "raw/manifest.json" or path.name == ".gitkeep":
            continue
        processed = False
        if path.suffix.lower() == ".md":
            processed = bool(parse_markdown(path).metadata.get("processed", False))
        files[relative] = {
            "sha256": _sha256(path),
            "size": path.stat().st_size,
            "processed": processed,
        }

    previous_keys = set(previous_files)
    current_keys = set(files)
    changed = sorted(
        relative
        for relative in current_keys & previous_keys
        if files[relative]["sha256"] != previous_files[relative].get("sha256")
    )
    removed = sorted(previous_keys - current_keys)
    manifest = {
        "version": 1,
        "files": files,
        "changed": changed,
        "removed": removed,
    }
    _write_json(manifest_path, manifest)
    return manifest


def find_uncovered_sources(vault: str | Path) -> list[str]:
    """Return raw source paths not cited by an authoritative wiki note."""
    root = vault_path(vault)
    cited: set[Path] = set()
    for path in _iter_files(root / "wiki", ".md"):
        note = parse_markdown(path)
        for target in _source_links(note.metadata):
            resolved = resolve_link(root, target)
            if resolved is not None:
                cited.add(resolved)

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
    if not raw_files:
        return []
    if not manifest_path.exists():
        return ["raw manifest is missing; run `wiki_tool manifest`"]

    manifest = _load_json(manifest_path, {})
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
        actual = _sha256(path)
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

        if not _name_matches(path, note_type, root):
            errors.append(f"{relative}: file name does not follow schema/naming.md")

        links = extract_wikilinks(note.body) + _metadata_links(metadata)
        for target in links:
            if resolve_link(root, target) is None:
                errors.append(f"{relative}: broken wiki link `[[{target}]]`")

        if relative.startswith(("wiki/", "proposed/")):
            source_links = _source_links(metadata)
            if not source_links:
                errors.append(f"{relative}: wiki note must cite at least one raw source")
            for source in source_links:
                if not _link_target_is_raw_source(root, source):
                    errors.append(
                        f"{relative}: source citation does not resolve to raw/sources: {source}"
                    )

    errors.extend(_manifest_errors(root))
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
    loaded = _load_json(catalog_path, {"notes": []})
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


def _append_log(root: Path, message: str) -> None:
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
    _append_log(
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


def apply_draft(
    vault: str | Path,
    draft: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Move an approved proposed note into its authoritative wiki directory."""
    root = vault_path(vault).resolve()
    draft_path = Path(draft).expanduser()
    if not draft_path.is_absolute():
        direct = (Path.cwd() / draft_path).resolve()
        draft_path = direct if direct.exists() else (root / draft_path).resolve()
    else:
        draft_path = draft_path.resolve()
    proposed_root = (root / "proposed").resolve()
    try:
        draft_path.relative_to(proposed_root)
    except ValueError as exc:
        raise DraftApplyError("draft must be located under vault/proposed/") from exc
    if not draft_path.is_file():
        raise DraftApplyError(f"draft does not exist: {draft_path}")

    note = parse_markdown(draft_path)
    if note.error:
        raise DraftApplyError(f"cannot apply invalid draft: {note.error}")
    note_type = note.metadata.get("type")
    if note_type not in TYPE_DIRECTORIES:
        raise DraftApplyError(f"draft type is not an applicable wiki type: {note_type}")

    target = root / "wiki" / TYPE_DIRECTORIES[note_type] / draft_path.name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not overwrite:
        raise DraftApplyError(f"refusing to overwrite existing note: {relative_path(root, target)}")

    backup = target.read_bytes() if target.exists() else None
    draft_bytes = draft_path.read_bytes()
    shutil.move(str(draft_path), str(target))
    lint = lint_vault(root)
    if not lint.ok:
        if target.exists():
            target.unlink()
        if backup is not None:
            target.write_bytes(backup)
        draft_path.write_bytes(draft_bytes)
        raise DraftApplyError("draft failed lint after apply: " + "; ".join(lint.errors))

    audit = audit_vault(root)
    return {
        "applied": relative_path(root, target),
        "audit": audit,
    }
