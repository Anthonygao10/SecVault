from __future__ import annotations

from pathlib import Path

from wiki_tool.operations import audit_vault, lint_vault, update_manifest

SOURCE = "raw/sources/source-2026-09-30-scan.md"


def test_manifest_does_not_rebless_modified_raw_file(good_vault: Path) -> None:
    source = good_vault / SOURCE
    source.write_text(source.read_text() + "\nTampered evidence.\n", encoding="utf-8")

    manifest = update_manifest(good_vault)

    assert manifest["changed"] == [SOURCE]
    assert any("hash does not match" in error for error in lint_vault(good_vault).errors)


def test_audit_fails_when_raw_file_was_modified(good_vault: Path) -> None:
    source = good_vault / SOURCE
    source.write_text(source.read_text() + "\nTampered evidence.\n", encoding="utf-8")

    report = audit_vault(good_vault)

    assert report["status"] == "failed"


def test_deleted_raw_file_is_not_forgotten(good_vault: Path) -> None:
    (good_vault / SOURCE).unlink()

    manifest = update_manifest(good_vault)

    assert manifest["removed"] == [SOURCE]
    assert any("missing raw file" in error for error in lint_vault(good_vault).errors)


def test_hash_ignores_checkout_line_endings(good_vault: Path) -> None:
    source = good_vault / SOURCE
    source.write_bytes(source.read_bytes().replace(b"\n", b"\r\n"))

    assert lint_vault(good_vault).ok
