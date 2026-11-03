---
name: secvault-maintain
description: Rebuilds and validates the SecVault catalog, raw manifest, source coverage, and maintenance log. Use after ingest, draft application, schema changes, or before committing vault changes.
---

# SecVault Maintain

This skill runs deterministic maintenance. It does not ask an LLM to
reconstruct indexes or decide whether a raw file is trustworthy.

## Standard pass

From the repository root, run:

```powershell
python -m wiki_tool index --vault vault
python -m wiki_tool manifest --vault vault
python -m wiki_tool coverage --vault vault --json
python -m wiki_tool lint --vault vault --json
python -m wiki_tool report --vault vault
python -m wiki_tool audit --vault vault --json
```

The audit command repeats the deterministic checks and appends an entry to
`vault/logs/wiki-log.md`. Generated catalog and manifest changes are expected;
review them before committing.

## Capture

Scanner findings enter the raw layer only through `wiki_tool capture`:

- Capture refuses to run unless the vault lints cleanly beforehand.
- Each finding becomes one raw note named by its stable ID. Existing notes are
  never overwritten, so a re-run of the same scan creates nothing.
- A finding that disappears from a scan of the same scanner and path prefix is
  marked `candidate_fixed` in `logs/capture-state.json`. A human confirms
  `fixed`.
- `python -m wiki_tool report --vault vault` summarizes the capture state
  read-only.

## Failure handling

- Read the file-specific lint errors.
- Fix schema violations in notes, proposed drafts, or schema files.
- Never edit a raw source to make lint pass.
- A raw hash mismatch means evidence changed after capture; stop and report
  it. `manifest` keeps the recorded hash and exits 1 for a changed or removed raw
  file, so re-running it does not clear the failure.
- Do not suppress a broken link, unknown tag, missing source citation, or
  secret-like value.
- Re-run the failing command and then the full audit after every fix.
