---
name: secvault-lint
description: Validates SecVault note front matter, tags, naming, links, source citations, raw hashes, and secret-like values. Use after any vault change or when a schema or integrity problem is suspected.
---

# SecVault Lint

Run the deterministic validator; do not replace it with prompt-based inspection.

```powershell
python -m wiki_tool lint --vault vault --json
```

## Interpreting failures

- Missing or invalid front matter: compare the note with the matching
  template and `vault/schema/front-matter.md`.
- Unknown tag: use only `vault/schema/tags.yaml`.
- Broken link: correct the Obsidian target or remove an unsupported link.
- Missing source citation: add a resolvable `[[raw/sources/...]]` entry.
- Raw hash mismatch (a changed or removed raw file): stop; do not edit the raw
  evidence. Restore the file from Git history after confirming the change was
  not intentional. `manifest` does not accept a changed file, so re-running it
  does not clear the failure.
- Missing manifest record for a new raw file: run `python -m wiki_tool manifest
  --vault vault` only when the capture is intentional and reviewed.
- Secret-like value: redact through the approved capture process and review
  the Git history; do not paste real credentials into a note.

After fixing an allowed file, rerun lint and then the full maintain audit.
Never weaken a validator to make a note pass.
