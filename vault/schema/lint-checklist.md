# Lint Checklist

Run this checklist after every ingest, apply, or maintenance change:

- [ ] Every note has parseable YAML front matter.
- [ ] `type`, `title`, `tags`, `created`, `updated`, and `sources` are present
      where required by the note type.
- [ ] Every tag is listed in `schema/tags.yaml`.
- [ ] Dates use `YYYY-MM-DD`.
- [ ] File names follow `schema/naming.md`.
- [ ] Every `[[wiki-link]]` resolves to a note or approved generated target.
- [ ] Every wiki note cites at least one existing raw source.
- [ ] Raw manifest hashes still match every raw source.
- [ ] No raw file was modified after capture.
- [ ] No secret-like value appears in the vault.
- [ ] Vulnerability status changes are represented in append-only
      `status_history`.
- [ ] Generated catalog and manifest can be rebuilt deterministically.
- [ ] Representative queries return expected notes, including a body-only
      match.
- [ ] Every draft sits directly inside `proposed/` and follows the naming rules.
      `review`, `approve`, and `apply` also refuse symbolic links, reserved
      Windows names, and alternate data streams.
- [ ] `logs/review-state.json` parses and matches its schema.
- [ ] No link resolves outside the vault. Rooted, drive-qualified, and `..`
      targets never resolve, and a symbolic link cannot point out of the vault.
- [ ] Captured raw notes keep their structure: scanner text cannot add headings,
      list items, or `[[` links. The injection tests check this, not lint.
- [ ] The Git diff contains no unauthorized direct write to `raw/` or `wiki/`.
