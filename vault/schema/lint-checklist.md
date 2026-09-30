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
- [ ] The Git diff contains no unauthorized direct write to `raw/` or `wiki/`.
