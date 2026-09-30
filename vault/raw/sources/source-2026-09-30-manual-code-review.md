---
type: source
title: "Manual code review: sample app"
tags:
  - source
  - input-validation
  - secrets-management
created: 2026-09-30
updated: 2026-09-30
sources: []
finding_id: "manual:sample-app:code-review"
scanner: manual
captured: 2026-09-30
processed: false
---

# Manual code review: sample app

This source records the intentionally vulnerable code paths that configuration
scanners do not cover:

- `manual:CWE-89:sample-app/app.py:27` — SQL injection because the search term
  is concatenated into a SQLite query.
- `manual:CWE-79:sample-app/app.py:39` — reflected cross-site scripting because
  the message is returned without output encoding.
- `manual:CWE-20:sample-app/app.py:33` — weak input validation because the
  search value has no meaningful length or character constraints.
- `manual:CWE-798:sample-app/app.py:11-15` — fake credential-like values are
  hardcoded in application source; the captured secret value is not repeated
  here.
