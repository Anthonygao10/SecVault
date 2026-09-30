# Naming Conventions

Use lowercase kebab-case for slugs. Keep names stable after a note is cited;
renames require updating all Obsidian links and the catalog.

| Note type | Location | Pattern |
|---|---|---|
| Source | `raw/sources/` | `source-YYYY-MM-DD-<slug>.md` |
| Vulnerability | `wiki/vulnerabilities/` or `proposed/` | `vuln-<slug>.md` |
| Postmortem | `wiki/postmortems/` or `proposed/` | `postmortem-<slug>.md` |
| Concept | `wiki/concepts/` or `proposed/` | `concept-<slug>.md` |
| Entity | `wiki/entities/` or `proposed/` | `entity-<slug>.md` |
| Log | `logs/` | `log-YYYY-MM-DD-<slug>.md` |

The generated catalog is `logs/catalog.json`; the raw manifest is
`raw/manifest.json`; and the append-only maintenance log is
`logs/wiki-log.md`. These generated files are not wiki notes.

Names should describe the stable subject rather than a transient scan run.
Use the finding ID in front matter for identity and lifecycle tracking.
