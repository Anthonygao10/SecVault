# Product Requirements Document

## SecVault: Security & Bug Memory Layer for AI Coding Agents

| | |
|---|---|
| **Author** | [Your name] |
| **Status** | Draft, v0.3 |
| **Last updated** | September 30, 2026 |
| **Target use** | Personal / portfolio project for DevOps and cybersecurity internship applications |
| **Inspiration** | "How To Build LLM Wiki In Obsidian: A Memory Layer For Any Agentic AI" (YouTube tutorial by Callum / Wander Lutes) |

### Changelog

- **v0.3:** Added threat model (section 9), repo layout and sample app (5.6), decision to make `wiki_tool` filesystem-only with Obsidian as an optional viewer, stable finding IDs and idempotent capture, `status_history` finding lifecycle, query spec, automated test requirement, scanner updates (Trivy, gitleaks), split of the review loop from Ollama in the milestones, resolved the open questions, and added tutorial-derived details (Web Clipper capture, Windows launchers, body-text search, PDF folder reserved).
- **v0.3 implementation clarification:** Product workflow skills live in portable `.agents/skills/` and are entered through root `AGENTS.md`; tool-specific adapters such as `.cursor/rules/` and the development `memory-bank/` are build-time context, not product dependencies. Raw evidence remains immutable, so manifest `processed` state is derived from authoritative wiki citations rather than written back into raw notes.
- **v0.2:** Initial structured draft.

---

## 1. Overview

SecVault is a git-versioned Obsidian vault that acts as a persistent, shared memory layer for a software project's security and bug history. Raw findings (security scan output, CI failures, incident notes) are captured unmodified, compiled by an AI coding agent into a linked wiki of vulnerability records, bug postmortems, and concept pages, and governed by a schema that both humans and agents must follow.

The design adapts the "LLM Wiki" pattern from the source tutorial (raw layer, wiki layer, schema layer) to a narrow, high-value domain: security. It then extends the pattern with DevOps practices the tutorial does not cover: CI-driven raw capture, lint checks as a pull-request gate, scheduled maintenance, automated tests for the tooling, a threat model for feeding untrusted text to an agent, and Docker packaging so the system can be installed on any machine.

The payoff: an AI coding assistant working on the project can consult the vault and recall that a similar SQL injection pattern, hardcoded secret, or overly permissive IAM policy was found before, instead of rediscovering the same class of problem every session.

## 2. Problem Statement

- AI coding assistants have no persistent memory of a project's security history; every session starts from zero context on past bugs and vulnerabilities.
- Security scan output (Trivy, Checkov, linters, CI failures) is usually read once in a PR check and then lost, with no structured record of what was found or how it was fixed.
- Free-form notes and wikis drift out of shape as AI agents edit them. Without enforced structure, naming, and validation, an agent-maintained knowledge base becomes inconsistent and untrustworthy as it grows.
- There is no lightweight, portable, git-native way to give a project security "institutional memory" that travels with the codebase and can be diffed, reviewed, and rolled back like code.

## 3. Goals

- Build a working, demoable vault that compiles raw security findings into a structured, cross-linked wiki with full source traceability.
- Make the schema the contract: every note an agent writes must follow required front matter, naming conventions, allowed tags, and templates, and this is enforced by code, not just by prompting.
- Use deterministic Python tooling for indexing, validation, and querying, so the LLM handles only extraction and drafting.
- Automate raw capture and validation through CI/CD so the vault stays current without manual copy-paste.
- Keep a human in the loop: agent-generated content is reviewed before it becomes authoritative.
- Treat all raw content as untrusted input to the agent (see section 9).
- Support a fully local, private mode (Ollama) and stay agent-agnostic so the vault is not locked to one AI provider.
- Package the system so it can be installed on a fresh machine with minimal setup.

## 4. Non-Goals

- Not a general-purpose second brain. Scope is limited to bugs, vulnerabilities, and security-relevant project context.
- Not a replacement for vulnerability management platforms (Snyk, Dependabot, etc.). SecVault ingests their output.
- Not vector-database RAG in v1. Retrieval is catalog- and index-first (see 5.2 and 6.3); embeddings and graph RAG are future extensions.
- Not autonomous remediation. The agent drafts records; a human approves them.
- Not a hosted, multi-tenant, or team-shared service in v1.
- PDF ingestion and advanced knowledge-organization methods (for example Zettelkasten-style systems) are out of scope for v1. A `raw/files/` folder is reserved for PDFs and other non-Markdown material so the layout does not change later.

## 5. System Architecture

### 5.1 The Three Layers

- **Raw layer:** captured source material stored exactly as received and never modified. For SecVault this means scanner reports, CI failure logs, incident notes, and fix diffs. Markdown sources live in `raw/sources/`; non-Markdown files are reserved for `raw/files/`.
- **Wiki layer:** structured, cross-linked notes the agent compiles from raw sources: vulnerability records, bug postmortems, concept pages (e.g. input validation, least privilege), and entity pages (affected components, tools). Every wiki note cites the raw source it came from.
- **Schema layer:** the rules that keep the other two aligned: an `agents.md` file (the vault's constitution), a front matter schema, naming conventions, workflow recipes, a lint checklist, templates, repo-local skills, and the Python tooling. This layer is the contract between the human and whatever agent is working in the vault.

### 5.2 Core Loop: Ingest, Maintain, Query

The tutorial's central idea is that repeatable behavior comes from skills plus scripts, not from prompting alone. SecVault adopts the same three-stage loop, each backed by a repo-local skill that calls a Python tool:

- **Ingest:** detect new raw sources with no wiki coverage, extract concepts and entities, and write notes from templates that link back to the source.
- **Maintain:** check what changed, rebuild the index and catalog, update the raw source manifest, lint front matter and links, verify that representative queries still resolve, and append an entry to the wiki log.
- **Query:** search the catalog and index first, then open only the relevant pages. This keeps retrieval cheap and traceable compared with pulling large chunks into context.

Git provides the safety net. Every stage ends in a commit, the wiki log records what the agent did, and any bad ingest can be rolled back to a known-good save point.

### 5.3 DevOps Extensions (beyond the tutorial)

The tutorial runs entirely on one machine and is triggered by prompting an agent. SecVault adds the automation and packaging layer:

- **CI-driven raw capture:** a GitHub Actions workflow runs security scanners on each push or PR and writes normalized, redacted reports into the raw layer.
- **Lint as a merge gate:** the same Python lint and structure checks the agent uses locally run in CI, so a PR that breaks the schema fails its checks.
- **Scheduled maintenance:** a scheduled workflow (daily or weekly) runs the deterministic parts of the maintain loop, mirroring the tutorial's idea of running maintenance on a timer or heartbeat.
- **Automated tests:** `wiki_tool` has a pytest suite with good and bad fixture vaults, and the suite also runs in CI.
- **Docker packaging:** the tooling, scripts, and dependencies are containerized for a one-command install on a new machine.
- **PR-based review** for team-style workflows, layered on top of the local review folder described in 6.6.

### 5.4 Execution Split: CI vs. Local

A design decision worth stating explicitly: LLM drafting should not run inside standard CI runners. Hosted runners have no GPU, and small local models are slow and error-prone on them. The split is:

| Where | What runs |
|---|---|
| **Runs in CI** | Security scans, raw-layer writes, catalog and index builds, lint and structure validation, tests, scheduled deterministic maintenance. |
| **Runs locally** | LLM extraction and drafting (cloud coding agent or Ollama), human review of proposed notes, applying approved drafts. |
| **Optional later** | A self-hosted runner with a model attached, if fully automated drafting is ever needed. |

### 5.5 Data Flow

1. A developer pushes code to the tracked project.
2. GitHub Actions runs Trivy (config scanning), Checkov, gitleaks, and project tests/linters, then writes normalized and redacted findings into the vault's raw layer. Findings can also be added manually (for example via the Obsidian Web Clipper or by dropping in an incident note).
3. On the developer's machine, the ingest skill detects raw sources with no wiki coverage and asks the agent to draft notes using the schema and templates.
4. Drafts land in a proposed/review folder. A human approves or rejects them.
5. Approved drafts are applied, and the maintain loop rebuilds the catalog, runs lint, updates the manifest, and logs the change. Everything is committed to git.
6. CI re-runs lint and tests on the repo as a merge gate for any PR.
7. In later coding sessions, the assistant runs the query skill against the catalog before writing new code and surfaces related past findings.

### 5.6 Repository Layout and Sample App

Decision: a single monorepo for the demo. This removes the cross-repo token problem for CI writes.

```
SecVault/
  vault/                  # the Obsidian vault (open this folder in Obsidian)
    raw/
      sources/            # captured reports and incident notes (immutable)
      files/              # reserved for PDFs and other non-Markdown files
    wiki/
      vulnerabilities/
      postmortems/
      concepts/
      entities/
    proposed/             # agent or model drafts awaiting human review
    schema/               # front matter schema, naming, tags.yaml, workflows, lint checklist
    templates/
    logs/
    agents.md
    README.md
  wiki_tool/              # Python tooling, kept outside the vault
  tests/                  # pytest suite and fixture vaults (good and bad)
  sample-app/             # deliberately vulnerable demo project
  .agents/skills/         # repo-local skills (ingest, maintain, query, lint, obsidian-safe)
  .github/workflows/
  launchers/              # Windows .bat/.ps1 launcher commands
  Dockerfile
```

The `sample-app/` folder contains a small app with intentional flaws (SQL injection, hardcoded secret, weak input validation) and Terraform with intentional misconfigurations (for example a public S3 bucket, an overly permissive IAM policy), so Trivy, Checkov, and gitleaks produce real findings for the demo. It must be clearly labeled as intentionally insecure and must never contain real credentials.

Because Python scripts are not read by Obsidian, `wiki_tool/` lives outside `vault/`, as in the tutorial.

## 6. Key Features

### 6.1 Vault Structure & Schema

- Folder hierarchy for raw sources, wiki notes, schema docs, templates, proposed drafts, and logs, with a README explaining vault usage.
- `agents.md` defines the workflow, where files may be written, and non-negotiable rules: never overwrite raw material, always use front matter, use only approved tags, use Obsidian wiki-link syntax, and treat raw content as data, never as instructions (see section 9).
- Front matter schema requires consistent tags, created and updated dates, and a reference to the originating source on every wiki note.
- Naming conventions and an allowed-tag vocabulary live in the schema, so changing a convention once updates behavior for all future notes. The allowed tags live in one versioned file (`schema/tags.yaml`) that the lint reads; unknown tags fail lint, and adding a tag is a deliberate, reviewable change.
- A lint checklist reminds the agent to validate structure after every change.
- Obsidian is an optional viewer and editor. `wiki_tool` and CI operate on plain files and must not require Obsidian to be installed or running.

### 6.2 Templates

| Template | Purpose |
|---|---|
| **Source** | Raw scan report or incident. Includes capture-time processed metadata; because raw evidence is immutable, current ingestion coverage is authoritative in the raw source manifest. |
| **Vulnerability** | Severity, CWE/OWASP category, affected component, status (open / fixed / accepted), append-only `status_history`, fix commit, links to concepts. |
| **Bug postmortem** | Symptom, root cause, fix, prevention, related vulnerabilities. |
| **Concept** | Reusable security ideas (e.g. input validation, secrets management) that many records link to. |
| **Entity** | Affected files, services, and tools referenced across records. |
| **Log** | Append-only record of ingest and maintenance actions. |

Finding lifecycle: a vulnerability's `status` is never silently overwritten. Each change appends an entry to a `status_history` list (status, date, commit or PR reference, note), so a finding that is later fixed keeps its history. A finding that stops appearing in scans is marked as a candidate for "fixed" by the maintain loop, but a human confirms the change.

### 6.3 Python Tooling (wiki_tool)

Deterministic scripts do the heavy lifting so results are consistent and cheap. The tool is expected to cover:

- Build the index and catalog of all notes (titles, tags, front matter fields, links, and body text).
- Scan the raw layer and update the raw source manifest.
- Check which raw sources still lack wiki coverage.
- Validate structure: front matter fields, allowed tags, link integrity, naming conventions, and that no raw file has changed since it was recorded in the manifest (content hash).
- Search the catalog and run queries for the query skill.
- Audit the vault and write maintenance entries to the log.

The schema is encoded in these scripts (for example the allowed-tag list), so rules are enforced by code rather than hoped for from the model.

**Query specification (v1):** keyword and tag matching over titles, front matter fields, and body text (the tutorial's first maintain pass failed because catalog search did not include body text). Results are ranked by simple weighted scoring (title > tags/front matter > body), limited to the top N, and returned as JSON with path, title, type, severity and status where applicable, source citation, and a short snippet. The maintain loop runs a small set of known queries as a regression check.

**Testing:** a pytest suite with fixture vaults covers every validator. At minimum: a valid vault passes; missing front matter, unknown tag, broken link, missing source citation, and a modified raw file each fail with a clear message; redaction removes seeded fake secrets.

### 6.4 Repo-Local Skills

- Ingest, maintain, query, and lint skills scoped to the vault repository, each calling the Python tool.
- Obsidian-aware skills (Obsidian CLI, Markdown, Bases, Canvas, Defuddle, from the Obsidian skill pack referenced in the tutorial) so the agent writes valid Obsidian syntax and links.
- An obsidian-safe skill that routes all Obsidian actions through the firewall wrapper (6.7).
- The Obsidian CLI must be enabled in Obsidian's general settings for agents to connect to the vault. It is used only for interactive local sessions, never in CI or Docker.
- A setup/handoff file that a coding agent can follow to recreate the structure, in the spirit of the tutorial's agent handoff file.

### 6.5 Automated Raw Capture (CI)

- Workflow runs scanners on push and PR and writes reports into the raw layer using the source template.
- Output is normalized and redacted before it is written (see 6.10).
- Each finding gets a stable ID (for example a hash of scanner, rule ID, file path, and normalized location). Re-running a scan on unchanged code does not create duplicate raw sources or duplicate vulnerability notes, and the same finding seen again updates a "last seen" value in the manifest rather than creating a new file.
- Scheduled workflow performs deterministic maintenance (catalog rebuild, lint, coverage report) and reports failures.
- Manual capture (Obsidian Web Clipper, pasted incident notes) uses the same source template and lands in `raw/sources/`.

### 6.6 Human-in-the-Loop Review

- Local model or agent output is written to a proposed folder, never directly into the wiki.
- The reviewer approves a draft, then an apply step writes it into the wiki and triggers the maintain loop. The apply step refuses to overwrite an existing note unless explicitly confirmed.
- For team-style use, approved changes to the vault repository go through a normal pull request with lint checks required.
- Reviewer focus: severity and status fields, accuracy of root cause, and correct source citation.
- This review loop works with any agent, not only Ollama, and is built before the local model is connected.

### 6.7 Vault Firewall

- A wrapper script sits in front of the Obsidian CLI and checks the target vault name against an allowlist before passing any command through.
- An accompanying skill instructs the agent to call the wrapper instead of the raw CLI.
- Expected behavior: a request to write to any non-approved vault is refused with a clear policy message.
- Limitation to document: this is a guardrail against agent mistakes, not a hard security boundary against a determined bypass. Stronger isolation (sandboxed mounts) is a future option.

### 6.8 Local-First Privacy

- Default configuration supports Ollama so no vulnerability data has to leave the machine.
- Launcher commands provide an app-like flow: check raw sources, draft with the local model, apply latest draft. The tutorial uses double-click commands on macOS; SecVault provides Windows `.bat`/PowerShell equivalents.
- Sequencing rule from the tutorial: get the workflow reliable with a stronger cloud agent first, tune schema and skills, then introduce the local model. Local models make more mistakes, so a shaky foundation makes them worse.
- Optional hosted-model configuration with a documented trade-off: convenience versus data exposure.

### 6.9 Coding-Assistant Recall

- The tracked project's own agent instructions tell the assistant to run the vault's query skill before working on security-sensitive areas.
- Results return the relevant notes (vulnerability records, concepts) with their source citations.
- Future extension: expose the same query interface through an MCP server so any assistant can call it as a tool.

### 6.10 Sensitive Data Handling

- Scanner output can contain secrets, tokens, or internal paths. The CI capture step must redact secret values before writing to the raw layer.
- Redaction is tested: fixtures seeded with fake secrets (AWS-style keys, tokens, private key headers) must come out redacted, and lint flags secret-like strings found anywhere in the vault.
- The vault repository is private by default, and a `.gitignore` excludes local config and Obsidian workspace files.
- Vulnerability records for unfixed issues are treated as sensitive and are never sent to a hosted model unless the user opts in.

## 7. Tech Stack

| Component | Choice |
|---|---|
| **Knowledge base** | Obsidian vault (Markdown, YAML front matter, wiki links) as viewer/editor; Obsidian CLI for local agent sessions only |
| **Version control** | Git, with commits at each workflow stage and a private remote |
| **Tooling** | Python scripts (`wiki_tool`) with pytest, plus repo-local agent skills |
| **Coding agent** | Any agentic coding tool (agent-agnostic by design) |
| **Local model** | Ollama, with launcher scripts and a proposed/review folder |
| **CI/CD** | GitHub Actions: scan, capture, lint and test gate, scheduled maintenance |
| **Security scanning** | Trivy (IaC/config; successor to tfsec, which is deprecated, with tfsec optional), Checkov, gitleaks for secrets, project linters and tests (extendable) |
| **Packaging** | Docker image for tooling and scripts |
| **Access control** | Obsidian-safe wrapper script and skill with a vault allowlist |

## 8. Milestones / Phased Rollout

The tutorial's own order is followed: initialize git, build structure and schema, add tooling, validate with a demo ingest, then add advanced features. Commit at the end of every phase.

### Phase 1: Foundation

- Install Obsidian, Python, Git, a coding agent; create the repo with `vault/` and open it in Obsidian; enable the Obsidian CLI.
- Initialize git with a `.gitignore`; commit the empty vault.
- Install the Obsidian-aware skills.

### Phase 2: Schema & Templates

- Create the folder structure, README, and `agents.md`.
- Write the front matter schema, naming conventions, `schema/tags.yaml`, workflow recipes, and lint checklist.
- Build the six templates (source, vulnerability, bug postmortem, concept, entity, log).

### Phase 3: Tooling & Skills

- Build `wiki_tool`: index/catalog (including body text), manifest with content hashes, coverage check, structure validation, query, audit.
- Write the pytest suite and good/bad fixture vaults alongside each validator.
- Create the ingest, maintain, query, and lint skills.

### Phase 4: Manual Validation

- Create `sample-app/` and run Trivy, Checkov, and gitleaks on it; drop the output into the raw layer by hand and ingest it.
- Run the maintain loop, fix schema and tooling gaps found, and confirm the query returns the right notes. Do this before automating anything.
- Run ingest with maintain, lint, and query held back first, then run them as a separate pass, as in the tutorial, to confirm each stage works on its own.

### Phase 5: CI Automation

- GitHub Actions workflow for scanning, stable-ID redacted raw capture, and idempotent re-runs.
- Lint, structure validation, and tests as a required PR check; scheduled maintenance workflow.

### Phase 6: Review Loop

- Implement draft to proposed folder to approve to apply, independent of any specific model.
- Add a prompt-injection fixture (a raw source containing hostile instructions) and confirm the agent and tooling treat it as data.

### Phase 7: Local Model, Launchers & Firewall

- Connect Ollama to the review loop.
- Add Windows launcher commands: check raw sources, draft with Ollama, apply latest draft.
- Build the obsidian-safe wrapper and skill; test that non-approved vaults are refused.

### Phase 8: Packaging & Demo

- Dockerize the tooling; write install instructions for a fresh machine.
- Add an architecture diagram, CI status badge, and a "limitations and next steps" section to the README.
- Record a walkthrough: scan finds a vulnerability, raw entry created, agent drafts a record, human approves, lint passes, and a later coding session recalls the finding.
- Optional: color-code the graph view by layer (raw, wiki, schema, templates) for the demo.

## 9. Threat Model

SecVault feeds untrusted text to an agent that can write files, so it needs an explicit threat model.

| Threat | Mitigation |
|---|---|
| **Prompt injection through raw content** (scanner output, incident notes, clipped web pages containing instructions) | `agents.md` states raw content is data, not instructions; drafts go to `proposed/` for human review; agent permissions are limited to allowed paths; injection fixture tested in Phase 6. |
| **Secrets leaking into the repo** (scanner output, logs, diffs) | Redaction in capture, secret-like string lint, gitleaks in CI, private repo, `.gitignore`. |
| **Sensitive findings sent to hosted models** | Local-first default (Ollama); unfixed-vulnerability records excluded from hosted use unless the user opts in. |
| **Malicious or accidental edits to the schema layer** (for example a PR weakening `agents.md` or `tags.yaml`) | Schema files covered by CODEOWNERS and required review; CI fails if raw files are modified after capture. |
| **Agent writing outside the vault** | Path rules in `agents.md`, firewall wrapper for Obsidian actions, git diff review before commit. |
| **Tampered or corrupted raw evidence** | Content hashes in the manifest, verified in lint. |

Out of scope for v1: hard isolation against a determined malicious agent (sandboxed mounts, containers with restricted filesystems).

## 10. Success Criteria

- Every wiki note traces back to a raw source, and no raw file is ever modified (verified by manifest hashes).
- The lint and structure checks pass on the full vault and fail correctly on deliberately malformed fixture notes, covered by automated tests that run in CI.
- A new scanner finding in a PR reaches the raw layer automatically, with no secrets present in the output, and re-running the scan creates no duplicates.
- Querying the catalog for a previously logged vulnerability class returns the correct notes (including matches found only in body text), and the coding assistant can use them.
- The firewall refuses writes to a non-approved vault.
- No agent-drafted note reaches the authoritative wiki without explicit human approval.
- A raw source containing injected instructions does not change agent behavior or cause writes outside allowed paths.
- The system installs on a fresh machine from written instructions in under 15 minutes.

## 11. Future Extensions

- PDF ingestion (convert PDF reports to Markdown into `raw/files/` and `raw/sources/`, then run the normal ingest).
- Embedding-based retrieval or graph RAG layered on top of the catalog.
- MCP server exposing the query interface to any AI assistant.
- Heartbeat-style automation: a frequent check for new raw files that runs the full loop only when something changed.
- Sandboxed mounts or containers as a stronger firewall than the wrapper script.
- Separate-repo deployment (vault in its own private repo, written to by CI with a scoped deploy key).
- Team-shared, hosted deployment with Terraform-managed infrastructure.

## 12. Decisions and Open Questions

### Decided

- **Vault location:** monorepo for v1 (see 5.6). Revisit a separate repo as a future extension.
- **Tag vocabulary:** strict and versioned in `schema/tags.yaml`; unknown tags fail lint.
- **Finding lifecycle:** append-only `status_history`; "fixed" confirmed by a human.
- **Firewall:** wrapper plus documented limitations is sufficient for the demo.
- **Obsidian dependency:** optional viewer only; tooling and CI are filesystem-based.
- **Build agents:** Claude Sonnet 5.5 High plans and Claude Haiku 5.5 (max) implements
  in Cursor; the product remains agent-agnostic.

### Still open

- Which Ollama model gives acceptable drafts on the available hardware.
- Exact stable-ID scheme for findings when code moves between lines or files.
- Whether the maintain loop should auto-open a PR for scheduled changes or only report them.
