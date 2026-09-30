# Project Brief: SecVault

_Source of truth: `SecVault_PRD.md` (Draft v0.3, last updated 2026-09-30). If this file and the PRD disagree, the PRD wins; update this file._

## What it is
SecVault is a git-versioned Obsidian vault that acts as a persistent security and bug memory layer for AI coding agents. Raw findings (scanner output, CI failures, incident notes) are captured unmodified, compiled by an agent into a linked wiki (vulnerability records, postmortems, concepts, entities), and governed by a schema that both humans and agents must follow. The schema is enforced by code, not just by prompts.

## Why it exists
- AI coding assistants have no memory of a project's security history.
- Scan output is read once in a PR check and then lost.
- Agent-maintained wikis drift without enforced structure.
- There is no lightweight, portable, git-native "institutional memory" for security.

## Nature of the project
Personal / portfolio project for DevOps and cybersecurity internship applications. It is a demo, not a product. Inspired by the "LLM Wiki in Obsidian" tutorial (raw / wiki / schema layers), extended with DevOps practices: CI capture, lint as a merge gate, scheduled maintenance, pytest suite, threat model, Docker packaging.

## Core goals
1. Working, demoable vault: raw findings -> structured, cross-linked wiki with full source traceability.
2. Schema is the contract, enforced by deterministic Python (`wiki_tool`). The LLM only extracts and drafts.
3. CI automates raw capture and validation.
4. Human in the loop: agent output is reviewed before it becomes authoritative.
5. All raw content is untrusted input (prompt-injection aware).
6. Local/private mode (Ollama); agent-agnostic.
7. Installable on a fresh machine in under 15 minutes.

## Non-goals (v1)
- Not a general second brain (scope is security/bugs only).
- Not a replacement for Snyk/Dependabot; it ingests their output.
- No vector-DB RAG (catalog/index-first retrieval).
- No autonomous remediation.
- No hosted / multi-tenant / team-shared service.
- No PDF ingestion (`raw/files/` is reserved for later).

## Success criteria (summary)
- Every wiki note traces to a raw source; raw files never modified (manifest hashes).
- Lint passes on the real vault and fails correctly on bad fixtures, tested in CI.
- New scanner finding reaches the raw layer automatically, redacted, with no duplicates on re-run.
- Query finds prior vulnerability classes, including body-text-only matches.
- Firewall refuses writes to non-approved vaults.
- No agent draft reaches the wiki without human approval.
- Injected instructions in raw sources do not change agent behavior.
- Fresh-machine install in under 15 minutes.
