---
type: vulnerability
title: "Public S3 bucket and unrestricted ingress"
tags:
  - vulnerability
  - owasp-a05-security-misconfiguration
  - least-privilege
  - infrastructure-as-code
created: 2026-09-30
updated: 2026-09-30
sources:
  - "[[raw/sources/source-2026-09-30-trivy-config]]"
  - "[[raw/sources/source-2026-09-30-checkov-config]]"
severity: high
cwe: "CWE-284"
owasp: "A05:2021-Security-Misconfiguration"
component: "sample-app/main.tf"
status: open
status_history:
  - status: open
    date: 2026-09-30
    ref: "trivy:AWS-0086:sample-app/main.tf:25"
    note: "First recorded from Trivy and Checkov configuration scans."
finding_id: "trivy:AWS-0086:sample-app/main.tf:25"
fix_commit: null
---

# Public S3 bucket and unrestricted ingress

The Terraform fixture disables S3 public-access protections, grants public
object reads, and permits broad inbound network access. Together these
settings expose data and expand the reachable attack surface.

## Remediation

Enable every S3 public-access block, remove wildcard principals, restrict
security-group ingress to required CIDRs and ports, and enforce these controls
with infrastructure-as-code checks.
