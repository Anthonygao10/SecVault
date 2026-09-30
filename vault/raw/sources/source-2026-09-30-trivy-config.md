---
type: source
title: "Trivy configuration scan: sample app"
tags:
  - source
  - infrastructure-as-code
created: 2026-09-30
updated: 2026-09-30
sources: []
finding_id: "trivy:sample-app:config"
scanner: trivy
captured: 2026-09-30
processed: false
---

# Trivy configuration scan: sample app

Capture mode: normalized scanner output. The source was captured from
`sample-app/main.tf`; no cloud resources were contacted.

## Findings

- `trivy:AWS-0086:sample-app/main.tf:25` — HIGH — S3 public ACL access block is disabled.
- `trivy:AWS-0087:sample-app/main.tf:26` — HIGH — S3 public policy access block is disabled.
- `trivy:AWS-0089:sample-app/main.tf:18` — LOW — S3 bucket logging is missing.
- `trivy:AWS-0090:sample-app/main.tf:18` — MEDIUM — S3 bucket versioning is missing.
- `trivy:AWS-0091:sample-app/main.tf:27` — HIGH — S3 public ACLs are not ignored.
- `trivy:AWS-0093:sample-app/main.tf:28` — HIGH — public bucket access is not restricted.
- `trivy:AWS-0107:sample-app/main.tf:67` — HIGH — security-group ingress is unrestricted.
- `trivy:AWS-0124:sample-app/main.tf:63` — LOW — security-group rule description is missing.
- `trivy:AWS-0132:sample-app/main.tf:18` — HIGH — S3 encryption does not use a customer-managed key.
