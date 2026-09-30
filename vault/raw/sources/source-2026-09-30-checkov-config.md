---
type: source
title: "Checkov Terraform scan: sample app"
tags:
  - source
  - infrastructure-as-code
  - least-privilege
created: 2026-09-30
updated: 2026-09-30
sources: []
finding_id: "checkov:sample-app:terraform"
scanner: checkov
captured: 2026-09-30
processed: false
---

# Checkov Terraform scan: sample app

Capture mode: normalized scanner output from Checkov 3.3.20. The report
contained no credential values.

## Failed checks

- `checkov:CKV_AWS_53:sample-app/main.tf:22-29` — S3 public ACL block is disabled.
- `checkov:CKV_AWS_54:sample-app/main.tf:22-29` — S3 public policy block is disabled.
- `checkov:CKV_AWS_55:sample-app/main.tf:22-29` — S3 public ACLs are not ignored.
- `checkov:CKV_AWS_56:sample-app/main.tf:22-29` — public buckets are not restricted.
- `checkov:CKV_AWS_70:sample-app/main.tf:31-44` — bucket policy allows any principal.
- `checkov:CKV_AWS_62:sample-app/main.tf:46-57` — IAM policy grants full administrative actions.
- `checkov:CKV_AWS_287:sample-app/main.tf:46-57` — IAM policy may expose credentials.
- `checkov:CKV_AWS_288:sample-app/main.tf:46-57` — IAM policy permits data exfiltration.
- `checkov:CKV_AWS_289:sample-app/main.tf:46-57` — IAM policy permits unconstrained exposure.
- `checkov:CKV_AWS_286:sample-app/main.tf:46-57` — IAM policy permits privilege escalation.
- `checkov:CKV_AWS_63:sample-app/main.tf:46-57` — IAM policy allows wildcard actions.
- `checkov:CKV_AWS_355:sample-app/main.tf:46-57` — IAM policy allows wildcard resources.
- `checkov:CKV_AWS_290:sample-app/main.tf:46-57` — IAM policy grants unconstrained write access.
- `checkov:CKV_AWS_23:sample-app/main.tf:59-69` — security-group rule lacks a description.
- `checkov:CKV_AWS_24:sample-app/main.tf:59-69` — unrestricted SSH ingress.
- `checkov:CKV_AWS_25:sample-app/main.tf:59-69` — unrestricted RDP ingress.
- `checkov:CKV_AWS_260:sample-app/main.tf:59-69` — unrestricted HTTP ingress.
- `checkov:CKV2_AWS_62:sample-app/main.tf:18-20` — S3 notifications are missing.
- `checkov:CKV_AWS_144:sample-app/main.tf:18-20` — S3 replication is missing.
- `checkov:CKV2_AWS_61:sample-app/main.tf:18-20` — S3 lifecycle configuration is missing.
- `checkov:CKV_AWS_18:sample-app/main.tf:18-20` — S3 access logging is missing.
- `checkov:CKV2_AWS_5:sample-app/main.tf:59-69` — security group is unattached.
- `checkov:CKV_AWS_21:sample-app/main.tf:18-20` — S3 versioning is missing.
- `checkov:CKV2_AWS_6:sample-app/main.tf:18-20` — S3 public-access block is missing.
- `checkov:CKV_AWS_145:sample-app/main.tf:18-20` — S3 KMS encryption is missing.
- `checkov:CKV2_AWS_40:sample-app/main.tf:46-57` — IAM policy grants full IAM privileges.
