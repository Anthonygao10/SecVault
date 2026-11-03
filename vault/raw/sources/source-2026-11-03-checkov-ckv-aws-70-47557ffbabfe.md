---
type: source
title: "Checkov CKV_AWS_70: Ensure S3 bucket does not allow an action with any Principal"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "47557ffbabfe"
scanner: checkov
captured: 2026-11-03
processed: false
---

# Checkov CKV_AWS_70: Ensure S3 bucket does not allow an action with any Principal

Capture mode: normalized and redacted Checkov output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Checkov
- Rule: `CKV_AWS_70`
- Severity: not reported
- Location: `sample-app/main.tf` line 31
- Resource: `aws_s3_bucket_policy.public_demo`
- Revision: `18dfb07b42b9`

## Reference

https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/bc-aws-s3-23
