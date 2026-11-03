---
type: source
title: "Checkov CKV_AWS_18: Ensure the S3 bucket has access logging enabled"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "34fb4dffba3f"
scanner: checkov
captured: 2026-11-03
processed: false
---

# Checkov CKV_AWS_18: Ensure the S3 bucket has access logging enabled

Capture mode: normalized and redacted Checkov output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Checkov
- Rule: `CKV_AWS_18`
- Severity: not reported
- Location: `sample-app/main.tf` line 18
- Resource: `aws_s3_bucket.public_demo`
- Revision: `18dfb07b42b9`

## Reference

https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-13-enable-logging
