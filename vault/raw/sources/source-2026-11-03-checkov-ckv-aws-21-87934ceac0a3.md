---
type: source
title: "Checkov CKV_AWS_21: Ensure all data stored in the S3 bucket have versioning enabled"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "87934ceac0a3"
scanner: checkov
captured: 2026-11-03
processed: false
---

# Checkov CKV_AWS_21: Ensure all data stored in the S3 bucket have versioning enabled

Capture mode: normalized and redacted Checkov output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Checkov
- Rule: `CKV_AWS_21`
- Severity: not reported
- Location: `sample-app/main.tf` line 18
- Resource: `aws_s3_bucket.public_demo`
- Revision: `18dfb07b42b9`

## Reference

https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/s3-policies/s3-16-enable-versioning
