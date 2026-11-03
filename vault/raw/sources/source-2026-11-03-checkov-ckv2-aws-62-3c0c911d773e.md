---
type: source
title: "Checkov CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "3c0c911d773e"
scanner: checkov
captured: 2026-11-03
processed: false
---

# Checkov CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled

Capture mode: normalized and redacted Checkov output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Checkov
- Rule: `CKV2_AWS_62`
- Severity: not reported
- Location: `sample-app/main.tf` line 18
- Resource: `aws_s3_bucket.public_demo`
- Revision: `18dfb07b42b9`

## Reference

https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-logging-policies/bc-aws-2-62
