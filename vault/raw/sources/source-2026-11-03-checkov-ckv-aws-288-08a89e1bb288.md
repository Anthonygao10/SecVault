---
type: source
title: "Checkov CKV_AWS_288: Ensure IAM policies does not allow data exfiltration"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "08a89e1bb288"
scanner: checkov
captured: 2026-11-03
processed: false
---

# Checkov CKV_AWS_288: Ensure IAM policies does not allow data exfiltration

Capture mode: normalized and redacted Checkov output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Checkov
- Rule: `CKV_AWS_288`
- Severity: not reported
- Location: `sample-app/main.tf` line 46
- Resource: `aws_iam_policy.overly_permissive_demo`
- Revision: `18dfb07b42b9`

## Reference

https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-iam-policies/bc-aws-288
