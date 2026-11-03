---
type: source
title: "Checkov CKV2_AWS_5: Ensure that Security Groups are attached to another resource"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "3c33ee6d29da"
scanner: checkov
captured: 2026-11-03
processed: false
---

# Checkov CKV2_AWS_5: Ensure that Security Groups are attached to another resource

Capture mode: normalized and redacted Checkov output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Checkov
- Rule: `CKV2_AWS_5`
- Severity: not reported
- Location: `sample-app/main.tf` line 59
- Resource: `aws_security_group.open_demo`
- Revision: `18dfb07b42b9`

## Reference

https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-networking-policies/ensure-that-security-groups-are-attached-to-ec2-instances-or-elastic-network-interfaces-enis
