---
type: source
title: "Checkov CKV_AWS_24: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "9602187eb851"
scanner: checkov
captured: 2026-11-03
processed: false
---

# Checkov CKV_AWS_24: Ensure no security groups allow ingress from 0.0.0.0:0 to port 22

Capture mode: normalized and redacted Checkov output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Checkov
- Rule: `CKV_AWS_24`
- Severity: not reported
- Location: `sample-app/main.tf` line 59
- Resource: `aws_security_group.open_demo`
- Revision: `18dfb07b42b9`

## Reference

https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-networking-policies/networking-1-port-security
