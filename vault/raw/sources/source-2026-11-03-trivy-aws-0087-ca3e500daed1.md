---
type: source
title: "Trivy AWS-0087: S3 Access block should block public policy"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources: []
finding_id: "ca3e500daed1"
scanner: trivy
captured: 2026-11-03
processed: false
---

# Trivy AWS-0087: S3 Access block should block public policy

Capture mode: normalized and redacted Trivy output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Trivy
- Rule: `AWS-0087`
- Severity: HIGH
- Location: `sample-app/main.tf` line 26
- Resource: `aws_s3_bucket_public_access_block.public_demo`
- Revision: `18dfb07b42b9`

## Description

Public access block does not block public policies

## Recommended action

Prevent policies that allow public access being PUT

## Reference

https://avd.aquasec.com/misconfig/aws-0087
