# Intentionally Insecure Sample App

This directory is a scanner fixture for SecVault. It is deliberately
vulnerable and must never be deployed or connected to real cloud resources.
Every credential-looking value is a publicly documented fake example.

The fixture contains:

- `app.py`: SQL injection, reflected output, weak input validation, and fake
  hardcoded cloud credentials.
- `main.tf`: a public S3 bucket, an overly permissive IAM policy, and an
  unrestricted security-group ingress rule.

The app is not part of SecVault's production tooling. Its purpose is to make
Trivy, Checkov, and gitleaks produce realistic findings for the Phase 4 demo.

## Local scan commands

Run these from the repository root. The local binaries are deliberately
ignored by Git under `.tools/`.

```powershell
& .tools\trivy\trivy.exe config --format json --output .tools\trivy-config.json sample-app
& .venv\Scripts\python.exe -m checkov.main -d sample-app --framework terraform --output json | Out-File -Encoding utf8 .tools\checkov.json
& .tools\gitleaks\gitleaks.exe dir sample-app --report-format json `
  --report-path .tools\gitleaks.json --no-banner
```

Findings are expected: Trivy reports nine Terraform misconfigurations,
Checkov reports failing Terraform checks, and gitleaks reports the deliberately
fake API key. A non-zero scanner exit code means findings were detected; it is
not a failed SecVault build.

This paragraph is a no-op edit that exercises the pull request capture preview.
