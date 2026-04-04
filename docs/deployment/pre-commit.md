# Pre-commit Hook

Scan staged git changes for sensitive data before committing.

## Setup with pre-commit framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: dlpscan
        name: dlpscan
        entry: python -m dlpscan.hooks
        language: python
        stages: [commit]
```

## Manual Setup

```bash
cp dlpscan/hooks.py .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Options

```bash
python -m dlpscan.hooks \
  --min-confidence 0.5 \
  --require-context \
  --categories "Credit Card Numbers" "Generic Secrets" \
  --allowlist allowlist.json \
  --format json \
  --baseline baseline.json
```

## `.dlpscanignore`

Create a `.dlpscanignore` file in the repo root to skip files:

```
# Skip test fixtures
tests/fixtures/*
*.test.js
vendor/*
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings |
| 1 | Findings detected |
| 2 | Error (bad config, etc.) |
