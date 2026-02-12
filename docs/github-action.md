# GitHub Action — PolicyShield Lint Rules

A reusable GitHub Action that validates, lints, and tests your PolicyShield rules on every PR.

## Quick start

```yaml
# .github/workflows/policy-check.yml
name: Policy Check

on:
  pull_request:
    paths:
      - 'policies/**'

jobs:
  lint-rules:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mishabar410/PolicyShield/.github/actions/lint-rules@main
        with:
          rules-path: policies/
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `rules-path` | `policies/` | Path to rules YAML file or directory |
| `test-path` | *(empty)* | Path to test YAML file (skipped if empty) |
| `python-version` | `3.12` | Python version to use |
| `policyshield-version` | `latest` | Specific version to install |

## With rule tests

```yaml
- uses: mishabar410/PolicyShield/.github/actions/lint-rules@main
  with:
    rules-path: policies/rules.yaml
    test-path: tests/test_rules.yaml
```

## Pinned version

```yaml
- uses: mishabar410/PolicyShield/.github/actions/lint-rules@main
  with:
    policyshield-version: '0.5.0'
```
