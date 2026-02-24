# 514 — Test Coverage Report

## Goal

Add `policyshield test --coverage` flag that shows which tools are covered by rules.

## Context

- Users want to know if all their tools have matching rules
- Coverage = tools referenced in rules vs. tools used in test cases
- Output: table of tools + coverage status (covered / uncovered / wildcard)

## Code

### Modify: `policyshield/cli/main.py`

Add `--coverage` flag to `test` subcommand.

### Modify: `policyshield/testing/runner.py`

Add `compute_coverage(ruleset, test_suites) -> CoverageReport`:

```python
@dataclass
class CoverageReport:
    covered_tools: set[str]        # Tools in both rules and tests
    uncovered_tools: set[str]      # Tools in rules but no test
    untested_rules: set[str]       # Rule IDs with no matching test
    wildcard_rules: int            # Rules matching any tool (*)
    coverage_pct: float

def compute_coverage(ruleset, test_suites):
    rule_tools = {r.when.tool for r in ruleset.rules if r.when.tool != "*"}
    tested_tools = {tc.tool_name for suite in test_suites for tc in suite.test_cases}
    covered = rule_tools & tested_tools
    uncovered = rule_tools - tested_tools
    ...
```

### Output format

```
📊 Rule Coverage Report

  Tools covered: 8/12 (66.7%)
  ✓ read_file      → rule: allow-reads
  ✓ write_file     → rule: approve-write
  ✗ exec_command   → rule: block-exec (NO TESTS)
  ✗ delete_file    → rule: block-delete (NO TESTS)
  ★ * (wildcard)   → 2 rules
```

## Tests

- Test 100% coverage scenario
- Test partial coverage with uncovered tools
- Test wildcard rules counted separately

## Self-check

```bash
policyshield test tests/ --coverage
```

## Commit

```
feat(cli): add --coverage flag to test command for rule coverage reporting
```
