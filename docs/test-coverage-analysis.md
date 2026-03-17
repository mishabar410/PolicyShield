# Test Coverage Analysis & Improvement Proposals

## Overview

PolicyShield currently enforces an **85% coverage threshold** in CI across ~17,600 lines of source code,
tested by 125+ Python test files and 8 TypeScript test files. While overall coverage is strong, this
analysis identifies targeted gaps where additional tests would meaningfully reduce risk.

---

## 1. `retry_with_backoff` (approval/retry.py) — No Direct Tests

**Severity: High**

The `retry_with_backoff` async utility is used by all approval backends (Telegram, Slack, webhook)
for resilience, but has no dedicated test file. There are no direct tests for:

- Exponential backoff calculation (`base_delay * 2^attempt`)
- `max_delay` cap enforcement
- Non-retryable exceptions propagating immediately
- Correct exception raised after all retries exhausted
- `max_retries=0` edge case (execute once, no retry)

**Proposed tests:**
```python
# tests/test_approval_retry.py
async def test_exponential_backoff_delays()
async def test_max_delay_cap()
async def test_non_retryable_exception_raises_immediately()
async def test_exhausted_retries_raises_last_error()
async def test_max_retries_zero()
async def test_retryable_exception_list()
```

---

## 2. `SlackApprovalBackend` (approval/slack.py) — HTTP Error Paths Untested

**Severity: High**

`wait_for_response` (the async polling loop) and `_send_slack_notification` (the actual HTTP POST)
have no test coverage for their failure paths:

- `wait_for_response`: no timeout behavior test, no test that loop exits cleanly
- `_send_slack_notification`: httpx exceptions (timeouts, connection errors, non-2xx responses) not tested
- `health()` with a `None` or invalid `webhook_url`
- `stop()` method not tested at all
- Truncation of long argument strings (>500 chars) in the notification body

**Proposed tests:**
```python
# tests/test_slack_approval.py
async def test_wait_for_response_times_out()
async def test_wait_for_response_exits_on_response()
async def test_send_notification_http_timeout()
async def test_send_notification_connection_error()
async def test_send_notification_non_2xx_response()
def test_health_with_none_webhook_url()
def test_health_with_invalid_url()
def test_stop_cleans_up()
def test_long_args_are_truncated()
```

---

## 3. MCP Server Admin Tools (mcp_server.py) — Auth/Token Validation Gaps

**Severity: High**

The MCP server exposes `kill_switch`, `resume`, and `reload` tools that require an `admin_token`.
The token validation logic is covered superficially — the following paths are not tested:

- `kill_switch` with empty string token when token is required
- `kill_switch` / `resume` / `reload` with mismatched token (wrong value, not just missing)
- `constraints` tool with a large policy summary (truncation behavior)
- Missing required field `tool_name` in `check` arguments (KeyError path)
- Malformed / non-JSON arguments passed to any tool handler
- PII matches serialization when `pii_matches` list is non-empty
- `modified_args` serialization in `check` response when args are rewritten

**Proposed tests:**
```python
# tests/test_mcp_coverage.py (extend existing)
def test_kill_switch_empty_token_rejected()
def test_kill_switch_wrong_token_rejected()
def test_resume_wrong_token_rejected()
def test_reload_wrong_token_rejected()
def test_check_missing_tool_name_field()
def test_check_pii_matches_serialized()
def test_check_modified_args_serialized()
def test_constraints_with_large_summary()
```

---

## 4. `LLMGuard` (shield/llm_guard.py) — HTTP Error Paths & Cache Concurrency

**Severity: Medium**

`_call_llm` is always mocked in tests. Real failure paths are not exercised:

- Non-2xx status codes from the LLM API
- Network timeout / connection error
- Malformed response JSON (no `choices` key)
- API key lookup: `api_key=None` with no environment variable set
- `fail_closed=True` vs `fail_closed=False` behaviour for each distinct error type
- Cache thread-safety under concurrent `analyze()` calls
- Cache eviction when `max_cache_size` is reached (LRU eviction correctness)
- Explanation field truncation (>200 chars stripped)
- Markdown fence stripping from LLM response (```` ```json ... ``` ````)

**Proposed tests:**
```python
# tests/test_llm_guard.py (extend existing)
async def test_call_llm_non_2xx_fail_closed()
async def test_call_llm_non_2xx_fail_open()
async def test_call_llm_timeout_fail_closed()
async def test_call_llm_malformed_json()
async def test_call_llm_no_choices_key()
def test_no_api_key_raises()
def test_cache_eviction_at_max_size()
def test_cache_concurrent_writes_thread_safe()
def test_explanation_truncated_over_200_chars()
def test_markdown_fence_stripped()
```

---

## 5. `sanitize_args` (approval/sanitizer.py) — Secret Pattern Coverage

**Severity: Medium**

Several secret patterns are declared in the regex list but have no dedicated test assertions:

| Pattern | Status |
|---------|--------|
| `AKIA…` / `ASIA…` AWS keys | Not explicitly tested |
| `ghp_` / `github_pat_` GitHub PAT | Not explicitly tested |
| `sk-proj-` / `sk-ant-` API keys | Partially tested |
| Generic 40-char base64 token | Boundary (exactly 40 chars) not tested |

Also missing:
- Deep nesting (3+ levels) sanitization
- Mixed-type structures (tuples, sets)
- `MAX_VALUE_LENGTH` boundary: 199, 200, 201 character strings

**Proposed tests:**
```python
# tests/test_sanitizer.py (extend existing)
def test_aws_access_key_redacted()
def test_aws_session_token_redacted()
def test_github_pat_ghp_redacted()
def test_github_pat_long_format_redacted()
def test_generic_token_exactly_40_chars_redacted()
def test_generic_token_39_chars_not_redacted()
def test_deeply_nested_dict_sanitized()
def test_max_value_length_boundary()
```

---

## 6. `ContextEvaluator` (shield/context.py) — Malformed Input Handling

**Severity: Medium**

The `evaluate()` method is exercised for happy-path cases, but invalid/malformed inputs are not:

- `time_of_day` with invalid format (e.g. `"25:00-26:00"`, `"not-a-time"`)
- `day_of_week` with invalid day names or mixed case (`"MON-FRI"` vs `"mon-fri"`)
- Invalid timezone in `__init__` (should raise `ValueError`)
- `evaluate()` with an empty `conditions` dict (should pass with no restrictions)
- Boolean and float values in `_check_value` comparisons
- `evaluate()` with `None` context passed

**Proposed tests:**
```python
# tests/test_context_evaluator.py (extend existing)
def test_invalid_time_format_raises()
def test_invalid_day_name_raises()
def test_invalid_timezone_raises_on_init()
def test_empty_conditions_always_passes()
def test_boolean_value_comparison()
def test_none_context_handled()
```

---

## 7. Reporting Modules (reporting/compliance.py, reporting/incident.py) — Robustness

**Severity: Medium**

Both reporting modules parse raw trace files. Malformed or unusual input is not tested:

**Compliance report:**
- Trace file with partial/corrupted JSON lines
- Missing fields in trace entries (e.g. no `verdict`, no `tool`)
- HTML output escaping — special characters (`<`, `>`, `&`) in tool names or session IDs
- `top_blocked_tools` correctly limited to 10 entries
- Trace files spanning multiple months

**Incident timeline:**
- Unsorted trace files (events should sort by timestamp)
- Missing `timestamp` field (falls back to `"unknown"`)
- Events with no `rule_id` or `message` field
- `render_timeline_text` icon logic (`!!` vs `OK`)

**Proposed tests:**
```python
# tests/test_compliance_report.py (extend existing)
def test_malformed_json_line_skipped()
def test_missing_verdict_field_handled()
def test_html_escaping_tool_name_with_special_chars()
def test_top_blocked_tools_capped_at_ten()

# tests/test_incident_timeline.py (extend existing)
def test_events_sorted_by_timestamp()
def test_missing_timestamp_uses_unknown()
def test_event_without_rule_id()
def test_render_icon_violation_vs_ok()
```

---

## 8. `CLIBackend` (approval/cli_backend.py) — Input Edge Cases

**Severity: Low**

User-facing `wait_for_response` reads stdin, but non-standard input variants are not tested:

- Input with surrounding whitespace: `"  y  "` should be accepted as approval
- Case-insensitive matching: `"Y"`, `"YES"`, `"Yes"` all treated as approve
- `KeyboardInterrupt` during prompt → graceful deny
- `pending()` return type and ordering guarantee

---

## 9. `CanaryRouter` (shield/canary.py) — Thread Safety & Edge Cases

**Severity: Low**

- No thread-safety tests for concurrent `should_apply_canary` calls
- `canary_percent` boundary values (`0.0`, `1.0`, `< 0`, `> 1`) not all asserted
- `promote_after=0` (immediate promotion) not tested
- `reset()` called on a rule that was never seen (should be a no-op)

---

## 10. MCP Proxy Tool Listing (mcp_proxy.py) — Regex Pattern Filtering

**Severity: Low**

The `handle_list_tools` path that filters regex-pattern rules from tool descriptions
has minimal coverage:
- Tools matching regex patterns should be omitted from listed tools
- Tools matching wildcard `*` rules
- `handle_list_tools` with no rules defined

---

## Priority Matrix

| Area | Severity | Effort | Recommended Action |
|------|----------|--------|--------------------|
| `retry_with_backoff` | High | Low | Create `tests/test_approval_retry.py` |
| Slack HTTP error paths | High | Medium | Extend `tests/test_tier2.py` or create dedicated file |
| MCP admin token validation | High | Low | Extend `tests/test_mcp_coverage.py` |
| `LLMGuard` HTTP errors | Medium | Medium | Extend `tests/test_llm_guard.py` |
| `sanitize_args` secret patterns | Medium | Low | Extend `tests/test_sanitizer.py` |
| `ContextEvaluator` bad input | Medium | Low | Extend `tests/test_context_evaluator.py` |
| Reporting robustness | Medium | Medium | Extend existing reporting tests |
| `CLIBackend` input edge cases | Low | Low | Extend `tests/test_approval.py` |
| `CanaryRouter` thread safety | Low | Medium | Extend `tests/test_canary.py` |
| MCP proxy tool listing | Low | Low | Extend `tests/test_mcp_coverage.py` |
