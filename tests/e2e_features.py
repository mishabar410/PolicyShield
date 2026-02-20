#!/usr/bin/env python3
"""Comprehensive PolicyShield feature test — all 8 features via direct API."""

import json
import urllib.request
import urllib.error
import time
import sys

BASE = "http://localhost:8100/api/v1"
PASS = "✅"
FAIL = "❌"
results = []


def api(method, path, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read().decode()[:200]}
    except Exception as e:
        return {"error": str(e)}


def check(tool_name, args, session_id="default"):
    return api("POST", "/check", {"tool_name": tool_name, "args": args, "session_id": session_id})


def test(name, passed, details=""):
    status = PASS if passed else FAIL
    results.append((name, passed))
    print(f"  {status} {name}")
    if details:
        print(f"     → {details}")


print("=" * 60)
print("  PolicyShield Comprehensive Feature Test")
print("=" * 60)

# ── Feature 1: BLOCK ──────────────────────────────────────
print("\n🔒 Feature 1: BLOCK (arbitrary rule enforcement)")
r = check("read", {"path": "notes.txt"}, "s1")
test(
    "1a. Block read notes.txt",
    r.get("verdict") == "BLOCK" and r.get("rule_id") == "block-read-notes",
    f"verdict={r.get('verdict')} rule={r.get('rule_id')}",
)

r = check("read", {"path": "hello.txt"}, "s1")
test("1b. Allow read hello.txt", r.get("verdict") == "ALLOW", f"verdict={r.get('verdict')}")

# ── Feature 2: REDACT ─────────────────────────────────────
print("\n🔏 Feature 2: REDACT (PII masking)")
r = check("write", {"path": "data.txt", "content": "Email: john@company.com, SSN: 123-45-6789"}, "s2")
has_pii = len(r.get("pii_types", [])) > 0
has_modified = r.get("modified_args") is not None
test(
    "2a. Detect PII in write args",
    r.get("verdict") == "REDACT" and (has_pii or has_modified),
    f"verdict={r.get('verdict')} pii_types={r.get('pii_types')} modified={has_modified}",
)
if has_modified:
    masked = r["modified_args"].get("content", "")
    test(
        "2b. PII actually masked in modified_args",
        "***" in masked or "[REDACTED]" in masked or "john@company.com" not in masked,
        f"masked_content={masked[:80]}...",
    )

r = check("write", {"path": "safe.txt", "content": "Hello world, no PII here"}, "s2")
test(
    "2c. No PII detected in clean write",
    r.get("verdict") in ("ALLOW", "REDACT") and len(r.get("pii_types", [])) == 0,
    f"verdict={r.get('verdict')} pii_types={r.get('pii_types')}",
)

# ── Feature 3: APPROVE ────────────────────────────────────
print("\n👤 Feature 3: APPROVE (human-in-the-loop)")
r = check("write", {"path": "config/.env", "content": "API_KEY=secret"}, "s3")
has_approval = r.get("approval_id") is not None
test(
    "3a. Write .env triggers APPROVE",
    r.get("verdict") == "APPROVE" and has_approval,
    f"verdict={r.get('verdict')} approval_id={r.get('approval_id')}",
)

if has_approval:
    aid = r["approval_id"]
    # 3b: Check pending approvals
    pending = api("GET", "/pending-approvals")
    found = any(a.get("approval_id") == aid for a in pending.get("approvals", []))
    test("3b. Approval listed in pending", found, f"pending_count={len(pending.get('approvals', []))}")

    # 3c: Deny approval
    deny = api("POST", "/respond-approval", {"approval_id": aid, "approved": False, "responder": "test"})
    test("3c. Deny approval", deny.get("status") == "ok" or deny.get("approval_id") == aid, f"response={deny}")

    # 3d: New request + approve
    r2 = check("write", {"path": "config/.env", "content": "API_KEY=secret"}, "s3b")
    if r2.get("approval_id"):
        aid2 = r2["approval_id"]
        approve = api("POST", "/respond-approval", {"approval_id": aid2, "approved": True, "responder": "test"})
        test(
            "3d. Approve new request",
            approve.get("status") == "ok" or approve.get("approval_id") == aid2,
            f"response={approve}",
        )

r2 = check("write", {"path": "readme.txt", "content": "normal file"}, "s3")
test(
    "3e. Write non-.env has no approval_id",
    r2.get("approval_id") is None,
    f"verdict={r2.get('verdict')} approval_id={r2.get('approval_id')}",
)

# ── Feature 4: RATE LIMITING ──────────────────────────────
print("\n⏱️  Feature 4: RATE LIMITING (session-based)")
# Note: session state is built BEFORE increment, so:
# After call #1, tool_count.read=0 at eval (incremented to 1 after)
# After call #4, tool_count.read=3 at eval (not > 3 yet!)
# After call #5, tool_count.read=4 at eval (> 3 → BLOCK!)
session = f"rate-{int(time.time())}"
for i in range(4):
    r = check("read", {"path": f"file{i}.txt"}, session)
test(
    "4a. First 4 reads allowed (count not yet > 3 at eval time)",
    r.get("verdict") == "ALLOW",
    f"verdict after 4 reads={r.get('verdict')}",
)

r = check("read", {"path": "file5.txt"}, session)
test(
    "4b. 5th read blocked (count=4 > 3 at eval time)",
    r.get("verdict") == "BLOCK",
    f"verdict={r.get('verdict')} msg={r.get('message', '')[:60]}",
)

# ── Feature 5: KILL SWITCH ────────────────────────────────
print("\n🚨 Feature 5: KILL SWITCH")
kill_r = api("POST", "/kill")
test(
    "5a. Kill switch activated", kill_r.get("status") == "killed" or "kill" in str(kill_r).lower(), f"response={kill_r}"
)

r = check("read", {"path": "hello.txt"}, "s5")
test(
    "5b. All calls blocked after kill",
    r.get("verdict") == "BLOCK",
    f"verdict={r.get('verdict')} msg={r.get('message', '')[:60]}",
)

resume_r = api("POST", "/resume")
test(
    "5c. Resume from kill switch",
    resume_r.get("status") == "resumed" or "resum" in str(resume_r).lower(),
    f"response={resume_r}",
)

r = check("read", {"path": "hello.txt"}, "s5b")
test("5d. Normal operation after resume", r.get("verdict") == "ALLOW", f"verdict={r.get('verdict')}")

# ── Feature 6: HOT RELOAD ────────────────────────────────
print("\n🔄 Feature 6: HOT RELOAD")
health_before = api("GET", "/health")
hash_before = health_before.get("rules_hash")
rules_before = health_before.get("rules_count")

reload_r = api("POST", "/reload")
test(
    "6a. Hot reload endpoint works",
    reload_r.get("status") == "ok" and reload_r.get("rules_count", 0) > 0,
    f"response={reload_r}",
)

health_after = api("GET", "/health")
test(
    "6b. Rules reloaded successfully",
    health_after.get("rules_count", 0) > 0,
    f"rules_count={health_after.get('rules_count')} hash={health_after.get('rules_hash')}",
)

# ── Feature 7: PII POST-CHECK ────────────────────────────
print("\n🔍 Feature 7: PII POST-CHECK (output scanning)")
post_r = api(
    "POST",
    "/post-check",
    {
        "tool_name": "read",
        "args": {"path": "contacts.txt"},
        "result": "Name: John Smith, Email: john@acme.com, SSN: 123-45-6789, Phone: 555-123-4567",
        "session_id": "s7",
    },
)
pii_found = len(post_r.get("pii_types", [])) > 0
test("7a. PII detected in tool output", pii_found, f"pii_types={post_r.get('pii_types')}")

post_r2 = api(
    "POST",
    "/post-check",
    {
        "tool_name": "read",
        "args": {"path": "readme.txt"},
        "result": "This is a normal readme file with no sensitive data.",
        "session_id": "s7",
    },
)
test("7b. No PII in clean output", len(post_r2.get("pii_types", [])) == 0, f"pii_types={post_r2.get('pii_types')}")

# ── Feature 8: CONSTRAINTS INJECTION ─────────────────────
print("\n📋 Feature 8: CONSTRAINTS INJECTION")
constraints_r = api("GET", "/constraints")
summary = constraints_r.get("summary", "")
test("8a. Constraints endpoint returns rules", len(summary) > 50 and "BLOCK" in summary, f"summary_len={len(summary)}")
test(
    "8b. All rule types present in constraints",
    "BLOCK" in summary and "REDACT" in summary and "APPROVE" in summary,
    f"has_BLOCK={'BLOCK' in summary} has_REDACT={'REDACT' in summary} has_APPROVE={'APPROVE' in summary}",
)

# ── SUMMARY ───────────────────────────────────────────────
print("\n" + "=" * 60)
passed = sum(1 for _, p in results if p)
total = len(results)
print(f"  Results: {passed}/{total} passed")
if passed == total:
    print("  🎉 ALL FEATURES VERIFIED!")
else:
    failed = [name for name, p in results if not p]
    print(f"  Failed: {', '.join(failed)}")
print("=" * 60)
sys.exit(0 if passed == total else 1)
