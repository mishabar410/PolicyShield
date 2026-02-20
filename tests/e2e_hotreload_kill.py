#!/usr/bin/env python3
"""Test hot reload and kill switch via direct API."""
import json
import urllib.request

BASE = "http://localhost:8100/api/v1"

def api(method, path, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())

def check(tool, args, session="test"):
    return api("POST", "/check", {"tool_name": tool, "args": args, "session_id": session})

print("=== HOT RELOAD TEST ===")

# Before reload: secret.txt should be BLOCKED (rule was appended to file)
r = check("read", {"path": "secret.txt"}, "hr1")
print(f"Before reload: secret.txt verdict = {r['verdict']}")

# Reload rules
reload = api("POST", "/reload")
print(f"Reload: status={reload['status']} rules_count={reload['rules_count']} hash={reload['rules_hash']}")

# After reload: secret.txt should now be BLOCKED by new rule
r = check("read", {"path": "secret.txt"}, "hr2")
print(f"After reload: secret.txt verdict = {r['verdict']} rule = {r.get('rule_id')}")
assert r["verdict"] == "BLOCK" and r.get("rule_id") == "block-secret-txt", f"Hot reload failed: {r}"
print("✅ Hot reload verified — new rule active after reload!\n")

print("=== KILL SWITCH TEST ===")

# Activate kill switch
kill = api("POST", "/kill")
print(f"Kill: {kill}")

# Any call should be blocked
r = check("read", {"path": "hello.txt"}, "ks1")
print(f"During kill: hello.txt verdict = {r['verdict']}")
assert r["verdict"] == "BLOCK", f"Kill switch failed: {r}"

# Resume
resume = api("POST", "/resume")
print(f"Resume: {resume}")

# Normal operation
r = check("read", {"path": "hello.txt"}, "ks2")
print(f"After resume: hello.txt verdict = {r['verdict']}")
assert r["verdict"] == "ALLOW", f"Resume failed: {r}"
print("✅ Kill switch verified — block all + resume works!")
