"""Standalone check — simplest usage."""

from policyshield.shield.engine import ShieldEngine

engine = ShieldEngine(rules="policies/rules.yaml")
result = engine.check("send_email", {"to": "user@example.com", "body": "Hello"})
print(f"Verdict: {result.verdict.value}")
print(f"Message: {result.message}")
