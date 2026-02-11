"""Example: nanobot with PolicyShield enforcement.

Shows how to pass shield_config to AgentLoop so that every
tool call is pre-checked against your policy rules.
"""

# In your nanobot config or startup code, pass shield_config:
#
#   loop = AgentLoop(
#       bus=bus,
#       provider=provider,
#       workspace=Path("."),
#       shield_config={
#           "rules_path": "policies/rules.yaml",
#           "mode": "ENFORCE",       # or AUDIT / DISABLED
#           "fail_open": True,       # pass through on shield error
#       },
#   )
#
# That's it — all tool calls now run through PolicyShield.
# Blocked calls return "🛡️ BLOCKED: ..." to the LLM instead of executing.

# Example rules.yaml:
EXAMPLE_RULES = """
shield_name: nanobot-guard
version: 1
rules:
  - id: block-rm
    when:
      tool: exec
      args:
        command: "rm *"
    then: BLOCK
    message: "Destructive rm commands are not allowed"

  - id: block-curl
    when:
      tool: exec
      args:
        command: "curl *"
    then: BLOCK
    message: "HTTP requests via curl are not allowed"

  - id: audit-write
    when:
      tool: write_file
    then: ALLOW
    message: "File write logged"
"""

if __name__ == "__main__":
    print("See comments above for usage.")
    print("Example rules:")
    print(EXAMPLE_RULES)
