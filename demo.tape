# PolicyShield Demo — VHS recording script
# Prerequisites: server must be running on port 8100 with demo rules
#   policyshield server --rules policies/demo-verify.yaml --port 8100
#
# Record: vhs demo.tape

Output demo.gif

Set Shell "zsh"
Set FontSize 15
Set Width 900
Set Height 500
Set Theme "Catppuccin Mocha"
Set Padding 15
Set TypingSpeed 35ms
Set CursorBlink false

Sleep 500ms
Type `echo "  PolicyShield - Runtime Firewall for AI Agents"`
Enter
Sleep 1.5s

# ── Test 1: BLOCK ──
Type `echo "  -> Checking: cat /etc/hosts (harmless command)"`
Enter
Sleep 1s

Type `curl -s -X POST http://localhost:8100/api/v1/check \`
Enter
Type `  -H "Content-Type: application/json" \`
Enter
Type `  -d '{"tool_name":"exec","args":{"command":"cat /etc/hosts"}}' \`
Enter
Type `  | python3 -m json.tool`
Enter
Sleep 3s

# ── Test 2: ALLOW ──
Type `echo "  -> Checking: pwd (not in the block list)"`
Enter
Sleep 1s

Type `curl -s -X POST http://localhost:8100/api/v1/check \`
Enter
Type `  -H "Content-Type: application/json" \`
Enter
Type `  -d '{"tool_name":"exec","args":{"command":"pwd"}}' \`
Enter
Type `  | python3 -m json.tool`
Enter
Sleep 3s

# ── Conclusion ──
Type `echo "  cat -> BLOCKED by PolicyShield (no LLM would refuse this)"`
Enter
Type `echo "  pwd -> ALLOWED (not in the rules)"`
Enter
Type `echo "  That is a firewall, not alignment."`
Enter
Sleep 3s
