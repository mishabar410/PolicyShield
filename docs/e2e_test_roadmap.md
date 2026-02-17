# E2E Test Roadmap

Чеклист для полного E2E тестирования PolicyShield на живом сервере.

## ✅ Проверено

- [x] Health check (`/api/v1/health`)
- [x] ALLOW verdict (`read_file`, `search`, `list_dir`)
- [x] BLOCK verdict (`exec`, `shell`, `unknown_tool`)
- [x] APPROVE verdict — возвращает `approval_id` (`write_file`)
- [x] REDACT verdict — PII detection (`send_message`, `send_email`)
- [x] Honeypot traps (`admin_panel`, `get_credentials`, `delete_all_data`)
- [x] Kill switch — activate (`/api/v1/kill`) + deactivate (`/api/v1/resume`)
- [x] Sanitizer: path traversal (`../../etc/passwd` → BLOCK)
- [x] Sanitizer: shell injection (`; rm -rf /` → BLOCK)
- [x] Sanitizer: SSRF (`http://169.254.169.254/...` → BLOCK)
- [x] Sanitizer: SQL injection (`' OR '1'='1` → BLOCK)
- [x] Sanitizer: url_schemes (`file:///etc/passwd` → BLOCK)
- [x] Telegram — бот отправляет сообщение с кнопками Approve/Deny
- [x] APPROVE round-trip (REST): submit → respond → `status:approved`
- [x] APPROVE round-trip (Telegram): submit → Deny в Telegram → `status:denied, responder:misha_bar_410`
- [x] Post-check PII (`/api/v1/post-check`) — SSN, email, phone detected + redacted
- [x] Hot reload — добавил правило, `/api/v1/reload` → 6→7 rules, hash изменился
- [x] Constraints (`/api/v1/constraints`) — список правил
- [x] Doctor command (`policyshield doctor`)
- [x] Auto rule generation (`policyshield generate-rules --tools`)

## ⚠️ Не реализовано

- [ ] Server status (`/api/v1/server-status`) — returns 404
