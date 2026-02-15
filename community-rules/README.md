# Community Rule Packs for PolicyShield

Ready-made policy rule sets for common compliance and security scenarios.

## Available Packs

| Pack | File | Rules | Focus |
|------|------|-------|-------|
| **GDPR** | [`gdpr.yaml`](gdpr.yaml) | 8 rules | EU data protection, cross-border transfers, data minimization |
| **HIPAA** | [`hipaa.yaml`](hipaa.yaml) | 9 rules | PHI protection, minimum necessary standard, patient record safety |
| **PCI-DSS** | [`pci-dss.yaml`](pci-dss.yaml) | 9 rules | Cardholder data protection, CVV blocking, payment gateway enforcement |

## Usage

```bash
# Validate a rule pack
policyshield validate community-rules/gdpr.yaml

# Start server with a rule pack
policyshield server --rules community-rules/hipaa.yaml --port 8100

# Lint for issues
policyshield lint community-rules/pci-dss.yaml
```

## Combining Packs

You can reference rules from multiple files by combining them into a single YAML:

```yaml
# my-rules.yaml — combine packs with your custom rules
shield_name: my-agent
version: 1

# Include your custom rules alongside a compliance pack
rules:
  # ... your rules here
  # Copy relevant rules from community packs
```

> **Note:** Rule composition (`include:` / `extends:`) is on the [roadmap](../ROADMAP.md) for v1.0.

## Customization

These packs are starting points, not complete compliance solutions. You should:

1. **Review each rule** against your specific data processing activities
2. **Adjust tool names** to match your agent's actual tool names
3. **Add custom PII patterns** for domain-specific identifiers
4. **Set appropriate rate limits** based on your expected usage patterns
5. **Configure approval backends** (Telegram, Webhook) for human-in-the-loop rules

## Contributing Rules

Have a rule pack for a new compliance framework or industry? We welcome contributions!

1. Create a YAML file following the existing format
2. Include a header comment with the framework name and usage instructions
3. Add tests via `policyshield test`
4. Open a PR

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.
