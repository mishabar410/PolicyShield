# 503 — JS/TS SDK Package

## Goal

Create `@policyshield/client` npm package — a typed HTTP client for PolicyShield.

## Context

- Currently only the OpenClaw plugin has TS types
- Need a standalone, framework-agnostic SDK for any JS/TS project
- Should use `fetch` (no external deps) with typed request/response

## Code

### New directory: `sdks/typescript/`

```
sdks/typescript/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts
│   ├── client.ts        # PolicyShieldClient class
│   └── types.ts         # Shared types (import from plugins/openclaw/src/types.ts)
├── tests/
│   └── client.test.ts
└── README.md
```

### `src/client.ts`

```typescript
export class PolicyShieldClient {
  constructor(private baseUrl: string, private options?: { apiToken?: string; timeout?: number })

  async check(request: CheckRequest): Promise<CheckResponse>
  async postCheck(request: PostCheckRequest): Promise<PostCheckResponse>
  async health(): Promise<HealthResponse>
  async kill(reason?: string): Promise<void>
  async resume(): Promise<void>
  async waitForApproval(approvalId: string, opts?: { timeout?: number; pollInterval?: number }): Promise<ApprovalStatusResponse>
}
```

### `package.json`

- Name: `@policyshield/client`
- Zero runtime dependencies (uses native `fetch`)
- Exports ESM + CJS

## Tests

- Mock `fetch` globally
- Test `check()` sends correct request, parses response
- Test auth header when `apiToken` set
- Test `waitForApproval()` polls until resolved

## Self-check

```bash
cd sdks/typescript && npm run build && npm test
```

## Commit

```
feat(sdk): add @policyshield/client TypeScript SDK
```
