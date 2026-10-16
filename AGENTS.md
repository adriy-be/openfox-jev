# AGENTS.md — openfox-jev

## What this is

Standalone OpenFox plugin (API v2, JavaScript ESM, zero runtime dependencies)
that reviews tool-approval confirmations before execution using a System One
decision model + deterministic policy.

## Commands

```bash
npm test                      # node:test over tests/*.test.js
node benchmark/run.js --backend local   # benchmark (needs a System One server)
node --check src/*.js         # syntax check
```

No build step. No lint config — keep style consistent with existing files:
2-space indent, single quotes, no semicolon-less style (semicolons used),
no comments unless explaining a security decision.

## Architecture

```
src/index.js     register(registry): settings schema, approval reviewer, RPCs
src/reviewer.js  orchestration: config → security → transport → policy → audit
src/policy.js    pure deterministic policy (no I/O) → {decision, reason, rule_id, model_verdict, confidence}
src/client.js    typed System One protocol: questions, truncate, validate, decide
src/security.js  redaction + mandatory hard rules (DENY rules evaluated first)
src/providers.js verified endpoint resolution (origin mapping, never blind append)
src/audit.js     bounded JSONL audit log, rotation, never throws
```

## Invariants (do not break)

1. Mandatory OpenFox rules are upstream and run before this plugin — never
   attempt to downgrade them.
2. Hard DENY rules are evaluated before ESCALATE rules and before the model.
3. `allow` is one-time: nothing is persisted between evaluations.
4. Shadow mode always returns `ask`.
5. Cloud backends require explicit consent (`cloudConsent`), even in shadow.
6. Credentials only flow through `context.providerAccess.requestJson` with a
   verified origin — never hand API keys to `fetch` for cloud URLs.
7. Any backend failure, invalid schema, timeout or truncation ⇒ `ask`.
8. Audit failures never change the decision.

## Tests

- `tests/providers.test.js` — endpoint verification, origin mismatches.
- `tests/client.test.js` — protocol validation, truncation, error classes.
- `tests/policy.test.js` — every rule in priority order.
- `tests/security.test.js` — redaction + hard rules.
- `tests/reviewer.test.js` — modes, provider lifecycle, failures, audit.
- `tests/integration.test.js` — register() wiring, real loopback HTTP server,
  concurrency, one-time approval, RPC status.

Fixtures and mocks only — never run destructive commands against a real
workspace.

## Upstream dependency

Requires `PluginApprovalReviewer` + `PluginContext.providerAccess` from
openfox PR co-l/openfox#439. Do not fork OpenFox behavior inside this repo.