# Implementation Report — openfox-jev

## 1. Implemented features

### Upstream OpenFox (PR co-l/openfox#439, 3 commits)
1. **`PluginApprovalReviewer` API (v2)** — `registerApprovalReviewer()` with
   `evaluate(ApprovalContext) → allow | ask | deny`, wired into *both*
   confirmation entry points (`requestPathAccess`, `requestUserConfirmation`)
   before tool execution and after all mandatory security rules.
   - `allow` is one-time (never written to the session allowlist).
   - `ask` reuses the native `chat.path_confirmation` UI (no duplicate dialogs).
   - `deny` blocks with a reason surfaced to the agent.
   - Fail-closed: absence, throw, 15 s timeout or invalid decision ⇒ native
     flow. Multiple reviewers combine strictest-wins. Cancellation signal
     passed through; night-mode/sub-agent/dangerous-mode ordering unchanged.
2. **`PluginContext.providerAccess`** — narrow capability: `listProviders()`
   (non-sensitive metadata), `getProvider(id)`, `requestJson(providerId,
   endpointKey, body, {timeoutMs})`. Server-side credential resolution
   (legacy `apiKey` + `credentialRef`/auth-adapter `getAccessContext`),
   origin-verified endpoint map, `redirect: 'error'`, loopback-only HTTP,
   HTTPS for remote, 10 s default / 60 s max timeout, 1 MB response cap,
   no credentials in errors. Not a generic authenticated proxy.
3. **`optionsFrom: 'providers'`** on settings select fields — dynamic
   Provider Manager dropdown in the settings UI (validated by type only when
   dynamic; stale stored values stay visible).

### Standalone plugin (`openfox-jev`, JS ESM, zero deps)
- `src/index.js` — API v2 registration: FR/EN settings (general/model/policy/
  privacy), approval reviewer, RPCs (`testConnection`, `connectionStatus`,
  `listBackends`). Cloud keys are never re-entered — the only credential
  field is the optional `localApiKey` for the loopback Jev server.
- `src/reviewer.js` — orchestration: config → mandatory security → provider
  lifecycle/consent → transport → validation → policy → shadow/enforce →
  audit. Default mode `shadow`, default disabled.
- `src/client.js` — typed System One protocol (choice/noul/score questions),
  state truncation with visible marker, strict response validation, error
  classification. No chat-completions path exists.
- `src/policy.js` — pure priority-ordered policy returning
  `{decision, reason, rule_id, model_verdict, confidence}`; conservative
  thresholds (minApproval 0.85, confidence 0.55, self_advocating 0.6,
  secrets/exfil 0.7, blast 1.6/2.0); distinguishes `confidence` from
  `probabilities.APPROVE`.
- `src/security.js` — redaction (tokens, keys, JWTs, credentialed URLs) +
  deterministic hard rules (DENY first: wipe-home/root, fork bomb, format,
  dd, force-push-main, private keys; then ESCALATE: git --no-verify,
  force-push, sudo, destructive rm, writes outside project, git mutations).
- `src/providers.js` — verified endpoint resolution: OpenRouter
  `/api/alpha/decisions`, DeepInfra `/v1/decisions`, local
  `127.0.0.1:8765/v1/systemone`, custom HTTPS; never blind appending.
- `src/audit.js` — JSONL, redacted/hashed operations, size rotation,
  failures swallowed.
- `benchmark/run.js` + `benchmarks/holdout.jsonl` (24 labelled samples) —
  per-backend metrics with a hard safety bar (non-zero false auto-approvals ⇒
  exit 1).

## 2. Tested behavior
- **Plugin**: 130/130 node:test pass — endpoint verification & origin
  mismatches, apiKey/credentialRef reuse, removed/disabled providers, URL
  changes, no cross-origin leakage, protocol validation, every policy rule,
  redaction, hard rules, shadow/enforce/disabled, offline/timeout/invalid
  schema, concurrency, cancellation, one-time approval, sub-agent/night-mode
  fail-closed, audit fields/rotation/failure-isolation, real loopback Jev
  server round-trip, RPC status.
- **Upstream**: 46 new vitest cases; full suite 6048 tests pass (0 failures);
  `tsc --noEmit` and `eslint src/` clean; pre-commit hooks (duplicate, lint,
  format, typecheck, test) pass on all 3 commits.
- **Benchmark (fake deterministic server)**: 0 false automatic approvals,
  100% correct approval rate on allow-labelled samples, escalation rate 0.33.

## 3. Assumptions
- Upstream PR #439 is merged (or applied) before the plugin can review
  confirmations; on stock OpenFox the plugin loads but reviews nothing.
- OpenRouter/DeepInfra "Decisions" endpoints follow the documented paths in
  the spec; origins are pinned, so a provider URL edit to another host fails
  closed rather than silently working.
- Provider dropdown uses the upstream `optionsFrom: 'providers'` extension;
  without it the stored providerId is still honored at runtime.
- Default thresholds are conservative starting points pending labelled tuning.
- One reviewer slot is sufficient; strictest-wins covers future multi-plugin
  cases.

## 4. Remaining limitations
- Only eligible confirmation paths are reviewed; `ask_user` and other flows
  are untouched by design.
- Local Jev `model` field is ignored server-side (0.8B vs 2B is a server
  choice); the plugin cannot detect which is loaded.
- Cost estimates use placeholder per-token prices.
- `git_mutation` escalates all state-changing git commands — intentionally
  conservative; tune via policy/thresholds, not by weakening hard rules.
- Concurrent confirmations each invoke the reviewer independently (no
  cross-request caching) — acceptable at approval frequency.
- The 24-sample holdout is a smoke corpus, not a statistical benchmark; real
  evaluation needs mined, human-labelled data.

## 5. Deliverables checklist
- [x] Standalone `openfox-jev` repository (installable via GitHub URL)
- [x] Minimal upstream patch as 3 reviewable commits → PR #439
- [x] Installation instructions (README §Installation)
- [x] Configuration guide (README §Configuration)
- [x] Working tests (130 plugin + 46 upstream, all green)
- [x] Security review (docs/SECURITY_REVIEW.md)
- [x] This report
- [x] No upstream push beyond the PR branch, no package publish