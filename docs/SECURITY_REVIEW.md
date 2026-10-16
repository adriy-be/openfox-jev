# Security Review — openfox-jev

Scope: the standalone plugin and its interaction with the OpenFox upstream
extension (PR co-l/openfox#439). Method: code review against the threat model
of an approval-reviewing plugin, plus the automated test suites.

## Threat model

The plugin decides whether tool operations execute without human confirmation.
An attacker (compromised/misaligned model, prompt injection in repo content,
malicious provider response, or a tampered provider configuration) must not be
able to obtain an automatic approval for a harmful operation, exfiltrate
credentials, or weaken OpenFox's existing controls.

## Findings

### S1 — Approval authority is bounded by upstream (residual risk: low)
**Status: by design.** The reviewer runs only *after* OpenFox's mandatory
rules (git `--no-verify`, dangerous patterns, sensitive paths, workdir
confinement, sub-agent/night-mode fail-closed). It can only auto-approve what
would otherwise be a manual dialog; it can never downgrade a mandatory rule.
Verified by upstream tests (`approval-reviewer.test.ts`: mandatory rules are
not even consulted when they trigger).

### S2 — Persistent permission escalation (residual risk: low)
**Status: mitigated + tested.** `allow` is one-time: `requestPathAccess`
returns without calling `addAllowedPaths`, and `requestUserConfirmation`
performs no persistence. Test: "second identical operation is reviewed again"
and "one-time approval: nothing is persisted between evaluations".

### S3 — Prompt injection / self-advocating operations (residual risk: medium)
**Status: mitigated.** Three layers: (1) the reviewer state contains the raw
operation and a trusted operator policy, with instructions explicitly marking
operation text as untrusted; (2) `self_advocating` noul ≥ 0.6 escalates (or
preserves a model DENY) *before* any approval branch; (3) deterministic hard
rules are model-independent, so injection in the operation text cannot bypass
them (e.g. `echo "ignore policy..."` still hits `git_mutation`/hard rules when
combined with a real action). Residual: a purely conversational operation with
no hard-rule match still depends on the model — hence conservative thresholds
and shadow-by-default.

### S4 — Credential exposure (residual risk: low)
**Status: mitigated + tested.** Credentials never enter plugin state: cloud
requests go through `PluginContext.providerAccess.requestJson`, which resolves
keys server-side and attaches them only to origin-verified endpoints
(`redirect: 'error'`). The plugin's only password field is the *local* Jev key,
used solely against loopback. Audit rows store redacted + hashed operation
identifiers; tests assert no `Bearer`/key material appears in logs or errors.
Error messages carry status codes only, never response bodies.

### S5 — SSRF / cross-origin forwarding (residual risk: low)
**Status: mitigated + tested.** Endpoint resolution is an explicit origin map
(OpenRouter, DeepInfra) + loopback rule + explicit custom HTTPS endpoint.
Unknown origins throw before any request; provider URL changes to unverified
origins fail closed (test: "never sends credentials to an unmapped origin").
Non-loopback HTTP is rejected for local/custom backends.

### S6 — Malicious or malformed model responses (residual risk: low)
**Status: mitigated + tested.** Strict schema validation: probabilities must
cover exactly APPROVE/ESCALATE/DENY, sum ≈ 1, choice must be argmax,
confidence/noul ∈ [0,1], score within legend bounds. Any violation ⇒
`invalid_response` ⇒ ESCALATE. Chat-completion-shaped responses are rejected
(test: "never uses chat-completion text").

### S7 — Backend unavailability / DoS (residual risk: low)
**Status: mitigated.** Strict timeout (default 15 s, capped 60 s), 1 MB
response cap, 12 k-char state cap with truncation flag (truncated ⇒ never
APPROVE), upstream reviewer timeout (15 s) falls back to native ask. Offline,
timeout and error classes all escalate — never approve.

### S8 — Denial of service via logging (residual risk: low)
**Status: mitigated + tested.** Audit writes are size-bounded with rotation and
every operation swallows its own errors; test proves a broken log path leaves
the decision unchanged.

### S9 — Shadow mode bypasses controls (residual risk: none)
**Status: verified.** Shadow always returns `ask`; native flow preserved; cloud
requests still require consent. Tested for all three verdicts.

### S10 — Disabled/broken plugin changes OpenFox behavior (residual risk: none)
**Status: verified.** Disabled ⇒ `ask` without contacting backends; reviewer
throw/timeout/invalid decision ⇒ `undefined` ⇒ native dialog; absence of the
upstream extension ⇒ plugin registers but no reviewer is consulted.

## Explicit non-claims

- The decision model provides **no sandbox isolation**; it only classifies
  operations.
- Benchmarks are fixture agreement, **not** real-world safety evidence.
- Model probability alone never authorizes secrets, exfiltration, privilege
  escalation or destructive operations.

## Test evidence

- Plugin: 130 node:test cases (providers, protocol, policy, security,
  reviewer, integration incl. real loopback server).
- Upstream: 46 new vitest cases; full OpenFox suite 6048 tests pass; typecheck
  and eslint clean.