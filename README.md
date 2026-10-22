# openfox-jev — Intelligent Tool Approval for OpenFox

Replaces unnecessary manual approval prompts with intelligent decisions from a
**System One** compatible decision model, evaluated by a **deterministic
approval policy** — while never weakening OpenFox's mandatory security
boundaries.

| Backend | Route | Credentials |
|---|---|---|
| **Jev-Style local** (0.8B / 2B) | `http://127.0.0.1:8765/v1/systemone` | none by default (optional local key) |
| **Drex v2.0 via OpenRouter** | `https://openrouter.ai/api/alpha/decisions` | existing OpenFox Provider Manager key |
| **Drex v2.0 via DeepInfra** | `https://api.deepinfra.com/v1/decisions` | existing OpenFox Provider Manager key |

**No API key is ever entered twice.** The plugin stores only the selected
provider ID and approval-specific settings.

## How a decision is made

```
confirmation request (before tool execution) — tool commands **and**
File Access / folder-access dialogs
  → 1. OpenFox mandatory rules (git --no-verify, dangerous patterns,
        sensitive paths, workdir confinement, sub-agent/night-mode) — unchanged
  → 2. Plugin deterministic hard rules (destructive, secrets, exfil,
        privilege escalation, force-push, injection, truncation,
        secret folders, sensitive files, home/root access)
  → 3. Sanitized operation → typed System One questions (choice/noul/score).
        File Access requests carry no command, so the plugin synthesizes an
        explicit operation ("File access request: <tool> wants read/write
        access to <paths>") for the model to judge
  → 4. Strict response validation (probabilities, confidence, legend bounds)
  → 5. Deterministic policy → APPROVE | ESCALATE | DENY
  → 6. Shadow mode? record prediction only, keep native approval
```

- **APPROVE** — executes without a manual dialog, **one-time only** (never
  persisted to the session allowlist).
- **ESCALATE** — the existing OpenFox confirmation dialog appears.
- **DENY** — blocked, with an explanation returned to the agent.

## Installation

1. Prerequisites: OpenFox ≥ 2.0.140 with the upstream `PluginApprovalReviewer`
   extension (PR: `co-l/openfox#439`).
2. OpenFox → **Settings → Plugins → Install from GitHub** →
   `https://github.com/adriy-be/openfox-jev`
3. Enable the plugin.

### Local Jev-Style server (optional)

The plugin never starts it — run it yourself (CPU is fine):

```bash
jev-style serve --backend torch --device cpu --port 8765   # 0.8B or 2B
```

The server keeps the model loaded; the plugin sends no reload commands and
never triggers a GPU workload.

## Configuration guide

**General**
- *Enable smart approvals* — off = native OpenFox behavior, byte-for-byte.
- *Mode* — `shadow` (default: assess + record, never act) / `enforce`.
- *Approval timeout* — backend requests beyond it escalate to manual.

**Model**
- *Decision provider* — dropdown of **existing** OpenFox providers (Provider
  Manager). Cloud keys are never re-entered — the only credential field is the
  optional `localApiKey` for the loopback Jev server.
- *Backend type* — Auto (verified origin mapping), Local Jev-Style,
  OpenRouter, DeepInfra, or Custom (HTTPS required).
- *Decision model* — free text (default `nace-ai/drex-v2.0`; local servers
  ignore it).
- *Local Jev URL* — loopback only, default `http://127.0.0.1:8765`.
- *Connection test* — shows provider · model · mode · latency. Both the
  connection test and the status line resolve **global** settings (the host
  RPCs carry no project context), so a project-scoped provider/model override
  is used for decisions but not shown here.

**Approval policy**
- *Operator policy* — trusted instructions for the model (e.g. "Routine
  read-only git commands are allowed.").
- *Minimum approval probability / confidence* — conservative defaults 0.85 /
  0.55.
- *Blast radius thresholds* — escalate ≥ 1.6, hard-escalate ≥ 2.0 (0–4 scale).
- *Audit logging* — structured JSONL, redacted/hashed operations, rotation.

**Privacy**
- *Permit sending approval data to a cloud provider* — explicit opt-in,
  **required even in shadow mode** for OpenRouter/DeepInfra. Local Jev never
  needs it. Recognized credential patterns (bearer tokens, API keys, private
  key blocks, JWTs, `key=value` pairs, embedded URL credentials) are redacted
  before egress; escalation occurs when redaction removes decision-critical
  context. Redaction is pattern-based and best-effort — see *Limitations*.

## Shadow mode

Runs the full assessment, records the predicted verdict in the audit log, and
**always returns `ask`** so OpenFox's native approval flow is untouched. Use it
to collect real approval cases before switching to enforce.

## Default operator policy (conservative)

Automatic approval is **opt-in per operation class** and **fail-closed by
default**: with no operator policy the plugin can only escalate. The policy
below is the recommended starting point — narrow, explicit trust rules that
auto-approve only read-only, non-mutating work and leave every state-changing
operation to a human. Paste it into *Operator policy*, then widen it only for
classes you have watched in shadow mode.

```
Routine read-only git commands (status, log, diff) are allowed.
Everything else requires confirmation.
```

A slightly wider but still conservative default that also permits a scoped
commit (never `--no-verify`, never force, never push):

```
Routine read-only git commands (status, log, diff) are allowed.
A git commit that stages a specific file and does not use --no-verify is
allowed. Push, force-push, reset --hard, clean, rebase, merge and every other
state-changing command require confirmation.
```

What this default deliberately does **not** auto-approve: pushes of any kind,
`reset --hard`, `clean -f/-x`, `fetch --prune`, `git rm`, unscoped `git add`,
`--no-verify`, and force-push. Those are escalated to a human **before** the
model is consulted, so no model verdict — however confident — can silently
auto-approve history-rewriting or data-destroying operations.

## Security properties

- Mandatory OpenFox rules are evaluated **before** the plugin and cannot be
  downgraded by any model verdict.
- Credentials are resolved server-side by OpenFox and only attached to
  **verified endpoint origins** — never forwarded cross-origin
  (`redirect: 'error'`), no arbitrary authenticated proxy.
- HTTPS required for remote endpoints; local HTTP restricted to loopback.
- Strict timeouts, response size caps, strict schema validation — invalid
  responses escalate, never approve.
- Truncated operations are never auto-approved; operations are never approved
  on agent-supplied claims of safety.
- File Access (folder/path) requests are reviewed too: access to secret key
  folders (`.ssh`, `.gnupg`) and shadow password files is **denied**,
  upstream-sensitive files and home/root access are **escalated**, and every
  other folder request goes through the same model + policy gate.
- Reviewer absence, errors or timeouts fall back to the native confirmation
  flow (fail-closed). Disabling the plugin restores stock OpenFox behavior.
- Audit logging failures never change a decision.
- This plugin does **not** provide sandbox isolation — it only decides
  approvals.

## Tests

```bash
npm test        # node:test — 261 tests: providers, client, policy,
                # security, reviewer, integration (real loopback server,
                # 15-row mocked-DeepInfra regression matrix)
```

## Benchmark

```bash
node benchmark/run.js --backend local --url http://127.0.0.1:8765
node benchmark/run.js --backend jev-0.8b --url http://127.0.0.1:8765
node benchmark/run.js --backend jev-2b   --url http://127.0.0.1:8766
node benchmark/run.js --backend jev-0.8b,jev-2b --url :8765 --url-2b :8766  # 0.8B vs 2B
node benchmark/run.js --backend openrouter --api-key $OPENROUTER_API_KEY
node benchmark/run.js --backend deepinfra  --api-key $DEEPINFRA_API_KEY
node benchmark/run.js --backend deepinfra --api-key $DEEPINFRA_API_KEY --model <id>
```

Same labelled corpus (`benchmarks/holdout.jsonl`, 24 samples) and the same
typed questions across all backends. Metrics: false automatic approvals
(**safety bar — run exits non-zero if > 0**), false denials, escalation rate,
correct approval rate, model/e2e latency, token usage, estimated cost.

**Benchmarks measure fixture agreement, not real-world safety.** Transport
differences (route, auth, latency) are reported separately from model
differences because every route runs the identical question set.

## Limitations

- Requires the upstream OpenFox extension (PR #439); on stock OpenFox the
  plugin loads but cannot review confirmations.
- Only eligible confirmation paths are reviewed: path/command gates,
  **File Access / folder-access dialogs**, and git/workspace confirmations.
  `ask_user` and night-mode/sub-agent flows are untouched by design.
- Local Jev servers ignore the `model` field — 0.8B vs 2B is a server-side
  choice, benchmarked via the `jev-0.8b` / `jev-2b` backends (separate URLs).
- Thresholds are conservative defaults; tune with labelled data
  (`benchmark/run.js`).
- Cloud cost estimates use configurable per-token prices — verify against
  current provider pricing.
- Secret redaction is **pattern-based and best-effort**. It recognizes a
  fixed set of credential shapes (bearer tokens, `sk-`/`ghp_`-style API keys,
  AWS keys, private key blocks, JWTs, `key=value` pairs, embedded URL
  credentials). A secret that matches none of these patterns is **not
  guaranteed to be detected** and may still egress. The
  `redaction_incomplete` escalation is a safety net that fires when a pattern
  *did* match and decision-critical context was removed — it is not a
  guarantee that every secret is caught.

## License

MIT