# Delivery report — Drex v2.0 as a working approval reviewer

Task: make the System One decision model (Drex v2.0 via DeepInfra) actually work
as OpenFox's intelligent approval reviewer — and stop the excessive prompts.
Two repos: the plugin `openfox-jev` and the OpenFox host.

## Root causes (with evidence)

**RC1 — no Drex calls at all.** The host's plugin channel
(`provider-access.ts` `findProvider`, used only by `requestJson`) threw
`'Provider is disabled'` for any `isActive:false` provider. DeepInfra is not
the chat model (`isActive:false`), so every plugin request died before the
network. Evidence: 142 audit rows with `ruleId: provider_disabled`
(`~/.local/state/openfox-jev/decisions.jsonl`); the last 35 of 40 rows. The
running host (systemd user service, started 2026-10-18) still executed this
code. The plugin-side check had already been removed, but the host-side gate
remained.

**RC2 — excessive prompts.** `security.js` escalated every git command
(`git_mutation`) before the model, so Drex was never consulted for routine git.

**RC3 — settings clobber.** `settings('project')` without `projectId` fell back
to the global segment, and the host returns schema defaults for unset keys — a
blind merge would overwrite stored globals with defaults.

**RC4 — no diagnostics.** Disabled/no-provider exits were unaudited; no
counters; `connectionStatus` claimed `running:true` without evidence.

**RC5 — raw command lost.** The command gate passed only the localized
description into the reviewer context, not the raw command.

**F8 — verified correct, unchanged.** The plugin already speaks the typed
System One protocol (`api.deepinfra.com` → `/v1/decisions`, never a blind path
append).

## Files changed

**Host `/tmp/openfox`** — branch `fix/approval-diagnostics`, commit `e29a8d4`:
- `src/server/plugins/provider-access.ts` — RC1 gate removed from `findProvider`.
- `src/server/plugins/settings.ts`, `src/plugin/index.ts`,
  `src/server/plugins/host.ts` — `onlyStored` flag for project settings.
- `src/server/tools/tool-helpers.ts`, `src/server/tools/path-security.ts` —
  stable reason codes (`night_mode`, `sub_agent`, `git_no_verify`,
  `dangerous_command`) + raw-command passthrough into the reviewer context.
- `src/server/tools/shell.ts` — command gate passes the raw command.
- Test files (57 tests green).

**Plugin `/srv/git/openfox-jev`** — branch `fix/drex-approval-reviewer`,
commit `60ac790` (plus the diagnostics follow-up):
- `src/security.js` — argument-aware git policy + `firstGitInvocation` /
  `gitMutationDecision`.
- `src/reviewer.js` — counters, audit on early exits, truthful probe,
  `getDiagnostics()`.
- `src/index.js` — `onlyStored` merge, truthful `connectionStatus` (now also
  exposes counters + last decision), tolerant `register()`.
- `README.md` — conservative default operator policy.
- `tests/*` — 15-row mocked-DeepInfra matrix, counter and audit-row tests.

## Before / after audit evidence

| | Before | After |
|---|---|---|
| Last 40 rows | `provider_disabled` × 35 | — |
| Live probe | — | `ruleId: approved`, `outcome: shadow_approve`, `latencyMs: 1750`, `rawVerdict: APPROVE`, `model: nace-ai/drex-v2.0` |

## DeepInfra verification (live)

One authenticated real request to `https://api.deepinfra.com/v1/decisions`
with `nace-ai/drex-v2.0` (provider still `isActive:false`): **HTTP 200**, valid
System One schema, `verdict.choice: APPROVE`, probabilities sum **1.0000**,
latency 1307 ms. Recorded metadata only — no credential, no response body.
End-to-end reviewer path over the same backend: `shadow_approve` (shadow mode
correctly asks).

## Test results

- Plugin: **257 / 257** `node:test` pass; `node --check` clean on all `src/*.js`.
- Host: **6064 passed / 29 skipped / 0 failed** (vitest, full suite); typecheck
  clean (server + e2e + bench); pre-commit hook (lint / format / typecheck /
  test) passed on commit.
- Host dist rebuilt and deployed to the global install (verified:
  `Provider is disabled` absent, reason codes + `onlyStored` present); plugin
  `src/` deployed to `~/.config/openfox/plugins/openfox-jev`.

## Deployment & restart

Both repos committed on dedicated branches, **not pushed**. The running host
still served the old code; a deferred restart was scheduled
(`openfox-deferred-restart.service`, transient user unit) so it loads the new
dist + plugin after the session ends.

## Remaining mandatory confirmations — and why

`push` (all forms), `reset --hard/-H`, `clean -f/-x/-d`, `fetch --prune/-p`,
`git rm`, unscoped / `-A` / `.` `git add`, `mv`, `am`, `pull`, `restore`,
`--no-verify`, force-push (escalate; force-push to `main`/`master` **deny**),
plus every pre-existing hard rule (`rm -rf /home|/`, fork bomb, `mkfs`, `dd` to
device, private-key access, `.ssh`/`.gnupg`/shadow access, sensitive-file /
home / root access, `sudo`). These escalate **before** the model by design:
history-rewriting, data-destroying and hook-bypassing operations must never be
auto-approved on model probability alone — the conservative default documented
in the README.

## Introduced risks

- **Host gate removal** widens `requestJson` to inactive providers — bounded by
  the verified-origin map, HTTPS, `redirect:'error'`, strict timeout and a
  1 MB cap; a plugin selecting a provider is explicit operator consent.
- **Git policy narrowing** moves routine mutations to the model gate — bounded
  by the deterministic policy (min probability 0.85, min confidence 0.55,
  blast-radius caps, `policy_allows` check) and by shadow mode being the
  default.
- **Deferred restart** briefly interrupts the host; sessions persist to disk
  and the service auto-restarts.
