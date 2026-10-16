import { appendFileSync, existsSync, mkdirSync, renameSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'
import { hashId, redactSecrets } from './security.js'

export const DEFAULT_MAX_BYTES = 4 * 1024 * 1024
export const DEFAULT_KEEP = 1

export function defaultLogPath() {
  if (process.env.OPENFOX_JEV_LOG) return process.env.OPENFOX_JEV_LOG
  return join(homedir(), '.local', 'state', 'openfox-jev', 'decisions.jsonl')
}

/**
 * Lightweight structured audit log.
 *
 * - One JSON line per decision, stable schema.
 * - Operation identifiers are redacted then hashed (raw commands are never
 *   stored by default).
 * - Bounded storage with rotation (size cap, keeps N prior generations).
 * - Logging failures NEVER affect the approval decision: every method swallows
 *   its own errors.
 */
export function createAuditLog({ filePath = defaultLogPath(), maxBytes = DEFAULT_MAX_BYTES, keep = DEFAULT_KEEP, enabled = true } = {}) {
  const state = { failures: 0 }

  function rotateIfNeeded() {
    try {
      if (!existsSync(filePath) || maxBytes <= 0) return
      if (statSync(filePath).size < maxBytes) return
      for (let i = keep; i >= 1; i -= 1) {
        const from = i === 1 ? filePath : `${filePath}.${i - 1}`
        const to = `${filePath}.${i}`
        if (existsSync(from)) renameSync(from, to)
      }
    } catch {
      state.failures += 1
    }
  }

  function write(line) {
    if (!enabled) return
    try {
      mkdirSync(dirname(filePath), { recursive: true })
      rotateIfNeeded()
      appendFileSync(filePath, `${line}\n`, { mode: 0o600 })
    } catch {
      state.failures += 1
    }
  }

  return {
    filePath,
    get failures() {
      return state.failures
    },

    /**
     * Record one decision. All fields are optional; missing data is recorded
     * as null rather than throwing.
     *
     * @param {object} record
     */
    record(record = {}) {
      const operation = typeof record.operation === 'string' ? record.operation : ''
      const { text: redactedOp } = redactSecrets(operation)
      const row = {
        ts: record.ts ?? new Date().toISOString(),
        mode: record.mode ?? null,
        providerId: record.providerId ?? null,
        model: record.model ?? null,
        operationCategory: record.operationCategory ?? null,
        operationHash: operation ? hashId(redactedOp) : null,
        operationRedacted: operation ? redactedOp.slice(0, 200) : null,
        rawVerdict: record.rawVerdict ?? null,
        decision: record.decision ?? null,
        ruleId: record.ruleId ?? null,
        approvalProbability: record.approvalProbability ?? null,
        confidence: record.confidence ?? null,
        risk: record.risk ?? null,
        latencyMs: record.latencyMs ?? null,
        outcome: record.outcome ?? null,
        errorClass: record.errorClass ?? null,
        humanApprovalRequired: record.humanApprovalRequired ?? null,
        truncated: record.truncated ?? false,
        policyVersion: record.policyVersion ?? null,
      }
      try {
        write(JSON.stringify(row))
      } catch {
        state.failures += 1
      }
      return row
    },
  }
}