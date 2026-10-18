import { homedir } from 'node:os'

const SECRET_PATTERNS = [
  // Bearer/API-style tokens
  /\b(?:sk|pk|rk|ghp|gho|ghu|ghs|ghr|xox[baprs])[-_][A-Za-z0-9._-]{8,}/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi,
  // AWS
  /\bAKIA[0-9A-Z]{16}\b/g,
  // Private key blocks
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  // JWTs
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  // key=value style credentials
  /\b(?:api[_-]?key|apikey|secret|token|password|passwd|authorization)\s*[=:]\s*["']?[^\s"',;]{6,}/gi,
  // URLs with embedded credentials
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@]+:[^\s/@]+@[^\s"']+/gi,
]

export const REDACTION_PLACEHOLDER = '[REDACTED]'

/**
 * Redact credential-looking material from text before it leaves the process.
 * Returns { text, redacted: boolean, removedChars: number }.
 */
export function redactSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) return { text: text ?? '', redacted: false, removedChars: 0 }
  let output = text
  let removed = 0
  for (const pattern of SECRET_PATTERNS) {
    output = output.replace(pattern, (match) => {
      removed += match.length
      return REDACTION_PLACEHOLDER
    })
  }
  return { text: output, redacted: removed > 0, removedChars: removed }
}

/**
 * Redact a structured state object (values only, keys preserved).
 * Returns { state, redacted, removedChars }.
 */
export function redactState(state) {
  if (typeof state === 'string') return redactSecrets(state)
  let removed = 0
  const walk = (value) => {
    if (typeof value === 'string') {
      const result = redactSecrets(value)
      removed += result.removedChars
      return result.text
    }
    if (Array.isArray(value)) return value.map(walk)
    if (value && typeof value === 'object') {
      const out = {}
      for (const [key, entry] of Object.entries(value)) out[key] = walk(entry)
      return out
    }
    return value
  }
  const redacted = walk(state)
  return { state: redacted, redacted: removed > 0, removedChars: removed }
}

export function hashId(text) {
  let h1 = 0x811c9dc5
  for (let i = 0; i < text.length; i += 1) {
    h1 ^= text.charCodeAt(i)
    h1 = Math.imul(h1, 0x01000193)
  }
  return (h1 >>> 0).toString(16).padStart(8, '0')
}

/**
 * Mandatory deterministic security rules evaluated BEFORE the model.
 * Returns { decision: 'DENY'|'ESCALATE'|null, ruleId, reason }.
 *
 * These mirror OpenFox's own hard rules; a model can only ever be consulted
 * after they pass, and can never downgrade them.
 */
const HARD_DENY = [
  {
    id: 'wipe_home_or_root',
    reason: 'Recursive deletion of home or root directories is prohibited.',
    test: (op) => /\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b[^\n]*\s(?:~|\/(?:\*|home|etc|var|usr|opt|root)?)(?=[\s/*]|$)/.test(op.command ?? ''),
    decision: 'DENY',
  },
  {
    id: 'fork_bomb',
    reason: 'Fork bombs are prohibited.',
    test: (op) => /:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;/.test(op.command ?? ''),
    decision: 'DENY',
  },
  {
    id: 'format_disk',
    reason: 'Formatting block devices is prohibited.',
    test: (op) => /\b(?:mkfs\.\w+|fdisk|parted|diskpart)\b/.test(op.command ?? ''),
    decision: 'DENY',
  },
  {
    id: 'dd_to_device',
    reason: 'Raw writes to block devices are prohibited.',
    test: (op) => /\bdd\b[^\n]*\bof=\/dev\/(?:sd|hd|nvme|disk)/.test(op.command ?? ''),
    decision: 'DENY',
  },
  {
    id: 'force_push_protected',
    reason: 'Force-pushing to protected branches is prohibited.',
    test: (op) => /\bgit\b[^\n|;&]*\bpush\b[^\n|;&]*(?:\s--force|\s-f\b)[^\n|;&]*\b(?:main|master)\b/.test(op.command ?? ''),
    decision: 'DENY',
  },
  {
    id: 'private_key_access',
    reason: 'Accessing private key material is prohibited.',
    test: (op) =>
      (op.paths ?? []).some((p) => /(?:^|\/)(?:id_(?:rsa|ed25519|ecdsa|dsa)|[^/]*\.pem|[^/]*\.key)$/.test(p)) ||
      /\b(?:cat|less|head|tail|cp|scp)\s+[^\n]*\b(?:id_(?:rsa|ed25519)|[^/\s]+\.pem|[^/\s]+\.key)\b/.test(op.command ?? ''),
    decision: 'DENY',
  },
  {
    id: 'secret_folder_access',
    reason: 'Access to secret key directories or shadow password files is prohibited.',
    test: (op) =>
      (op.paths ?? []).some((p) => {
        const normalized = (p ?? '').replace(/\/+$/, '')
        return (
          /(^|\/)\.ssh(\/|$)/.test(normalized) ||
          /(^|\/)\.gnupg(\/|$)/.test(normalized) ||
          normalized === '/etc/shadow' ||
          normalized === '/etc/gshadow'
        )
      }),
    decision: 'DENY',
  },
  {
    id: 'sensitive_file_access',
    reason: 'Access to files that may contain secrets requires human confirmation.',
    test: (op) => op.reason === 'sensitive_file' || op.reason === 'both',
    decision: 'ESCALATE',
  },
  {
    id: 'home_or_root_access',
    reason: 'Access to the home directory or the filesystem root is too broad for automatic approval.',
    test: (op) =>
      (op.paths ?? []).some((p) => {
        const normalized = (p ?? '').replace(/\/+$/, '')
        return p === '/' || normalized === homedir()
      }),
    decision: 'ESCALATE',
  },
  {
    id: 'git_no_verify',
    reason: 'Bypassing git hooks (--no-verify) requires explicit human confirmation.',
    test: (op) => /\bgit\b[^\n|;&]*\s--no-verify\b/.test(op.command ?? ''),
    decision: 'ESCALATE',
  },
  {
    id: 'force_push',
    reason: 'Force-pushing rewrites history and requires human approval.',
    test: (op) => /\bgit\b[^\n|;&]*\bpush\b[^\n|;&]*(?:\s--force(?:-with-lease)?|\s-f\b)/.test(op.command ?? ''),
    decision: 'ESCALATE',
  },
  {
    id: 'privilege_escalation',
    reason: 'Privilege escalation requires human approval.',
    test: (op) => /(?:^|[\s;&|])sudo\s|\brunas\b|Start-Process\b[^\n]*-Verb\s+RunAs/i.test(op.command ?? ''),
    decision: 'ESCALATE',
  },
  {
    id: 'destructive_rm',
    reason: 'Recursive deletion is a destructive shell operation and requires human confirmation.',
    test: (op) => /\brm\s+-[a-z]*[rf][a-z]*\b/.test(op.command ?? ''),
    decision: 'ESCALATE',
  },
  {
    id: 'write_outside_project',
    reason: 'Writing files outside the project requires human confirmation.',
    test: (op) => {
      if (op.tool !== 'write_file' && op.tool !== 'edit_file') return false
      const workdir = op.workdir ?? ''
      return (op.paths ?? []).some(
        (p) =>
          !p.startsWith('/tmp/') &&
          !p.startsWith('/var/tmp/') &&
          (!workdir || !p.startsWith(workdir)),
      )
    },
    decision: 'ESCALATE',
  },
  {
    id: 'git_mutation',
    reason: 'State-changing git operations require human confirmation.',
    test: (op) =>
      /\bgit\b\s+(?:commit|push|merge|rebase|reset|checkout|switch|restore|stash|tag|branch|cherry-pick|revert|clean|mv|rm|add|am|pull|fetch\s+--prune)\b/.test(
        op.command ?? '',
      ),
    decision: 'ESCALATE',
  },
]

/**
 * Evaluate mandatory security rules for a reviewed operation.
 * @param {{ tool?: string, command?: string, paths?: string[], description?: string }} operation
 */
export function evaluateSecurity(operation) {
  const op = {
    tool: operation?.tool ?? '',
    command: operation?.command ?? operation?.description ?? '',
    paths: Array.isArray(operation?.paths) ? operation.paths : [],
    workdir: operation?.workdir ?? '',
    reason: operation?.reason ?? null,
  }
  for (const rule of HARD_DENY) {
    if (rule.test(op)) return { decision: rule.decision, ruleId: rule.id, reason: rule.reason }
  }
  return { decision: null, ruleId: null, reason: null }
}