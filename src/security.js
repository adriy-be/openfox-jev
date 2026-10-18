import { homedir } from 'node:os'
import { lstatSync, readlinkSync, realpathSync } from 'node:fs'
import { posix } from 'node:path'

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

const WRITE_TOOLS = new Set(['write_file', 'edit_file'])

/**
 * Explicit description for pure File Access requests (no command/description).
 * Judging an empty operation is unreliable, so the model and the deterministic
 * rules are both given this synthesized text instead of a blank.
 */
export function fileAccessOperation(context) {
  const paths = Array.isArray(context?.paths) ? context.paths.filter(Boolean) : []
  if (paths.length === 0) return ''
  const access = WRITE_TOOLS.has(context?.tool) ? 'write' : 'read'
  const reason = context?.reason ? ` — reason: ${context.reason}` : ''
  return `File access request: ${context?.tool ?? 'unknown tool'} wants ${access} access to ${paths.join(', ')}${reason}`
}

/**
 * Canonical operation-text selection. The first non-blank of
 * command/description, else the synthesized File Access description, else ''.
 * Deterministic security rules, model state and the audit id all derive their
 * operation text from this single source so they can never judge different
 * texts. An empty or whitespace-only command cannot bypass the rules.
 */
export function resolveOperationText(context) {
  const direct = [context?.command, context?.description].find((s) => typeof s === 'string' && s.trim() !== '')
  if (direct !== undefined) return direct
  return fileAccessOperation(context)
}

/**
 * Textual path normalization for containment checks. Unifies separators,
 * resolves `.`/`..` segments, and resolves relative paths against `base`.
 * Handles both POSIX and Windows (drive-letter) paths as plain text.
 */
export function normalizePathText(p, base) {
  if (typeof p !== 'string' || p.length === 0) return ''
  let s = p.replace(/\\/g, '/')
  const drive = /^[a-zA-Z]:/.test(s) ? s.slice(0, 2) : ''
  if (drive) s = s.slice(2)
  const rooted = s.startsWith('/')
  if (!rooted) {
    const b = base ? base.replace(/\\/g, '/').replace(/^[a-zA-Z]:/, '') : ''
    s = (b.startsWith('/') ? b : '/' + b) + '/' + s
  }
  const norm = posix.normalize(s)
  return drive ? drive + norm : norm
}

function tryRealpath(p) {
  try {
    return realpathSync(p).replace(/\\/g, '/')
  } catch {
    return null
  }
}

/**
 * Absolute form of `candidate` without lexical `.`/`..` resolution, so that
 * symlink segments and `..` survive for the filesystem to resolve. Relative
 * candidates are joined onto `workdir` verbatim.
 */
function originalAbsPath(candidate, workdir) {
  let s = candidate.replace(/\\/g, '/')
  if (!s.startsWith('/') && !/^[a-zA-Z]:/.test(s)) {
    const base = workdir.replace(/\\/g, '/').replace(/\/+$/, '')
    s = base + '/' + s
  }
  return s
}

/**
 * Physical path resolution, mirroring how the OS resolves a path: symlinks are
 * followed and `..` steps back from the CURRENT physical location, not the
 * textual one. Node's realpathSync resolves `symlink/..` logically (back to the
 * symlink's own directory), which hides exactly the escape we must catch, so
 * the path is resolved component by component here instead.
 *
 * Handles both POSIX (/…) and Windows (X:…) roots: a drive letter is treated
 * as the root exactly like `/`, so containment works identically on both.
 *
 * Returns the physical absolute path (deepest existing prefix plus any
 * non-existing tail), or null when the path is unresolvable (symlink loop).
 */
export function resolvePhysicalPath(p, maxSymlinks = 40) {
  const s = p.replace(/\\/g, '/')
  const drive = /^[a-zA-Z]:/.test(s) ? s.slice(0, 2) : null
  let base = drive || '/'
  const comps = (drive ? s.slice(2) : s).split('/').filter((c) => c !== '' && c !== '.')
  const stack = []
  let symlinks = 0
  let i = 0
  const abs = () => (base === '/' ? (stack.length ? '/' + stack.join('/') : '/') : base + '/' + stack.join('/'))
  while (i < comps.length) {
    const comp = comps[i]
    if (comp === '..') {
      stack.pop()
      i += 1
      continue
    }
    stack.push(comp)
    const candidate = abs()
    let st
    try {
      st = lstatSync(candidate)
    } catch {
      const tail = comps.slice(i + 1).join('/')
      return abs() + (tail ? '/' + tail : '')
    }
    if (st.isSymbolicLink()) {
      symlinks += 1
      if (symlinks > maxSymlinks) return null
      const target = readlinkSync(candidate).replace(/\\/g, '/')
      stack.pop()
      const targetDrive = /^[a-zA-Z]:/.test(target) ? target.slice(0, 2) : null
      if (target.startsWith('/') || targetDrive) {
        base = targetDrive || '/'
        stack.length = 0
      }
      const targetComps = target.replace(/^[a-zA-Z]:/, '').split('/').filter((c) => c !== '' && c !== '.')
      comps.splice(i, 1, ...targetComps)
      continue
    }
    i += 1
  }
  return abs()
}

/**
 * Whether `candidate` is contained within `workdir`. Conservative and
 * fail-closed: an empty/ambiguous workdir, a textual escape, or a symlink that
 * resolves outside the workdir all count as NOT contained (→ escalate).
 *
 * Symlink escapes are detected by physically resolving the ORIGINAL (not
 * lexically normalized) path: normalization would collapse `symlink/..` to the
 * textual parent and hide the escape, whereas the kernel resolves the symlink
 * before the `..`. Unresolvable paths (symlink loops) are rejected.
 */
export function isWithinProject(candidate, workdir) {
  if (!workdir || !candidate) return false
  const rootNorm = normalizePathText(workdir)
  const candNorm = normalizePathText(candidate, workdir)
  if (candNorm !== rootNorm && !candNorm.startsWith(rootNorm + '/')) return false
  const rootReal = tryRealpath(workdir)
  if (!rootReal) return true
  // Physical resolution runs for POSIX and Windows (drive-letter) roots alike.
  const candReal = resolvePhysicalPath(originalAbsPath(candidate, workdir))
  if (candReal === null) return false
  return candReal === rootReal || candReal.startsWith(rootReal + '/')
}

const TMP_EXCEPTIONS = ['/tmp', '/var/tmp']

function isTmpException(path) {
  return TMP_EXCEPTIONS.some((t) => isWithinProject(path, t))
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
      return (op.paths ?? []).some((p) => !isTmpException(p) && !isWithinProject(p, workdir))
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
    command: resolveOperationText(operation),
    paths: Array.isArray(operation?.paths) ? operation.paths : [],
    workdir: operation?.workdir ?? '',
    reason: operation?.reason ?? null,
  }
  for (const rule of HARD_DENY) {
    if (rule.test(op)) return { decision: rule.decision, ruleId: rule.id, reason: rule.reason }
  }
  return { decision: null, ruleId: null, reason: null }
}