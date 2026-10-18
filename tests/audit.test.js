import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createAuditLog, keyedHash } from '../src/audit.js'

function tempAudit(opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'jev-audit-priv-'))
  const log = createAuditLog({ filePath: join(dir, 'd.jsonl'), ...opts })
  return { dir, log }
}

describe('audit log privacy', () => {
  it('by default stores metadata only — no raw operation text', () => {
    const { dir, log } = tempAudit()
    try {
      log.record({ decision: 'APPROVE', operation: 'curl https://api.test -d "payload=value" --flag' })
      const content = readFileSync(join(dir, 'd.jsonl'), 'utf8')
      assert.ok(!content.includes('curl https://api.test'), 'raw command must not be stored by default')
      assert.ok(!content.includes('payload=value'), 'raw payload must not be stored by default')
      const row = JSON.parse(content.trim().split('\n')[0])
      assert.equal(row.operationRedacted, null, 'operationRedacted is null in metadata-only mode')
      assert.ok(row.operationHash, 'a keyed hash is still recorded')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('verboseOperation is an explicit opt-in and stores redacted text only', () => {
    const { dir, log } = tempAudit({ verboseOperation: true })
    try {
      log.record({ decision: 'APPROVE', operation: 'curl -H "Authorization: Bearer sk-abcdef1234567890" https://x.test' })
      const content = readFileSync(join(dir, 'd.jsonl'), 'utf8')
      const row = JSON.parse(content.trim().split('\n')[0])
      assert.ok(row.operationRedacted, 'verbose mode stores the redacted operation')
      assert.ok(!content.includes('sk-abcdef1234567890'), 'secrets stay redacted even in verbose mode')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('verboseOperation: false (explicit) stores no operation text', () => {
    const { dir, log } = tempAudit({ verboseOperation: false })
    try {
      log.record({ decision: 'APPROVE', operation: 'npm publish' })
      const content = readFileSync(join(dir, 'd.jsonl'), 'utf8')
      const row = JSON.parse(content.trim().split('\n')[0])
      assert.equal(row.operationRedacted, null)
      assert.ok(!content.includes('npm publish'))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('a callback verboseOperation is evaluated per record — live toggling applies without recreating the logger', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-audit-priv-'))
    let verbose = false
    const log = createAuditLog({ filePath: join(dir, 'd.jsonl'), verboseOperation: () => verbose })
    try {
      log.record({ decision: 'APPROVE', operation: 'first op' })
      verbose = true
      log.record({ decision: 'APPROVE', operation: 'second op' })
      verbose = false
      log.record({ decision: 'APPROVE', operation: 'third op' })
      const rows = readFileSync(join(dir, 'd.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
      assert.equal(rows[0].operationRedacted, null, 'off at record time → metadata only')
      assert.equal(rows[1].operationRedacted, 'second op', 'on at record time → redacted text stored')
      assert.equal(rows[2].operationRedacted, null, 'toggled back off → metadata only')
      assert.ok(rows.every((r) => r.operationHash), 'keyed fingerprint preserved in every mode')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('secrets never reach the audit log when a callback enables verbose logging', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-audit-priv-'))
    const log = createAuditLog({ filePath: join(dir, 'd.jsonl'), verboseOperation: () => true })
    try {
      log.record({ decision: 'APPROVE', operation: 'curl -H "Authorization: Bearer sk-abcdef1234567890" https://x.test' })
      const content = readFileSync(join(dir, 'd.jsonl'), 'utf8')
      assert.ok(!content.includes('sk-abcdef1234567890'), 'secret must stay redacted under a callback-enabled verbose log')
      assert.ok(content.includes('[REDACTED]'))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('keyedHash is stable for a fixed key, differs across texts and across keys', () => {
    const k1 = Buffer.from('key-one')
    const k2 = Buffer.from('key-two')
    assert.equal(keyedHash(k1, 'git status'), keyedHash(k1, 'git status'))
    assert.notEqual(keyedHash(k1, 'git status'), keyedHash(k1, 'git push'))
    assert.notEqual(keyedHash(k1, 'git status'), keyedHash(k2, 'git status'))
    assert.match(keyedHash(k1, 'git status'), /^[0-9a-f]{32}$/)
  })

  it('two logs with different keys fingerprint the same operation differently', () => {
    const a = tempAudit({ hmacKey: Buffer.from('alpha') })
    const b = tempAudit({ hmacKey: Buffer.from('beta') })
    try {
      a.log.record({ decision: 'APPROVE', operation: 'git status' })
      b.log.record({ decision: 'APPROVE', operation: 'git status' })
      const r1 = JSON.parse(readFileSync(join(a.dir, 'd.jsonl'), 'utf8').trim().split('\n')[0])
      const r2 = JSON.parse(readFileSync(join(b.dir, 'd.jsonl'), 'utf8').trim().split('\n')[0])
      assert.notEqual(r1.operationHash, r2.operationHash)
    } finally {
      rmSync(a.dir, { recursive: true, force: true })
      rmSync(b.dir, { recursive: true, force: true })
    }
  })

  it('writes the log with 0600 permissions', () => {
    const { dir, log } = tempAudit()
    try {
      log.record({ decision: 'APPROVE', operation: 'x' })
      assert.equal(statSync(join(dir, 'd.jsonl')).mode & 0o777, 0o600)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('record() never throws even when the log path is unwritable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-audit-priv2-'))
    try {
      const blocker = join(dir, 'blocker')
      writeFileSync(blocker, 'x')
      const log = createAuditLog({ filePath: join(blocker, 'd.jsonl') })
      assert.doesNotThrow(() => log.record({ decision: 'APPROVE', operation: 'x' }))
      assert.ok(log.failures > 0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('rotation keeps bounded storage', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-audit-priv3-'))
    try {
      const path = join(dir, 'rot.jsonl')
      const log = createAuditLog({ filePath: path, maxBytes: 500, keep: 1 })
      for (let i = 0; i < 50; i += 1) log.record({ decision: 'ESCALATE', operation: `op-${i}` })
      assert.ok(existsSync(path))
      assert.ok(existsSync(`${path}.1`))
      assert.ok(statSync(path).size < 2000)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
