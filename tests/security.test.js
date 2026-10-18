import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { mkdtempSync, mkdirSync, rmSync, symlinkSync } from 'node:fs'
import { redactSecrets, redactState, evaluateSecurity, hashId } from '../src/security.js'

describe('secret redaction', () => {
  it('redacts bearer tokens', () => {
    const { text, redacted } = redactSecrets('curl -H "Authorization: Bearer sk-abcdef1234567890" https://x.test')
    assert.equal(redacted, true)
    assert.ok(!text.includes('sk-abcdef1234567890'))
    assert.ok(text.includes('[REDACTED]'))
  })

  it('redacts private key blocks', () => {
    const input = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----'
    const { text, redacted } = redactSecrets(input)
    assert.equal(redacted, true)
    assert.ok(!text.includes('MIIEvQIBADANBg'))
  })

  it('redacts api_key=value pairs', () => {
    const { text } = redactSecrets('api_key=supersecretvalue123')
    assert.ok(!text.includes('supersecretvalue123'))
  })

  it('redacts URLs with embedded credentials', () => {
    const { text } = redactSecrets('git clone https://user:pass@example.com/repo.git')
    assert.ok(!text.includes('user:pass@'))
  })

  it('leaves clean text untouched', () => {
    const { text, redacted } = redactSecrets('git status')
    assert.equal(redacted, false)
    assert.equal(text, 'git status')
  })

  it('redacts nested state objects', () => {
    const { state, redacted } = redactState({ command: 'curl -H "Bearer sk-abcdefghijkl" x', nested: { token: 'ghp_abcdefghij12345' } })
    assert.equal(redacted, true)
    assert.ok(!JSON.stringify(state).includes('sk-abcdefghijkl'))
    assert.ok(!JSON.stringify(state).includes('ghp_abcdefghij12345'))
  })

  it('hashes are stable and non-reversible enough for audit ids', () => {
    assert.equal(hashId('git status'), hashId('git status'))
    assert.notEqual(hashId('git status'), hashId('git push'))
    assert.match(hashId('anything'), /^[0-9a-f]{8}$/)
  })
})

describe('mandatory security rules', () => {
  it('denies recursive deletion of home/root', () => {
    const r = evaluateSecurity({ tool: 'run_command', command: 'rm -rf /' })
    assert.equal(r.decision, 'DENY')
    assert.equal(r.ruleId, 'wipe_home_or_root')
  })

  it('denies fork bombs', () => {
    assert.equal(evaluateSecurity({ command: ':(){ :|:& };:' }).decision, 'DENY')
  })

  it('denies disk formatting', () => {
    assert.equal(evaluateSecurity({ command: 'mkfs.ext4 /dev/sda1' }).decision, 'DENY')
  })

  it('denies dd to block devices', () => {
    assert.equal(evaluateSecurity({ command: 'dd if=image.iso of=/dev/sda' }).decision, 'DENY')
  })

  it('denies force-push to main', () => {
    const r = evaluateSecurity({ command: 'git push --force origin main' })
    assert.equal(r.decision, 'DENY')
    assert.equal(r.ruleId, 'force_push_protected')
  })

  it('escalates force-push to other branches', () => {
    const r = evaluateSecurity({ command: 'git push -f origin feature' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'force_push')
  })

  it('escalates git --no-verify', () => {
    const r = evaluateSecurity({ command: 'git commit -m "x" --no-verify' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'git_no_verify')
  })

  it('escalates privilege escalation (sudo)', () => {
    const r = evaluateSecurity({ command: 'sudo systemctl restart nginx' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'privilege_escalation')
  })

  it('denies private key file access via paths', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: ['/home/u/.ssh/id_rsa'] })
    assert.equal(r.decision, 'DENY')
    assert.equal(r.ruleId, 'private_key_access')
  })

  it('denies private key access via command', () => {
    assert.equal(evaluateSecurity({ command: 'cat ~/.ssh/id_ed25519' }).decision, 'DENY')
  })

  it('allows routine read-only git', () => {
    const r = evaluateSecurity({ command: 'git status' })
    assert.equal(r.decision, null)
    assert.equal(evaluateSecurity({ command: 'git diff HEAD' }).decision, null)
    assert.equal(evaluateSecurity({ command: 'git log --oneline -10' }).decision, null)
  })

  it('escalates state-changing git operations', () => {
    const r = evaluateSecurity({ command: 'git commit -m "x"' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'git_mutation')
    assert.equal(evaluateSecurity({ command: 'git push origin feature' }).ruleId, 'git_mutation')
    assert.equal(evaluateSecurity({ command: 'git checkout dev' }).ruleId, 'git_mutation')
  })

  it('escalates writes outside the project', () => {
    const r = evaluateSecurity({ tool: 'write_file', paths: ['/etc/hosts'], workdir: '/workspace/project' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'write_outside_project')
    assert.equal(
      evaluateSecurity({ tool: 'write_file', paths: ['/workspace/project/src/a.js'], workdir: '/workspace/project' }).decision,
      null,
    )
    assert.equal(
      evaluateSecurity({ tool: 'write_file', paths: ['/tmp/scratch.txt'], workdir: '/workspace/project' }).decision,
      null,
    )
  })

  it('escalates destructive rm even on build output', () => {
    const r = evaluateSecurity({ command: 'rm -rf build/' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'destructive_rm')
  })

  it('allows routine build commands', () => {
    assert.equal(evaluateSecurity({ command: 'npm run build' }).decision, null)
  })

  it('allows routine file operations inside workdir', () => {
    assert.equal(
      evaluateSecurity({ tool: 'write_file', paths: ['/workspace/project/src/a.js'], workdir: '/workspace/project' }).decision,
      null,
    )
  })

  it('does not flag --no-verify outside git', () => {
    assert.equal(evaluateSecurity({ command: 'grep --no-verify foo bar' }).decision, null)
  })
})

describe('file access security rules', () => {
  it('denies access to the .ssh folder', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: ['/home/u/.ssh'], workdir: '/w', reason: 'outside_workdir' })
    assert.equal(r.decision, 'DENY')
    assert.equal(r.ruleId, 'secret_folder_access')
  })

  it('denies access to files inside the .ssh folder', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: ['/home/u/.ssh/known_hosts'], workdir: '/w', reason: 'outside_workdir' })
    assert.equal(r.decision, 'DENY')
    assert.equal(r.ruleId, 'secret_folder_access')
  })

  it('denies access to the .gnupg folder', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: ['/root/.gnupg'], workdir: '/w', reason: 'outside_workdir' })
    assert.equal(r.decision, 'DENY')
    assert.equal(r.ruleId, 'secret_folder_access')
  })

  it('denies access to shadow password files', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: ['/etc/shadow'], workdir: '/w', reason: 'outside_workdir' })
    assert.equal(r.decision, 'DENY')
    assert.equal(r.ruleId, 'secret_folder_access')
    assert.equal(
      evaluateSecurity({ tool: 'read_file', paths: ['/etc/gshadow'], workdir: '/w', reason: 'outside_workdir' }).ruleId,
      'secret_folder_access',
    )
  })

  it('does not deny unrelated paths that merely resemble the patterns', () => {
    assert.equal(
      evaluateSecurity({ tool: 'read_file', paths: ['/srv/data/ssh-config-notes.md'], workdir: '/w', reason: 'outside_workdir' }).decision,
      null,
    )
    assert.equal(evaluateSecurity({ tool: 'read_file', paths: ['/etc/shadowcopy'], workdir: '/w', reason: 'outside_workdir' }).decision, null)
  })

  it('escalates upstream sensitive-file reasons before the model', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: ['/w/.env'], workdir: '/w', reason: 'sensitive_file' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'sensitive_file_access')
    assert.equal(
      evaluateSecurity({ tool: 'write_file', paths: ['/etc/hosts', '/w/.env'], workdir: '/w', reason: 'both' }).ruleId,
      'sensitive_file_access',
    )
  })

  it('escalates file access to the home directory', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: [homedir()], workdir: '/w', reason: 'outside_workdir' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'home_or_root_access')
  })

  it('escalates file access to the filesystem root', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: ['/'], workdir: '/w', reason: 'outside_workdir' })
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'home_or_root_access')
  })

  it('hard deny still wins over the sensitive-file reason', () => {
    const r = evaluateSecurity({ tool: 'read_file', paths: ['/home/u/.ssh/id_rsa'], workdir: '/w', reason: 'both' })
    assert.equal(r.decision, 'DENY')
    assert.equal(r.ruleId, 'private_key_access')
  })

  it('command confirmations are unaffected by the new path rules', () => {
    assert.equal(
      evaluateSecurity({ tool: 'run_command', command: 'git status', workdir: '/w', reason: 'dangerous_command' }).decision,
      null,
    )
  })
})

describe('secure project path containment', () => {
  const WORK = '/workspace/project'
  const writeOp = (path, workdir = WORK) => evaluateSecurity({ tool: 'write_file', paths: [path], workdir })

  it('escalates a sibling directory that shares the workdir prefix', () => {
    const r = writeOp('/workspace/project-evil/x.js')
    assert.equal(r.decision, 'ESCALATE')
    assert.equal(r.ruleId, 'write_outside_project')
  })

  it('rejects ../ traversal that lands outside the workdir', () => {
    assert.equal(writeOp('/workspace/project/../project-evil/x.js').decision, 'ESCALATE')
  })

  it('rejects deep ../ traversal escaping to /etc', () => {
    assert.equal(writeOp('/workspace/project/../../etc/passwd').decision, 'ESCALATE')
  })

  it('allows a relative path that stays inside the workdir', () => {
    assert.equal(writeOp('src/a.js').decision, null)
  })

  it('rejects a relative path that escapes the workdir', () => {
    assert.equal(writeOp('../evil.js').decision, 'ESCALATE')
  })

  it('allows a non-existing target inside the workdir', () => {
    assert.equal(writeOp('/workspace/project/new/deep/file.txt').decision, null)
  })

  it('escalates writes to the filesystem root', () => {
    assert.equal(writeOp('/').decision, 'ESCALATE')
  })

  it('escalates writes to the home directory', () => {
    assert.equal(evaluateSecurity({ tool: 'edit_file', paths: [homedir()], workdir: '/w' }).decision, 'ESCALATE')
  })

  it('handles Windows-style paths textually', () => {
    const win = (path, workdir) => evaluateSecurity({ tool: 'write_file', paths: [path], workdir })
    assert.equal(win('C:/workspace/project/src/a.js', 'C:/workspace/project').decision, null)
    assert.equal(win('C:/workspace/project-evil/x.js', 'C:/workspace/project').decision, 'ESCALATE')
    assert.equal(win('C:/workspace/project/../evil.js', 'C:/workspace/project').decision, 'ESCALATE')
  })

  it('catches a symlink inside the workdir that points outside', () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-contain-'))
    try {
      const work = join(dir, 'work')
      mkdirSync(work)
      symlinkSync('/etc', join(work, 'link'))
      assert.equal(evaluateSecurity({ tool: 'write_file', paths: [join(work, 'ok.txt')], workdir: work }).decision, null)
      const escaped = evaluateSecurity({ tool: 'write_file', paths: [join(work, 'link', 'passwd')], workdir: work })
      assert.equal(escaped.decision, 'ESCALATE')
      assert.equal(escaped.ruleId, 'write_outside_project')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('keeps the /tmp and /var/tmp exceptions narrow (no sibling prefix)', () => {
    assert.equal(writeOp('/tmp/scratch.txt').decision, null)
    assert.equal(writeOp('/var/tmp/scratch.txt').decision, null)
    assert.equal(writeOp('/tmp-evil/x.txt').decision, 'ESCALATE')
  })
})