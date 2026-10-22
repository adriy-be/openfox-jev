import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { register } from '../src/index.js'
import { createAuditLog } from '../src/audit.js'

process.env.OPENFOX_JEV_LOG = join(tmpdir(), 'openfox-jev-test-log.jsonl')

function jevAnswer(choice = 'APPROVE') {
  return {
    model: 'jev-style',
    answers: {
      verdict: {
        type: 'choice',
        choice,
        confidence: 0.9,
        probabilities:
          choice === 'APPROVE'
            ? { APPROVE: 0.9, ESCALATE: 0.07, DENY: 0.03 }
            : { APPROVE: 0.05, ESCALATE: 0.15, DENY: 0.8 },
      },
      destructive: { type: 'noul', noul: 0.05 },
      reads_secrets: { type: 'noul', noul: 0.02 },
      exfiltration: { type: 'noul', noul: 0.01 },
      self_advocating: { type: 'noul', noul: 0.01 },
      policy_allows: { type: 'noul', noul: 0.95 },
      blast_radius: { type: 'score', score: 0.4 },
    },
    usage: { input_tokens: 120, output_tokens: 0 },
    latency_ms: 3,
  }
}

let auditDir

function makeRegistry(settings, providerAccess, projectSettings) {
  const registered = { settings: null, reviewers: [], rpc: new Map() }
  const registry = {
    context: {
      id: 'openfox-jev',
      version: '1.0.0',
      runtime: { mode: 'test', configDirectory: auditDir },
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      storage: { get: () => undefined, set() {} },
      settings: (scope, projectId, options) =>
        scope === 'project' && projectId ? (options?.onlyStored ? (projectSettings ?? {}) : {}) : settings,
      notify() {},
      publish() {},
      ...(providerAccess ? { providerAccess } : {}),
    },
    registerSettings: (schema) => {
      registered.settings = schema
    },
    registerApprovalReviewer: (reviewer) => {
      registered.reviewers.push(reviewer)
    },
    registerRpc: (method, handler) => {
      registered.rpc.set(method, handler)
    },
  }
  register(registry)
  return registered
}

function providerAccessStub(providers, responder) {
  return {
    listProviders: () => providers,
    getProvider: (id) => providers.find((p) => p.id === id),
    requestJson: responder,
  }
}

const OPENROUTER = {
  id: 'or-1',
  name: 'OpenRouter',
  url: 'https://openrouter.ai/api/v1',
  backend: 'openai',
  isActive: true,
  hasCredential: true,
  models: ['nace-ai/drex-v2.0'],
}

const ROUTINE = { kind: 'path', tool: 'run_command', command: 'git status', workdir: '/w', sessionId: 's1' }

describe('plugin registration (OpenFox API v2)', () => {
  let registered
  before(() => {
    auditDir = mkdtempSync(join(tmpdir(), 'jev-int-'))
  })
  after(() => {
    rmSync(auditDir, { recursive: true, force: true })
  })

  it('registers settings, an approval reviewer and RPCs', () => {
    registered = makeRegistry({ enabled: false }, undefined)
    assert.ok(registered.settings.fields.length > 0)
    assert.equal(registered.reviewers.length, 1)
    assert.equal(registered.reviewers[0].id, 'openfox-jev')
    assert.ok(registered.rpc.has('testConnection'))
    assert.ok(registered.rpc.has('connectionStatus'))
  })

  it('settings schema has FR/EN labels and no API key fields', () => {
    const fields = registered.settings.fields
    for (const field of fields) {
      assert.ok(field.label.en && field.label.fr, `${field.key} missing FR/EN label`)
    }
    const providerKeys = fields.filter((f) => f.type === 'select' && f.key === 'providerId')
    assert.equal(providerKeys.length, 1)
    assert.equal(providerKeys[0].optionsFrom, 'providers')
    const passwordFields = fields.filter((f) => f.type === 'password')
    for (const field of passwordFields) {
      assert.ok(/local/i.test(field.key), `unexpected credential field ${field.key}`)
    }
  })

  it('default mode is shadow and default is disabled', () => {
    const mode = registered.settings.fields.find((f) => f.key === 'mode')
    assert.equal(mode.default, 'shadow')
    const enabled = registered.settings.fields.find((f) => f.key === 'enabled')
    assert.equal(enabled.default, false)
  })

  it('the decision model is free text', () => {
    const model = registered.settings.fields.find((f) => f.key === 'model')
    assert.equal(model.type, 'text')
    assert.equal(model.optionsFrom, undefined)
  })
})

describe('end-to-end approval lifecycle (mocked provider)', () => {
  let auditDir2
  before(() => {
    auditDir2 = mkdtempSync(join(tmpdir(), 'jev-e2e-'))
  })
  after(() => {
    rmSync(auditDir2, { recursive: true, force: true })
  })

  function reviewerWith(settings, responder) {
    const access = providerAccessStub([OPENROUTER], responder)
    const registered = makeRegistry(settings, access)
    return registered.reviewers[0]
  }

  it('disabled plugin: always ask, backend never called', async () => {
    let calls = 0
    const reviewer = reviewerWith({ enabled: false, providerId: 'or-1' }, async () => {
      calls += 1
      return jevAnswer()
    })
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(calls, 0)
  })

  it('shadow mode: ask regardless of verdict, backend called', async () => {
    let calls = 0
    const reviewer = reviewerWith(
      { enabled: true, mode: 'shadow', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine git allowed.' },
      async () => {
        calls += 1
        return jevAnswer('APPROVE')
      },
    )
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(calls, 1)
    assert.ok(result.meta.outcome.startsWith('shadow_'))
  })

  it('enforce mode: approve routine operation', async () => {
    const reviewer = reviewerWith(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine read-only git commands are allowed.' },
      async () => jevAnswer('APPROVE'),
    )
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'allow')
  })

  it('offline backend: safe escalation', async () => {
    const reviewer = reviewerWith(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'x' },
      async () => {
        throw new Error('fetch failed: ECONNREFUSED 127.0.0.1:8765')
      },
    )
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.errorClass, 'offline')
  })

  it('HTTP timeout: safe escalation', async () => {
    const reviewer = reviewerWith(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'x', timeoutMs: 50 },
      async () => {
        const err = new Error('The operation was aborted due to timeout')
        err.name = 'TimeoutError'
        throw err
      },
    )
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.errorClass, 'timeout')
  })

  it('provider switching: decision follows the selected provider only', async () => {
    const providers = [OPENROUTER, { ...OPENROUTER, id: 'di-1', name: 'DeepInfra', url: 'https://api.deepinfra.com/v1/openai' }]
    const seen = []
    const access = providerAccessStub(providers, async (providerId, endpointKey) => {
      seen.push({ providerId, endpointKey })
      return jevAnswer(providerId === 'di-1' ? 'DENY' : 'APPROVE')
    })
    const settings = { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'x' }
    const registered = makeRegistry(settings, access)
    const reviewer = registered.reviewers[0]

    const first = await reviewer.evaluate(ROUTINE)
    assert.equal(first.action, 'allow')

    const withDi = { ...settings, providerId: 'di-1' }
    const registered2 = makeRegistry(withDi, access)
    const second = await registered2.reviewers[0].evaluate(ROUTINE)
    assert.equal(second.action, 'deny')
    assert.deepEqual(seen, [
      { providerId: 'or-1', endpointKey: 'decisions' },
      { providerId: 'di-1', endpointKey: 'decisions' },
    ])
  })

  it('unattended/sub-agent context: mandatory fail-closed rules still apply', async () => {
    const reviewer = reviewerWith(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'x' },
      async () => jevAnswer('APPROVE'),
    )
    const result = await reviewer.evaluate({ ...ROUTINE, command: 'rm -rf /', isSubAgent: true, nightMode: true })
    assert.equal(result.action, 'deny')
    assert.equal(result.meta.ruleId, 'wipe_home_or_root')
  })

  it('one-time approval: nothing is persisted between evaluations', async () => {
    let calls = 0
    const reviewer = reviewerWith(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine git allowed.' },
      async () => {
        calls += 1
        return jevAnswer('APPROVE')
      },
    )
    const first = await reviewer.evaluate({ ...ROUTINE, paths: ['/outside/file.txt'] })
    const second = await reviewer.evaluate({ ...ROUTINE, paths: ['/outside/file.txt'] })
    assert.equal(first.action, 'allow')
    assert.equal(second.action, 'allow')
    assert.equal(calls, 2, 'each operation must be reviewed again')
    const reviewerState = JSON.stringify(reviewer)
    assert.ok(!reviewerState.includes('/outside/file.txt'), 'no path memory inside the reviewer')
  })

  it('concurrent tool calls each get an independent decision', async () => {
    const reviewer = reviewerWith(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine git allowed.' },
      async (_id, _key, body) => {
        await new Promise((r) => setTimeout(r, 10))
        return jevAnswer(body.state.includes('bad') ? 'DENY' : 'APPROVE')
      },
    )
    const results = await Promise.all([
      reviewer.evaluate({ ...ROUTINE, command: 'git status' }),
      reviewer.evaluate({ ...ROUTINE, command: 'rm -rf /' }),
      reviewer.evaluate({ ...ROUTINE, command: 'git diff' }),
    ])
    assert.deepEqual(results.map((r) => r.action), ['allow', 'deny', 'allow'])
  })

  it('connection status reports provider, model and mode but is not "running" before a probe', async () => {
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, model: 'nace-ai/drex-v2.0' },
      providerAccessStub([OPENROUTER], async () => jevAnswer()),
    )
    const status = await registered.rpc.get('connectionStatus')()
    assert.equal(status.running, false)
    assert.match(status.statusText.en, /OpenRouter/)
    assert.match(status.statusText.en, /nace-ai\/drex-v2\.0/)
    assert.match(status.statusText.en, /enforce/)
    assert.match(status.statusText.en, /not tested/)

    const probe = await registered.rpc.get('testConnection')()
    assert.equal(probe.running, true)
    const verified = await registered.rpc.get('connectionStatus')()
    assert.equal(verified.running, true)
    assert.match(verified.statusText.en, /verified/)
    assert.match(verified.statusText.en, /\d+ ms, \d+s ago/)
  })

  it('connection status warns when cloud consent is missing', async () => {
    const registered = makeRegistry(
      { enabled: true, mode: 'shadow', providerId: 'or-1', cloudConsent: false },
      providerAccessStub([OPENROUTER], async () => jevAnswer()),
    )
    const status = await registered.rpc.get('connectionStatus')()
    assert.equal(status.running, false)
    assert.match(status.statusText.en, /consent/i)
  })

  it('connection status exposes in-process counters and the last decision (no secrets)', async () => {
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine git allowed.' },
      providerAccessStub([OPENROUTER], async () => jevAnswer('APPROVE')),
    )
    const reviewer = registered.reviewers[0]
    await reviewer.evaluate(ROUTINE) // allow
    await reviewer.evaluate({ ...ROUTINE, command: 'rm -rf /' }) // mandatory deny

    const status = await registered.rpc.get('connectionStatus')()
    assert.ok(status.diagnostics, 'connectionStatus must carry the diagnostic snapshot')
    assert.deepEqual(status.diagnostics.counters, {
      confirmations: 2,
      reviewer_invocations: 1,
      skipped_before_reviewer: 1,
      backend_requests_attempted: 1,
      backend_requests_succeeded: 1,
      backend_requests_failed: 0,
      auto_approved: 1,
      manual_escalations: 0,
      denied: 1,
    })
    assert.equal(status.diagnostics.lastDecision.action, 'deny')
    assert.equal(status.diagnostics.lastDecision.ruleId, 'wipe_home_or_root')
    assert.ok(!JSON.stringify(status.diagnostics).includes('rm -rf /'), 'diagnostics must not carry operation text')
  })
})

describe('local Jev-Style backend over real loopback HTTP', () => {
  let server
  let port
  let received
  let auditDir3

  before(async () => {
    auditDir3 = mkdtempSync(join(tmpdir(), 'jev-local-'))
    received = []
    server = createServer((req, res) => {
      let body = ''
      req.on('data', (chunk) => {
        body += chunk
      })
      req.on('end', () => {
        if (req.url === '/v1/systemone' && req.method === 'POST') {
          received.push(JSON.parse(body))
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify(jevAnswer('APPROVE')))
          return
        }
        res.writeHead(404)
        res.end()
      })
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    port = server.address().port
  })

  after(() => {
    server.close()
    rmSync(auditDir3, { recursive: true, force: true })
  })

  it('sends typed questions to the local systemone endpoint and approves', async () => {
    const registered = makeRegistry(
      {
        enabled: true,
        mode: 'enforce',
        providerId: '',
        backendKind: 'local',
        localUrl: `http://127.0.0.1:${port}`,
        operatorPolicy: 'Routine read-only git commands are allowed.',
      },
      undefined,
    )
    const result = await registered.reviewers[0].evaluate(ROUTINE)
    assert.equal(result.action, 'allow')
    assert.equal(received.length, 1)
    const request = received[0]
    assert.equal(request.model, 'jev-style')
    assert.ok(request.state.includes('git status'))
    assert.ok(request.state.includes('Routine read-only git commands are allowed.'))
    assert.equal(request.questions.verdict.type, 'choice')
    assert.equal(request.questions.blast_radius.type, 'score')
    assert.equal(request.questions.self_advocating.type, 'noul')
  })

  it('local backend does not require cloud consent', async () => {
    const registered = makeRegistry(
      {
        enabled: true,
        mode: 'enforce',
        backendKind: 'local',
        localUrl: `http://127.0.0.1:${port}`,
        cloudConsent: false,
        operatorPolicy: 'x',
      },
      undefined,
    )
    const result = await registered.reviewers[0].evaluate(ROUTINE)
    assert.equal(result.action, 'allow')
  })

  it('refuses non-loopback local URLs', async () => {
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', backendKind: 'local', localUrl: 'http://192.168.1.10:8765', operatorPolicy: 'x' },
      undefined,
    )
    const result = await registered.reviewers[0].evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.outcome, 'escalated_error')
  })

  it('local server offline: safe escalation', async () => {
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', backendKind: 'local', localUrl: 'http://127.0.0.1:1', operatorPolicy: 'x' },
      undefined,
    )
    const result = await registered.reviewers[0].evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.ok(['offline', 'timeout'].includes(result.meta.errorClass))
  })
})

describe('audit log integration', () => {
  it('records one row per review with required fields', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-audit-int-'))
    try {
      const audit = createAuditLog({ filePath: join(dir, 'd.jsonl') })
      const registered = makeRegistry(
        { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine git allowed.' },
        providerAccessStub([OPENROUTER], async () => jevAnswer('APPROVE')),
      )
      // Rebuild reviewer with this audit instance
      const { createReviewer } = await import('../src/reviewer.js')
      const reviewer = createReviewer({
        getSettings: () => ({ enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine git allowed.' }),
        providerAccess: providerAccessStub([OPENROUTER], async () => jevAnswer('APPROVE')),
        audit,
      })
      await reviewer.evaluate(ROUTINE)
      const { readFileSync } = await import('node:fs')
      const rows = readFileSync(join(dir, 'd.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
      assert.equal(rows.length, 1)
      assert.equal(rows[0].decision, 'APPROVE')
      assert.equal(rows[0].humanApprovalRequired, false)
      assert.equal(rows[0].mode, 'enforce')
      assert.ok(registered.reviewers.length === 1)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('audit toggle off (register-level): no JSONL is written', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-audit-off-'))
    try {
      process.env.OPENFOX_JEV_LOG = join(dir, 'should-not-exist.jsonl')
      const registered = makeRegistry(
        { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine git allowed.', auditEnabled: false },
        providerAccessStub([OPENROUTER], async () => jevAnswer('APPROVE')),
      )
      const result = await registered.reviewers[0].evaluate(ROUTINE)
      assert.equal(result.action, 'allow')
      const { existsSync } = await import('node:fs')
      assert.equal(existsSync(join(dir, 'should-not-exist.jsonl')), false, 'register()-created audit must honor the auditEnabled toggle')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('local Jev-Style backend cancellation over real loopback HTTP', () => {
  let server
  let port
  let hits

  before(async () => {
    hits = []
    server = createServer((req, res) => {
      let body = ''
      req.on('data', (chunk) => {
        body += chunk
      })
      req.on('end', () => {
        if (req.url === '/v1/systemone' && req.method === 'POST') {
          hits.push(JSON.parse(body))
          // Deliberately slow: the cancellation test must abort before the
          // response arrives, proving the signal reaches the local fetch.
          setTimeout(() => {
            res.writeHead(200, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify(jevAnswer('APPROVE')))
          }, 2_000)
          return
        }
        res.writeHead(404)
        res.end()
      })
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    port = server.address().port
  })

  after(() => {
    server.close()
  })

  it('aborts a slow local backend request and never allows', async () => {
    const registered = makeRegistry(
      {
        enabled: true,
        mode: 'enforce',
        providerId: '',
        backendKind: 'local',
        localUrl: `http://127.0.0.1:${port}`,
        operatorPolicy: 'x',
        timeoutMs: 30_000,
      },
      undefined,
    )
    const controller = new AbortController()
    const started = Date.now()
    const pending = registered.reviewers[0].evaluate({ ...ROUTINE, signal: controller.signal })
    setTimeout(() => controller.abort(), 10)
    const result = await pending
    assert.ok(Date.now() - started < 5_000, 'cancellation must not wait for the full backend timeout')
    assert.equal(result.action, 'ask', 'a cancelled local operation must never be allowed')
    assert.equal(result.meta.errorClass, 'cancelled')
    assert.equal(result.meta.humanApprovalRequired, true)
  })
})

describe('File Access (folder access) end-to-end', () => {
  const FOLDER_ACCESS = { kind: 'path', tool: 'read_file', paths: ['/srv/git/other-project'], workdir: '/w', reason: 'outside_workdir', sessionId: 's1' }

  it('shadow mode asks for folder access even when the model approves', async () => {
    let calls = 0
    const registered = makeRegistry(
      { enabled: true, mode: 'shadow', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Reading other projects is allowed.' },
      providerAccessStub([OPENROUTER], async () => {
        calls += 1
        return jevAnswer('APPROVE')
      }),
    )
    const result = await registered.reviewers[0].evaluate(FOLDER_ACCESS)
    assert.equal(result.action, 'ask')
    assert.ok(result.meta.outcome.startsWith('shadow_'))
    assert.equal(calls, 1)
  })

  it('enforce mode approves a non-sensitive outside-workdir read, one-time only', async () => {
    let calls = 0
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Reading other projects is allowed.' },
      providerAccessStub([OPENROUTER], async () => {
        calls += 1
        return jevAnswer('APPROVE')
      }),
    )
    const first = await registered.reviewers[0].evaluate(FOLDER_ACCESS)
    const second = await registered.reviewers[0].evaluate(FOLDER_ACCESS)
    assert.equal(first.action, 'allow')
    assert.equal(second.action, 'allow')
    assert.equal(calls, 2, 'folder access is never remembered between evaluations')
  })

  it('denies .ssh folder access without contacting the backend', async () => {
    let calls = 0
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Everything is allowed.' },
      providerAccessStub([OPENROUTER], async () => {
        calls += 1
        return jevAnswer('APPROVE')
      }),
    )
    const result = await registered.reviewers[0].evaluate({ ...FOLDER_ACCESS, paths: ['/home/u/.ssh'] })
    assert.equal(result.action, 'deny')
    assert.equal(result.meta.ruleId, 'secret_folder_access')
    assert.equal(calls, 0)
  })

  it('escalates sensitive file access without contacting the backend', async () => {
    let calls = 0
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Everything is allowed.' },
      providerAccessStub([OPENROUTER], async () => {
        calls += 1
        return jevAnswer('APPROVE')
      }),
    )
    const result = await registered.reviewers[0].evaluate({ ...FOLDER_ACCESS, workdir: '/w', paths: ['/w/.env'], reason: 'sensitive_file' })
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.ruleId, 'sensitive_file_access')
    assert.equal(calls, 0)
  })

  it('escalates home directory access without contacting the backend', async () => {
    let calls = 0
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Everything is allowed.' },
      providerAccessStub([OPENROUTER], async () => {
        calls += 1
        return jevAnswer('APPROVE')
      }),
    )
    const result = await registered.reviewers[0].evaluate({ ...FOLDER_ACCESS, paths: [homedir()] })
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.ruleId, 'home_or_root_access')
    assert.equal(calls, 0)
  })

  it('audit records the file_access category for folder access', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-fa-audit-'))
    try {
      const audit = createAuditLog({ filePath: join(dir, 'd.jsonl') })
      const { createReviewer } = await import('../src/reviewer.js')
      const reviewer = createReviewer({
        getSettings: () => ({ enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Reading other projects is allowed.' }),
        providerAccess: providerAccessStub([OPENROUTER], async () => jevAnswer('APPROVE')),
        audit,
      })
      await reviewer.evaluate(FOLDER_ACCESS)
      const rows = readFileSync(join(dir, 'd.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line))
      assert.equal(rows.length, 1)
      assert.equal(rows[0].operationCategory, 'file_access')
      assert.ok(rows[0].operationHash)
      assert.equal(rows[0].operationRedacted, null, 'metadata-only by default')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('local loopback backend receives the synthesized file access operation', async () => {
    const received = []
    const server = createServer((req, res) => {
      let body = ''
      req.on('data', (chunk) => {
        body += chunk
      })
      req.on('end', () => {
        if (req.url === '/v1/systemone' && req.method === 'POST') {
          received.push(JSON.parse(body))
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify(jevAnswer('APPROVE')))
          return
        }
        res.writeHead(404)
        res.end()
      })
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      const port = server.address().port
      const registered = makeRegistry(
        {
          enabled: true,
          mode: 'enforce',
          providerId: '',
          backendKind: 'local',
          localUrl: `http://127.0.0.1:${port}`,
          operatorPolicy: 'Reading other projects is allowed.',
        },
        undefined,
      )
      const result = await registered.reviewers[0].evaluate(FOLDER_ACCESS)
      assert.equal(result.action, 'allow')
      assert.equal(received.length, 1)
      assert.ok(received[0].state.includes('File access request: read_file wants read access to /srv/git/other-project'))
    } finally {
      server.close()
    }
  })
})

describe('15-row regression matrix (mocked DeepInfra decisions endpoint)', () => {
  let server
  let port
  let hits
  let respondWith
  let delayMs
  let statusToReturn

  function fakeAnswer(overrides = {}) {
    return {
      model: 'nace-ai/drex-v2.0',
      answers: {
        verdict: {
          type: 'choice',
          choice: 'APPROVE',
          confidence: 0.9,
          probabilities: { APPROVE: 0.9, ESCALATE: 0.07, DENY: 0.03 },
        },
        destructive: { type: 'noul', noul: 0.05 },
        reads_secrets: { type: 'noul', noul: 0.02 },
        exfiltration: { type: 'noul', noul: 0.01 },
        self_advocating: { type: 'noul', noul: 0.01 },
        policy_allows: { type: 'noul', noul: 0.95 },
        blast_radius: { type: 'score', score: 0.4 },
        ...overrides,
      },
      usage: { input_tokens: 120, output_tokens: 0 },
      latency_ms: 3,
    }
  }

  before(async () => {
    hits = []
    respondWith = () => ({ status: 200, body: fakeAnswer() })
    delayMs = 0
    statusToReturn = 200
    mockDeepInfra = { id: 'di-mock', name: 'DeepInfra (mock)', url: 'https://api.deepinfra.com/v1/openai', backend: 'openai', isActive: false, hasCredential: true }
    server = createServer((req, res) => {
      let body = ''
      req.on('data', (chunk) => {
        body += chunk
      })
      req.on('end', () => {
        if (req.url !== '/v1/decisions' || req.method !== 'POST') {
          res.writeHead(404)
          res.end()
          return
        }
        hits.push(JSON.parse(body))
        setTimeout(() => {
          const { status, body: out } = respondWith(JSON.parse(body))
          res.writeHead(status, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify(out))
        }, delayMs)
      })
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    port = server.address().port
  })

  after(() => {
    server.close()
  })

  beforeEach(() => {
    hits.length = 0
    delayMs = 0
    statusToReturn = 200
    respondWith = () => ({ status: 200, body: fakeAnswer() })
  })

  let mockDeepInfra
  function CUSTOM() {
    return {
      enabled: true,
      mode: 'enforce',
      backendKind: 'custom',
      customEndpoint: `http://127.0.0.1:${port}/v1/decisions`,
      providerId: 'di-mock',
      cloudConsent: true,
      operatorPolicy: 'Routine read-only git commands are allowed.',
    }
  }

  function customReviewer(settings) {
    const access = providerAccessStub([mockDeepInfra], async () => fakeAnswer())
    return makeRegistry({ ...CUSTOM(), ...settings }, access).reviewers[0]
  }

  it('row 1 — disabled plugin: ask, backend never called, audit ruleId disabled', async () => {
    const reviewer = customReviewer({ enabled: false })
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.ruleId, 'disabled')
    assert.equal(result.meta.outcome, 'skipped_disabled')
    assert.equal(hits.length, 0)
  })

  it('row 2 — unregistered reviewer: register() survives a missing reviewer slot, host keeps native confirmations', () => {
    const registry = {
      context: {
        id: 'openfox-jev',
        version: '1.0.0',
        runtime: { mode: 'test', configDirectory: join(tmpdir()) },
        logger: { debug() {}, info() {}, warn() {}, error() {} },
        storage: { get: () => undefined, set() {} },
        settings: () => ({ enabled: true }),
        notify() {},
        publish() {},
      },
      registerSettings() {},
      // registerApprovalReviewer intentionally absent — the host never offered the slot.
      registerRpc() {},
    }
    assert.doesNotThrow(() => register(registry))
  })

  it('row 3 — shadow mode: model approves, outcome still asks (shadow_approve), one backend call', async () => {
    const reviewer = customReviewer({ mode: 'shadow' })
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.outcome, 'shadow_approve')
    assert.equal(hits.length, 1)
  })

  it('row 4 — enforce mode: confident approval of a routine operation auto-allows', async () => {
    const reviewer = customReviewer({})
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'allow')
    assert.equal(hits.length, 1)
    assert.equal(hits[0].model, 'nace-ai/drex-v2.0')
    assert.ok(hits[0].state.includes('git status'))
  })

  it('row 5 — remote backend without cloud consent: ask before any network call', async () => {
    const reviewer = customReviewer({ cloudConsent: false })
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.ruleId, 'privacy_consent')
    assert.equal(hits.length, 0)
  })

  it('row 6 — missing provider or missing credential: ask, never allow', async () => {
    const registered = makeRegistry({ enabled: true, mode: 'enforce', providerId: 'does-not-exist', cloudConsent: true, operatorPolicy: 'x' }, undefined)
    const result = await registered.reviewers[0].evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.ruleId, 'provider_unavailable')

    const deepInfra = { id: 'di-1', name: 'DeepInfra', url: 'https://api.deepinfra.com/v1/openai', backend: 'openai', isActive: false, hasCredential: false }
    const access = providerAccessStub([deepInfra], async () => {
      throw new Error('no configured credentials for provider di-1')
    })
    const registered2 = makeRegistry({ enabled: true, mode: 'enforce', providerId: 'di-1', backendKind: 'deepinfra', cloudConsent: true, operatorPolicy: 'x' }, access)
    const result2 = await registered2.reviewers[0].evaluate(ROUTINE)
    assert.equal(result2.action, 'ask')
    assert.equal(result2.meta.errorClass, 'provider_unavailable')
  })

  it('row 7 — authentication failure (401 and 403): ask, never allow', async () => {
    for (const status of [401, 403]) {
      respondWith = () => ({ status, body: { error: 'invalid api key' } })
      const reviewer = customReviewer({})
      const result = await reviewer.evaluate(ROUTINE)
      assert.equal(result.action, 'ask')
      assert.equal(result.meta.errorClass, 'auth')
      assert.equal(result.meta.outcome, 'escalated_auth')
    }
    assert.equal(hits.length, 2)
  })

  it('row 8 — invalid System One schema: ask, never allow', async () => {
    respondWith = () => ({ status: 200, body: { choices: [{ message: 'APPROVE' }] } })
    const reviewer = customReviewer({})
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.errorClass, 'invalid_response')
    assert.equal(result.meta.ruleId, 'invalid_response')
  })

  it('row 9 — confident approve (probability 0.95, blast radius 0): allowed and audited as APPROVE', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-row9-'))
    try {
      respondWith = () => ({
        status: 200,
        body: fakeAnswer({
          verdict: { type: 'choice', choice: 'APPROVE', confidence: 0.95, probabilities: { APPROVE: 0.95, ESCALATE: 0.04, DENY: 0.01 } },
          blast_radius: { type: 'score', score: 0 },
        }),
      })
      const audit = createAuditLog({ filePath: join(dir, 'd.jsonl') })
      const { createReviewer } = await import('../src/reviewer.js')
      const reviewer = createReviewer({
        getSettings: () => ({ ...CUSTOM() }),
        providerAccess: providerAccessStub([mockDeepInfra], async () => fakeAnswer()),
        audit,
      })
      const result = await reviewer.evaluate(ROUTINE)
      assert.equal(result.action, 'allow')
      assert.equal(result.meta.ruleId, 'approved')
      const rows = readFileSync(join(dir, 'd.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
      assert.equal(rows.length, 1)
      assert.equal(rows[0].decision, 'APPROVE')
      assert.equal(rows[0].ruleId, 'approved')
      assert.equal(rows[0].humanApprovalRequired, false)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('row 10 — uncertain verdict (approval probability below threshold): ask', async () => {
    respondWith = () => ({
      status: 200,
      body: fakeAnswer({ verdict: { type: 'choice', choice: 'APPROVE', confidence: 0.9, probabilities: { APPROVE: 0.5, ESCALATE: 0.3, DENY: 0.2 } } }),
    })
    const reviewer = customReviewer({})
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.ruleId, 'low_probability')
  })

  it('row 11 — mandatory security rule: rm -rf / denied before the model, zero backend calls', async () => {
    const reviewer = customReviewer({})
    const result = await reviewer.evaluate({ ...ROUTINE, command: 'rm -rf /' })
    assert.equal(result.action, 'deny')
    assert.equal(result.meta.ruleId, 'wipe_home_or_root')
    assert.equal(hits.length, 0)
  })

  it('row 12 — force push: escalated before the model, zero backend calls', async () => {
    const reviewer = customReviewer({})
    const result = await reviewer.evaluate({ ...ROUTINE, command: 'git push --force origin feature' })
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.ruleId, 'force_push')
    assert.equal(hits.length, 0)
    const protectedResult = await reviewer.evaluate({ ...ROUTINE, command: 'git push --force origin main' })
    assert.equal(protectedResult.action, 'deny')
    assert.equal(protectedResult.meta.ruleId, 'force_push_protected')
    assert.equal(hits.length, 0)
  })

  it('row 13 — backend timeout: safe escalation, never allow', async () => {
    delayMs = 2_000
    const reviewer = customReviewer({ timeoutMs: 60 })
    const result = await reviewer.evaluate(ROUTINE)
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.errorClass, 'timeout')
    assert.equal(result.meta.outcome, 'escalated_timeout')
  })

  it('row 14 — cancelled before the request: ask, zero backend calls', async () => {
    const controller = new AbortController()
    controller.abort()
    const reviewer = customReviewer({})
    const result = await reviewer.evaluate({ ...ROUTINE, signal: controller.signal })
    assert.equal(result.action, 'ask')
    assert.equal(result.meta.errorClass, 'cancelled')
    assert.equal(result.meta.ruleId, 'cancelled')
    assert.equal(hits.length, 0)
  })

  it('row 15 — plugin reload: fresh process state, counters reset, one-time approval preserved', async () => {
    const { createReviewer } = await import('../src/reviewer.js')
    const access = providerAccessStub([mockDeepInfra], async () => fakeAnswer())
    const before = createReviewer({ getSettings: () => ({ ...CUSTOM() }), providerAccess: access })
    await before.evaluate(ROUTINE)
    assert.equal(before.getDiagnostics().counters.auto_approved, 1)

    const after = createReviewer({ getSettings: () => ({ ...CUSTOM() }), providerAccess: access })
    assert.deepEqual(after.getDiagnostics().counters, {
      confirmations: 0,
      reviewer_invocations: 0,
      skipped_before_reviewer: 0,
      backend_requests_attempted: 0,
      backend_requests_succeeded: 0,
      backend_requests_failed: 0,
      auto_approved: 0,
      manual_escalations: 0,
      denied: 0,
    })
    const result = await after.evaluate(ROUTINE)
    assert.equal(result.action, 'allow', 'reload must not remember or block a previously approved operation')
    assert.equal(after.getDiagnostics().counters.auto_approved, 1, 'counters must not persist across reloads')
  })
})

describe('diagnostics counters and audit completeness', () => {
  it('counters track every outcome class and never leak operation text', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-counters-'))
    try {
      let responder = async () => jevAnswer('APPROVE')
      const audit = createAuditLog({ filePath: join(dir, 'd.jsonl') })
      const { createReviewer } = await import('../src/reviewer.js')
      const reviewer = createReviewer({
        getSettings: () => ({ enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, operatorPolicy: 'Routine git allowed.' }),
        providerAccess: providerAccessStub([OPENROUTER], (...args) => responder(...args)),
        audit,
      })

      await reviewer.evaluate(ROUTINE)
      responder = async () => {
        throw new Error('fetch failed: ECONNREFUSED 127.0.0.1:8765')
      }
      await reviewer.evaluate(ROUTINE)
      responder = async () => {
        throw new Error('Provider request failed with status 401')
      }
      await reviewer.evaluate(ROUTINE)
      await reviewer.evaluate({ ...ROUTINE, command: 'rm -rf /' })

      const { counters, lastDecision } = reviewer.getDiagnostics()
      assert.deepEqual(counters, {
        confirmations: 4,
        reviewer_invocations: 3,
        skipped_before_reviewer: 1,
        backend_requests_attempted: 3,
        backend_requests_succeeded: 1,
        backend_requests_failed: 2,
        auto_approved: 1,
        manual_escalations: 2,
        denied: 1,
      })
      assert.equal(lastDecision.action, 'deny')
      assert.equal(lastDecision.ruleId, 'wipe_home_or_root')
      const snapshot = JSON.stringify(reviewer.getDiagnostics())
      assert.ok(!snapshot.includes('rm -rf /'), 'diagnostics must not carry operation text')
      assert.ok(!snapshot.includes('sk-'), 'diagnostics must not carry credentials')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('disabled and no_provider early exits are audited with stable ruleIds', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'jev-audit-early-'))
    try {
      const audit = createAuditLog({ filePath: join(dir, 'd.jsonl') })
      const { createReviewer } = await import('../src/reviewer.js')
      const disabled = createReviewer({ getSettings: () => ({ enabled: false }), providerAccess: providerAccessStub([OPENROUTER], async () => jevAnswer()), audit })
      await disabled.evaluate(ROUTINE)
      const noProvider = createReviewer({
        getSettings: () => ({ enabled: true, mode: 'enforce' }),
        providerAccess: providerAccessStub([OPENROUTER], async () => jevAnswer()),
        audit,
      })
      await noProvider.evaluate(ROUTINE)
      const rows = readFileSync(join(dir, 'd.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
      assert.equal(rows.length, 2)
      assert.equal(rows[0].ruleId, 'disabled')
      assert.equal(rows[0].outcome, 'skipped_disabled')
      assert.equal(rows[1].ruleId, 'no_provider')
      assert.equal(rows[1].outcome, 'escalated_no_provider')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('project settings resolution (onlyStored merge)', () => {
  function captureLocalServer() {
    const received = []
    const server = createServer((req, res) => {
      let body = ''
      req.on('data', (chunk) => {
        body += chunk
      })
      req.on('end', () => {
        if (req.url === '/v1/systemone' && req.method === 'POST') {
          received.push(JSON.parse(body))
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify(jevAnswer('APPROVE')))
          return
        }
        res.writeHead(404)
        res.end()
      })
    })
    return { server, received }
  }

  it('a stored project override wins over the stored global value', async () => {
    const { server, received } = captureLocalServer()
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      const registered = makeRegistry(
        { enabled: true, mode: 'enforce', backendKind: 'local', localUrl: `http://127.0.0.1:${server.address().port}`, operatorPolicy: 'GLOBAL POLICY A' },
        undefined,
        { operatorPolicy: 'PROJECT POLICY B' },
      )
      await registered.reviewers[0].evaluate({ ...ROUTINE, projectId: 'proj-1' })
      assert.equal(received.length, 1)
      assert.ok(received[0].state.includes('PROJECT POLICY B'))
      assert.ok(!received[0].state.includes('GLOBAL POLICY A'))
    } finally {
      server.close()
    }
  })

  it('an unset project key does not clobber the stored global with a schema default', async () => {
    const { server, received } = captureLocalServer()
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      const registered = makeRegistry(
        { enabled: true, mode: 'enforce', backendKind: 'local', localUrl: `http://127.0.0.1:${server.address().port}`, operatorPolicy: 'GLOBAL POLICY A' },
        undefined,
        { mode: 'shadow' },
      )
      await registered.reviewers[0].evaluate({ ...ROUTINE, projectId: 'proj-1' })
      assert.ok(received[0].state.includes('GLOBAL POLICY A'), 'stored global must survive an unset project key')
    } finally {
      server.close()
    }
  })

  it('without a projectId the project scope is never consulted', async () => {
    const { server, received } = captureLocalServer()
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      const registered = makeRegistry(
        { enabled: true, mode: 'enforce', backendKind: 'local', localUrl: `http://127.0.0.1:${server.address().port}`, operatorPolicy: 'GLOBAL POLICY A' },
        undefined,
        { operatorPolicy: 'PROJECT POLICY B' },
      )
      await registered.reviewers[0].evaluate(ROUTINE)
      assert.ok(received[0].state.includes('GLOBAL POLICY A'))
      assert.ok(!received[0].state.includes('PROJECT POLICY B'))
    } finally {
      server.close()
    }
  })
})

describe('connection probe — genuine connectivity/protocol test', () => {
  function loopbackServer(handler) {
    const server = createServer((req, res) => {
      let body = ''
      req.on('data', (chunk) => {
        body += chunk
      })
      req.on('end', () => handler(req, res, body))
    })
    return server
  }

  it('reports success only when the backend returns a valid System One schema (local, no provider)', async () => {
    const server = loopbackServer((req, res) => {
      if (req.url === '/v1/systemone' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(jevAnswer('APPROVE')))
        return
      }
      res.writeHead(404)
      res.end()
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      const port = server.address().port
      const registered = makeRegistry({ enabled: true, mode: 'enforce', providerId: '', backendKind: 'local', localUrl: `http://127.0.0.1:${port}` }, undefined)
      const out = await registered.rpc.get('testConnection')()
      assert.equal(out.running, true)
      assert.equal(out.statusTone, 'success')
      assert.match(out.statusText.en, /valid System One schema/)
      assert.match(out.statusText.en, /\d+ ms/)
    } finally {
      server.close()
    }
  })

  it('an offline backend reports failure, never success (no more false positives)', async () => {
    const registered = makeRegistry({ enabled: true, mode: 'enforce', backendKind: 'local', localUrl: 'http://127.0.0.1:1' }, undefined)
    const out = await registered.rpc.get('testConnection')()
    assert.equal(out.running, false)
    assert.equal(out.statusTone, 'danger')
    assert.match(out.statusText.en, /could not be reached/)
  })

  it('a slow backend reports a timeout, not a success', async () => {
    const server = loopbackServer((req, res) => {
      setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(jevAnswer('APPROVE')))
      }, 2_000)
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      const port = server.address().port
      const registered = makeRegistry({ enabled: true, mode: 'enforce', backendKind: 'local', localUrl: `http://127.0.0.1:${port}`, timeoutMs: 60 }, undefined)
      const out = await registered.rpc.get('testConnection')()
      assert.equal(out.running, false)
      assert.equal(out.statusTone, 'danger')
      assert.match(out.statusText.en, /did not respond in time/)
    } finally {
      server.close()
    }
  })

  it('a backend returning a non-System One body reports an invalid schema', async () => {
    const server = loopbackServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ choices: [{ message: 'APPROVE' }] }))
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      const port = server.address().port
      const registered = makeRegistry({ enabled: true, mode: 'enforce', backendKind: 'local', localUrl: `http://127.0.0.1:${port}` }, undefined)
      const out = await registered.rpc.get('testConnection')()
      assert.equal(out.running, false)
      assert.equal(out.statusTone, 'danger')
      assert.match(out.statusText.en, /invalid System One schema/)
    } finally {
      server.close()
    }
  })

  it('a cloud backend without a selected provider reports provider missing (no network call)', async () => {
    const registered = makeRegistry({ enabled: true, mode: 'enforce', backendKind: 'openrouter', providerId: '' }, undefined)
    const out = await registered.rpc.get('testConnection')()
    assert.equal(out.running, false)
    assert.match(out.statusText.en, /no decision provider/i)
  })

  it('a cloud backend without consent reports consent required (no network call)', async () => {
    const access = providerAccessStub([OPENROUTER], async () => jevAnswer())
    const registered = makeRegistry({ enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: false }, access)
    const out = await registered.rpc.get('testConnection')()
    assert.equal(out.running, false)
    assert.match(out.statusText.en, /consent/i)
  })

  it('an authentication failure is reported distinctly and leaks no credentials', async () => {
    const access = providerAccessStub([OPENROUTER], async () => {
      throw new Error('Provider request failed with status 401')
    })
    const registered = makeRegistry({ enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true }, access)
    const out = await registered.rpc.get('testConnection')()
    assert.equal(out.running, false)
    assert.match(out.statusText.en, /Authentication failed/)
    assert.ok(!/sk-|Bearer|credential value/i.test(out.statusText.en))
  })

  it('probe errors never leak credentials, tokens or URLs from raw transport exceptions', async () => {
    const access = providerAccessStub([OPENROUTER], async () => {
      throw new Error('fetch failed: https://admin:Sup3rS3cret@internal.corp/api?api_key=sk-abcdef1234567890 Authorization: Bearer ghp_abcdefghij12345')
    })
    const registered = makeRegistry({ enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true }, access)
    const out = await registered.rpc.get('testConnection')()
    assert.equal(out.running, false)
    const text = out.statusText.en
    assert.ok(!text.includes('Sup3rS3cret'), 'URL-embedded credential must not leak')
    assert.ok(!text.includes('internal.corp'), 'URL host must not leak')
    assert.ok(!text.includes('sk-abcdef1234567890'), 'API key must not leak')
    assert.ok(!text.includes('ghp_abcdefghij12345'), 'Bearer token must not leak')
  })

  it('an unclassified transport error carrying a sensitive payload leaks nothing', async () => {
    const access = providerAccessStub([OPENROUTER], async () => {
      throw new Error('unexpected: session token=deadbeefcafebabe1234 exposed in response body')
    })
    const registered = makeRegistry({ enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true }, access)
    const out = await registered.rpc.get('testConnection')()
    assert.equal(out.running, false)
    assert.equal(out.statusTone, 'danger')
    assert.ok(!out.statusText.en.includes('deadbeefcafebabe1234'), 'sensitive payload must not leak')
    assert.ok(!out.statusText.en.includes('unexpected:'), 'raw exception text must not leak')
  })

  it('a disabled plugin reports disabled without probing', async () => {
    const access = providerAccessStub([OPENROUTER], async () => {
      throw new Error('should not be called')
    })
    const registered = makeRegistry({ enabled: false, providerId: 'or-1', cloudConsent: true }, access)
    const out = await registered.rpc.get('testConnection')()
    assert.equal(out.running, false)
    assert.match(out.statusText.en, /disabled/i)
  })

  it('a healthy probe without an operator policy flags escalation-only mode', async () => {
    const server = loopbackServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(jevAnswer('APPROVE')))
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    try {
      const port = server.address().port
      const registered = makeRegistry({ enabled: true, mode: 'enforce', backendKind: 'local', localUrl: `http://127.0.0.1:${port}` }, undefined)
      const out = await registered.rpc.get('testConnection')()
      assert.equal(out.running, true)
      assert.match(out.statusText.en, /operator policy/i)
    } finally {
      server.close()
    }
  })
})