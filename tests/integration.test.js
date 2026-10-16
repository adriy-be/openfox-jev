import { describe, it, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
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

function makeRegistry(settings, providerAccess) {
  const registered = { settings: null, reviewers: [], rpc: new Map() }
  const registry = {
    context: {
      id: 'openfox-jev',
      version: '1.0.0',
      runtime: { mode: 'test', configDirectory: auditDir },
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      storage: { get: () => undefined, set() {} },
      settings: (scope) => (scope === 'project' ? {} : settings),
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

  it('the decision model is a select, not free text', () => {
    const model = registered.settings.fields.find((f) => f.key === 'model')
    assert.equal(model.type, 'select')
    assert.ok(Array.isArray(model.options) && model.options.length > 0, 'model select must declare options')
    assert.ok(model.options.some((o) => o.value === ''))
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

  it('connection status RPC reports provider, model and mode', async () => {
    const registered = makeRegistry(
      { enabled: true, mode: 'enforce', providerId: 'or-1', cloudConsent: true, model: 'nace-ai/drex-v2.0' },
      providerAccessStub([OPENROUTER], async () => jevAnswer()),
    )
    const status = await registered.rpc.get('connectionStatus')()
    assert.equal(status.running, true)
    assert.match(status.statusText.en, /OpenRouter/)
    assert.match(status.statusText.en, /nace-ai\/drex-v2\.0/)
    assert.match(status.statusText.en, /enforce/)
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