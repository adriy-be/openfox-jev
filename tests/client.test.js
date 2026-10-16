import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { decide, validateResponse, truncateState, QUESTIONS, classifyError, TRUNCATION_MARKER } from '../src/client.js'

function validResponse() {
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
      blast_radius: { type: 'score', score: 0.4, confidence: 0.8 },
    },
    usage: { input_tokens: 100, output_tokens: 0 },
  }
}

describe('request protocol', () => {
  it('builds typed questions with choice/noul/score types', () => {
    assert.equal(QUESTIONS.verdict.type, 'choice')
    assert.deepEqual(Object.keys(QUESTIONS.verdict.criteria), ['APPROVE', 'ESCALATE', 'DENY'])
    for (const key of ['destructive', 'reads_secrets', 'exfiltration', 'self_advocating', 'policy_allows']) {
      assert.equal(QUESTIONS[key].type, 'noul')
    }
    assert.equal(QUESTIONS.blast_radius.type, 'score')
    assert.equal(QUESTIONS.blast_radius.criteria.length, 5)
  })

  it('truncates oversized state with a visible marker', () => {
    const long = 'x'.repeat(50_000)
    const { state, truncated } = truncateState(long, 1000)
    assert.equal(truncated, true)
    assert.ok(state.includes(TRUNCATION_MARKER.replace('N', String(50_000 - 1000))))
    assert.ok(state.length < 1200)
    const small = truncateState('short', 1000)
    assert.equal(small.truncated, false)
  })
})

describe('response validation', () => {
  it('accepts a valid response', () => {
    const { errors, answers } = validateResponse(validResponse())
    assert.deepEqual(errors, [])
    assert.equal(answers.verdict.choice, 'APPROVE')
  })

  it('rejects missing answers', () => {
    assert.ok(validateResponse({}).errors.length > 0)
    assert.ok(validateResponse(null).errors.length > 0)
  })

  it('rejects probabilities that do not cover exactly the options', () => {
    const raw = validResponse()
    raw.answers.verdict.probabilities = { APPROVE: 1 }
    assert.ok(validateResponse(raw).errors.some((e) => e.includes('exactly')))
  })

  it('rejects probabilities that do not sum to 1', () => {
    const raw = validResponse()
    raw.answers.verdict.probabilities = { APPROVE: 0.5, ESCALATE: 0.2, DENY: 0.1 }
    assert.ok(validateResponse(raw).errors.some((e) => e.includes('sum')))
  })

  it('rejects a choice that is not the argmax', () => {
    const raw = validResponse()
    raw.answers.verdict.choice = 'DENY'
    raw.answers.verdict.probabilities = { APPROVE: 0.9, ESCALATE: 0.07, DENY: 0.03 }
    assert.ok(validateResponse(raw).errors.some((e) => e.includes('argmax')))
  })

  it('rejects out-of-range confidence', () => {
    const raw = validResponse()
    raw.answers.verdict.confidence = 1.5
    assert.ok(validateResponse(raw).errors.some((e) => e.includes('confidence')))
  })

  it('rejects missing noul answers', () => {
    const raw = validResponse()
    delete raw.answers.reads_secrets
    assert.ok(validateResponse(raw).errors.some((e) => e.includes('reads_secrets')))
  })

  it('rejects noul values outside [0,1]', () => {
    const raw = validResponse()
    raw.answers.exfiltration.noul = 2
    assert.ok(validateResponse(raw).errors.some((e) => e.includes('exfiltration')))
  })

  it('rejects score outside legend bounds', () => {
    const raw = validResponse()
    raw.answers.blast_radius.score = 9
    assert.ok(validateResponse(raw).errors.some((e) => e.includes('blast_radius')))
  })
})

describe('decide()', () => {
  it('returns validated answers on success', async () => {
    const result = await decide({
      transport: async () => validResponse(),
      endpointKey: 'decisions',
      model: 'm',
      state: 'git status',
    })
    assert.equal(result.ok, true)
    assert.equal(result.answers.verdict.choice, 'APPROVE')
    assert.ok(result.latencyMs >= 0)
  })

  it('never uses chat-completion text: invalid schema → error result', async () => {
    const result = await decide({
      transport: async () => ({ choices: [{ message: { content: 'APPROVE' } }] }),
      endpointKey: 'decisions',
      model: 'm',
      state: 'x',
    })
    assert.equal(result.ok, false)
    assert.equal(result.errorClass, 'invalid_response')
  })

  it('classifies timeouts', async () => {
    const result = await decide({
      transport: async () => {
        const err = new Error('The operation was aborted due to timeout')
        err.name = 'TimeoutError'
        throw err
      },
      endpointKey: 'decisions',
      model: 'm',
      state: 'x',
    })
    assert.equal(result.ok, false)
    assert.equal(result.errorClass, 'timeout')
  })

  it('classifies offline backends', async () => {
    const result = await decide({
      transport: async () => {
        throw new Error('fetch failed: ECONNREFUSED 127.0.0.1:8765')
      },
      endpointKey: 'systemone',
      model: 'm',
      state: 'x',
    })
    assert.equal(result.ok, false)
    assert.equal(result.errorClass, 'offline')
  })

  it('classifies provider unavailability without leaking credentials', async () => {
    const result = await decide({
      transport: async () => {
        throw new Error('Provider has no configured credentials')
      },
      endpointKey: 'decisions',
      model: 'm',
      state: 'x',
    })
    assert.equal(result.ok, false)
    assert.equal(result.errorClass, 'provider_unavailable')
    assert.ok(!result.error.includes('sk-'))
  })

  it('propagates truncation flag', async () => {
    const result = await decide({
      transport: async () => validResponse(),
      endpointKey: 'decisions',
      model: 'm',
      state: 'y'.repeat(50_000),
      maxStateChars: 500,
    })
    assert.equal(result.ok, true)
    assert.equal(result.truncated, true)
  })

  it('classifyError maps generic failures', () => {
    assert.equal(classifyError(new Error('Provider not found')), 'provider_unavailable')
    assert.equal(classifyError(new Error('Provider request failed with status 500')), 'http_error')
    assert.equal(classifyError(new Error('Provider returned an invalid JSON response')), 'invalid_response')
  })

  it('classifyError distinguishes cancellation from timeout', () => {
    assert.equal(classifyError(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' })), 'cancelled')
    assert.equal(classifyError(Object.assign(new Error('timed out'), { name: 'TimeoutError' })), 'timeout')
  })

  it('passes the cancellation signal to the transport', async () => {
    const controller = new AbortController()
    let sawSignal = null
    const result = await decide({
      transport: async (_key, _body, _timeoutMs, signal) => {
        sawSignal = signal
        return validResponse()
      },
      endpointKey: 'decisions',
      model: 'm',
      state: 'x',
      signal: controller.signal,
    })
    assert.equal(result.ok, true)
    assert.equal(sawSignal, controller.signal, 'transport must receive the caller signal')
  })

  it('pre-aborted signal short-circuits without contacting the backend', async () => {
    const controller = new AbortController()
    controller.abort()
    let transportCalled = false
    const result = await decide({
      transport: async () => {
        transportCalled = true
        return validResponse()
      },
      endpointKey: 'decisions',
      model: 'm',
      state: 'x',
      signal: controller.signal,
    })
    assert.equal(transportCalled, false, 'no backend contact when already cancelled')
    assert.equal(result.ok, false)
    assert.equal(result.errorClass, 'cancelled')
  })

  it('abort during flight classifies as cancelled, never approved', async () => {
    const controller = new AbortController()
    const pending = decide({
      transport: (_key, _body, _timeoutMs, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true })
        }),
      endpointKey: 'decisions',
      model: 'm',
      state: 'x',
      signal: controller.signal,
    })
    setTimeout(() => controller.abort(), 5)
    const out = await pending
    assert.equal(out.ok, false)
    assert.equal(out.errorClass, 'cancelled')
  })
})