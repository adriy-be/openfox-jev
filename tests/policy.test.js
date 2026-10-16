import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { applyPolicy, DEFAULT_THRESHOLDS } from '../src/policy.js'

function answers(overrides = {}) {
  return {
    verdict: {
      type: 'choice',
      choice: 'APPROVE',
      confidence: 0.9,
      probabilities: { APPROVE: 0.9, ESCALATE: 0.07, DENY: 0.03 },
      ...overrides.verdict,
    },
    destructive: { type: 'noul', noul: 0.05, ...overrides.destructive },
    reads_secrets: { type: 'noul', noul: 0.02, ...overrides.reads_secrets },
    exfiltration: { type: 'noul', noul: 0.01, ...overrides.exfiltration },
    self_advocating: { type: 'noul', noul: 0.01, ...overrides.self_advocating },
    policy_allows: { type: 'noul', noul: 0.95, ...overrides.policy_allows },
    blast_radius: { type: 'score', score: 0.4, ...overrides.blast_radius },
  }
}

const baseInput = { hasPolicy: true, truncated: false, redactedIncomplete: false }

describe('mandatory security rules take precedence', () => {
  it('security DENY wins over an APPROVE verdict', () => {
    const result = applyPolicy(answers(), {
      ...baseInput,
      security: { decision: 'DENY', ruleId: 'wipe_home_or_root', reason: 'prohibited' },
    })
    assert.equal(result.decision, 'DENY')
    assert.equal(result.rule_id, 'wipe_home_or_root')
    assert.equal(result.model_verdict, 'APPROVE')
  })

  it('security ESCALATE wins over an APPROVE verdict', () => {
    const result = applyPolicy(answers(), {
      ...baseInput,
      security: { decision: 'ESCALATE', ruleId: 'git_no_verify', reason: 'confirm' },
    })
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'git_no_verify')
  })
})

describe('completeness rules', () => {
  it('failed assessment escalates', () => {
    const result = applyPolicy({}, { ...baseInput, assessmentFailed: true })
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'assessment_failed')
  })

  it('incomplete redaction escalates', () => {
    const result = applyPolicy(answers(), { ...baseInput, redactedIncomplete: true })
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'redaction_incomplete')
  })

  it('truncated operation is never auto-approved', () => {
    const result = applyPolicy(answers(), { ...baseInput, truncated: true })
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'truncated')
  })

  it('truncated operation with model DENY still denies', () => {
    const result = applyPolicy(
      answers({ verdict: { choice: 'DENY', confidence: 0.9, probabilities: { APPROVE: 0.02, ESCALATE: 0.08, DENY: 0.9 } } }),
      { ...baseInput, truncated: true },
    )
    assert.equal(result.decision, 'DENY')
    assert.equal(result.rule_id, 'truncated_deny')
  })

  it('invalid/missing verdict escalates (default model verdict ESCALATE)', () => {
    const result = applyPolicy({}, baseInput)
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.model_verdict, 'ESCALATE')
  })
})

describe('prompt injection protection', () => {
  it('self_advocating signal escalates even with full approval probability', () => {
    const result = applyPolicy(answers({ self_advocating: { noul: 0.9 } }), baseInput)
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'self_advocating')
  })

  it('self_advocating with model DENY denies', () => {
    const result = applyPolicy(
      answers({
        self_advocating: { noul: 0.9 },
        verdict: { choice: 'DENY', confidence: 0.9, probabilities: { APPROVE: 0, ESCALATE: 0.1, DENY: 0.9 } },
      }),
      baseInput,
    )
    assert.equal(result.decision, 'DENY')
    assert.equal(result.rule_id, 'self_advocating_deny')
  })

  it('self_advocating runs before the secrets rules', () => {
    const result = applyPolicy(
      answers({ self_advocating: { noul: 0.9 }, reads_secrets: { noul: 0.9 }, exfiltration: { noul: 0.9 } }),
      baseInput,
    )
    assert.equal(result.rule_id, 'self_advocating')
  })
})

describe('secrets and exfiltration', () => {
  it('secrets + exfiltration denies deterministically', () => {
    const result = applyPolicy(answers({ reads_secrets: { noul: 0.8 }, exfiltration: { noul: 0.8 } }), baseInput)
    assert.equal(result.decision, 'DENY')
    assert.equal(result.rule_id, 'secrets_exfil')
  })

  it('secrets alone escalates despite APPROVE verdict', () => {
    const result = applyPolicy(answers({ reads_secrets: { noul: 0.8 } }), baseInput)
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'secrets_read')
  })

  it('exfiltration alone escalates despite APPROVE verdict', () => {
    const result = applyPolicy(answers({ exfiltration: { noul: 0.8 } }), baseInput)
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'exfiltration')
  })

  it('secrets below threshold do not block approval', () => {
    const result = applyPolicy(answers({ reads_secrets: { noul: 0.3 } }), baseInput)
    assert.equal(result.decision, 'APPROVE')
  })
})

describe('confidence, probability and blast radius', () => {
  it('low confidence escalates an APPROVE verdict', () => {
    const result = applyPolicy(
      answers({ verdict: { choice: 'APPROVE', confidence: 0.3, probabilities: { APPROVE: 0.9, ESCALATE: 0.07, DENY: 0.03 } } }),
      baseInput,
    )
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'low_confidence')
  })

  it('low approval probability escalates', () => {
    const result = applyPolicy(
      answers({ verdict: { choice: 'APPROVE', confidence: 0.9, probabilities: { APPROVE: 0.5, ESCALATE: 0.4, DENY: 0.1 } } }),
      baseInput,
    )
    // probabilities must still sum to 1 for validation; policy checks threshold
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'low_probability')
  })

  it('high blast radius escalates an APPROVE verdict', () => {
    const result = applyPolicy(answers({ blast_radius: { score: 3 } }), baseInput)
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'high_blast_radius')
  })

  it('blast radius at escalate threshold escalates', () => {
    const result = applyPolicy(answers({ blast_radius: { score: DEFAULT_THRESHOLDS.escalateBlastRadius } }), baseInput)
    assert.equal(result.decision, 'ESCALATE')
  })

  it('missing policy escalates even with strong approval', () => {
    const result = applyPolicy(answers(), { ...baseInput, hasPolicy: false })
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'policy_not_confirmed')
  })

  it('policy_allows below threshold escalates', () => {
    const result = applyPolicy(answers({ policy_allows: { noul: 0.3 } }), baseInput)
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'policy_not_confirmed')
  })
})

describe('happy path and model deny', () => {
  it('routine read-only operation approves', () => {
    const result = applyPolicy(answers(), baseInput)
    assert.equal(result.decision, 'APPROVE')
    assert.equal(result.rule_id, 'approved')
    assert.equal(result.model_verdict, 'APPROVE')
    assert.ok(result.confidence >= DEFAULT_THRESHOLDS.minConfidence)
    assert.ok(typeof result.reason === 'string' && result.reason.length > 0)
  })

  it('confident model DENY denies', () => {
    const result = applyPolicy(
      answers({ verdict: { choice: 'DENY', confidence: 0.9, probabilities: { APPROVE: 0.01, ESCALATE: 0.09, DENY: 0.9 } } }),
      baseInput,
    )
    assert.equal(result.decision, 'DENY')
    assert.equal(result.rule_id, 'model_deny')
  })

  it('uncertain model DENY escalates instead of denying', () => {
    const result = applyPolicy(
      answers({ verdict: { choice: 'DENY', confidence: 0.3, probabilities: { APPROVE: 0.3, ESCALATE: 0.35, DENY: 0.35 } } }),
      baseInput,
    )
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'model_deny_uncertain')
  })

  it('model ESCALATE escalates', () => {
    const result = applyPolicy(
      answers({ verdict: { choice: 'ESCALATE', confidence: 0.8, probabilities: { APPROVE: 0.1, ESCALATE: 0.8, DENY: 0.1 } } }),
      baseInput,
    )
    assert.equal(result.decision, 'ESCALATE')
    assert.equal(result.rule_id, 'model_escalate')
  })

  it('output always contains the five required fields', () => {
    const result = applyPolicy(answers(), baseInput)
    for (const key of ['decision', 'reason', 'rule_id', 'model_verdict', 'confidence']) {
      assert.ok(key in result, `missing ${key}`)
    }
  })
})