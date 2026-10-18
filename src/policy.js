export const POLICY_VERSION = 'openfox-jev/1'

export const DEFAULT_THRESHOLDS = {
  minApprovalProbability: 0.85,
  minConfidence: 0.55,
  selfAdvocating: 0.6,
  readsSecrets: 0.7,
  exfiltration: 0.7,
  destructive: 0.7,
  policyAllows: 0.7,
  maxBlastRadius: 2.0,
  escalateBlastRadius: 1.6,
}

export const VERDICTS = ['APPROVE', 'ESCALATE', 'DENY']

function clamp01(value) {
  return typeof value === 'number' && Number.isFinite(value) ? Math.min(1, Math.max(0, value)) : undefined
}

function noul(answers, key) {
  const entry = answers?.[key]
  return typeof entry?.noul === 'number' ? entry.noul : undefined
}

function choiceEntry(answers, key) {
  const entry = answers?.[key]
  if (entry?.type === 'choice' && typeof entry.choice === 'string') return entry
  return undefined
}

function scoreValue(answers, key) {
  const entry = answers?.[key]
  return typeof entry?.score === 'number' && Number.isFinite(entry.score) ? entry.score : undefined
}

/**
 * Deterministic approval policy. Pure function: no OpenFox, no HTTP, no I/O.
 *
 * Inputs:
 *   answers      — validated System One answers (from client.js)
 *   input        — { truncated, redactedIncomplete, hasPolicy, security }
 *   thresholds   — optional overrides of DEFAULT_THRESHOLDS
 *   context      — optional { kind, tool } for the reason text
 *
 * Output: { decision, reason, rule_id, model_verdict, confidence }
 *   decision ∈ 'APPROVE' | 'ESCALATE' | 'DENY'
 *
 * Rule order is priority-ordered: mandatory security first, hard-deny next,
 * completeness/assessment failures escalate, and APPROVE requires sufficient
 * probability plus agreement with every relevant policy check.
 */
export function applyPolicy(answers, input = {}, thresholds = {}, context = {}) {
  const t = { ...DEFAULT_THRESHOLDS, ...thresholds }
  const result = (decision, ruleId, reason, modelVerdict, confidence) => ({
    decision,
    reason,
    rule_id: ruleId,
    model_verdict: modelVerdict ?? 'ESCALATE',
    confidence: clamp01(confidence) ?? 0,
  })

  const verdict = choiceEntry(answers, 'verdict')
  const modelVerdict = verdict && VERDICTS.includes(verdict.choice) ? verdict.choice : 'ESCALATE'
  const confidence = clamp01(verdict?.confidence) ?? 0
  const approveProbability = clamp01(verdict?.probabilities?.APPROVE) ?? 0

  // Rule 1: mandatory OpenFox security restrictions always take precedence.
  if (input.security?.decision === 'DENY') {
    return result('DENY', input.security.ruleId ?? 'mandatory_deny', input.security.reason, modelVerdict, confidence)
  }
  if (input.security?.decision === 'ESCALATE') {
    return result('ESCALATE', input.security.ruleId ?? 'mandatory_confirm', input.security.reason, modelVerdict, confidence)
  }

  // Rule 2: failed or incomplete assessment escalates.
  if (input.assessmentFailed) {
    return result('ESCALATE', 'assessment_failed', 'The decision model did not return a usable assessment.', modelVerdict, confidence)
  }
  if (input.redactedIncomplete) {
    return result('ESCALATE', 'redaction_incomplete', 'Redaction removed information required for a reliable judgment.', modelVerdict, confidence)
  }

  // Rule 3: truncated operations are never auto-approved.
  if (input.truncated) {
    if (modelVerdict === 'DENY') {
      return result('DENY', 'truncated_deny', 'The operation was truncated and the model classified it as prohibited.', modelVerdict, confidence)
    }
    return result('ESCALATE', 'truncated', 'The operation was truncated and cannot be approved automatically.', modelVerdict, confidence)
  }

  const selfAdvocating = noul(answers, 'self_advocating') ?? 0
  const readsSecrets = noul(answers, 'reads_secrets') ?? 0
  const exfiltration = noul(answers, 'exfiltration') ?? 0
  const destructive = noul(answers, 'destructive') ?? 0
  const policyAllows = noul(answers, 'policy_allows') ?? 0
  const blastRadius = scoreValue(answers, 'blast_radius')
  const blast = typeof blastRadius === 'number' ? blastRadius : t.escalateBlastRadius

  // Rule 3b: a verdict that contradicts its own probability distribution is
  // never acted on — the model chose an option that is not the most probable.
  if (verdict && verdict.probabilities) {
    const maxProbability = Math.max(...VERDICTS.map((key) => verdict.probabilities[key] ?? -1))
    const chosen = verdict.probabilities[verdict.choice] ?? -1
    if (chosen < maxProbability) {
      return result('ESCALATE', 'contradictory_verdict', 'The model verdict contradicts its own probability distribution.', modelVerdict, confidence)
    }
  }

  // Rule 4: prompt-injection signal runs first so policy can never be talked
  // into approving an operation that advocates for its own approval.
  if (selfAdvocating >= t.selfAdvocating) {
    if (modelVerdict === 'DENY') {
      return result('DENY', 'self_advocating_deny', 'The operation contains instructions attempting to influence its own approval.', modelVerdict, confidence)
    }
    return result('ESCALATE', 'self_advocating', 'The operation contains instructions attempting to influence its own approval.', modelVerdict, confidence)
  }

  // Rule 5: secrets + exfiltration is a deterministic prohibition.
  if (readsSecrets >= t.readsSecrets && exfiltration >= t.exfiltration) {
    return result('DENY', 'secrets_exfil', 'The operation reads secrets and transmits them to an external destination.', modelVerdict, confidence)
  }

  // Rule 6: secrets, privilege escalation or exfiltration are never
  // auto-approved by model probability alone.
  if (readsSecrets >= t.readsSecrets) {
    if (modelVerdict === 'DENY') {
      return result('DENY', 'secrets_read_deny', 'The operation accesses credentials or secrets.', modelVerdict, confidence)
    }
    return result('ESCALATE', 'secrets_read', 'The operation accesses credentials, private keys or other secrets.', modelVerdict, confidence)
  }
  if (exfiltration >= t.exfiltration) {
    if (modelVerdict === 'DENY') {
      return result('DENY', 'exfiltration_deny', 'The operation transmits sensitive local data externally.', modelVerdict, confidence)
    }
    return result('ESCALATE', 'exfiltration', 'The operation transmits sensitive local data to an external destination.', modelVerdict, confidence)
  }

  // Rule 6b: destructive operations are never auto-approved on model
  // probability alone — they require a human decision (or a model deny).
  if (destructive >= t.destructive) {
    if (modelVerdict === 'DENY') {
      return result('DENY', 'destructive_deny', 'The operation destroys or irreversibly modifies valuable data.', modelVerdict, confidence)
    }
    return result('ESCALATE', 'destructive', 'The operation could destroy or irreversibly modify valuable data.', modelVerdict, confidence)
  }

  // Rule 7: low-confidence or contradictory answers escalate.
  if (modelVerdict === 'APPROVE' && confidence < t.minConfidence) {
    return result('ESCALATE', 'low_confidence', 'Model approval confidence is below the required threshold.', modelVerdict, confidence)
  }
  if (modelVerdict === 'APPROVE' && blast >= t.escalateBlastRadius) {
    if (blast >= t.maxBlastRadius) {
      return result('ESCALATE', 'high_blast_radius', 'Potential impact of a wrong approval is too high for automation.', modelVerdict, confidence)
    }
    return result('ESCALATE', 'high_blast_radius', 'Potential impact of a wrong approval is too high for automation.', modelVerdict, confidence)
  }

  // Rule 8: APPROVE requires sufficient probability AND agreement with all
  // relevant policy checks.
  if (modelVerdict === 'APPROVE') {
    if (!input.hasPolicy || policyAllows < t.policyAllows) {
      return result('ESCALATE', 'policy_not_confirmed', 'The operator policy does not explicitly permit this exact operation.', modelVerdict, confidence)
    }
    if (approveProbability < t.minApprovalProbability) {
      return result('ESCALATE', 'low_probability', 'Approval probability is below the required threshold.', modelVerdict, confidence)
    }
    return result('APPROVE', 'approved', 'Operation is routine, permitted by policy and supported by the model.', modelVerdict, confidence)
  }

  // Rule 9: a model DENY is a judgment, not a guarantee — model confidence is
  // not proof of safety, so only a sufficiently supported deny (high confidence
  // and a near-zero approval probability) blocks execution. Every uncertain
  // model deny escalates to a human. The rules above are deterministic
  // prohibitions: they may DENY regardless of the model's own verdict.
  if (modelVerdict === 'DENY') {
    if (confidence >= t.minConfidence && (approveProbability === 0 || approveProbability < 0.2)) {
      return result('DENY', 'model_deny', 'The model classified this operation as prohibited.', modelVerdict, confidence)
    }
    return result('ESCALATE', 'model_deny_uncertain', 'The model leaned towards denial without sufficient confidence.', modelVerdict, confidence)
  }

  return result('ESCALATE', 'model_escalate', 'The model requires human approval for this operation.', modelVerdict, confidence)
}