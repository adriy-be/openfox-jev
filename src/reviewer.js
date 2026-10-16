import { decide, DEFAULT_MODEL as CLIENT_DEFAULT_MODEL, QUESTIONS, combineSignals } from './client.js'
import { applyPolicy, POLICY_VERSION, DEFAULT_THRESHOLDS } from './policy.js'
import { evaluateSecurity, redactState } from './security.js'
import { createAuditLog } from './audit.js'
import { resolveEndpoint, detectKind, isRemoteBackend, defaultModelFor, isLoopbackUrl } from './providers.js'

export const MODES = ['shadow', 'enforce']

const OPERATION_CATEGORIES = {
  run_command: 'shell',
  execute_command: 'shell',
  read_file: 'read',
  write_file: 'write',
  edit_file: 'write',
  workspace: 'workspace',
  command: 'git',
}

function num(value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function bool(value, fallback) {
  if (typeof value === 'boolean') return value
  if (value === 'true') return true
  if (value === 'false') return false
  return fallback
}

export function readConfig(settings = {}) {
  return {
    enabled: bool(settings.enabled, false),
    mode: MODES.includes(settings.mode) ? settings.mode : 'shadow',
    providerId: typeof settings.providerId === 'string' ? settings.providerId : '',
    backendKind: typeof settings.backendKind === 'string' ? settings.backendKind : '',
    model: typeof settings.model === 'string' && settings.model ? settings.model : '',
    localUrl: typeof settings.localUrl === 'string' ? settings.localUrl : '',
    localApiKey: typeof settings.localApiKey === 'string' ? settings.localApiKey : '',
    customEndpoint: typeof settings.customEndpoint === 'string' ? settings.customEndpoint : '',
    operatorPolicy: typeof settings.operatorPolicy === 'string' ? settings.operatorPolicy : '',
    timeoutMs: Math.min(Math.max(num(settings.timeoutMs, 15_000), 1_000), 60_000),
    cloudConsent: bool(settings.cloudConsent, false),
    auditEnabled: bool(settings.auditEnabled, true),
    thresholds: {
      minApprovalProbability: num(settings.minApprovalProbability, DEFAULT_THRESHOLDS.minApprovalProbability),
      minConfidence: num(settings.minConfidence, DEFAULT_THRESHOLDS.minConfidence),
      escalateBlastRadius: num(settings.escalateBlastRadius, DEFAULT_THRESHOLDS.escalateBlastRadius),
      maxBlastRadius: num(settings.maxBlastRadius, DEFAULT_THRESHOLDS.maxBlastRadius),
    },
  }
}

/**
 * Build the System One state from the actual reviewed operation.
 * Tool arguments and repository content are untrusted data; the operator
 * policy is trusted and clearly separated.
 */
export function buildState(context, config) {
  return {
    tool: context.tool ?? '',
    kind: context.kind ?? 'path',
    command: context.command ?? context.description ?? '',
    paths: context.paths ?? [],
    workdir: context.workdir ?? '',
    reason: context.reason ?? null,
    policy: config.operatorPolicy || 'No operator policy configured: prefer escalation for anything non-routine.',
  }
}

function transportFor(providerAccess, provider, config) {
  const kind = config.backendKind || (provider ? detectKind(provider) : 'local')
  const { endpointKey, url } = resolveEndpoint(provider, {
    backendKind: config.backendKind || undefined,
    localUrl: config.localUrl,
    customEndpoint: config.customEndpoint,
  })

  if (kind === 'local' || kind === 'custom' || !providerAccess) {
    // Direct fetch: local loopback or explicitly configured custom endpoint.
    // Credentials are never attached here — cloud credentials only ever flow
    // through providerAccess.requestJson with a verified origin mapping.
    const target = url
    return async (key, body, timeoutMs, signal) => {
      const headers = { 'Content-Type': 'application/json' }
      if (config.localApiKey && isLoopbackUrl(target)) headers['Authorization'] = `Bearer ${config.localApiKey}`
      const response = await fetch(target, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        redirect: 'error',
        signal: combineSignals(timeoutMs, signal),
      })
      if (!response.ok) throw new Error(`Provider request failed with status ${response.status}`)
      const text = await response.text()
      if (text.length > 1_000_000) throw new Error('Provider response exceeded size limit')
      try {
        return JSON.parse(text)
      } catch {
        throw new Error('Provider returned an invalid JSON response')
      }
    }
  }

  return (key, body, timeoutMs, signal) =>
    providerAccess.requestJson(provider.id, key, body, signal ? { timeoutMs, signal } : { timeoutMs })
}

/**
 * Create the approval reviewer.
 *
 * @param {object} deps
 * @param {() => Record<string, unknown>} deps.getSettings
 * @param {{ listProviders(): unknown[], getProvider(id): any, requestJson(...): Promise<any> }} [deps.providerAccess]
 * @param {object} [deps.audit] audit log (createAuditLog result)
 */
export function createReviewer({ getSettings, providerAccess, audit }) {
  const log = audit ?? createAuditLog({ enabled: true })

  async function assess(context, config, provider) {
    const kind = config.backendKind || (provider ? detectKind(provider) : 'local')
    const model = config.model || defaultModelFor(provider, { backendKind: kind })
    const state = buildState(context, config)
    const { state: safeState, redacted } = redactState(state)
    const transport = transportFor(providerAccess, provider, config)

    const result = await decide({
      transport,
      endpointKey: kind === 'local' ? 'systemone' : 'decisions',
      model,
      state: safeState,
      timeoutMs: config.timeoutMs,
      signal: context.signal,
    })
    return { ...result, model, redacted, state: safeState, kind }
  }

  function escalate(config, provider, context, ruleId, reason, extra = {}) {
    return {
      action: 'ask',
      reason,
      meta: {
        decision: 'ESCALATE',
        ruleId,
        modelVerdict: extra.modelVerdict ?? null,
        confidence: extra.confidence ?? 0,
        approvalProbability: extra.approvalProbability ?? 0,
        latencyMs: extra.latencyMs ?? null,
        outcome: extra.outcome ?? 'escalated',
        errorClass: extra.errorClass ?? null,
        humanApprovalRequired: true,
        model: extra.model ?? null,
        risk: extra.risk ?? null,
        truncated: extra.truncated ?? false,
      },
    }
  }

  function record(config, provider, context, meta, operationText) {
    if (!config.auditEnabled) return
    try {
      log.record({
        mode: config.mode,
        providerId: provider?.id ?? null,
        model: meta.model ?? null,
        operationCategory: OPERATION_CATEGORIES[context.tool] ?? 'other',
        operation: operationText,
        rawVerdict: meta.modelVerdict ?? null,
        decision: meta.decision ?? null,
        ruleId: meta.ruleId ?? null,
        approvalProbability: meta.approvalProbability ?? null,
        confidence: meta.confidence ?? null,
        risk: meta.risk ?? null,
        latencyMs: meta.latencyMs ?? null,
        outcome: meta.outcome ?? null,
        errorClass: meta.errorClass ?? null,
        humanApprovalRequired: meta.humanApprovalRequired ?? null,
        truncated: meta.truncated ?? false,
        policyVersion: POLICY_VERSION,
      })
    } catch {
      // Logging failures never change the approval decision.
    }
  }

  /**
   * Review one confirmation request. Returns { action: 'allow'|'ask'|'deny',
   * reason?, meta } — the OpenFox host maps these to allow/ask/deny.
   */
  async function evaluate(context) {
    const config = readConfig(getSettings() ?? {})
    const operationText = context.command || context.description || (context.paths ?? []).join(' ') || context.tool || ''

    if (!config.enabled) return { action: 'ask', reason: 'Smart approvals disabled.', meta: { decision: 'ESCALATE', ruleId: 'disabled', humanApprovalRequired: true } }

    // A cancelled operation is never auto-approved: fail closed to the native
    // confirmation flow without contacting the backend.
    if (context.signal?.aborted) {
      const meta = { decision: 'ESCALATE', ruleId: 'cancelled', outcome: 'escalated_cancelled', humanApprovalRequired: true, errorClass: 'cancelled' }
      record(config, null, context, meta, operationText)
      return { action: 'ask', reason: 'Operation was cancelled; falling back to manual confirmation.', meta }
    }

    // Mandatory deterministic security rules run first and are not optional.
    const security = evaluateSecurity(context)
    if (security.decision === 'DENY') {
      const meta = { decision: 'DENY', ruleId: security.ruleId, outcome: 'denied', humanApprovalRequired: false, modelVerdict: null, confidence: 0, approvalProbability: 0 }
      record(config, null, context, meta, operationText)
      return { action: 'deny', reason: security.reason, meta }
    }
    if (security.decision === 'ESCALATE') {
      const meta = { decision: 'ESCALATE', ruleId: security.ruleId, outcome: 'escalated_mandatory', humanApprovalRequired: true, modelVerdict: null, confidence: 0, approvalProbability: 0 }
      record(config, null, context, meta, operationText)
      return { action: 'ask', reason: security.reason, meta }
    }

    const provider = config.providerId && providerAccess ? providerAccess.getProvider(config.providerId) : undefined
    const kind = config.backendKind || (provider ? detectKind(provider) : null)

    if (config.providerId && !provider) {
      const meta = { decision: 'ESCALATE', ruleId: 'provider_unavailable', outcome: 'escalated_provider_missing', humanApprovalRequired: true, errorClass: 'provider_unavailable' }
      record(config, null, context, meta, operationText)
      return { action: 'ask', reason: 'Selected provider is missing or was removed from the Provider Manager.', meta }
    }
    if (!kind) {
      return escalate(config, undefined, context, 'no_provider', 'No decision backend configured.', { outcome: 'escalated_no_provider' })
    }
    if (kind !== 'local' && !provider) {
      const meta = { decision: 'ESCALATE', ruleId: 'provider_unavailable', outcome: 'escalated_provider_missing', humanApprovalRequired: true, errorClass: 'provider_unavailable' }
      record(config, null, context, meta, operationText)
      return { action: 'ask', reason: 'Selected provider is missing or was removed from the Provider Manager.', meta }
    }
    if (provider && !provider.isActive) {
      const meta = { decision: 'ESCALATE', ruleId: 'provider_disabled', outcome: 'escalated_provider_disabled', humanApprovalRequired: true, errorClass: 'provider_unavailable' }
      record(config, provider, context, meta, operationText)
      return { action: 'ask', reason: 'Selected provider is disabled.', meta }
    }
    if (provider && isRemoteBackend(provider, { backendKind: config.backendKind || undefined }) && !config.cloudConsent) {
      const meta = { decision: 'ESCALATE', ruleId: 'privacy_consent', outcome: 'escalated_no_consent', humanApprovalRequired: true }
      record(config, provider, context, meta, operationText)
      return { action: 'ask', reason: 'Cloud inference for approval data is not permitted (privacy consent required).', meta }
    }

    let assessment
    try {
      assessment = await assess(context, config, provider)
    } catch (error) {
      const meta = { decision: 'ESCALATE', ruleId: 'backend_error', outcome: 'escalated_error', humanApprovalRequired: true, errorClass: 'unknown' }
      record(config, provider, context, meta, operationText)
      return { action: 'ask', reason: 'Decision backend failed; falling back to manual confirmation.', meta }
    }

    if (!assessment.ok) {
      const ruleId =
        assessment.errorClass === 'invalid_response' ? 'invalid_response' : assessment.errorClass === 'cancelled' ? 'cancelled' : 'backend_error'
      const meta = {
        decision: 'ESCALATE',
        ruleId,
        outcome: `escalated_${assessment.errorClass}`,
        humanApprovalRequired: true,
        errorClass: assessment.errorClass,
        latencyMs: assessment.latencyMs,
        model: assessment.model,
        truncated: assessment.truncated,
      }
      record(config, provider, context, meta, operationText)
      return { action: 'ask', reason: 'Decision backend returned no usable assessment.', meta }
    }

    const verdictEntry = assessment.answers.verdict
    const policy = applyPolicy(
      assessment.answers,
      {
        truncated: assessment.truncated,
        redactedIncomplete: assessment.redacted && assessment.truncated,
        hasPolicy: Boolean(config.operatorPolicy && config.operatorPolicy.trim()),
        security: { decision: null },
      },
      config.thresholds,
      { kind: context.kind, tool: context.tool },
    )

    const meta = {
      decision: policy.decision,
      ruleId: policy.rule_id,
      modelVerdict: policy.model_verdict,
      confidence: policy.confidence,
      approvalProbability: verdictEntry?.probabilities?.APPROVE ?? 0,
      risk: assessment.answers.blast_radius?.score ?? null,
      latencyMs: assessment.latencyMs,
      model: assessment.model,
      truncated: assessment.truncated,
      humanApprovalRequired: policy.decision !== 'APPROVE',
      outcome: policy.decision === 'APPROVE' ? 'auto_approved' : policy.decision === 'DENY' ? 'denied' : 'escalated',
      errorClass: null,
    }

    // Shadow mode: record the prediction, never act on it.
    if (config.mode === 'shadow') {
      meta.outcome = `shadow_${policy.decision.toLowerCase()}`
      meta.humanApprovalRequired = true
      record(config, provider, context, meta, operationText)
      return { action: 'ask', reason: 'Shadow mode: prediction recorded, native approval flow preserved.', meta }
    }

    record(config, provider, context, meta, operationText)

    if (policy.decision === 'APPROVE') return { action: 'allow', reason: policy.reason, meta }
    if (policy.decision === 'DENY') return { action: 'deny', reason: policy.reason, meta }
    return { action: 'ask', reason: policy.reason, meta }
  }

  return { evaluate, questions: QUESTIONS, defaultModel: CLIENT_DEFAULT_MODEL }
}