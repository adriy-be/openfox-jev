/**
 * Backend configuration: explicit, verified endpoint resolution per provider
 * kind. Credentials are never handled here — the OpenFox server resolves them
 * through PluginContext.providerAccess.
 *
 * Endpoint rules:
 * - Known cloud providers (OpenRouter, DeepInfra) use their documented
 *   Decisions endpoints, matched by trusted origin — never by appending a
 *   path to whatever URL the provider happens to have.
 * - Local Jev-Style servers use http://127.0.0.1:8765/v1/systemone (loopback
 *   only by default), overridable via the `localUrl` setting.
 * - Anything else requires an explicit `customEndpoint` that passes
 *   validation (HTTPS required unless loopback).
 */

export const DEFAULT_MODEL = 'nace-ai/drex-v2.0'

export const BACKEND_KINDS = ['local', 'openrouter', 'deepinfra', 'custom']

const VERIFIED_ORIGINS = {
  'https://openrouter.ai': 'decisions',
  'https://api.deepinfra.com': 'decisions',
}

export const LOCAL_DEFAULT_URL = 'http://127.0.0.1:8765'

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]'])

export function isLoopbackUrl(url) {
  try {
    return LOOPBACK_HOSTS.has(new URL(url).hostname.toLowerCase())
  } catch {
    return false
  }
}

/**
 * Resolve the System One endpoint for a provider.
 *
 * @param {object} provider OpenFox provider info (id, name, url, backend, isLocal)
 * @param {object} settings plugin settings { backendKind, localUrl, customEndpoint }
 * @returns {{ endpointKey: string, url: string }} endpointKey is passed to
 *   providerAccess.requestJson; url is used directly for local mode.
 * @throws when no verified mapping exists — never a blind append.
 */
export function resolveEndpoint(provider, settings = {}) {
  const kind = settings.backendKind ?? detectKind(provider)

  if (kind === 'local') {
    const base = (settings.localUrl || provider?.url || LOCAL_DEFAULT_URL).replace(/\/+$/, '')
    let parsed
    try {
      parsed = new URL(base)
    } catch {
      throw new Error('Local Jev URL is not a valid URL')
    }
    if (!LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
      throw new Error('Local Jev URL must be a loopback address (127.0.0.1/localhost)')
    }
    return { endpointKey: 'systemone', url: `${parsed.origin}/v1/systemone` }
  }

  if (kind === 'custom') {
    const raw = settings.customEndpoint
    if (!raw) throw new Error('Custom endpoint is not configured')
    let parsed
    try {
      parsed = new URL(raw)
    } catch {
      throw new Error('Custom endpoint is not a valid URL')
    }
    if (parsed.protocol !== 'https:' && !LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
      throw new Error('Custom endpoints must use HTTPS (loopback HTTP allowed)')
    }
    return { endpointKey: 'decisions', url: parsed.toString() }
  }

  // Cloud providers: the selected backend kind must match the provider's
  // verified origin exactly. An explicit openrouter/deepinfra kind is never
  // silently redirected to a different cloud — credentials would be forwarded
  // to an unverified origin.
  const origin = safeOrigin(provider?.url)
  const expectedOrigin = kind === 'openrouter' ? 'https://openrouter.ai' : kind === 'deepinfra' ? 'https://api.deepinfra.com' : null
  if (kind === 'openrouter' || kind === 'deepinfra') {
    if (origin !== expectedOrigin) {
      throw new Error(
        `Provider URL origin ${origin ?? '(invalid)'} does not match the verified ${kind} origin ${expectedOrigin}. ` +
          'Update the provider in OpenFox Provider Manager or choose another backend.',
      )
    }
    return { endpointKey: 'decisions', url: null }
  }
  if (origin && VERIFIED_ORIGINS[origin]) {
    return { endpointKey: VERIFIED_ORIGINS[origin], url: null }
  }
  throw new Error(`No verified endpoint mapping for provider origin ${origin ?? '(invalid)'}`)
}

function safeOrigin(url) {
  try {
    return new URL(url).origin
  } catch {
    return null
  }
}

/**
 * Best-effort backend kind detection from provider metadata.
 * Explicit settings always win.
 */
export function detectKind(provider) {
  if (!provider) return 'local'
  const origin = safeOrigin(provider.url)
  if (origin === 'https://openrouter.ai') return 'openrouter'
  if (origin === 'https://api.deepinfra.com') return 'deepinfra'
  if (provider.isLocal || (origin && LOOPBACK_HOSTS.has(new URL(origin).hostname))) return 'local'
  return 'custom'
}

/**
 * Whether the selected backend performs remote (cloud) inference — drives the
 * privacy consent requirement.
 */
export function isRemoteBackend(provider, settings = {}) {
  const kind = settings.backendKind ?? detectKind(provider)
  return kind === 'openrouter' || kind === 'deepinfra' || kind === 'custom'
}

/**
 * Default model for a backend kind (local Jev servers ignore the model field).
 */
export function defaultModelFor(provider, settings = {}) {
  const kind = settings.backendKind ?? detectKind(provider)
  return kind === 'local' ? (settings.localModel || 'jev-style') : DEFAULT_MODEL
}