import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { resolveEndpoint, detectKind, isRemoteBackend, defaultModelFor, isLoopbackUrl } from '../src/providers.js'

describe('endpoint resolution', () => {
  it('maps OpenRouter origin to the verified decisions endpoint', () => {
    const result = resolveEndpoint({ url: 'https://openrouter.ai/api/v1' }, { backendKind: 'openrouter' })
    assert.equal(result.endpointKey, 'decisions')
  })

  it('maps DeepInfra origin to the verified decisions endpoint', () => {
    const result = resolveEndpoint({ url: 'https://api.deepinfra.com/v1/openai' }, { backendKind: 'deepinfra' })
    assert.equal(result.endpointKey, 'decisions')
  })

  it('detects backend kind from provider origin', () => {
    assert.equal(detectKind({ url: 'https://openrouter.ai/api/v1' }), 'openrouter')
    assert.equal(detectKind({ url: 'https://api.deepinfra.com/v1' }), 'deepinfra')
    assert.equal(detectKind({ url: 'http://127.0.0.1:8765' }), 'local')
    assert.equal(detectKind({ url: 'https://other.example.com/v1', isLocal: true }), 'local')
    assert.equal(detectKind({ url: 'https://other.example.com/v1' }), 'custom')
  })

  it('rejects a provider whose origin does not match the verified mapping', () => {
    assert.throws(
      () => resolveEndpoint({ url: 'https://attacker.example.com/v1' }, { backendKind: 'openrouter' }),
      /does not match the verified openrouter origin/,
    )
  })

  it('never blindly appends /v1/systemone to a cloud URL', () => {
    assert.throws(() => resolveEndpoint({ url: 'https://openrouter.ai/api/v1' }, { backendKind: 'local' }), /loopback/)
  })

  it('local endpoint defaults to loopback systemone route', () => {
    const result = resolveEndpoint(undefined, { backendKind: 'local' })
    assert.equal(result.url, 'http://127.0.0.1:8765/v1/systemone')
    assert.equal(result.endpointKey, 'systemone')
  })

  it('local endpoint honors a custom loopback URL', () => {
    const result = resolveEndpoint(undefined, { backendKind: 'local', localUrl: 'http://localhost:9000/' })
    assert.equal(result.url, 'http://localhost:9000/v1/systemone')
  })

  it('rejects non-loopback local URLs', () => {
    assert.throws(() => resolveEndpoint(undefined, { backendKind: 'local', localUrl: 'http://10.0.0.5:8765' }), /loopback/)
  })

  it('custom endpoint requires HTTPS unless loopback', () => {
    assert.throws(() => resolveEndpoint(undefined, { backendKind: 'custom', customEndpoint: 'http://plain.example.com' }), /HTTPS/)
    assert.throws(() => resolveEndpoint(undefined, { backendKind: 'custom' }), /not configured/)
    const ok = resolveEndpoint(undefined, { backendKind: 'custom', customEndpoint: 'https://decisions.example.com/v1' })
    assert.equal(ok.url, 'https://decisions.example.com/v1')
  })

  it('classifies remote backends for privacy consent', () => {
    assert.equal(isRemoteBackend({ url: 'https://openrouter.ai/api/v1' }, {}), true)
    assert.equal(isRemoteBackend({ url: 'http://127.0.0.1:8765' }, {}), false)
    assert.equal(isRemoteBackend(undefined, { backendKind: 'local' }), false)
    assert.equal(isRemoteBackend(undefined, { backendKind: 'deepinfra' }), true)
  })

  it('default model per backend', () => {
    assert.equal(defaultModelFor(undefined, { backendKind: 'local' }), 'jev-style')
    assert.equal(defaultModelFor(undefined, { backendKind: 'openrouter' }), 'nace-ai/drex-v2.0')
    assert.equal(defaultModelFor({ url: 'https://api.deepinfra.com/v1' }, {}), 'nace-ai/drex-v2.0')
  })

  it('loopback detection', () => {
    assert.equal(isLoopbackUrl('http://127.0.0.1:8765'), true)
    assert.equal(isLoopbackUrl('http://localhost:8765'), true)
    assert.equal(isLoopbackUrl('https://example.com'), false)
    assert.equal(isLoopbackUrl('not a url'), false)
  })
})