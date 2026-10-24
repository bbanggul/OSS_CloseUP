import test from 'node:test'
import assert from 'node:assert/strict'
import { matchesAiGroup, currentAiData } from '../src/aiPresentation.js'
import { getAiFinding, generateAiFinding } from '../src/api.js'

test('unranked severity does not become a P grade', () => {
  const f = { type: 'vulnerability', severity: 'CRITICAL', packages: [{ priority: null }] }
  assert.equal(matchesAiGroup(f, 'P0'), false)
  assert.equal(matchesAiGroup(f, 'unranked-CRITICAL'), true)
  f.packages[0].priority = 'P2'
  assert.equal(matchesAiGroup(f, 'P2'), true)
  assert.equal(matchesAiGroup(f, 'unranked-CRITICAL'), false)
})

test('package priorities can place the same finding in multiple groups', () => {
  const f = { type: 'vulnerability', severity: 'HIGH', packages: [{ priority: 'P0' }, { priority: 'P1' }] }
  assert.equal(matchesAiGroup(f, 'P0'), true)
  assert.equal(matchesAiGroup(f, 'P1'), true)
})

test('unknown, missing package, license and maintenance stay distinct', () => {
  assert.equal(matchesAiGroup({ severity: 'UNKNOWN', packages: [{ priority: 'P0' }] }, 'P0'), false)
  assert.equal(matchesAiGroup({ severity: 'UNKNOWN' }, 'unknown'), true)
  assert.equal(matchesAiGroup({ severity: 'HIGH' }, 'unranked-HIGH'), true)
  for (const type of ['license', 'maintenance']) {
    assert.equal(matchesAiGroup({ type, severity: 'HIGH', packages: [{ priority: 'P0' }] }, type), true)
    assert.equal(matchesAiGroup({ type, severity: 'HIGH', packages: [{ priority: 'P0' }] }, 'P0'), false)
  }
})

test('old report prose is hidden but individual explanations remain readable', () => {
  const old = { status: 'succeeded', output: { highlights: ['old paragraphs'] } }
  assert.equal(currentAiData(old).status, 'stale')
  assert.equal(currentAiData(old).output, undefined)
  assert.equal(currentAiData(old, 'finding-1'), old)
  const grouped = { status: 'succeeded', output: { layout: 'grouped-v2', groups: [] } }
  assert.equal(currentAiData(grouped).status, 'stale')
  const narrative = { status: 'succeeded', output: { layout: 'package-v1', paragraphs: [] } }
  assert.equal(currentAiData(narrative), narrative)
})

test('finding read and manual generate address the selected finding only', async () => {
  const original = globalThis.fetch
  const calls = []
  globalThis.fetch = async (...args) => {
    calls.push(args)
    return { ok: true, text: async () => '{"status":"not_generated"}' }
  }
  try {
    await getAiFinding('scan-1', 'finding-2')
    await generateAiFinding('scan-1', 'finding-2')
    assert.equal(calls[0][0], '/api/scans/scan-1/ai/findings/finding-2')
    assert.deepEqual(calls[1], ['/api/scans/scan-1/ai/findings/finding-2', { method: 'POST' }])
  } finally { globalThis.fetch = original }
})
