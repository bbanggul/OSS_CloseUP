import test from 'node:test'
import assert from 'node:assert/strict'
import { parseRoute, routeHash } from '../src/display.js'
const scan = '326ca7d4-0177-434b-ac3b-9649a7bd5df0'
for (const section of ['findings','licenses','maintenance','packages']) {
  test(`${section} route survives reload`, () => {
    assert.deepEqual(parseRoute(routeHash(scan, null, section)), { scanId: scan, findingId: null, section })
  })
}
test('unknown section does not produce a list route', () => {
  assert.equal(parseRoute(`#/scan/${scan}/other`).scanId, null)
})

test('package routes round-trip, including scoped names', () => {
  const scan = '11111111-1111-1111-1111-111111111111'
  for (const pkg of [{ name: 'form-data', version: '2.3.3' }, { name: '@babel/core', version: '7.0.0-beta.1' }]) {
    assert.deepEqual(parseRoute(routeHash(scan, null, 'first', pkg)), { scanId: scan, findingId: null, pkg })
  }
  assert.deepEqual(parseRoute(`#/scan/${scan}/package/no-version`), { scanId: scan, findingId: null })
})
