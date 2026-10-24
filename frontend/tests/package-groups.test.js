import test from 'node:test'
import assert from 'node:assert/strict'
import { commonFixText, packageGroups, selectPackageGroups } from '../src/packageGroups.js'

const link = (name, version = '1', priority = 'P1', rank = 0) =>
  ({ name, installed_version: version, priority, priority_rank: rank })
const finding = (id, packages, severity = 'HIGH') => ({ finding_id: id, canonical_id: id, severity, packages })

test('groups by name and version, counts a finding once per group across install paths', () => {
  const input = [finding('CVE-a', [link('a'), link('a'), link('b')]), finding('CVE-b', [link('a')]), finding('CVE-c', [link('a', '2')])]
  const before = JSON.stringify(input)
  const { groups } = packageGroups(input)
  assert.equal(groups.length, 3)
  assert.deepEqual(groups.map(g => g.entries.length), [2, 1, 1])
  assert.equal(groups[0].counts.HIGH, 2)
  assert.equal(JSON.stringify(input), before)
})
test('retains missing links and UNKNOWN; never infers grade from severity', () => {
  const result = packageGroups([finding('a', []), finding('b', [link('x', '1', null)], 'CRITICAL'), finding('c', [link('x', '1', null)], null)])
  assert.equal(result.unlinked.length, 1)
  assert.equal(result.groups[0].priority, null)
  assert.equal(result.groups[0].counts.UNKNOWN, 1)
})
test('representative grade uses only this package links and preserves stored order', () => {
  const { groups } = packageGroups([
    finding('a', [link('x', '1', 'P2', 8), link('y', '1', 'P0', 0)]),
    finding('b', [link('x', '1', 'P1', 5)]),
    finding('c', [link('z', '1', 'P1', 2)]),
  ])
  assert.deepEqual(selectPackageGroups(groups).map(g => g.name), ['y', 'z', 'x'])
  assert.deepEqual(selectPackageGroups(groups, '', 'P1').map(g => g.name), ['z', 'x'])
})
test('identifier search retains full package counts and all related findings', () => {
  const { groups } = packageGroups([finding('CVE-a', [link('x')]), finding('CVE-b', [link('x')])])
  const rows = selectPackageGroups(groups, 'cve-a')
  assert.equal(rows.length, 1)
  assert.equal(rows[0].entries.length, 2)
  assert.equal(selectPackageGroups(groups, 'missing').length, 0)
})

test('display ranks are global package positions, preserved after search and filtering', () => {
  const { groups } = packageGroups([
    finding('a', [link('first', '1', 'P0', 0)]),
    finding('b', [link('second', '1', 'P0', 1)]),
    finding('c', [link('third', '1', 'P1', 2)]),
    finding('d', [link('unknown', '1', null)]),
  ])
  assert.deepEqual(groups.map(g => g.displayRank), [1, 2, 3, undefined])
  assert.equal(selectPackageGroups(groups, 'second')[0].displayRank, 2)
  assert.equal(selectPackageGroups(groups, '', 'P1')[0].displayRank, 3)
})

const ranged = (introduced, fixed) => ({ value: fixed, range: { type: 'SEMVER', events: [{ introduced }, { fixed }] } })
const fixLink = (version, candidates, relationship = 'direct') =>
  ({ name: 'pkg', installed_version: version, priority: 'P1', priority_rank: 0, relationship, fixed_version_candidates: candidates })

test('common fix is the highest confirmed fix that clears every range, not the latest release', () => {
  const { groups } = packageGroups([
    finding('a', [fixLink('2.3.3', [ranged('0', '2.5.4')])]),
    finding('b', [fixLink('2.3.3', [ranged('0', '2.5.6')])]),
  ])
  assert.deepEqual(groups[0].commonFix, { version: '2.5.6', total: 2, missing: 0, unverified: 0, majorChange: false, status: 'all', covered: 2 })
})
test('a candidate that falls inside another advisory range is rejected', () => {
  const { groups } = packageGroups([
    finding('a', [fixLink('1.0.0', [ranged('0', '1.2.0')])]),
    finding('b', [fixLink('1.0.0', [ranged('0', '1.0.5'), ranged('1.1.0', '1.3.0')])]),
  ])
  assert.equal(groups[0].commonFix.status, 'conflict')
  assert.equal(groups[0].commonFix.version, '1.2.0')
})
test('missing fix information makes the result partial, never all', () => {
  const { groups } = packageGroups([
    finding('a', [fixLink('1.0.0', [ranged('0', '1.4.0')])]),
    finding('b', [fixLink('1.0.0', [])]),
  ])
  const fix = groups[0].commonFix
  assert.equal(fix.status, 'partial')
  assert.equal(fix.covered, 1)
  assert.equal(fix.missing, 1)
})
test('no confirmed range gives none; open-ended ranges count as affected', () => {
  assert.equal(packageGroups([finding('a', [fixLink('1.0.0', ['1.2.0'])])]).groups[0].commonFix.status, 'none')
  const open = { value: '9.9.9', range: { type: 'SEMVER', events: [{ introduced: '1.5.0' }] } }
  const { groups } = packageGroups([
    finding('a', [fixLink('1.0.0', [ranged('0', '1.6.0')])]),
    finding('b', [fixLink('1.0.0', [ranged('0', '1.1.0'), open])]),
  ])
  assert.equal(groups[0].commonFix.status, 'conflict')
})
test('major and 0.x minor changes are flagged; indirect packages mention parent updates', () => {
  const major = packageGroups([finding('a', [fixLink('1.9.0', [ranged('0', '2.0.1')])])]).groups[0]
  assert.equal(major.commonFix.majorChange, true)
  assert.equal(packageGroups([finding('a', [fixLink('0.2.0', [ranged('0', '0.3.1')])])]).groups[0].commonFix.majorChange, true)
  const indirect = packageGroups([finding('a', [fixLink('2.3.3', [ranged('0', '2.5.4')], 'indirect')])]).groups[0]
  assert.match(commonFixText(indirect), /overrides/)
  assert.match(commonFixText(major), /호환성/)
})
test('advisories with no known fix stay uncovered instead of blocking the common version', () => {
  const lastAffected = { value: null, range: { type: 'SEMVER', events: [{ introduced: '4.0.0' }, { last_affected: '4.17.23' }] } }
  const { groups } = packageGroups([
    finding('a', [fixLink('4.17.15', [ranged('0', '4.17.21')])]),
    finding('b', [fixLink('4.17.15', [lastAffected])]),
  ])
  const fix = groups[0].commonFix
  assert.equal(fix.status, 'partial')
  assert.equal(fix.version, '4.17.21')
  assert.equal(fix.covered, 1)
})
