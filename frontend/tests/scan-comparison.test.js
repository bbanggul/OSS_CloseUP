import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { comparisonRows, comparisonError, findingText } from '../src/scanComparison.js'
import { createScan, compareScans, getProjectScans } from '../src/api.js'
import { parseRoute, routeHash } from '../src/display.js'
const original = globalThis.fetch
afterEach(() => { globalThis.fetch = original })
const directory = new URL('../../backend/tests/fixtures/scan_compare/examples/', import.meta.url)
for (const name of readdirSync(directory)) {
  test(`comparison display preserves contract: ${name}`, () => {
    const data = JSON.parse(readFileSync(new URL(name, directory)))
    const rows = comparisonRows(data)
    assert.equal(rows.length, data.items.length)
    for (const state of ['new','persisting','not_detected','not_comparable']) {
      assert.equal(rows.filter(x => x.status === state).length, data.summary[state])
    }
    data.items.forEach((item, i) => {
      for (const side of ['base','target']) for (const id of item[`${side}_finding_ids`]) {
        const finding = data.finding_catalog[side][id]
        for (const identifier of finding.identifiers) assert.ok(rows[i][`${side}Findings`].includes(identifier))
      }
    })
    for (const side of ['base','target']) for (const id of data.unlinked_findings[side]) {
      assert.ok(findingText(data, side, [id]).length > 0)
      assert.ok(!findingText(data, side, [id]).includes('undefined'))
    }
  })
}
test('upload sends project only for an explicit rescan', async () => {
  const forms=[]
  globalThis.fetch=async (_path,options) => { forms.push(options.body); return Response.json({scan_id:'new'}) }
  const f=new Blob(['{}'])
  await createScan(f,f)
  await createScan(f,f,'project-1')
  assert.equal(forms[0].has('project_id'),false)
  assert.equal(forms[1].get('project_id'),'project-1')
})
test('comparison direction and cancellation signal reach API', async () => {
  const controller=new AbortController()
  globalThis.fetch=async (path, options) => {
    assert.equal(path,'/api/scans/target/compare?base=base')
    assert.equal(options.signal,controller.signal)
    return Response.json({items:[]})
  }
  await compareScans('target','base',controller.signal)
})
test('history pagination and routing',async () => {
  globalThis.fetch=async path => { assert.equal(path,'/api/projects/p/scans?limit=50&offset=50');return Response.json({items:[]}) }
  await getProjectScans('p',50)
  const id='11111111-1111-1111-1111-111111111111'
  assert.equal(parseRoute(routeHash(id,null,'compare')).section,'compare')
})
test('domain errors explain how to recover', () => {
  assert.match(comparisonError({body:{detail:{code:'scan_processing'}}}),/완료/)
  assert.match(comparisonError({body:{detail:{code:'different_project'}}}),/같은 프로젝트/)
})
