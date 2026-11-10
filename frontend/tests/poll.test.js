import { test } from 'node:test'
import assert from 'node:assert/strict'
import { pollOutcome } from '../src/poll.js'
import { getPackageResults } from '../src/api.js'

const ok = (value) => ({ status: 'fulfilled', value })
const fail = (status, message = 'x') => ({ status: 'rejected', reason: Object.assign(new Error(message), { status }) })

test('진행 중 409는 오류로 띄우지 않고 이전 값을 유지한 채 1초 뒤 다시 받는다', () => {
  const o = pollOutcome([ok(1), ok(2), ok(3), ok(4), fail(409)], true, 0)
  assert.equal(o.retry, true)
  assert.deepEqual(o.failed, [false, false, false, false, false])
  assert.deepEqual(o.updates[4], { keep: true })
  assert.deepEqual(o.updates[0], { value: 1 })
  assert.equal(o.delay, 1000)
  assert.equal(o.conflictRetries, 1)
  // 진행 중에는 횟수와 무관하게 계속 숨긴다
  assert.equal(pollOutcome([fail(409)], true, 50).retry, true)
})

test('끝난 검사의 409는 3번까지만 조용히 재시도하고 그 뒤에는 오류로 보인다', () => {
  let n = 0
  for (; n < 3; n++) {
    const o = pollOutcome([ok(1), fail(409)], false, n)
    assert.equal(o.retry, true); assert.equal(o.delay, 1000)
  }
  const last = pollOutcome([ok(1), fail(409)], false, n)
  assert.equal(last.retry, false)
  assert.deepEqual(last.failed, [false, true])
  assert.deepEqual(last.updates[1], { value: null })
  assert.equal(last.delay, null)
  assert.equal(last.conflictRetries, 0)
})

test('409가 아닌 실패는 진행 중에도 바로 오류로 보인다', () => {
  const o = pollOutcome([fail(503), ok(2)], true, 0)
  assert.equal(o.retry, false)
  assert.deepEqual(o.failed, [true, false])
  assert.deepEqual(o.updates[0], { value: null })
  assert.equal(o.delay, 3000)
})

test('정상 응답이면 재시도 횟수를 초기화하고, 끝난 검사는 더 부르지 않는다', () => {
  const o = pollOutcome([ok(1)], false, 2)
  assert.equal(o.conflictRetries, 0); assert.equal(o.delay, null)
})

test('snapshot_changed 응답은 JSON 원문 대신 안내 문장으로 보인다', async () => {
  const original = globalThis.fetch
  let n = 0
  globalThis.fetch = async () => ++n === 1
    ? Response.json({ snapshot_id: 's1', result_state: 'ready', unlinked_finding_count: 0, total: 1, items: [{ package_group_id: 'g' }] })
    : Response.json({ detail: { code: 'snapshot_changed', snapshot_id: 's2' } }, { status: 409 })
  try {
    await assert.rejects(getPackageResults('scan'), (e) => e.status === 409 && e.message === '검사 결과가 갱신됐습니다. 다시 불러와 주세요.' && !e.message.includes('{'))
  } finally { globalThis.fetch = original }
})
