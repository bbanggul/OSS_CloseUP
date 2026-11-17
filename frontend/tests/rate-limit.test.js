import { test } from 'node:test'
import assert from 'node:assert/strict'

import { rateLimitNotice } from '../src/display.js'

test('GitHub 한도 초과 안내: 개수와 KST 시각', () => {
  assert.equal(rateLimitNotice({ status: 'completed' }), null)
  assert.equal(rateLimitNotice(null), null)
  assert.deepEqual(rateLimitNotice({ github_rate_limited: 1281, rate_limit_reset: '1794917698' }), { count: 1281, at: '21:14' })
  assert.deepEqual(rateLimitNotice({ github_rate_limited: 3 }), { count: 3, at: null })
})
