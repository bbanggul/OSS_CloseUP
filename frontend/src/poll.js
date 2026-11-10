// 검사 화면 폴링 한 번의 결과 정리.
// 검사가 진행 중이면 결과 스냅숏이 계속 바뀌어, 목록을 나눠 받는 사이 409(snapshot_changed)가 날 수 있다.
// 이 경우 오류로 띄우지 않고 이전 값을 유지한 채 곧 다시 받는다. 검사가 끝난 뒤에는 3번까지만 조용히 재시도한다.
export const MAX_SETTLED_CONFLICT_RETRIES = 3

const conflict = (result) => result.status === 'rejected' && result.reason?.status === 409

export function pollOutcome(results, active, conflictRetries) {
  const retry = results.some(conflict) && (active || conflictRetries < MAX_SETTLED_CONFLICT_RETRIES)
  const hidden = (result) => retry && conflict(result)
  return {
    retry,
    conflictRetries: retry ? conflictRetries + 1 : 0,
    // keep: 이전 값 유지, value: 새 값, null: 실패
    updates: results.map((result) => result.status === 'fulfilled' ? { value: result.value } : hidden(result) ? { keep: true } : { value: null }),
    failed: results.map((result) => result.status === 'rejected' && !hidden(result)),
    delay: active || retry ? (retry ? 1000 : 3000) : null,
  }
}
