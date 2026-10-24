const GRADES = ['P0', 'P1', 'P2', 'P3', 'INFO']

// Same presentation contract as ai_groups.py; consumes priority, never calculates it.
export function matchesAiGroup(finding, key) {
  if (['license', 'maintenance'].includes(finding.type)) return finding.type === key
  if (!finding.severity || finding.severity === 'UNKNOWN') return key === 'unknown'
  const packages = finding.packages?.length ? finding.packages : [{ priority: null }]
  return packages.some((pkg) => {
    const group = GRADES.includes(pkg.priority) ? pkg.priority
      : ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(finding.severity) ? `unranked-${finding.severity}` : 'unranked'
    return group === key
  })
}

export function currentAiData(data, findingId) {
  if (!findingId && data?.status === 'succeeded' && data.output?.layout !== 'package-v1') {
    return { status: 'stale', message: '새 우선 확인 보고서 형식으로 보고서를 다시 생성해 주세요.' }
  }
  return data
}
