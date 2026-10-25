import { SEVERITIES, compareSemver, findingLabel, parseSemver, rangeFixFor, uniqueFixVersions } from './display.js'

const grades = { P0: 0, P1: 1, P2: 2, P3: 3 }

// Presentation grouping only. Never merge advisory aliases or infer priority from severity.
export function packageGroups(findings) {
  const groups = new Map()
  const unlinked = []
  for (const finding of findings || []) {
    const links = (finding.packages || []).filter(p => p.name && p.installed_version)
    if (!links.length) unlinked.push(finding)
    for (const pkg of links) {
      const key = JSON.stringify([pkg.name, pkg.installed_version])
      if (!groups.has(key)) groups.set(key, { key, name: pkg.name, version: pkg.installed_version, entries: [], priority: null, rank: Infinity })
      const group = groups.get(key)
      const id = finding.finding_id || finding.finding_key || finding
      let entry = group.entries.find(e => e.id === id)
      if (!entry) {
        entry = { id, finding, packages: [] }
        group.entries.push(entry)
      }
      entry.packages.push(pkg)
      if (pkg.priority in grades) {
        if (group.priority === null || grades[pkg.priority] < grades[group.priority]) {
          group.priority = pkg.priority
          group.rank = pkg.priority_rank ?? Infinity
        } else if (pkg.priority === group.priority) {
          group.rank = Math.min(group.rank, pkg.priority_rank ?? Infinity)
        }
      }
    }
  }
  for (const group of groups.values()) {
    group.counts = Object.fromEntries(SEVERITIES.map(s => [s, 0]))
    for (const { finding } of group.entries) {
      group.counts[SEVERITIES.includes(finding.severity) ? finding.severity : 'UNKNOWN']++
    }
    group.commonFix = commonFixVersion(group)
  }
  const all = [...groups.values()]
  selectPackageGroups(all).filter(g => g.priority in grades).forEach((g, i) => { g.displayRank = i + 1 })
  return { groups: all, unlinked }
}

export function selectPackageGroups(groups, query = '', priority = 'all', order = 'priority') {
  const q = query.trim().toLowerCase()
  const rows = groups.filter(g => (priority === 'all' || (g.priority || 'unranked') === priority)
    && (!q || [g.name, g.version, ...g.entries.map(e => findingLabel(e.finding))].some(v => String(v).toLowerCase().includes(q))))
  // Preserve published link rank until the package-sort API is supplied.
  return order === 'original' ? rows : [...rows].sort((a, b) =>
    (grades[a.priority] ?? 4) - (grades[b.priority] ?? 4) || a.rank - b.rank
    || a.name.localeCompare(b.name) || a.version.localeCompare(b.version))
}

// 설치 버전이 이 후보의 영향 범위 안에 있는지. 범위를 해석할 수 없으면 null(확인 불가).
function affectedBy(version, candidates) {
  let readable = false
  for (const c of candidates || []) {
    const range = c && c.range
    if (!range || !Array.isArray(range.events) || (range.type && range.type !== 'SEMVER')) continue
    readable = true
    let introduced = null
    for (const event of range.events) {
      if (event && event.introduced !== undefined) {
        if (introduced !== null) return null // 끝이 없는 범위가 겹치면 판단하지 않는다
        introduced = String(event.introduced)
      } else if (event && introduced !== null && (event.fixed !== undefined || event.last_affected !== undefined)) {
        const end = String(event.fixed ?? event.last_affected)
        const afterStart = introduced === '0' || compareSemver(version, introduced) >= 0
        const cmp = compareSemver(version, end)
        if (cmp === null) return null
        if (afterStart && (event.fixed !== undefined ? cmp === -1 : cmp <= 0)) return true
        introduced = null
      }
    }
    if (introduced !== null && (introduced === '0' || compareSemver(version, introduced) >= 0)) return true
  }
  return readable ? false : null
}

// 0.x는 minor 변경도 호환성이 깨질 수 있어 주요 변경으로 본다.
function majorChange(from, to) {
  const a = parseSemver(from), b = parseSemver(to)
  if (!a || !b) return false
  return a.nums[0] !== b.nums[0] || (a.nums[0] === 0 && a.nums[1] !== b.nums[1])
}

// 패키지의 확인된 취약점을 함께 해결하는 수정 버전. 최신 버전이 아니라, 각 취약점의
// 범위로 확인된 수정 버전 중 가장 높은 값을 고른 뒤 모든 영향 범위 밖인지 다시 확인한다.
// status: all(전체 확인) | partial(일부만 확인) | conflict(후보가 다른 범위에 걸림) | none
export function commonFixVersion(group) {
  const installed = group.version
  const rows = group.entries.map(({ packages }) => {
    const candidates = packages.flatMap(p => p.fixed_version_candidates || [])
    return { candidates, target: rangeFixFor(installed, candidates), reported: uniqueFixVersions(candidates).length > 0 }
  })
  const targets = rows.map(r => r.target).filter(Boolean)
  const total = rows.length
  const missing = rows.filter(r => !r.reported).length
  const unverified = rows.filter(r => r.reported && !r.target).length
  if (!targets.length) return { status: 'none', total, covered: 0, missing, unverified }
  const version = targets.sort((a, b) => compareSemver(a, b)).at(-1)
  const checks = rows.map(r => affectedBy(version, r.candidates))
  const result = { version, total, missing, unverified, majorChange: majorChange(installed, version) }
  // 수정 버전이 확인된 취약점에 후보가 걸리면 공통 버전을 정할 수 없다.
  if (rows.some((r, i) => r.target && checks[i] === true)) return { ...result, status: 'conflict', covered: 0 }
  // 범위로 확인된 경우만 해결로 센다. 수정 버전이 알려지지 않은 취약점은 해결로 세지 않는다.
  const covered = checks.filter(x => x === false).length
  return { ...result, status: covered === total ? 'all' : 'partial', covered }
}

export function commonFixText(group) {
  const fix = group.commonFix || { status: 'none' }
  const indirect = group.entries.every(e => e.packages.every(p => p.relationship === 'indirect'))
  const notes = []
  if (fix.status === 'all') notes.push(`${fix.version} 이상이면 이 패키지에서 확인된 ${fix.total}건이 모두 영향 범위를 벗어납니다. 최신 버전이 아니라 확인된 최소 공통 버전입니다.`)
  else if (fix.status === 'partial') notes.push(`${fix.version} 이상이면 ${fix.covered}건이 해결되는 것으로 확인됩니다. 나머지 ${fix.total - fix.covered}건은 수정 정보가 없거나 범위로 확인되지 않아 각 취약점에서 따로 확인하세요.`)
  else if (fix.status === 'conflict') notes.push(`가장 높은 수정 버전 ${fix.version}도 다른 취약점의 영향 범위에 들어가 공통 버전을 정하지 못했습니다. 각 취약점의 수정 정보를 확인하세요.`)
  else notes.push('범위로 확인된 수정 버전이 없어 공통 버전을 정하지 못했습니다. 각 취약점의 수정 정보를 확인하세요.')
  if (fix.majorChange && fix.status !== 'conflict') notes.push('현재 버전과 주요 버전이 달라 호환성 확인이 필요합니다.')
  if (indirect && (fix.status === 'all' || fix.status === 'partial')) notes.push('직접 설치한 패키지가 아니라서 상위 패키지 업데이트나 overrides가 필요할 수 있습니다.')
  if (fix.status === 'all' || fix.status === 'partial') notes.push('변경 후 테스트하고 다시 검사해 확인하세요.')
  return notes.join(' ')
}
