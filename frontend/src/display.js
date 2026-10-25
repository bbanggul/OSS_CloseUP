// 화면 표시용 계산 모음. React와 분리해 node --test로 검증한다.

// 검사 단계. 메인 화면에는 도구 이름 대신 역할 이름을 쓴다.
export const STAGES = [
  ['trivy', '취약점 검사 (1차)'],
  ['osv', '취약점 검사 (2차)'],
  ['syft', '패키지 목록·라이선스 확인'],
  ['package_storage', '패키지 저장'],
  ['normalization', '결과 정리'],
  ['github', '유지보수 정보 조회'],
]

export const VULN_STAGES = ['trivy', 'osv']
export const ACTIVE = new Set(['queued', 'running'])
const DONE = new Set(['completed', 'partial', 'failed', 'timeout', 'skipped'])
const FAILED = new Set(['failed', 'timeout'])

// 단계 안의 세부 진행(예: 유지보수 34/76). 필드가 없으면 null.
export function stageProgress(stage) {
  if (!stage || typeof stage !== 'object') return null
  const done = stage.completed ?? stage.processed ?? stage.progress ?? stage.done
  const total = stage.total ?? stage.count ?? stage.packages
  if (typeof done === 'number' && typeof total === 'number' && total > 0) {
    const clamped = Math.min(Math.max(done, 0), total)
    return { done: clamped, total, percent: Math.round((clamped / total) * 100) }
  }
  return null
}

// 전체 진행률. 실제로 끝난 단계와 진행 중 단계의 세부 진행만 반영한다.
// 시간이 지나면 저절로 오르는 값은 만들지 않는다.
export function computeProgress(scan) {
  if (!scan) return null
  const toolStatus = scan.tool_status || {}
  let sum = 0
  let current = null
  const failed = []
  for (const [key, name] of STAGES) {
    const stage = toolStatus[key] || {}
    if (DONE.has(stage.status)) {
      sum += 1
    } else if (stage.status === 'running') {
      const detail = stageProgress(stage)
      if (detail) sum += detail.done / detail.total
      if (!current) current = { name, detail }
    }
    if (FAILED.has(stage.status)) failed.push(name)
  }
  // 도구 실행 전에 worker 자체가 실패한 경우(예: 결과 폴더 권한)
  const worker = toolStatus.worker
  const workerReason = worker && FAILED.has(worker.status) ? (worker.reason || '알 수 없는 오류') : null

  let percent = Math.round((sum / STAGES.length) * 100)
  if (scan.status === 'completed' || scan.status === 'partial') percent = 100
  if (ACTIVE.has(scan.status) && percent >= 100) percent = 99 // 끝나기 전에는 100%를 보이지 않는다

  return { percent, status: scan.status, current, failed, workerReason }
}

// 같은 수정 후보 값을 도구별로 중복 보고하는 경우가 있어 고유 값만 남긴다.
// 어떤 값이 설치 버전에 맞는지는 판정하지 않는다(priority·추천 규칙의 영역).
export function uniqueFixVersions(candidates) {
  const seen = new Set()
  const out = []
  for (const c of candidates || []) {
    const value = c && typeof c === 'object' ? c.value : c
    if (typeof value === 'string' && value && !seen.has(value)) {
      seen.add(value)
      out.push(value)
    }
  }
  return out
}

// 배포 방식에 따라 의무가 생길 수 있어 확인을 안내할 라이선스(잠정 목록, 공동 합의 필요).
// 위험 판정이 아니라 '확인 필요' 안내 기준이다.
export const LICENSE_REVIEW_PATTERNS = [/\b(A|L)?GPL\b/i, /\bSSPL\b/i, /\bEUPL\b/i]

export function licenseState(licenses) {
  const list = (licenses || []).filter((x) => typeof x === 'string' && x.trim())
  if (list.length === 0) return 'unknown'
  if (list.some((l) => LICENSE_REVIEW_PATTERNS.some((re) => re.test(l)))) return 'review'
  return 'ok'
}

// AI 보고서 상태를 화면 문구로 바꾼다. 본문은 succeeded일 때만 보여준다.
export function aiReportView({ loading, data, error } = {}) {
  if (loading) return { tone: 'muted', message: 'AI 설명을 불러오는 중입니다.' }
  if (error) return { tone: 'error', message: 'AI 설명을 불러오지 못했습니다. 검사 결과는 아래에서 그대로 확인할 수 있습니다.' }
  const status = data && data.status
  const meta = data && data.prompt_version
    ? `${data.model || '모델 미기록'} · 프롬프트 ${data.prompt_version}${data.created_at ? ` · ${data.created_at.slice(0, 16).replace('T', ' ')} 생성` : ''}`
    : null
  switch (status) {
    case 'stale':
      return { tone: 'muted', message: data.message || '검사 정보 또는 보고서 형식이 변경되었습니다. AI 설명을 다시 생성해 주세요.' }
    case 'succeeded':
      return { tone: 'muted', message: '이 검사 결과를 바탕으로 만든 설명입니다.', output: data.output, meta }
    case 'pending':
    case 'running':
      return { tone: 'muted', message: 'AI 설명을 만들고 있습니다.', meta }
    case 'failed':
    case 'rejected':
      return { tone: 'error', message: data.message || '설명을 만들지 못했습니다.', meta }
    default:
      return { tone: 'muted', message: 'AI 설명은 아직 준비되지 않았습니다.' }
  }
}

// 취약점 검사 단계 중 실패한 것이 있는지. 0건 안내 문구를 고르는 데 쓴다.
export function vulnScanFailed(scan) {
  const toolStatus = (scan && scan.tool_status) || {}
  return VULN_STAGES.some((key) => FAILED.has((toolStatus[key] || {}).status))
}

// ── 취약점 상세: 고치는 방법 ──────────────────────────────

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/

export function parseSemver(value) {
  const m = SEMVER.exec(String(value ?? '').trim())
  return m ? { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] || null } : null
}

// a<b: -1, a=b: 0, a>b: 1, 비교 불가: null. 정식 버전이 같은 숫자의 pre-release보다 크다.
export function compareSemver(a, b) {
  const x = parseSemver(a)
  const y = parseSemver(b)
  if (!x || !y) return null
  for (let i = 0; i < 3; i += 1) {
    if (x.nums[i] !== y.nums[i]) return x.nums[i] < y.nums[i] ? -1 : 1
  }
  if (x.pre === y.pre) return 0
  if (!x.pre) return 1
  if (!y.pre) return -1
  return x.pre < y.pre ? -1 : 1
}

// OSV 영향 범위(introduced ~ fixed)에 설치 버전이 들어가는 수정 버전만 고른다.
// 추측이 아니라 범위 데이터로 확인되는 값만 쓴다. 확인할 수 없으면 null.
export function rangeFixFor(installed, candidates) {
  if (!parseSemver(installed)) return null
  const matches = []
  for (const c of candidates || []) {
    const range = c && c.range
    if (!range || !Array.isArray(range.events) || (range.type && range.type !== 'SEMVER')) continue
    let introduced = null
    for (const event of range.events) {
      if (event && event.introduced !== undefined) {
        introduced = String(event.introduced)
      } else if (event && event.fixed !== undefined && introduced !== null) {
        const fixed = String(event.fixed)
        const afterStart = introduced === '0' || compareSemver(installed, introduced) >= 0
        const beforeFix = compareSemver(installed, fixed) === -1
        if (afterStart && beforeFix && parseSemver(fixed)) matches.push(fixed)
        introduced = null
      }
    }
  }
  if (matches.length === 0) return null
  // 여러 권고가 있으면 모두를 만족하는 가장 높은 값
  return matches.sort((a, b) => compareSemver(a, b)).at(-1)
}

// 복사용 명령어에 들어갈 값은 npm 이름·버전 형식일 때만 쓴다(이상한 문자열이 명령어에 섞이지 않게).
const NPM_NAME = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/

// 패키지별 고치는 방법. kind: direct | indirect | none | unverified
export function fixGuide(pkg) {
  const candidates = uniqueFixVersions(pkg && pkg.fixed_version_candidates)
  if (candidates.length === 0) return { kind: 'none', candidates }
  const target = rangeFixFor(pkg.installed_version, pkg.fixed_version_candidates)
  const safe = NPM_NAME.test(pkg.name || '') && parseSemver(target)
  if (!target || !safe) return { kind: 'unverified', candidates }
  if (pkg.relationship === 'direct') {
    return { kind: 'direct', target, candidates, commands: [`npm install ${pkg.name}@${target}`] }
  }
  if (pkg.relationship === 'indirect') {
    return { kind: 'indirect', target, candidates, commands: [`npm ls ${pkg.name}`, `npm update ${pkg.name}`] }
  }
  return { kind: 'unverified', candidates }
}

export function findingLabel(item) {
  const ids = Array.isArray(item && item.identifiers) ? item.identifiers : []
  return (item && item.canonical_id)
    || ids.map((x) => (typeof x === 'string' ? x : x.value || x.id)).filter(Boolean).join(', ')
    || (item && item.finding_key) || '—'
}

// ── 주소(#) 기반 화면 위치: 새로고침·뒤로 가기·주소 공유용 ──
const ROUTE = /^#\/scan\/([0-9a-fA-F-]{36})(?:\/finding\/([0-9a-fA-F-]{36})|\/package\/([^/]+)|\/(findings|licenses|maintenance|packages))?$/

// 패키지 주소는 '이름@버전'을 인코딩해 쓴다(@scope/name도 한 칸에 들어가도록).
export function packageFromKey(key) {
  let text
  try { text = decodeURIComponent(key || '') } catch { return null }
  const at = text.lastIndexOf('@')
  return at > 0 && at < text.length - 1 ? { name: text.slice(0, at), version: text.slice(at + 1) } : null
}

export function parseRoute(hash) {
  const m = ROUTE.exec(hash || '')
  if (!m) return { scanId: null, findingId: null }
  const pkg = m[3] ? packageFromKey(m[3]) : null
  return { scanId: m[1], findingId: m[2] || null, ...(pkg ? { pkg } : {}), ...(m[4] ? { section: m[4] } : {}) }
}

export function routeHash(scanId, findingId, section = 'first', pkg = null) {
  if (!scanId) return ''
  if (pkg) return `#/scan/${scanId}/package/${encodeURIComponent(`${pkg.name}@${pkg.version}`)}`
  return findingId ? `#/scan/${scanId}/finding/${findingId}` : `#/scan/${scanId}${section !== 'first' && ['findings', 'licenses', 'maintenance', 'packages'].includes(section) ? `/${section}` : ''}`
}

// ── 대시보드 요약(Figma 시안 기준) ─────────────────────────

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
const sevIndex = (s) => SEVERITIES.indexOf(SEVERITIES.includes(s) ? s : 'UNKNOWN')

export const RELATION_LABEL = { direct: '직접 설치', indirect: '다른 패키지가 사용', root: '프로젝트 자체', unknown: '확인 불가' }
export const relationLabel = (r) => RELATION_LABEL[r] || '확인 불가'

// findings 응답에는 라이선스·유지보수 유형도 들어올 수 있다. 취약점만 고른다.
export function vulnItems(findings) {
  return ((findings && findings.items) || []).filter((f) => !f.type || f.type === 'vulnerability')
}

export function severityCounts(items) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]))
  for (const item of items || []) counts[SEVERITIES[sevIndex(item.severity)]] += 1
  return counts
}

const PRIORITY_RANK = { P0: 0, P1: 1, P2: 2, P3: 3, INFO: 4 }

// 패키지별 우선순위 중 가장 급한 값. 계산되지 않았으면 null(산정 전).
export function bestPriority(finding) {
  const list = [...((finding && finding.packages) || []).map((p) => p && p.priority), finding && finding.priority]
    .filter((p) => p in PRIORITY_RANK)
  return list.sort((a, b) => PRIORITY_RANK[a] - PRIORITY_RANK[b])[0] || null
}

export const priorityComputed = (items) => (items || []).some((f) => bestPriority(f))

// 먼저 볼 항목: 우선순위 규칙이 계산한 값만 쓴다(심각도로 대신 정하지 않는다).
// 포함 범위와 개수는 잠정값이며 우선순위 규칙 담당과 합의가 필요하다.
export const FIRST_LOOK = { priorities: ['P0', 'P1', 'P2'], max: 5 }

// Use one representative package consistently for name, priority and fix information.
export function representativePackage(finding) {
  const p = bestPriority(finding)
  const packages = finding.packages || []
  const eligible = p ? packages.filter((x) => x.priority === p) : packages
  return [...eligible].sort((a, b) => (a.priority_rank ?? Infinity) - (b.priority_rank ?? Infinity)
    || (p ? Number(uniqueFixVersions(b.fixed_version_candidates).length > 0) - Number(uniqueFixVersions(a.fixed_version_candidates).length > 0) : 0)
    || String(a.name).localeCompare(String(b.name)))[0]
}

export function priorityStateText(state) {
  if (state?.current_result_available) return '조치 우선순위 계산 완료'
  if (state?.status === 'running') return '조치 우선순위를 계산하고 있습니다.'
  if (['failed', 'invalid_input', 'unavailable'].includes(state?.status)) return '우선순위 계산 결과를 사용할 수 없습니다. 검사 결과와 근거는 계속 확인할 수 있습니다.'
  return '조치 우선순위 산정 전입니다. 이전 검사는 새로 업로드해 주세요.'
}

export function firstLook(items) {
  return (items || [])
    .map((f) => ({ f, p: bestPriority(f), pkg: representativePackage(f) }))
    .filter((x) => x.p && FIRST_LOOK.priorities.includes(x.p))
    .sort((a, b) => PRIORITY_RANK[a.p] - PRIORITY_RANK[b.p]
      || (a.f.priority_rank ?? Infinity) - (b.f.priority_rank ?? Infinity)
      || Number(uniqueFixVersions(b.pkg?.fixed_version_candidates).length > 0) - Number(uniqueFixVersions(a.pkg?.fixed_version_candidates).length > 0)
      || String(findingLabel(a.f)).localeCompare(String(findingLabel(b.f))))
    .slice(0, FIRST_LOOK.max)
    .map((x) => ({ ...x.f, best_priority: x.p }))
}

export function packageSummary(packages) {
  const all = (packages && packages.items) || []
  const external = all.filter((i) => i.relationship !== 'root')
  const direct = external.filter((i) => i.relationship === 'direct').length
  const indirect = external.filter((i) => i.relationship === 'indirect').length
  return {
    total: external.length, direct, indirect, unknown: external.length - direct - indirect,
    root: all.find((i) => i.relationship === 'root') || null,
    status: ((packages && packages.package_storage) || {}).status || null,
  }
}

export function licenseSummary(packages) {
  const external = ((packages && packages.items) || []).filter((i) => i.relationship !== 'root')
  const review = external.filter((i) => licenseState(i.licenses) === 'review').length
  const unknown = external.filter((i) => licenseState(i.licenses) === 'unknown').length
  return { review, unknown, total: review + unknown }
}

// 유지보수: 확인된 사실(archived, deprecated)만 센다. null은 '아니오'가 아니다.
export function maintenanceSummary(maintenance) {
  const items = (maintenance && maintenance.items) || []
  const archived = items.filter((i) => i.archived === true).length
  const deprecated = items.filter((i) => i.deprecated === true).length
  const flagged = items.filter((i) => i.archived === true || i.deprecated === true).length
  return { archived, deprecated, flagged, status: ((maintenance && maintenance.collection) || {}).status || null }
}

// 고치는 방법 표에 쓰는 한 줄 요약. 추천 버전(우선순위 규칙) > 범위로 확인된 수정 버전 > 후보.
export function fixSummary(pkg) {
  if (!pkg) return { text: '—', tone: 'muted' }
  if (pkg.recommended_fixed_version) return { text: `수정 버전 ${pkg.recommended_fixed_version}`, tone: 'text' }
  const guide = fixGuide(pkg)
  if (guide.target) return { text: `수정 버전 ${guide.target}`, tone: 'text' }
  if (guide.candidates.length) return { text: `수정 후보 ${guide.candidates.join(', ')} (확인 필요)`, tone: 'muted' }
  return { text: '보고된 수정 버전 없음', tone: 'muted' }
}

export function stagesDone(scan) {
  const toolStatus = (scan && scan.tool_status) || {}
  return STAGES.filter(([key]) => DONE.has((toolStatus[key] || {}).status)).length
}

export function scanDuration(scan) {
  const start = scan && Date.parse(scan.started_at || scan.created_at)
  const end = scan && Date.parse(scan.finished_at)
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null
  const sec = Math.round((end - start) / 1000)
  return sec >= 60 ? `${Math.floor(sec / 60)}분 ${sec % 60}초` : `${sec}초`
}

// ── AI 설명 ─────────────────────────────────────────────
// 검사가 끝나면 이 심각도의 항목만 자동으로 설명을 만든다(소개서 3.6).
export const AI_AUTO_SEVERITIES = ['CRITICAL', 'HIGH']
// 자동 생성 파이프라인이 연결되면 true로 바꾼다. 업로드 화면의 외부 전송 안내도 이 값을 따른다.
export const AI_AUTO_EXPLAIN = false

export function aiFindingView(ai, severity) {
  const view = aiReportView(ai)
  const status = ai && ai.data && ai.data.status
  if (!ai.loading && !ai.error && (!status || status === 'not_generated')
      && !AI_AUTO_SEVERITIES.includes(severity)) {
    return { tone: 'muted', kind: 'skipped', message: `이 항목(${severity || 'UNKNOWN'})은 자동 설명 대상(CRITICAL·HIGH)이 아니에요. 검사 결과와 고치는 방법을 참고하세요.` }
  }
  const kind = ai.loading ? 'loading'
    : ai.error ? 'error'
      : status === 'succeeded' ? 'done'
        : status === 'pending' || status === 'running' ? 'running'
          : status === 'failed' || status === 'rejected' ? 'failed' : 'none'
  return { ...view, kind }
}

const AI_LABELS = { summary: '요약', reason: '왜 먼저 봐야 하나', recommendation: '권장 조치', next_actions: '다음 행동', highlights: '항목별 설명', uncertainty: '확인할 한계' }

// LLM 출력(JSON 객체)을 화면 섹션으로 바꾼다. 아는 키만 문장으로 보여주고 나머지는 원문으로 둔다.
export function aiSections(output) {
  if (!output || typeof output !== 'object') return { sections: [], evidence: [], extra: null }
  const sections = []
  const extra = {}
  let evidence = []
  for (const [key, value] of Object.entries(output)) {
    if (key === 'evidence' && Array.isArray(value)) {
      evidence = value.map((v) => (typeof v === 'string' ? v : v && (v.label || v.value || v.id))).filter(Boolean).map(String)
    } else if (AI_LABELS[key] && typeof value === 'string') {
      sections.push({ key, label: AI_LABELS[key], text: value })
    } else if (AI_LABELS[key] && Array.isArray(value) && value.every((v) => typeof v === 'string')) {
      sections.push({ key, label: AI_LABELS[key], list: value })
    } else {
      extra[key] = value
    }
  }
  return { sections, evidence, extra: Object.keys(extra).length ? extra : null }
}

// Ranking is global to the scan, independent of search and detail navigation order.
export function topFindingRank(items, findingId) {
  const index = firstLook(items).findIndex((finding) => finding.finding_id === findingId)
  return index < 0 ? null : index + 1
}

// Apply server priority groups and stored rank without changing the underlying findings.
export function priorityList(items, group = 'all', order = 'priority') {
  const rows = (items || []).filter((f) => group === 'all' || (bestPriority(f) || 'unranked') === group)
  if (order === 'original') return rows
  const grades = { P0: 0, P1: 1, P2: 2, P3: 3 }
  return [...rows].sort((a, b) => (grades[bestPriority(a)] ?? 4) - (grades[bestPriority(b)] ?? 4)
    || (a.priority_rank ?? Infinity) - (b.priority_rank ?? Infinity))
}
