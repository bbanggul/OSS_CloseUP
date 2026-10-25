import { useEffect, useRef, useState } from 'react'
import './closeup.css'
import {
  getScan, getPackages, getMaintenance, getFindings, getSbomInfo, downloadSbom,
} from './api'
import {
  STAGES, ACTIVE, stageProgress, computeProgress, stagesDone, scanDuration,
  licenseState, vulnScanFailed, vulnItems, priorityComputed,
  priorityStateText, relationLabel, licenseSummary, maintenanceSummary, packageSummary,
  findingLabel, parseRoute, routeHash,
} from './display'
import AiReport from './AiReport'
import FindingDetail from './FindingDetail'
import PackageDetail from './PackageDetail'
import Upload from './Upload'
import { SummaryCards, SeverityDonut } from './Overview'
import Icon from './Icons'
import PackageFindingList from './PackageFindingList'
import { packageGroups, selectPackageGroups } from './packageGroups'

const STATUS_LABEL = {
  pending: '대기', queued: '대기', running: '진행 중', completed: '완료',
  partial: '부분 완료', failed: '실패', timeout: '시간 초과', skipped: '건너뜀',
}
const STATUS_DOT = { completed: 'var(--oc-sea)', running: 'var(--oc-cyan)', queued: 'var(--oc-unknown)', pending: 'var(--oc-unknown)', partial: 'var(--oc-high)', failed: 'var(--oc-crit)', timeout: 'var(--oc-crit)', skipped: 'var(--oc-unknown)' }

const label = (status) => STATUS_LABEL[status] || status || '대기'

function StatusPill({ status, children }) {
  return <span className="oc-pill"><span className="oc-dot" style={{ background: STATUS_DOT[status] || 'var(--oc-unknown)' }} />{children || label(status)}</span>
}

const TABS = [
  ['first', '먼저 볼 항목', 'check'],
  ['findings', '취약점', 'alert'],
  ['licenses', '라이선스', 'doc'],
  ['maintenance', '유지보수', 'gear'],
  ['packages', '전체 패키지', 'box'],
]

// null은 false가 아니다. 확인되지 않은 값을 '아니오'로 표시하지 않는다.
function triState(value, yes, no) {
  if (value === true) return <span className="oc-tag warn" style={{ marginLeft: 0 }}>{yes}</span>
  if (value === false) return <span className="muted">{no}</span>
  return <span className="muted">확인 불가</span>
}

function formatDate(value, withTime = false) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return withTime
    ? date.toLocaleString('ko-KR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
    : date.toLocaleDateString('ko-KR')
}

const shortVersion = (raw) => {
  if (!raw) return null
  const match = String(raw).match(/Version:\s*(\S+)/)
  return match ? match[1] : String(raw).split('\n')[0]
}

const matches = (q, ...values) => !q || values.some((v) => String(v || '').toLowerCase().includes(q))

// ── 사이드바 ──
function Sidebar({ view, tab, counts, onTab, onNewScan, sbom, onSbom, sbomBusy }) {
  const hasScan = view !== 'upload'
  const sbomTitle = sbom && sbom.available
    ? `SPDX JSON · ${(sbom.artifact.size_bytes / 1024).toFixed(0)} KB · ${shortVersion(sbom.syft && sbom.syft.tool_version) ? `Syft ${shortVersion(sbom.syft.tool_version)} · ` : ''}SHA-256 ${sbom.artifact.sha256.slice(0, 12)}…`
    : hasScan ? `내려받을 수 있는 SBOM이 아직 없습니다(${label(sbom && sbom.syft && sbom.syft.status)}). 패키지가 0개라는 뜻이 아닙니다.` : '검사 후 내려받을 수 있습니다.'
  return (
    <aside className="oc-side" aria-label="메뉴">
      <div className="oc-side-in">
      <div className="oc-logo">
        <span className="mark">OC</span>
        <div><strong>OSS Close-up</strong><small>오픈소스 클로즈업</small></div>
      </div>
      <button type="button" className={`oc-newscan${view === 'upload' ? ' on' : ''}`} onClick={onNewScan}>
        <Icon name="plus" size={18} /> 새 검사
      </button>
      <div className="label">RESULT</div>
      {TABS.map(([key, name, icon]) => (
        <button key={key} type="button" disabled={!hasScan}
          className={`oc-nav${hasScan && view === 'result' && tab === key ? ' on' : ''}`}
          aria-current={hasScan && view === 'result' && tab === key ? 'page' : undefined}
          onClick={() => onTab(key)}>
          <Icon name={icon} /><span>{name}</span>
          {hasScan && counts[key] != null && <span className="cnt">{counts[key]}</span>}
        </button>
      ))}
      <div className="label">ETC</div>
      <button type="button" className="oc-nav" disabled={!(sbom && sbom.available) || sbomBusy} onClick={onSbom} title={sbomTitle}>
        <Icon name="download" /><span>{sbomBusy ? '내려받는 중…' : 'SBOM 내려받기'}</span>
      </button>
      <button type="button" className="oc-nav" disabled title="확장 단계에서 추가됩니다">
        <Icon name="chat" /><span>질문하기 · 준비 중</span>
      </button>
      <div className="grow" />
      <p className="foot">검사 결과는 검사 엔진 값을 그대로 보여줍니다.</p>
      </div>
    </aside>
  )
}

// ── 진행 ──
function Progress({ scan }) {
  const [open, setOpen] = useState(false)
  const progress = computeProgress(scan)
  if (!progress) return null
  const toolStatus = scan.tool_status || {}
  const failedAll = progress.status === 'failed'
  const partial = progress.status === 'partial' || (progress.failed.length > 0 && !failedAll)
  const active = ACTIVE.has(progress.status)
  if (!active && !failedAll && !partial) return null // 정상 완료면 상단 상태 알약으로 충분

  let message
  if (failedAll) message = '검사에 실패했습니다. 파일을 다시 올려 검사해 주세요.'
  else if (active) message = progress.current
    ? `${progress.current.name} 중${progress.current.detail ? ` (${progress.current.detail.done}/${progress.current.detail.total})` : ''}`
    : '검사를 준비하고 있습니다.'
  else message = '검사가 끝났지만 일부 단계를 확인하지 못했습니다.'

  return (
    <section className="oc-panel oc-progress" aria-label="검사 진행">
      <div className="oc-phead" style={{ marginBottom: 6 }}>
        <h2 className="oc-ptitle">검사 진행</h2>
        <StatusPill status={progress.status} />
      </div>
      <div className="line" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress.percent} aria-label="검사 진행률">
        <span className="bar"><span className={failedAll ? 'failed' : partial ? 'partial' : ''} style={{ width: `${progress.percent}%` }} /></span>
        <strong>{progress.percent}%</strong>
      </div>
      <p className={failedAll ? 'err' : 'sub'}>{message}</p>
      {progress.failed.length > 0 && (
        <p className="err">확인하지 못한 단계: {progress.failed.join(', ')}. 이 단계의 결과는 "확인 불가"로 표시됩니다.</p>
      )}
      {progress.workerReason && <p className="err">검사 시작 단계에서 실패했습니다 ({progress.workerReason}).</p>}
      <button type="button" className="oc-link" style={{ marginTop: 8 }} onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        {open ? '단계 닫기' : '단계별로 보기'}
      </button>
      {open && (
        <ul className="stages">
          {STAGES.map(([key, name]) => {
            const stage = toolStatus[key] || {}
            const detail = stageProgress(stage)
            return (
              <li key={key}>
                <span className="name">{name}</span>
                <StatusPill status={stage.status} />
                {detail && <span className="muted">{detail.done} / {detail.total}개</span>}
                {stage.error_message && <span className="err">{stage.error_message}</span>}
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}

// ── 목록 탭 ──
function Loading() { return <p className="oc-empty">불러오는 중…</p> }

function FirstLook({ vulns, findings, scan, q, onPackage, onTab }) {
  if (!findings) return <Loading />
  const status = (findings.normalization || {}).status
  if (status !== 'completed' && vulns.length === 0) {
    return <p className="oc-empty">취약점 결과를 정리하는 중입니다 ({label(status)}). 0건이라는 뜻이 아닙니다.</p>
  }
  if (vulns.length === 0) {
    return vulnScanFailed(scan)
      ? <p className="oc-empty err">취약점 검사 일부가 실패했습니다. 발견된 항목이 없어 보여도 확인하지 못한 취약점이 있을 수 있습니다.</p>
      : <p className="oc-empty">먼저 볼 취약점이 없습니다. 알려진 취약점이 발견되지 않았다는 뜻이며, 코드에 문제가 없다는 보장은 아닙니다.</p>
  }
  if (!priorityComputed(vulns)) {
    return (
      <p className="oc-empty">{findings.priority_evaluation?.current_result_available ? '계산은 완료됐지만 등급이 있는 연결 항목이 없습니다. 심각도와 패키지 연결 정보를 확인해 주세요.' : priorityStateText(findings.priority_evaluation)} <button type="button" className="oc-link" onClick={() => onTab('findings')}>취약점 탭</button>에서 전체 목록을 볼 수 있어요.</p>
    )
  }
  const top = selectPackageGroups(packageGroups(vulns).groups).filter(g => ['P0', 'P1', 'P2'].includes(g.priority)).slice(0, 5)
  const rows = selectPackageGroups(top, q)
  if (rows.length === 0) return <p className="oc-empty">{q ? '검색 결과가 없습니다.' : '먼저 볼 항목이 없습니다. 취약점 탭에서 전체 목록을 볼 수 있어요.'}</p>
  return (
    <>
      <PackageFindingList groups={rows} onPackage={onPackage} />
      <p className="oc-hint">패키지를 누르면 AI 설명, 수정 프롬프트, 취약점 목록을 볼 수 있습니다.</p>
    </>
  )
}

function Findings({ vulns, findings, scan, q, onOpen, onPackage, queryFailed }) {
  const [priorityFilter, setPriorityFilter] = useState('all')
  const [sortOrder, setSortOrder] = useState('priority')
  if (!findings) return queryFailed
    ? <p className="oc-empty" role="status">취약점 목록을 불러오지 못했습니다. 위의 ‘다시 불러오기’를 눌러 주세요.</p>
    : <Loading />
  const status = (findings.normalization || {}).status
  if (status !== 'completed' && vulns.length === 0) {
    return <p className="oc-empty">취약점 결과를 정리하는 중입니다 ({label(status)}). 취약점 0건이라는 뜻이 아닙니다.</p>
  }
  const scanFailed = vulnScanFailed(scan)
  if (vulns.length === 0) {
    return scanFailed
      ? <p className="oc-empty err">취약점 검사 일부가 실패했습니다. 발견된 항목이 없는 것처럼 보여도 확인하지 못한 취약점이 있을 수 있습니다.</p>
      : <p className="oc-empty">취약점 검사가 정상 완료되었고, 알려진 취약점은 발견되지 않았습니다. 코드에 문제가 없다는 보장은 아닙니다.</p>
  }
  const grouped = packageGroups(vulns)
  const rows = selectPackageGroups(grouped.groups, q, priorityFilter, sortOrder)
  const unlinked = grouped.unlinked.filter(f => matches(q, findingLabel(f)))
  return (
    <>
      <div className="oc-priority-controls">
        <label>조치 우선순위 <select value={priorityFilter} onChange={(e) => setPriorityFilter(e.target.value)}>
          <option value="all">전체</option><option value="P0">가장 먼저 확인</option>
          <option value="P1">이어서 확인</option><option value="P2">다음 조치 계획</option>
          <option value="P3">낮은 우선순위</option><option value="unranked">미산정·확인 필요</option>
        </select></label>
        <label>정렬 <select value={sortOrder} onChange={(e) => setSortOrder(e.target.value)}>
          <option value="priority">우선순위 높은 순</option><option value="original">기존 목록 순</option>
        </select></label>
        <span role="status">{rows.length}개 패키지 · 패키지–취약점 연결 {rows.reduce((n, g) => n + g.entries.length, 0)}건</span>
      </div>
      {scanFailed && <p className="err" style={{ marginBottom: 8 }}>취약점 검사 일부가 실패해 이 목록이 전부가 아닐 수 있습니다.</p>}
      {rows.length === 0 ? <p className="oc-empty">선택한 조건에 해당하는 패키지가 없습니다.</p> : (
        <PackageFindingList groups={rows} onPackage={onPackage} onOpen={onOpen} showFindings />
      )}
      {unlinked.length > 0 && <section aria-label="패키지 연결 미확인 취약점">
        <h3>패키지 연결 미확인 {unlinked.length}건</h3>
        <p className="oc-hint">패키지 필터와 별도로 표시합니다. 연결 정보가 없어도 취약점은 유지됩니다.</p>
        {unlinked.map(f => <p key={f.finding_id}><button type="button" className="oc-link" onClick={() => onOpen(f.finding_id)}>{findingLabel(f)} 상세 보기</button></p>)}
      </section>}
      <p className="oc-hint">패키지를 누르면 패키지 상세를, 취약점 식별자를 누르면 고치는 방법과 근거를 볼 수 있습니다. 심각도는 검사 엔진 값을 그대로 씁니다. 조치 우선순위는 별도 규칙으로 계산하며 심각도를 낮추지 않습니다.</p>
    </>
  )
}

// 라이선스 탭: 확인이 필요한 패키지만 모아서 보여준다. 법적 판정은 하지 않는다.
function Licenses({ data, q }) {
  if (!data) return <Loading />
  const status = (data.package_storage || {}).status
  const external = (data.items || []).filter((item) => item.relationship !== 'root')
  if (status !== 'completed' && external.length === 0) {
    return <p className="oc-empty">패키지 저장이 아직 끝나지 않았습니다 ({label(status)}). 라이선스 정보가 없다는 뜻이 아닙니다.</p>
  }
  const review = external.filter((item) => licenseState(item.licenses) === 'review')
  const unknown = external.filter((item) => licenseState(item.licenses) === 'unknown')
  const rows = [...review, ...unknown].filter((i) => matches(q, i.name, ...(i.licenses || [])))
  return (
    <>
      <p className="oc-summary">확인 필요 {review.length}개 · 정보 없음 {unknown.length}개 · 그 외 {external.length - review.length - unknown.length}개</p>
      {review.length + unknown.length === 0 ? (
        <p className="oc-empty">따로 확인을 안내할 라이선스가 없습니다. 패키지에 선언된 정보 기준이며, 법적 검토를 대신하지 않습니다.</p>
      ) : rows.length === 0 ? <p className="oc-empty">선택한 조건에 해당하는 패키지가 없습니다.</p> : (
        <table className="oc-table">
          <thead><tr><th>패키지</th><th>관계</th><th>선언 라이선스</th><th>안내</th></tr></thead>
          <tbody>
            {rows.map((item) => (
              <tr key={item.package_id}>
                <td className="pkg">{item.name}@{item.installed_version || '—'}</td>
                <td>{relationLabel(item.relationship)}</td>
                <td className="id">{(item.licenses || []).join(', ') || <span className="muted">정보 없음</span>}</td>
                <td>{licenseState(item.licenses) === 'review'
                  ? <><span className="oc-tag warn" style={{ marginLeft: 0 }}>조건 확인</span> 배포 방식에 따라 지켜야 할 의무가 있을 수 있습니다.</>
                  : <span className="muted">선언된 라이선스를 찾지 못했습니다.</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="oc-hint">패키지에 선언된 라이선스 기준입니다. 위험하다는 판정이 아니라 확인이 필요하다는 안내입니다.</p>
    </>
  )
}

function Maintenance({ data, q }) {
  if (!data) return <Loading />
  const status = (data.collection || {}).status
  const items = data.items || []
  if (status !== 'completed' && items.length === 0) {
    return <p className="oc-empty">유지보수 정보 조회가 아직 끝나지 않았습니다 ({label(status)}).</p>
  }
  // 확인 대상(archived·deprecated)을 위로, 나머지는 그 아래에 둔다
  const flagged = (i) => i.archived === true || i.deprecated === true
  const rows = [...items.filter(flagged), ...items.filter((i) => !flagged(i))].filter((i) => matches(q, i.name, i.repository_full_name))
  return (
    <>
      <p className="oc-summary">{items.length}개 패키지 · 활동이 낮다고 해서 취약한 것은 아닙니다</p>
      {rows.length === 0 ? <p className="oc-empty">선택한 조건에 해당하는 패키지가 없습니다.</p> : (
        <table className="oc-table">
          <thead><tr><th>패키지</th><th>저장소</th><th>최근 커밋</th><th>보관(archived)</th><th>사용 중단</th><th>조회 상태</th></tr></thead>
          <tbody>
            {rows.map((item) => (
              <tr key={item.package_id}>
                <td className="pkg">{item.name}</td>
                <td className="id">{item.repository_full_name || <span className="muted">매핑 없음</span>}</td>
                <td>{formatDate(item.latest_commit_at)}</td>
                <td>{triState(item.archived, 'archived', '아니오')}</td>
                <td>{triState(item.deprecated, 'deprecated', '아니오')}</td>
                <td><StatusPill status={item.github_status === 'success' ? 'completed' : item.github_status}>GitHub {item.github_status}</StatusPill>
                  {item.github_error && <span className="err"> {item.github_error}</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  )
}

function Packages({ data, q }) {
  if (!data) return <Loading />
  const status = (data.package_storage || {}).status
  const external = (data.items || []).filter((item) => item.relationship !== 'root')
  if (status !== 'completed' && external.length === 0) {
    return <p className="oc-empty">패키지 저장이 아직 끝나지 않았습니다 ({label(status)}). 0개라는 뜻이 아닙니다.</p>
  }
  const direct = external.filter((item) => item.relationship === 'direct').length
  const rows = external.filter((i) => matches(q, i.name, i.lockfile_path, ...(i.licenses || [])))
  return (
    <>
      <p className="oc-summary">외부 의존성 {external.length}개 · 직접 {direct}개 · 간접 {external.length - direct}개 (루트 프로젝트 제외)</p>
      {rows.length === 0 ? <p className="oc-empty">선택한 조건에 해당하는 패키지가 없습니다.</p> : (
        <table className="oc-table">
          <thead><tr><th>패키지</th><th>버전</th><th>관계</th><th>라이선스</th><th>설치 경로</th></tr></thead>
          <tbody>
            {rows.map((item) => (
              <tr key={item.package_id}>
                <td className="pkg">{item.name}</td>
                <td className="id">{item.installed_version || '—'}</td>
                <td>{relationLabel(item.relationship)}</td>
                <td>{item.licenses && item.licenses.length ? item.licenses.join(', ') : <span className="muted">정보 없음</span>}
                  {licenseState(item.licenses) === 'review' && <span className="oc-tag warn">조건 확인</span>}</td>
                <td className="path">{item.lockfile_path}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  )
}

export default function App() {
  const [scanId, setScanId] = useState(() => parseRoute(window.location.hash).scanId || '')
  const [detailId, setDetailId] = useState(() => parseRoute(window.location.hash).findingId)
  const [pkgRoute, setPkgRoute] = useState(() => parseRoute(window.location.hash).pkg || null)
  const listScroll = useRef(0)
  const [scan, setScan] = useState(null)
  const [packages, setPackages] = useState(null)
  const [findings, setFindings] = useState(null)
  const [maintenance, setMaintenance] = useState(null)
  const [sbom, setSbom] = useState(null)
  const [sbomBusy, setSbomBusy] = useState(false)
  const [tab, setTab] = useState(() => parseRoute(window.location.hash).section || 'first')
  const [q, setQ] = useState('')
  const [error, setError] = useState(null)
  const [findingsQueryFailed, setFindingsQueryFailed] = useState(false)
  const timer = useRef(null)

  const [reload, setReload] = useState(0)
  const generation = useRef(0)

  useEffect(() => {
    if (!scanId) return undefined
    let scheduledTimer
    const currentGeneration = ++generation.current
    const stale = () => generation.current !== currentGeneration

    async function tick() {
      setFindingsQueryFailed(false)
      try {
        const current = await getScan(scanId)
        if (stale()) return
        setScan(current)
        const results = await Promise.allSettled([
          getPackages(scanId), getFindings(scanId), getMaintenance(scanId), getSbomInfo(scanId),
        ])
        if (stale()) return
        const setters = [setPackages, setFindings, setMaintenance, setSbom]
        const names = ['패키지', '취약점', '유지보수', 'SBOM']
        const errors = []
        results.forEach((result, index) => {
          setters[index](result.status === 'fulfilled' ? result.value : null)
          if (result.status === 'rejected') errors.push(`${names[index]}: ${result.reason.message}`)
        })
        setFindingsQueryFailed(results[1].status === 'rejected')
        setError(errors.length ? errors.join(' / ') : null)
        if (ACTIVE.has(current.status)) {
          scheduledTimer = setTimeout(tick, 3000)
          timer.current = scheduledTimer
        }
      } catch (err) {
        if (!stale()) { setError(err.message); setFindingsQueryFailed(true) }
      }
    }

    tick()
    return () => { generation.current = currentGeneration + 1; clearTimeout(scheduledTimer) }
  }, [scanId, reload])

  // 뒤로 가기·앞으로 가기·주소 직접 수정 시 화면 위치를 따라간다
  useEffect(() => {
    const sync = () => {
      const route = parseRoute(window.location.hash)
      setDetailId(route.findingId)
      setPkgRoute(route.pkg || null)
      setTab(route.section || (route.findingId ? window.history.state?.section || 'findings' : 'first'))
      setQ('')
      setScanId((current) => {
        const next = route.scanId || ''
        if (next !== current) reset() // 다른 검사로 이동하면 이전 검사 결과를 비운다
        return next
      })
    }
    window.addEventListener('popstate', sync)
    window.addEventListener('hashchange', sync)
    return () => { window.removeEventListener('popstate', sync); window.removeEventListener('hashchange', sync) }
  }, [])

  // 목록으로 돌아오면 보던 위치로 스크롤을 되돌린다
  useEffect(() => {
    if (detailId || pkgRoute) window.scrollTo(0, 0)
    else requestAnimationFrame(() => window.scrollTo(0, listScroll.current))
  }, [detailId, pkgRoute])

  function openPackage(name, version) {
    if (!detailId && !pkgRoute) listScroll.current = window.scrollY
    const pkg = { name, version }
    window.history.pushState({ fromList: true, section: tab }, '', routeHash(scanId, null, tab, pkg))
    setDetailId(null)
    setPkgRoute(pkg)
  }

  function openDetail(id) {
    if (!pkgRoute) listScroll.current = window.scrollY
    window.history.pushState({ fromList: true, section: tab }, '', routeHash(scanId, id))
    setDetailId(id)
    setPkgRoute(null)
  }

  function closeDetail() {
    if (window.history.state && window.history.state.fromList) {
      window.history.back()
    } else {
      window.history.replaceState(null, '', routeHash(scanId) || window.location.pathname)
      setDetailId(null)
      setPkgRoute(null)
    }
  }

  function goToDetail(id) {
    window.history.replaceState(window.history.state, '', routeHash(scanId, id))
    setDetailId(id)
  }

  function reset() {
    generation.current++
    if (timer.current) clearTimeout(timer.current)
    setScan(null); setPackages(null); setFindings(null); setMaintenance(null); setSbom(null)
    setError(null); setFindingsQueryFailed(false); setQ('')
  }

  function start(id) {
    window.history.pushState(null, '', routeHash(id) || window.location.pathname)
    setDetailId(null)
    setPkgRoute(null)
    reset()
    setTab('first')
    setReload((value) => value + 1)
    setScanId(id)
  }

  function newScan() {
    if (!scanId) return
    window.history.pushState(null, '', window.location.pathname)
    reset()
    setDetailId(null)
    setPkgRoute(null)
    setScanId('')
  }

  function selectTab(key) {
    if (!scanId) return
    window.history.pushState(null, '', routeHash(scanId, null, key))
    setTab(key)
    setDetailId(null)
    setPkgRoute(null)
    setQ('')
    listScroll.current = 0
    window.scrollTo(0, 0)
  }

  async function downloadSbomFile() {
    if (!sbom || !sbom.available) return
    setSbomBusy(true)
    try {
      const blob = await downloadSbom(scanId)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url; link.download = sbom.filename
      document.body.appendChild(link); link.click(); link.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      setError(`SBOM: ${err.message} 다시 내려받기를 시도해 주세요.`)
    } finally {
      setSbomBusy(false)
    }
  }

  const vulns = vulnItems(findings)
  const detailIndex = detailId ? vulns.findIndex((f) => f.finding_id === detailId) : -1
  const view = !scanId ? 'upload' : detailId ? 'detail' : pkgRoute ? 'package' : 'result'
  const pkgGroup = pkgRoute ? packageGroups(vulns).groups.find((g) => g.name === pkgRoute.name && g.version === pkgRoute.version) : null

  const firstCount = findings && priorityComputed(vulns) ? Math.min(5, packageGroups(vulns).groups.filter(g => ['P0', 'P1', 'P2'].includes(g.priority)).length) : null
  const counts = {
    first: firstCount,
    findings: findings ? vulns.length : null,
    licenses: packages ? licenseSummary(packages).total : null,
    maintenance: maintenance ? maintenanceSummary(maintenance).flagged : null,
    packages: packages ? packageSummary(packages).total : null,
  }
  const root = packages ? packageSummary(packages).root : null
  const duration = scanDuration(scan)
  const tabName = (TABS.find(([key]) => key === tab) || TABS[0])[1]

  return (
    <div className="oc">
      <Sidebar view={view === 'package' ? 'detail' : view} tab={tab} counts={counts} onTab={selectTab} onNewScan={newScan}
        sbom={sbom} onSbom={downloadSbomFile} sbomBusy={sbomBusy} />

      <main className="oc-main">
        {error && view !== 'upload' && (
          <div role="alert" className="oc-alert">
            <span>{error}</span>
            <button type="button" className="oc-btn" onClick={() => setReload((v) => v + 1)}>다시 불러오기</button>
          </div>
        )}

        {view === 'upload' && <Upload onCreated={start} />}

        {view === 'detail' && (
          detailIndex >= 0 ? (
            <FindingDetail
              key={detailId}
              scanId={scanId}
              scanStatus={scan && scan.status}
              actionRank={null}
              finding={vulns[detailIndex]}
              index={detailIndex}
              total={vulns.length}
              onBack={closeDetail}
              onPrev={detailIndex > 0 ? () => goToDetail(vulns[detailIndex - 1].finding_id) : null}
              onNext={detailIndex < vulns.length - 1 ? () => goToDetail(vulns[detailIndex + 1].finding_id) : null}
            />
          ) : (
            <section className="oc-panel">
              <button type="button" className="oc-btn" onClick={closeDetail}>← 목록으로</button>
              <p className="oc-empty">{findings ? '이 검사에서 해당 취약점을 찾을 수 없습니다.' : '불러오는 중…'}</p>
            </section>
          )
        )}

        {view === 'package' && (
          pkgGroup ? (
            <PackageDetail
              key={`${pkgGroup.name}@${pkgGroup.version}`}
              scanId={scanId}
              scanStatus={scan && scan.status}
              group={pkgGroup}
              rankLabel={pkgGroup.displayRank ? `${pkgGroup.displayRank}위` : '미산정·확인 필요'}
              maintenance={maintenance}
              onBack={closeDetail}
              onFinding={openDetail}
            />
          ) : (
            <section className="oc-panel">
              <button type="button" className="oc-btn" onClick={closeDetail}>← 목록으로</button>
              <p className="oc-empty">{findings ? '이 검사에서 해당 패키지의 취약점을 찾을 수 없습니다.' : '불러오는 중…'}</p>
            </section>
          )
        )}

        {view === 'result' && (
          <>
            <div className="oc-head">
              <div>
                <h1>{tab === 'first' ? '검사 결과' : tabName}</h1>
                <p>
                  {[root ? [root.name, root.installed_version].filter(Boolean).join(' ') : null,
                    scan ? formatDate(scan.created_at, true) : null,
                    duration,
                    `검사 ID ${scanId.slice(0, 8)}`].filter(Boolean).join(' · ')}
                </p>
              </div>
              {scan && <StatusPill status={scan.status}>{`검사 ${label(scan.status)} · ${stagesDone(scan)}/${STAGES.length} 단계`}</StatusPill>}
            </div>

            <Progress scan={scan} />
            {tab === 'first' && <SummaryCards onNavigate={selectTab} packages={packages} vulns={vulns} findings={findings} maintenance={maintenance} scan={scan} />}

            {tab === 'first' && <>
            <p className="oc-hint" role="status">{priorityStateText(findings?.priority_evaluation)}{findings?.priority_evaluation?.current_result_available && ` · 심각도 미확인 ${findings.priority_evaluation.summary?.unknown_finding_count ?? 0}건`}</p>
            <div className="oc-row2">
              <AiReport scanId={scanId} scanStatus={scan && scan.status} findings={findings} onFinding={openDetail} onPackage={openPackage} />
              <SeverityDonut vulns={vulns} findings={findings} scan={scan} />
            </div>

            </>}

            <section className="oc-panel" aria-label={tabName}>
              <div className="oc-phead">
                <div className="left">
                  <h2 className="oc-ptitle">{tabName}</h2>

                </div>
                <label className="oc-search">
                  <Icon name="search" size={18} />
                  <input value={q} onChange={(e) => setQ(e.target.value)}
                    placeholder="패키지명 또는 CVE 검색" aria-label="패키지명 또는 CVE 검색" />
                </label>
              </div>
              {tab === 'first' && <FirstLook vulns={vulns} findings={findings} scan={scan} q={q.trim().toLowerCase()} onPackage={openPackage} onTab={selectTab} />}
              {tab === 'findings' && <Findings queryFailed={findingsQueryFailed} vulns={vulns} findings={findings} scan={scan} q={q.trim().toLowerCase()} onOpen={openDetail} onPackage={openPackage} />}
              {tab === 'licenses' && <Licenses data={packages} q={q.trim().toLowerCase()} />}
              {tab === 'maintenance' && <Maintenance data={maintenance} q={q.trim().toLowerCase()} />}
              {tab === 'packages' && <Packages data={packages} q={q.trim().toLowerCase()} />}
            </section>
          </>
        )}
      </main>
    </div>
  )
}
