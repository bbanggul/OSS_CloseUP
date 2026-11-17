import { useEffect, useState } from 'react'
import { getPackageDetail } from './api'
import AiReport from './AiReport'
import { findingLabel, rangeFixFor, relationLabel, SEVERITIES } from './display'
import { buildFixPrompt } from './fixPrompt'
import { SeverityBadge } from './PackageFindingList'

// 취약점마다 한 줄: 심각도 · 식별자(상세로 이동) · 내 버전 기준 수정 후보 · 확인한 도구.
// 심각도 순으로 위 SHOWN건만 보이고 나머지는 '더 보기'로 펼친다. 출처 링크는 취약점 상세에 있다.
const SHOWN = 5

export function PackageFindings({ findings, version, onFinding }) {
  const [all, setAll] = useState(false)
  const sorted = [...(findings || [])].sort((a, b) =>
    SEVERITIES.indexOf(a.severity || 'UNKNOWN') - SEVERITIES.indexOf(b.severity || 'UNKNOWN'))
  const hidden = Math.max(0, sorted.length - SHOWN)
  const visible = all ? sorted : sorted.slice(0, SHOWN)
  return <>
    <ul className="oc-group-findings oc-finding-lines">{visible.map(f => {
      const candidates = (f.installation_links || []).flatMap(l => l.fixed_version_candidates || [])
      const fix = version ? rangeFixFor(version, candidates) : null
      const tools = [...new Set(candidates.filter(c => fix && c.value === fix).map(c => c.source_tool).filter(Boolean))]
      const others = [...new Set(candidates.map(c => c.value || c.raw).filter(v => v && v !== fix))]
      return <li key={f.finding_id}>
        <div className="oc-finding-line">
          <SeverityBadge severity={f.severity} />
          <button type="button" className="oc-link" onClick={() => onFinding(f.finding_id)}>{findingLabel(f)}</button>
          {f.manual_review_required && <span className="oc-tag warn">수동 확인</span>}
        </div>
        <div className="oc-hint oc-finding-meta">
          {fix ? <>수정 후보 <strong>{fix}</strong> (현재 버전 기준){tools.length ? ` · ${tools.join('·')} 확인` : ''}</>
            : candidates.length ? '현재 버전에 맞는 수정 후보를 확인하지 못했습니다.' : '보고된 수정 후보 없음 · 수정 불가 판정은 아닙니다.'}
          {others.length > 0 && <details className="oc-more"><summary>{fix ? `다른 수정 후보 ${others.length}개` : `수정 후보 ${others.length}개`}</summary>
            <span>{others.join(', ')}{fix ? ' · 각 후보의 근거와 영향 범위를 별도로 확인하세요.' : ''}</span></details>}
        </div>
      </li>
    })}</ul>
    {hidden > 0 && <button type="button" className="oc-more-btn" aria-expanded={all} onClick={() => setAll(!all)}>
      {all ? '접기 ▴' : `나머지 ${hidden}건 더 보기 ▾`}</button>}
  </>
}

export default function PackageDetail({ scanId, groupId, snapshot, onBack, onFinding, onRefresh }) {
  const [state, setState] = useState(null)
  const [copied, setCopied] = useState('')
  const key = `${scanId}:${groupId}:${snapshot || ''}`
  useEffect(() => {
    let cancelled = false
    getPackageDetail(scanId, groupId, snapshot).then(data => {
      if (!cancelled) setState({ key, data })
    }).catch(error => { if (!cancelled) setState({ key, error }) })
    return () => { cancelled = true }
  }, [scanId, groupId, snapshot, key])
  const current = state?.key === key ? state : null
  const response = current?.data
  const group = response?.item
  let text = '', promptError = ''
  if (response) {
    try { text = buildFixPrompt(response) } catch (e) { promptError = e.message }
  }
  async function copy() {
    try {
      // Revalidate before copying so an older rendered snapshot is not silently reused.
      const fresh = await getPackageDetail(scanId, groupId, response.snapshot_id)
      await navigator.clipboard.writeText(buildFixPrompt(fresh))
      setCopied('복사했습니다.')
    } catch (e) {
      if (e.status === 409) setState({ key, error: e })
      else setCopied('복사하지 못했습니다. 아래 문구를 직접 선택해 복사해 주세요.')
    }
  }
  return <div className="oc-detail">
    <div className="oc-detailnav"><button type="button" className="oc-btn" onClick={onBack}>← 목록으로</button></div>
    {!current ? <p role="status">패키지 상세를 불러오는 중…</p> : current.error ?
      <section className="oc-panel" role="alert"><p>{current.error.status === 409 ? '검사 결과가 변경되었거나 아직 준비되지 않았습니다. 최신 자료를 다시 불러와 주세요.' : '패키지 상세를 불러오지 못했습니다.'}</p>
        <button className="oc-btn" onClick={onRefresh}>최신 결과 다시 불러오기</button></section> : <>
      <div><div className="oc-dtitle"><h1>{group.name}@{group.installed_version || '버전 미확인'}</h1>
        <span className="oc-pill">{group.global_rank != null ? `${group.global_rank}위` : group.priority_status === 'severity_unknown' ? '심각도 확인 필요' : '순위 미산정'}</span>
        <span className="oc-tag">{group.ecosystem}</span></div>
        <p className="oc-group-counts"><span>취약점 {group.finding_count}건</span>
          {SEVERITIES.filter(s => group.severity_counts[s]).map(s => <SeverityBadge key={s} severity={s} count={group.severity_counts[s]} />)}</p>
        <p className="oc-hint">전체 취약점 해결 여부 미확인 · 수정 후보는 취약점·설치별 근거입니다.</p>
        {response.result_state === 'partial' && <p className="err">부분 결과입니다. 확인하지 못한 취약점이 있을 수 있습니다.</p>}
        <p className="oc-hint">중복 검토: {response.deduplication_status === 'completed' ? '완료' : '확인 대기'}</p>
      </div>
      <section className="oc-panel"><h2 className="oc-ptitle">설치 정보</h2>
        {group.installations.map(p => <div key={p.package_id} style={{ marginTop: 10 }}>
          <strong>{p.lockfile_path || '설치 위치 미제공'}</strong> · {relationLabel(p.relationship)}
          <div className="oc-hint">라이선스: {p.licenses?.length ? p.licenses.join(' · ') : '정보 없음'}</div>
        </div>)}
      </section>
      <section className="oc-panel" aria-label="이 패키지의 취약점"><h2 className="oc-ptitle">이 패키지의 취약점</h2>
        <PackageFindings findings={group.findings || []} version={group.installed_version} onFinding={onFinding} />
      </section>
      {group.ecosystem === 'npm' && group.installed_version && <><AiReport scanId={scanId} scanStatus={response.result_state === 'partial' ? 'partial' : 'completed'} pkg={{ name: group.name, version: group.installed_version }} onFinding={onFinding} hideFindingList /></>}
      <section className="oc-panel" aria-label="수정 프롬프트"><div className="oc-phead"><h2 className="oc-ptitle">수정 프롬프트</h2>
        <button type="button" className="oc-btn" disabled={!text} onClick={copy}>복사</button></div>
        <p className="oc-hint">관련 취약점 전체와 설치별 근거를 AI 코딩 도구에 전달합니다. 복사 시 서버 AI를 호출하지 않습니다.</p>
        {promptError ? <p role="alert">{promptError}</p> : <pre className="oc-fix-prompt">{text}</pre>}
        <p role="status">{copied}</p>
      </section>
    </>}
  </div>
}
