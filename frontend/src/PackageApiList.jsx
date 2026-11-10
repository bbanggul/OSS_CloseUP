import { useState } from 'react'
import BulkFixPrompt from './BulkFixPrompt'
import { getPackageDetail } from './api'
import { findingLabel, SEVERITIES } from './display'
import { SeverityBadge } from './PackageFindingList'
import { PackageFindings } from './PackageDetail'

function Row({ group, scanId, snapshot, onPackage, onFinding, expandable, onRefresh }) {
  const [open, setOpen] = useState(false)
  const [state, setState] = useState(null)
  async function toggle() {
    setOpen(!open)
    if (open || state) return
    try { setState({ data: await getPackageDetail(scanId, group.package_group_id, snapshot) }) }
    catch (error) { setState({ error }) }
  }
  return <div className="oc-package-block with-findings">
    <div className="oc-package-row">
      {expandable && <button type="button" className="oc-package-toggle" aria-expanded={open} aria-label={`${group.name} 취약점 ${open ? '접기' : '펼치기'}`} onClick={toggle}>{open ? '▾' : '▸'}</button>}
      <button type="button" className="oc-package-group" onClick={() => onPackage(group.name, group.installed_version, group.package_group_id)}>
        <strong>{group.name}@{group.installed_version || '버전 미확인'}</strong>
        <span className="oc-pill">{group.global_rank != null ? `${group.global_rank}위` : group.priority_status === 'severity_unknown' ? '심각도 확인 필요' : '순위 미산정'}</span>
        <span>{group.finding_count}건</span>
        <span className="oc-group-counts">{SEVERITIES.filter(s => group.severity_counts[s]).map(s => <SeverityBadge key={s} severity={s} count={group.severity_counts[s]} />)}</span>
        <span aria-hidden="true">›</span>
      </button>
    </div>
    {open && (state?.error ? <p role="alert">{state.error.status === 409 ? '검사 결과가 변경됐습니다.' : '수정 근거를 불러오지 못했습니다.'} <button className="oc-link" onClick={onRefresh}>다시 불러오기</button></p>
      : state?.data ? <PackageFindings findings={state.data.item.findings} version={state.data.item.installed_version} onFinding={onFinding} /> : <p role="status">불러오는 중…</p>)}
  </div>
}

export default function PackageApiList({ data, failed, scanId, q = '', firstOnly, onPackage, onFinding, onRefresh, findingLabels = {} }) {
  const [priority, setPriority] = useState('all')
  if (!data) return <p role="status">{failed ? '패키지 목록을 불러오지 못했습니다. 다시 불러와 주세요.' : '패키지 목록을 불러오는 중…'}</p>
  if (!['ready', 'partial'].includes(data.result_state)) return <p role="status">{{ processing: '검사 결과를 준비 중입니다.', failed: '검사에 실패했습니다.', unavailable: '검증된 결과를 사용할 수 없습니다.' }[data.result_state] || '결과 상태를 확인할 수 없습니다.'} 취약점 0건이라는 뜻이 아닙니다.</p>
  if (data.zero_findings_confirmed) return <p className="oc-empty">검사가 완료되었고 알려진 취약점이 발견되지 않았습니다.</p>
  const query = q.trim().toLowerCase()
  const top = firstOnly ? data.items.filter(g => g.global_rank != null && ['P0', 'P1', 'P2'].includes(g.priority)).slice(0, 5) : data.items
  const rows = top.filter(g => (firstOnly || priority === 'all' || (g.priority || 'unranked') === priority) &&
    (!query || [g.name, g.installed_version, ...(g.finding_ids || []).map(id => findingLabels[id])].some(v => String(v || '').toLowerCase().includes(query))))
  const unlinked = data.unlinked.filter(f => !query || findingLabel(f).toLowerCase().includes(query))
  return <>
    {!firstOnly && <BulkFixPrompt key={`${scanId}:${data.snapshot_id}`} data={data} scanId={scanId} />}
    {data.result_state === 'partial' && <p className="err">부분 검사 결과입니다. 확보된 자료 기준의 순위이며 전체 결과가 아닐 수 있습니다.</p>}
    {!data.priority_evaluation?.current_result_available && <p className="oc-hint">현재 우선순위를 사용할 수 없어 숫자 순위 없이 표시합니다.</p>}
    {!firstOnly && <div className="oc-priority-controls"><label>조치 우선순위 <select value={priority} onChange={e => setPriority(e.target.value)}>
      <option value="all">전체</option><option value="P0">가장 먼저 확인</option><option value="P1">이어서 확인</option><option value="P2">다음 조치 계획</option><option value="P3">낮은 우선순위</option><option value="unranked">미산정·확인 필요</option>
    </select></label><span>{rows.length}개 패키지 · 검사 전체 고유 취약점 {data.unique_finding_count}건</span></div>}
    <div className="oc-package-groups">{rows.map(group => <Row key={`${data.snapshot_id}:${group.package_group_id}`} group={group} scanId={scanId} snapshot={data.snapshot_id}
      onPackage={onPackage} onFinding={onFinding} expandable={!firstOnly} onRefresh={onRefresh} />)}</div>
    {!rows.length && <p className="oc-empty">{firstOnly ? '먼저 볼 패키지가 없습니다. 취약점 탭에서 미확인·미연결 항목을 확인해 주세요.' : '선택한 조건에 해당하는 패키지가 없습니다.'}</p>}
    {!firstOnly && unlinked.length > 0 && <section><h3>패키지 연결 미확인 {unlinked.length}건</h3>{unlinked.map(f => <p key={f.finding_id}><button className="oc-link" onClick={() => onFinding(f.finding_id)}>{findingLabel(f)}</button></p>)}</section>}
    <p className="oc-hint">중복 검토: {data.deduplication_status === 'completed' ? '완료' : '확인 대기'} · 패키지별 건수의 합은 검사 전체 고유 취약점 수와 다를 수 있습니다.</p>
  </>
}
