import { useEffect, useState } from 'react'
import { compareScans, getProjectScans } from './api'
import { ACTIVE } from './display'
import { COMPARISON_LABELS, comparisonRows, comparisonError, findingText, comparisonReason } from './scanComparison.js'

const date = value => value ? new Date(value).toLocaleString('ko-KR') : '시각 없음'
const status = value => ({ completed: '완료', partial: '부분 완료', failed: '실패', queued: '대기', running: '진행 중' }[value] || value)

export default function ScanComparison({ scan, onOpen }) {
  const [offset, setOffset] = useState(0)
  const [historyResult, setHistoryResult] = useState(null)
  const [base, setBase] = useState('')
  const [result, setResult] = useState(null)
  const [filter, setFilter] = useState('all')
  const [revision, setRevision] = useState(0)
  const pair = `${base}:${scan.scan_id}:${scan.status}:${revision}`
  const historyKey = `${scan.project_id}:${scan.status}:${offset}:${revision}`
  const history = historyResult?.key === historyKey ? historyResult.data : null
  const historyError = historyResult?.key === historyKey ? historyResult.error : ''
  const error = result?.pair === pair ? result.error : '' 
  const data = result?.pair === pair ? result.data : null
  useEffect(() => {
    const controller = new AbortController()
    let active = true
    getProjectScans(scan.project_id, offset, controller.signal).then(value => {
      if (active) setHistoryResult({ key: historyKey, data: value })
    }).catch(err => { if (active) setHistoryResult({ key: historyKey, error: err.message }) })
    return () => { active = false; controller.abort() }
  }, [scan.project_id, offset, historyKey])
  useEffect(() => {
    const controller = new AbortController()
    let active = true
    if (base) compareScans(scan.scan_id, base, controller.signal).then(value => {
      if (active) setResult({ pair, data: value })
    }).catch(err => { if (active) setResult({ pair, error: comparisonError(err) }) })
    return () => { active = false; controller.abort() }
  }, [base, scan.scan_id, pair, scan.status])
  const rows = data ? comparisonRows(data).filter(row => filter === 'all' || row.status === filter) : []
  return <section className="oc-panel oc-compare" aria-label="이전 검사 비교">
    <h2>같은 프로젝트의 검사 이력</h2>
    <p>현재 검사: {date(scan.created_at)} · {scan.scan_id.slice(0, 8)} · {status(scan.status)}</p>
    <p className="muted">비교할 이전 검사를 선택하세요. 새 결과를 만들려면 위의 ‘이 프로젝트 재검사’를 사용하세요.</p>
    <button className="oc-btn" onClick={() => setRevision(v => v + 1)}>새로고침</button>
    {historyError && <p role="alert">{historyError}</p>}
    {!history && !historyError && <p role="status">검사 이력을 불러오는 중…</p>}
    {history && <>
      <div className="oc-tablewrap"><table><thead><tr><th>비교 선택</th><th>검사 시각</th><th>상태</th><th>결과</th></tr></thead>
        <tbody>{history.items.map(item => <tr key={item.scan_id}>
          <td>{item.scan_id === scan.scan_id ? '현재 검사' : <label><input type="radio" name="base-scan" value={item.scan_id}
            checked={base === item.scan_id} disabled={ACTIVE.has(item.status) || ACTIVE.has(scan.status)}
            onChange={() => { setBase(item.scan_id); setFilter('all') }} /> 이전 검사로 선택</label>}</td>
          <td>{date(item.created_at)}<br /><small>{item.scan_id.slice(0, 8)}</small></td><td>{status(item.status)}</td>
          <td><button className="oc-btn" onClick={() => onOpen(item.scan_id)}>열기</button></td>
        </tr>)}</tbody></table></div>
      {history.total < 2 && <p>아직 비교할 검사가 없습니다. 이 프로젝트로 재검사하면 이력이 추가됩니다.</p>}
      <div className="oc-compare-actions"><button className="oc-btn" disabled={!offset} onClick={() => setOffset(v => Math.max(0, v - 50))}>이전 이력</button>
        <span>전체 {history.total}개 검사</span><button className="oc-btn" disabled={offset + 50 >= history.total} onClick={() => setOffset(v => v + 50)}>다음 이력</button></div>
    </>}
    {ACTIVE.has(scan.status) && <p role="status">현재 검사가 끝나면 비교할 수 있습니다.</p>}
    {base && <p>선택한 이전 검사: <code>{base}</code></p>}
    {error && <p role="alert" className="oc-alert">{error}</p>}
    {base && !data && !error && <p role="status">비교 결과를 불러오는 중…</p>}
    {data && <>
      <h2>검사 비교 결과</h2>
      <p>이전 {date(data.base.created_at)} / 현재 {date(data.target.created_at)}</p>
      <p className="oc-hint">이번 검사에서 미검출된 항목도 수정 완료나 안전을 보장하지는 않습니다.</p>
      {!data.comparison_complete && <p role="status" className="oc-alert">일부 항목은 자료 부족이나 검사 실패로 비교할 수 없습니다.</p>}
      {data.warnings.includes('base_after_target') && <p role="status">이전 검사로 선택한 결과가 현재 검사보다 나중에 실행됐습니다. 선택한 방향으로 비교합니다.</p>}
      <div className="oc-compare-actions" aria-label="비교 항목 필터">
        <button className="oc-btn" aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>전체 {data.items.length}</button>
        {Object.entries(COMPARISON_LABELS).map(([key, text]) => <button className="oc-btn" key={key} aria-pressed={filter === key} onClick={() => setFilter(key)}>{text} {data.summary[key]}</button>)}
      </div>
      <p className="muted">설치 위치별 비교 항목 수입니다. 같은 취약점이 여러 위치에 있으면 각각 집계합니다. 식별자 충돌은 검토 묶음으로 표시합니다.</p>
      <p>저장된 취약점 수: 이전 {data.finding_counts.base.stored ?? '확인 불가'} / 현재 {data.finding_counts.target.stored ?? '확인 불가'}</p>
      <div className="oc-tablewrap"><table><thead><tr><th>패키지</th><th>이전 / 현재 버전</th><th>상태</th><th>취약점 및 근거</th></tr></thead>
        <tbody>{rows.map(row => <tr key={row.id}><td>{row.name}<br /><small>{row.basePath}<br />{row.targetPath}</small></td>
          <td>{row.baseVersion}<br />{row.targetVersion}</td><td>{COMPARISON_LABELS[row.status]}{row.conflict && <div>식별자 검토 묶음</div>}</td>
          <td><div>이전: {row.baseFindings}</div><div>현재: {row.targetFindings}</div><details><summary>판정 근거</summary><p>{comparisonReason(row.reason)}</p></details></td></tr>)}</tbody></table></div>
      {!rows.length && <p>해당 비교 항목이 없습니다.</p>}
      <details><summary>패키지 설치 변화 ({data.installations.length})</summary><ul>{data.installations.map(i => <li key={i.installation_id}>{i.name}: {i.base?.installed_version || '없음'} / {i.target?.installed_version || '없음'} ({({matched:'대응',added:'추가',removed:'제거',not_comparable:'비교 불가'})[i.state] || i.state})</li>)}</ul></details>
      <details><summary>패키지에 연결되지 않은 취약점 (별도 항목)</summary>{['base','target'].map(side => <div key={side}><h3>{side === 'base' ? '이전 검사' : '현재 검사'}</h3>
        <p>{data.unlinked_findings[side].map(f => findingText(data, side, [f])).join(', ') || '없음'}</p></div>)}</details>
      <details><summary>검사 환경과 제한 사항</summary><p>도구나 DB의 변경이 결과 차이의 원인임을 의미하지는 않습니다.</p>
        <pre>{JSON.stringify({ warnings: data.warnings, context_changes: data.context_changes, base_sources: data.base.sources, target_sources: data.target.sources }, null, 2)}</pre></details>
    </>}
  </section>
}
