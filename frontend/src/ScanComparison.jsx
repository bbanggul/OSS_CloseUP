import { useEffect, useState } from 'react'
import { compareScans, getProjectScans, renameScan } from './api'
import { ACTIVE } from './display'
import { COMPARISON_LABELS, comparisonRows, comparisonError, findingText, comparisonReason } from './scanComparison.js'

const date = value => value ? new Date(value).toLocaleString('ko-KR') : '시각 없음'
const status = value => ({ completed: '완료', partial: '부분 완료', failed: '실패', queued: '대기', running: '진행 중' }[value] || value)

function ScanName({ item, onSaved }) {
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  async function save(event) {
    event.preventDefault()
    setSaving(true); setError('')
    try {
      const updated = await renameScan(item.scan_id, name)
      onSaved(updated); setEditing(false)
    } catch (err) { setError(err.message) }
    finally { setSaving(false) }
  }
  return <div className="oc-scan-name">
    {editing ? <form onSubmit={save}>
      <input aria-label="검사 이름" maxLength={80} value={name} disabled={saving}
        placeholder="예: 수정 전 검사" onChange={e => setName(e.target.value)} autoFocus />
      <button className="oc-btn" disabled={saving}>저장</button>
      <button type="button" className="oc-btn" disabled={saving} onClick={() => { setEditing(false); setError('') }}>취소</button>
    </form> : <><strong>{item.display_name || '이름 없는 검사'}</strong>
      <button className="oc-btn" onClick={() => { setName(item.display_name || ''); setEditing(true) }}>이름 수정</button></>}
    {error && <p role="alert">{error}</p>}
    <small title={item.scan_id}>{date(item.created_at)} · {item.scan_id.slice(0, 8)}</small>
  </div>
}

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
    <h2>비교할 검사 선택</h2>
    <p>현재 검사: {history?.items.find(item => item.scan_id === scan.scan_id)?.display_name || scan.display_name || '이름 없는 검사'} · {date(scan.created_at)} · {scan.scan_id.slice(0, 8)} · {status(scan.status)}</p>
    <p className="muted">아래 이력에서 현재 결과와 비교할 검사를 선택하세요.</p>
    <button className="oc-btn" onClick={() => setRevision(v => v + 1)}>새로고침</button>
    {historyError && <p role="alert">{historyError}</p>}
    {!history && !historyError && <p role="status">검사 이력을 불러오는 중…</p>}
    {history && <>
      <div className="oc-tablewrap"><table><thead><tr><th>비교 선택</th><th>검사 이름 · 시각</th><th>상태</th><th>결과</th></tr></thead>
        <tbody>{history.items.map(item => <tr key={item.scan_id}>
          <td>{item.scan_id === scan.scan_id ? '현재 검사' : <label><input type="radio" name="base-scan" value={item.scan_id}
            checked={base === item.scan_id} disabled={ACTIVE.has(item.status) || ACTIVE.has(scan.status)}
            onChange={() => { setBase(item.scan_id); setFilter('all') }} /> 비교 대상으로 선택</label>}</td>
          <td><ScanName item={item} onSaved={updated => setHistoryResult(previous => previous?.key === historyKey ? {
            ...previous, data: { ...previous.data, items: previous.data.items.map(row => row.scan_id === updated.scan_id ? { ...row, ...updated } : row) },
          } : previous)} /></td><td>{status(item.status)}</td>
          <td><button className="oc-btn" onClick={() => onOpen(item.scan_id)}>열기</button></td>
        </tr>)}</tbody></table></div>
      {history.total < 2 && <p>아직 비교할 검사가 없습니다. 이 프로젝트로 재검사하면 이력이 추가됩니다.</p>}
      <div className="oc-compare-actions"><button className="oc-btn" disabled={!offset} onClick={() => setOffset(v => Math.max(0, v - 50))}>이전 이력</button>
        <span>전체 {history.total}개 검사</span><button className="oc-btn" disabled={offset + 50 >= history.total} onClick={() => setOffset(v => v + 50)}>다음 이력</button></div>
    </>}
    {ACTIVE.has(scan.status) && <p role="status">현재 검사가 끝나면 비교할 수 있습니다.</p>}
    {base && <p>비교 대상: {history?.items.find(item => item.scan_id === base)?.display_name || base.slice(0, 8)}</p>}
    {error && <p role="alert" className="oc-alert">{error}</p>}
    {base && !data && !error && <p role="status">비교 결과를 불러오는 중…</p>}
    {data && <>
      <h2>검사 비교 결과</h2>
      <p>이전 {date(data.base.created_at)} / 현재 {date(data.target.created_at)}</p>
      {data.warnings.includes('base_after_target') && <p role="status">비교 대상으로 선택한 결과가 현재 검사보다 나중에 실행됐습니다. 선택한 방향으로 비교합니다.</p>}
      <div className="oc-compare-actions" aria-label="비교 항목 필터">
        <button className="oc-btn" aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>전체 {data.items.length}</button>
        {Object.entries(COMPARISON_LABELS).map(([key, text]) => <button className="oc-btn" key={key} aria-pressed={filter === key} onClick={() => setFilter(key)}>{text} {data.summary[key]}</button>)}
      </div>
      <p className="muted">설치 위치별로 비교하므로 아래 항목 수는 검사별 취약점 수와 다를 수 있습니다.</p>
      <p>검사별 취약점 수: 이전 {data.finding_counts.base.stored ?? '확인 불가'} / 현재 {data.finding_counts.target.stored ?? '확인 불가'}</p>
      <div className="oc-comparison-list">
        {rows.map(row => <article className="oc-comparison-item" key={row.id}>
          <div className="oc-comparison-item-head"><h3>{row.name}</h3>
            <span className={`oc-comparison-status ${row.status}`}>{COMPARISON_LABELS[row.status]}</span></div>
          <p className="oc-version-change"><span>이전 <b>{row.baseVersion}</b></span><span>현재 <b>{row.targetVersion}</b></span></p>
          {row.baseFindings === row.targetFindings ? <p className="oc-comparison-findings">{row.targetFindings}</p> :
            <div className="oc-comparison-findings"><p><b>이전</b> {row.baseFindings}</p><p><b>현재</b> {row.targetFindings}</p></div>}
          {row.conflict && <p className="oc-comparison-note">여러 취약점의 식별자가 겹쳐 개별 비교가 필요합니다.</p>}
          <details><summary>상세 내용</summary><p>{comparisonReason(row.reason)}</p>
            <dl><dt>이전 설치 위치</dt><dd>{row.basePath}</dd><dt>현재 설치 위치</dt><dd>{row.targetPath}</dd></dl>
          </details>
        </article>)}
      </div>
      {!rows.length && <p>해당 비교 항목이 없습니다.</p>}
      <details><summary>패키지 구성 비교 ({data.installations.length})</summary><ul>{data.installations.map(i => <li key={i.installation_id}>{i.name}: {i.base?.installed_version || '없음'} / {i.target?.installed_version || '없음'} ({({matched:'대응',added:'추가',removed:'제거',not_comparable:'비교 불가'})[i.state] || i.state})</li>)}</ul></details>
      <details><summary>설치 위치를 확인할 수 없는 취약점</summary>{['base','target'].map(side => <div key={side}><h3>{side === 'base' ? '이전 검사' : '현재 검사'}</h3>
        <p>{data.unlinked_findings[side].map(f => findingText(data, side, [f])).join(', ') || '없음'}</p></div>)}</details>
      <details><summary>검사 도구 및 상세 정보</summary><p>도구나 DB의 변경이 결과 차이의 원인임을 의미하지는 않습니다.</p>
        <pre>{JSON.stringify({ warnings: data.warnings, context_changes: data.context_changes, base_sources: data.base.sources, target_sources: data.target.sources }, null, 2)}</pre></details>
    </>}
  </section>
}
