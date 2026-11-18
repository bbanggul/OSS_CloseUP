import { useState } from 'react'
import { getPackageDetail } from './api'
import { buildBulkFixPrompt, selectFixPackages } from './fixPrompt'

export default function BulkFixPrompt({ data, scanId }) {
  const [selected, setSelected] = useState([])
  const [rank, setRank] = useState('5')
  const [busy, setBusy] = useState(false)
  const [text, setText] = useState('')
  const [message, setMessage] = useState('')
  const choose = groups => { setSelected(groups.map(g => g.package_group_id)); setText(''); setMessage('') }
  const add = groups => { setSelected(ids => [...new Set([...ids, ...groups.map(g => g.package_group_id)])]); setText(''); setMessage('') }
  async function prepare() {
    setBusy(true); setText(''); setMessage('')
    try {
      const responses = []
      for (const group of data.items.filter(g => selected.includes(g.package_group_id))) {
        const response = await getPackageDetail(scanId, group.package_group_id, data.snapshot_id)
        if (response.scan_id !== scanId || response.snapshot_id !== data.snapshot_id || response.item?.package_group_id !== group.package_group_id) throw new Error('검사 결과가 변경됐습니다. 목록을 다시 불러와 주세요.')
        responses.push(response)
      }
      setText(buildBulkFixPrompt(responses))
    } catch (error) { setMessage(error.message) }
    finally { setBusy(false) }
  }
  async function copy() {
    try { await navigator.clipboard.writeText(text); setMessage('복사했습니다.') }
    catch { setMessage('자동 복사가 안 됩니다. 아래 내용을 선택해 복사해 주세요.') }
  }
  return <section className="oc-bulk-fix" aria-label="전체 수정 프롬프트">
    <h3>전체 수정 프롬프트</h3>
    <div className="oc-bulk-controls">
      {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(severity => <button key={severity} className="oc-btn" disabled={busy} onClick={() => add(selectFixPackages(data.items, severity))}>{severity} 전체 선택</button>)}
      <label><input type="number" min="1" step="1" aria-label="수정 순위 상한" value={rank} disabled={busy} onChange={e => setRank(e.target.value)} />위까지</label>
      <button className="oc-btn" disabled={busy || !Number.isInteger(Number(rank)) || Number(rank) < 1 || !data.priority_evaluation?.current_result_available} onClick={() => choose(selectFixPackages(data.items, null, rank))}>순위 선택</button>
      <button className="oc-btn" disabled={busy} onClick={() => choose(data.items)}>전체 선택</button>
      <button className="oc-btn" disabled={busy} onClick={() => choose([])}>선택 해제</button>
    </div>
    <p className="oc-hint">검사 전체 목록 기준 · 등급 선택은 누적, 순위 선택은 교체</p>
    <details><summary>선택 패키지 {selected.length}개</summary><div className="oc-bulk-packages">{data.items.map(g => <label key={g.package_group_id}>
      <input type="checkbox" disabled={busy} checked={selected.includes(g.package_group_id)} onChange={e => { setSelected(ids => e.target.checked ? [...ids, g.package_group_id] : ids.filter(id => id !== g.package_group_id)); setText(''); setMessage('') }} />
      {g.name}@{g.installed_version}{g.global_rank != null ? ` · ${g.global_rank}위` : ''}
    </label>)}</div></details>
    <button className="oc-btn primary" disabled={busy || !selected.length} onClick={prepare}>{busy ? '자료 준비 중…' : '프롬프트 만들기'}</button>
    {text && <><textarea aria-label="전체 수정 프롬프트 내용" readOnly value={text} rows={8} /><button className="oc-btn" onClick={copy}>프롬프트 복사</button></>}
    {message && <p role="status">{message}</p>}
  </section>
}
