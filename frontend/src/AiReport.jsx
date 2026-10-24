import { useEffect, useRef, useState } from 'react'
import { getAiReport, generateAiReport, getAiFinding, generateAiFinding, getAiPackage, generateAiPackage } from './api'
import { aiReportView, aiSections } from './display'
import AiNarrativeReport from './AiNarrativeReport'
import { currentAiData } from './aiPresentation'

const STATE_DOT = { loading: 'var(--oc-cyan)', running: 'var(--oc-cyan)', failed: 'var(--oc-crit)', error: 'var(--oc-crit)' }

const timeOf = (iso) => (iso ? iso.slice(11, 16) : null)

export function AiHeader({ title, data }) {
  const at = data && data.status === 'succeeded' ? timeOf(data.created_at) : null
  return (
    <div className="oc-phead" style={{ marginBottom: 0 }}>
      <div className="left"><span className="oc-chip">AI</span><h2 className="oc-ptitle">{title}</h2></div>
      {at && <span className="muted" style={{ fontSize: 12 }}>{at} 생성{data.model ? ` · ${data.model}` : ''}</span>}
    </div>
  )
}

// AI 본문. 아는 섹션(요약·이유·권고)은 문장으로, 근거는 칩으로, 모르는 키는 원문으로 보여준다.
export function AiBody({ view }) {
  if (!view.output) {
    return (
      <p className="state">
        {STATE_DOT[view.kind] && <span className="oc-dot" style={{ background: STATE_DOT[view.kind] }} />}
        <span className={view.tone === 'error' ? 'err' : ''}>{view.message}</span>
      </p>
    )
  }
  const { sections, evidence, extra } = aiSections(view.output)
  return (
    <>
      {sections.map((s) => (
        <div key={s.key} className="sec">
          <h3>{s.label}</h3>
          {s.text ? <p>{s.text}</p> : <ul>{s.list.map((x) => <li key={x}>{x}</li>)}</ul>}
        </div>
      ))}
      {evidence.length > 0 && (
        <div className="sec"><h3>근거</h3><div className="evi">{evidence.map((e) => <span key={e}>{e}</span>)}</div></div>
      )}
      {extra && <pre>{JSON.stringify(extra, null, 2)}</pre>}
    </>
  )
}

// 전체 AI 요약 보고서. 설명 조회가 실패해도 검사 결과 화면은 막지 않는다.
export default function AiReport({ scanId, scanStatus, findingId = null, pkg = null, onFinding, onPackage, hideFindingList = false }) {
  // 응답을 요청 키와 함께 저장하고, 키가 다르면(새 요청 중) 불러오는 중으로 본다.
  const requestKey = `${scanId}:${scanStatus}:${findingId || (pkg ? `package:${pkg.name}@${pkg.version}` : 'report')}`
  const pkgName = pkg ? pkg.name : null
  const pkgVersion = pkg ? pkg.version : null
  const create = () => (findingId ? generateAiFinding(scanId, findingId) : pkg ? generateAiPackage(scanId, pkg.name, pkg.version) : generateAiReport(scanId))
  const [result, setResult] = useState({ key: null })
  const [open, setOpen] = useState(true)
  const [generation, setGeneration] = useState({ key: null, busy: false, error: null })
  const activeRequest = useRef(null)
  const displayedRequest = useRef(null)
  const generationVersion = useRef(0)

  useEffect(() => {
    if (!scanId) return undefined
    displayedRequest.current = requestKey
    let cancelled = false
    let timer
    async function refresh() {
      const version = generationVersion.current
      try {
        const data = currentAiData(await (findingId ? getAiFinding(scanId, findingId) : pkgName ? getAiPackage(scanId, pkgName, pkgVersion) : getAiReport(scanId)), findingId)
        if (!cancelled && version === generationVersion.current && activeRequest.current !== requestKey) setResult({ key: requestKey, data })
        if (!cancelled && ['pending', 'running'].includes(data.status)) timer = setTimeout(refresh, 2500)
      } catch (error) {
        if (!cancelled && version === generationVersion.current && activeRequest.current !== requestKey) setResult({ key: requestKey, error })
      }
    }
    refresh()
    return () => { cancelled = true; clearTimeout(timer); displayedRequest.current = null }
  }, [scanId, findingId, pkgName, pkgVersion, requestKey])

  async function generate() {
    if (activeRequest.current !== null) return
    activeRequest.current = requestKey
    generationVersion.current += 1
    setGeneration({ key: requestKey, busy: true, error: null })
    try {
      const data = currentAiData(await create(), findingId)
      if (displayedRequest.current === requestKey) {
        setResult({ key: requestKey, data })
        setGeneration({ key: requestKey, busy: false, error: null })
      }
    } catch (error) {
      if (displayedRequest.current === requestKey) setGeneration({ key: requestKey, busy: false, error: error.message })
    } finally {
      generationVersion.current += 1
      activeRequest.current = null
    }
  }

  const current = result.key === requestKey ? result : { loading: true }
  const view = aiReportView(current)
  const kind = current.loading ? 'loading' : current.error ? 'error' : (current.data && current.data.status) || 'none'
  const busy = generation.key === requestKey && generation.busy
  const generationError = generation.key === requestKey ? generation.error : null
  const title = findingId ? 'AI 설명' : pkg ? 'AI 패키지 설명' : 'AI 요약 보고서'
  const canGenerate = ['completed', 'partial'].includes(scanStatus)
  return (
    <section className="oc-panel tint oc-ai" aria-label={title}>
      <div className="oc-phead" style={{ marginBottom: 0 }}>
        <AiHeader title={title} data={current.data} />
        <button type="button" className="oc-btn" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          {open ? '접기' : '펼치기'}
        </button>
      </div>
      {open && (
        <>
          {!findingId && view.output ? <AiNarrativeReport output={view.output} onFinding={onFinding} onPackage={pkg ? null : onPackage} hideFindingList={hideFindingList} /> : <AiBody view={{ ...view, kind }} />}
          <button type="button" className="oc-btn" disabled={!canGenerate || busy || current.loading || kind === 'succeeded'} onClick={generate}>
            {busy ? 'AI 설명 생성 중…' : kind === 'succeeded' ? 'AI 설명 생성 완료' : 'AI 설명 생성'}
          </button>
          {busy && <p className="state" role="status">설명을 생성하고 저장하고 있습니다. 잠시 기다려 주세요.</p>}
          {generationError && <p className="err" role="alert">{generationError}</p>}
          {!canGenerate && <p className="note">검사가 완료되거나 부분 완료된 뒤 생성할 수 있습니다.</p>}
          <p className="note">{findingId ? '생성 시 선택한 취약점의 패키지명·검사 식별자·등급·의존성 정보를 OpenAI에 전송합니다.' : `생성 시 ${pkg ? '이 패키지' : '먼저 볼 패키지'}의 이름과 취약점 설명(최대 3건)을 OpenAI에 전송합니다.`} API 사용료가 발생할 수 있습니다. {findingId ? 'AI는 근거에 맞는 설명을 선택합니다.' : '위험 설명만 AI가 쓰고, 패키지·설치 경로·수정 버전 문장은 검사 결과로 만듭니다.'}</p>
          <p className="note">순서·심각도·버전·검사 상태는 검사 시스템 값이며, AI는 설명에만 사용됩니다. 설명이 없어도 아래 검사 결과는 그대로 확인할 수 있습니다.</p>
        </>
      )}
    </section>
  )
}
