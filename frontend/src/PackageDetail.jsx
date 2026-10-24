import { useEffect, useState } from 'react'
import { getDependencyPaths } from './api'
import { findingLabel, fixSummary, SEVERITIES } from './display'
import { commonFixText } from './packageGroups'
import { buildFixPrompt } from './fixPrompt'
import { CommonFix, SeverityBadge } from './PackageFindingList'
import AiReport from './AiReport'

// 저장된 최단 경로를 '프로젝트 → 상위@버전 → 패키지@버전' 형태로 바꾼다.
function pathLabels(item) {
  const path = (item && item.path) || []
  return path.map((p, i) => (i === 0 ? p.name : `${p.name}@${p.version}`))
}

function FixPrompt({ group, path, pathState }) {
  const [copied, setCopied] = useState(false)
  const text = buildFixPrompt(group, { path })
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false) // 복사가 막힌 환경에서도 아래 문구를 직접 선택해 복사할 수 있다
    }
  }
  return (
    <section className="oc-panel" aria-label="수정 프롬프트">
      <div className="oc-phead">
        <h2 className="oc-ptitle">수정 프롬프트</h2>
        <button type="button" className="oc-btn" onClick={copy}>{copied ? '복사됨' : '복사'}</button>
      </div>
      <p className="oc-hint">Cursor 같은 AI 코딩 도구에 붙여넣으면, 프로젝트를 직접 확인하면서 이 패키지를 고치도록 요청합니다. 검사 결과의 식별자·심각도·버전만 넣고 권고 설명문은 넣지 않습니다.
        {pathState === 'loading' && ' 설치 경로를 불러오는 중입니다.'}
        {pathState === 'error' && ' 설치 경로를 불러오지 못해 경로 없이 만들었습니다.'}</p>
      <pre className="oc-fix-prompt">{text}</pre>
    </section>
  )
}

export default function PackageDetail({ scanId, scanStatus, group, rankLabel, onBack, onFinding }) {
  const firstId = group.entries[0]?.finding?.finding_id
  const [paths, setPaths] = useState({ key: null })
  const key = `${scanId}:${firstId}`
  useEffect(() => {
    if (!firstId) return undefined
    let cancelled = false
    getDependencyPaths(scanId, firstId)
      .then((data) => {
        if (cancelled) return
        const item = (data.items || []).find((x) => x.name === group.name && x.installed_version === group.version && x.status === 'available')
        setPaths({ key, path: pathLabels(item) })
      })
      .catch(() => { if (!cancelled) setPaths({ key, error: true }) })
    return () => { cancelled = true }
  }, [scanId, firstId, key, group.name, group.version])
  const current = paths.key === key ? paths : { loading: true }
  const indirect = group.entries.every((e) => e.packages.every((p) => p.relationship === 'indirect'))
  const sorted = [...group.entries].sort((a, b) => SEVERITIES.indexOf(a.finding.severity) - SEVERITIES.indexOf(b.finding.severity))

  return (
    <div className="oc-detail">
      <div className="oc-detailnav">
        <button type="button" className="oc-btn" onClick={onBack}>← 목록으로</button>
      </div>
      <div>
        <div className="oc-dtitle">
          <h1>{group.name}@{group.version}</h1>
          <span className="oc-pill">{rankLabel}</span>
          <span className="oc-tag">{indirect ? '다른 패키지가 사용' : '직접 설치'}</span>
        </div>
        <p className="oc-group-counts" style={{ marginTop: 8 }}>
          <span>취약점 {group.entries.length}건</span>
          {SEVERITIES.filter((s) => group.counts[s]).map((s) => <SeverityBadge key={s} severity={s} count={group.counts[s]} />)}
          <CommonFix fix={group.commonFix} />
        </p>
        {group.commonFix?.status !== 'all' && <p className="oc-hint">{commonFixText(group)}</p>}
      </div>

      <AiReport scanId={scanId} scanStatus={scanStatus} pkg={{ name: group.name, version: group.version }} onFinding={onFinding} hideFindingList />

      <FixPrompt group={group} path={current.path || []} pathState={current.loading ? 'loading' : current.error ? 'error' : 'ok'} />

      <section className="oc-panel" aria-label="이 패키지의 취약점">
        <h2 className="oc-ptitle" style={{ marginBottom: 10 }}>이 패키지의 취약점</h2>
        <ul className="oc-group-findings">{sorted.map(({ finding, packages }, i) => (
          <li key={finding.finding_id || i}>
            <button type="button" className="oc-link" disabled={!finding.finding_id} onClick={() => onFinding(finding.finding_id)}>{findingLabel(finding)}</button>
            <SeverityBadge severity={finding.severity} />
            {finding.manual_review_required && <span className="oc-tag warn">수동 확인</span>}
            <span className="muted">{[...new Set(packages.map((p) => fixSummary(p).text))].join(' · ')}</span>
          </li>
        ))}</ul>
      </section>
    </div>
  )
}
