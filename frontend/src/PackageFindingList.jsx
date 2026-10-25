import { useState } from 'react'
import { SEVERITIES, findingLabel, fixSummary } from './display'

export function SeverityBadge({ severity, count }) {
  const value = SEVERITIES.includes(severity) ? severity : 'UNKNOWN'
  return <span className={`oc-severity-badge oc-severity-${value}`}>
    <span className={`oc-dot sev-${value}`} aria-hidden="true" />
    <span>{value === 'UNKNOWN' ? '심각도 미확인' : value}</span>
    {count != null && <span className="oc-severity-count">{count}</span>}
  </span>
}

export function CommonFix({ fix }) {
  if (!fix || (fix.status !== 'all' && fix.status !== 'partial')) return <span className="muted">공통 수정 버전 확인 안 됨</span>
  return <span className="oc-common-fix">
    공통 수정 버전 <strong>{fix.version}</strong>
    {fix.status === 'partial' && <span className="muted"> ({fix.covered}/{fix.total}건 확인)</span>}
    {fix.majorChange && <span className="oc-tag warn">주요 버전 변경</span>}
  </span>
}

// 패키지 줄을 누르면 패키지 상세로 간다. showFindings면 왼쪽 화살표로 그 아래 취약점을 접고 펼친다(취약점 탭).
export default function PackageFindingList({ groups, onPackage, onOpen, showFindings = false }) {
  const [collapsed, setCollapsed] = useState(() => new Set())
  const toggle = (key) => setCollapsed((prev) => {
    const next = new Set(prev)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    return next
  })
  return <div className="oc-package-groups">
    {groups.map(group => { const open = showFindings && !collapsed.has(group.key); return <div className={`oc-package-block${showFindings ? ' with-findings' : ''}`} key={group.key}>
      <div className="oc-package-row">
      {showFindings && <button type="button" className="oc-package-toggle" aria-expanded={open}
        aria-label={`${group.name}@${group.version} 취약점 ${open ? '접기' : '펼치기'}`} onClick={() => toggle(group.key)}>
        <span aria-hidden="true">{open ? '▾' : '▸'}</span>
      </button>}
      <button type="button" className="oc-package-group"
        aria-label={`${group.name}@${group.version} 패키지 상세 열기`} onClick={() => onPackage(group.name, group.version)}>
        <strong>{group.name}@{group.version}</strong>
        <span className="oc-pill">{group.displayRank ? `${group.displayRank}위` : '미산정·확인 필요'}</span>
        <span>{group.entries.length}건</span>
        <span className="oc-group-counts">{SEVERITIES.filter(s => group.counts[s]).map(s =>
          <SeverityBadge key={s} severity={s} count={group.counts[s]} />)}</span>
        <CommonFix fix={group.commonFix} />
        <span className="oc-package-go" aria-hidden="true">›</span>
      </button>
      </div>
      {open && <ul className="oc-group-findings">{[...group.entries]
        .sort((a, b) => SEVERITIES.indexOf(a.finding.severity) - SEVERITIES.indexOf(b.finding.severity))
        .map(({ finding, packages }, i) => <li key={finding.finding_id || i}>
          <button type="button" className="oc-link" aria-label={`${findingLabel(finding)} 상세 열기`} disabled={!finding.finding_id} onClick={() => onOpen(finding.finding_id)}>{findingLabel(finding)}</button>
          <SeverityBadge severity={finding.severity} />
          {finding.manual_review_required && <span className="oc-tag warn">수동 확인</span>}
          <span className="muted">{[...new Set(packages.map(p => fixSummary(p).text))].join(' · ')}</span>
        </li>)}</ul>}
    </div> })}
  </div>
}
