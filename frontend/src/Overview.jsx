import {
  SEVERITIES, severityCounts, packageSummary, licenseSummary, maintenanceSummary, vulnScanFailed,
} from './display'
import Icon from './Icons'

const SEV_COLOR = { CRITICAL: 'var(--oc-crit)', HIGH: 'var(--oc-high)', MEDIUM: 'var(--oc-med)', LOW: 'var(--oc-low)', UNKNOWN: 'var(--oc-unknown)' }

function Card({ num, label, icon, children, onClick }) {
  return (
    <button type="button" className="oc-card" onClick={onClick} aria-label={`${label} 보기`}>
      <div className="top">
        <div><div className="num">{num}</div><div className="lab">{label}</div></div>
        <span className="ico"><Icon name={icon} /></span>
      </div>
      <div className="foot">{children}</div>
    </button>
  )
}

// 요약 카드 4칸. 세 축(보안·라이선스·유지보수)은 따로 세고 합친 점수를 만들지 않는다.
export function SummaryCards({ packages, vulns, findings, maintenance, scan, onNavigate }) {
  const pkg = packageSummary(packages)
  const lic = licenseSummary(packages)
  const mnt = maintenanceSummary(maintenance)
  const counts = severityCounts(vulns)
  const pkgReady = packages && (pkg.status === 'completed' || pkg.total > 0)
  const vulnReady = findings && (((findings.normalization || {}).status === 'completed') || vulns.length > 0)
  const mntReady = maintenance && (mnt.status === 'completed' || mnt.status === 'partial' || mnt.status === 'rate_limited' || (maintenance.items || []).length > 0)
  const failed = vulnScanFailed(scan)
  return (
    <section className="oc-panel oc-cards" aria-label="검사 요약">
      <Card num={pkgReady ? pkg.total : '—'} label="외부 패키지" icon="box" onClick={() => onNavigate?.('packages')}>
        {pkgReady
          ? <>직접 {pkg.direct} · 간접 {pkg.indirect}{pkg.unknown ? ` · 확인 불가 ${pkg.unknown}` : ''}</>
          : '패키지 목록을 정리하는 중'}
      </Card>
      <Card num={vulnReady ? vulns.length : '—'} label="취약점" icon="alert" onClick={() => onNavigate?.('findings')}>
        {!vulnReady ? '결과를 정리하는 중'
          : failed ? <span className="err">일부 검사 실패 · 전부가 아닐 수 있음</span>
            : vulns.length === 0 ? '알려진 취약점 없음'
              : SEVERITIES.filter((s) => counts[s]).map((s) => (
                <span key={s} className="s"><span className={`oc-dot sev-${s}`} />{s} {counts[s]}</span>
              ))}
      </Card>
      <Card num={pkgReady ? lic.total : '—'} label="라이선스 조건 확인" icon="doc" onClick={() => onNavigate?.('licenses')}>
        {pkgReady ? `조건 확인 ${lic.review} · 정보 없음 ${lic.unknown}` : '패키지 목록을 정리하는 중'}
      </Card>
      <Card num={mntReady ? mnt.flagged : '—'} label="유지보수 확인" icon="gear" onClick={() => onNavigate?.('maintenance')}>
        {!mntReady ? '저장소 정보를 조회하는 중'
          : <>보관(archived) {mnt.archived} · 사용 중단 {mnt.deprecated}{mnt.status === 'partial' || mnt.status === 'failed' || mnt.status === 'rate_limited' ? ' · 일부 확인 불가' : ''}</>}
      </Card>
    </section>
  )
}

// 심각도 분포. 건수만 보여준다(점수 아님).
export function SeverityDonut({ vulns, findings, scan }) {
  const counts = severityCounts(vulns)
  const total = vulns.length
  const ready = findings && (((findings.normalization || {}).status === 'completed') || total > 0)
  const failed = vulnScanFailed(scan)
  const R = 70
  const C = 2 * Math.PI * R
  const GAP = total > 1 ? 3 : 0
  let offset = 0
  const arcs = SEVERITIES.filter((s) => counts[s]).map((s) => {
    const len = (counts[s] / total) * C
    const arc = { s, len: Math.max(len - GAP, 1), offset }
    offset += len
    return arc
  })
  return (
    <section className="oc-panel oc-donut" aria-label="심각도 분포">
      <h2 className="oc-ptitle">심각도 분포</h2>
      <div className="chart">
        <svg width="176" height="176" viewBox="0 0 176 176" role="img"
          aria-label={ready ? SEVERITIES.filter((s) => counts[s]).map((s) => `${s} ${counts[s]}건`).join(', ') || '취약점 없음' : '정리 중'}>
          <circle cx="88" cy="88" r={R} fill="none" stroke="var(--oc-line)" strokeWidth="30" />
          {ready && arcs.map((a) => (
            <circle key={a.s} cx="88" cy="88" r={R} fill="none" stroke={SEV_COLOR[a.s]} strokeWidth="30"
              strokeDasharray={`${a.len} ${C - a.len}`} strokeDashoffset={-a.offset} />
          ))}
        </svg>
        <div className="center"><b>{ready ? total : '—'}</b><span>취약점</span></div>
      </div>
      {!ready ? <p className="msg">결과를 정리하는 중이에요.</p>
        : total === 0 ? <p className="msg">{failed ? '일부 검사가 실패해 확인하지 못한 취약점이 있을 수 있어요.' : '알려진 취약점이 발견되지 않았어요.'}</p>
          : (
            <ul className="legend">
              {SEVERITIES.filter((s) => counts[s]).map((s) => (
                <li key={s}><span className={`oc-dot sev-${s}`} /><span>{s}</span><b>{counts[s]}</b></li>
              ))}
            </ul>
          )}
    </section>
  )
}
