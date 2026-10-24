import { findingLabel } from './display'

// Package-first report: 무엇을(what) → 왜(why) → 어떻게 들어왔나(path) → 어떻게 고치나(fix).
// what·path·fix are server-written facts; only why comes from the model.
export default function AiNarrativeReport({ output, onFinding, onPackage, hideFindingList = false }) {
  const pkg = output.package || {}
  const findings = output.findings || []
  const order = ['what', 'why', 'path', 'fix']
  const paragraphs = order.flatMap((kind) => (output.paragraphs || []).filter((p) => p.kind === kind))
  return (
    <div className="oc-ai-narrative">
      <section className="oc-report-section">
        <h3>{output.title || '우선 확인 사항'}</h3>
        {onPackage && <button type="button" className="oc-report-primary-link" onClick={() => onPackage(pkg.name, pkg.version)}>
          {pkg.name} {pkg.version} <span aria-hidden="true">→</span>
        </button>}
        {paragraphs.map((p, i) => <p className="oc-report-body" key={`${p.kind}-${i}`}>{p.text}</p>)}
        {!hideFindingList && findings.length > 0 && <details className="oc-report-related-more">
          <summary>이 패키지의 취약점 {findings.length}건 보기</summary>
          <ul className="oc-report-related-list">{findings.map((f) => <li key={f.finding_id}>
            <button type="button" className="oc-report-text-link" disabled={!onFinding} onClick={() => onFinding?.(f.finding_id)}>
              {f.title || findingLabel({ identifiers: f.identifiers }) || '취약점 상세'}
            </button>
            <span className="muted"> · {f.severity}{f.fix_version ? ` · 수정 버전 ${f.fix_version}` : ''}</span>
          </li>)}</ul>
        </details>}
      </section>
    </div>
  )
}
