import { useEffect, useState } from 'react'
import { getDependencyPaths } from './api'

export default function DependencyPaths({ scanId, findingId }) {
  const [result, setResult] = useState(null)
  const [retry, setRetry] = useState(0)
  const key = `${scanId}/${findingId}/${retry}`
  useEffect(() => {
    let active = true
    getDependencyPaths(scanId, findingId).then(
      (data) => { if (active) setResult({ key, data }) },
      () => { if (active) setResult({ key, error: true }) },
    )
    return () => { active = false }
  }, [scanId, findingId, key])
  const current = result?.key === key ? result : null
  return <section className="oc-panel">
    <h2 className="oc-ptitle">의존 경로</h2>
    {!current ? <p role="status">의존 경로를 불러오는 중입니다.</p>
      : current.error ? <div role="status"><p>의존 경로를 불러오지 못했습니다.</p><button type="button" className="oc-btn" onClick={() => setRetry((n) => n + 1)}>다시 불러오기</button></div>
      : <>
        {!current.data.items.length && <p>이 취약점에 연결된 패키지 정보가 없습니다.</p>}
        {current.data.items.map((item) => <div key={item.package_id} className="oc-dependency-path">
          <p><strong>{item.name}@{item.installed_version}</strong></p>
          {item.status === 'available' ? <ol aria-label={`${item.name} 의존 경로`}>
            {item.path.map((node, index) => <li key={node.package_id}>
              {index > 0 && <span aria-hidden="true">→ </span>}
              {node.name}{node.version ? `@${node.version}` : ''}
            </li>)}
          </ol> : <p>저장된 의존 관계에서 프로젝트부터 이어지는 경로를 찾지 못했습니다.</p>}
        </div>)}
      </>}
  </section>
}
