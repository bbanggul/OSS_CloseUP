import { SEVERITIES, rangeFixFor } from './display.js'

// 사용자가 자기 AI 코딩 도구에 붙여넣는 수정 요청문.
// AI로 생성하지 않고 검사 사실만 정해진 틀에 채운다. 권고 설명문은 넣지 않는다
// (외부 문구가 사용자 AI에게 지시처럼 전달되지 않게 ID·심각도·버전만 쓴다).
const NPM_NAME = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/
const SAFE = /^[0-9A-Za-z@/._~+-]+$/
const SEV_LABEL = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW', UNKNOWN: '심각도 미확인' }

const ids = (finding) => {
  const list = (finding.identifiers || []).map((x) => (typeof x === 'string' ? x : x && (x.value || x.id))).filter((x) => x && SAFE.test(x))
  return list.length ? list.join(' / ') : '식별자 없음'
}

// parent: 간접 의존성의 바로 위 패키지 { name, version, deprecated } — deprecated는 npm 조회 결과(true/false/null).
export function buildFixPrompt(group, { path = [], parent = null } = {}) {
  if (!NPM_NAME.test(group.name || '')) throw new Error('invalid_package_name')
  const name = group.name
  const pkg = `${name}@${group.version}`
  const indirect = group.entries.every((e) => e.packages.every((p) => p.relationship === 'indirect'))
  const fix = group.commonFix || { status: 'none' }
  const total = group.entries.length
  const counts = SEVERITIES.filter((s) => group.counts[s]).map((s) => `${SEV_LABEL[s] || s} ${group.counts[s]}`).join(' · ')
  const order = (f) => { const i = SEVERITIES.indexOf(f.severity); return i < 0 ? SEVERITIES.length : i }
  const rows = [...group.entries].sort((a, b) => order(a.finding) - order(b.finding)).map(({ finding, packages }) => {
    const target = rangeFixFor(group.version, packages.flatMap((p) => p.fixed_version_candidates || []))
    return `  - ${ids(finding)} · ${SEV_LABEL[finding.severity] || '심각도 미확인'} · ${target ? `수정 버전 ${target}` : '수정 정보 없음'}`
  })
  const route = path.filter((x) => SAFE.test(String(x).replace(/\s/g, '')))
  const up = parent && NPM_NAME.test(parent.name || '') && SAFE.test(String(parent.version || '')) ? `${parent.name}@${parent.version}` : null
  const upDeprecated = indirect && up && parent.deprecated === true
  const L = []
  L.push('내 Node.js 프로젝트의 의존성 보안 취약점을 고쳐 줘.', '')
  L.push('[검사 결과] OSS CloseUP, package-lock.json 기준')
  L.push(`- 패키지: ${pkg} (${indirect ? '간접 의존성: 내가 직접 설치하지 않음' : '직접 의존성: package.json에 내가 설치함'})`)
  if (indirect && route.length > 1) L.push(`- 설치 경로: ${route.join(' → ')}`)
  if (upDeprecated) L.push(`- 상위 패키지 ${up}는 npm에 사용 중단(deprecated)으로 표시되어 있어.`)
  L.push(`- 확인된 취약점 ${total}건 (${counts})`, ...rows)
  if (fix.status === 'all') L.push(`- 목표 버전: ${fix.version} 이상 (위 ${total}건의 영향 범위를 모두 벗어나는 최소 버전)`)
  else if (fix.status === 'partial') L.push(`- 목표 버전: ${fix.version} 이상. 이 버전으로 ${fix.covered}건이 해결되는 것을 확인했어. 나머지 ${total - fix.covered}건은 수정 정보가 없어 해결 여부를 확인하지 못했어.`)
  else L.push('- 목표 버전: 검사 결과로 확인하지 못했어. 버전을 추측하지 말고 실제 배포 버전을 확인해서 제안해 줘.')
  if (fix.majorChange && fix.status !== 'conflict') L.push('- 주의: 목표 버전은 현재와 주요 버전이 달라서 호환되지 않는 변경이 있을 수 있어.')
  L.push('', '[작업 순서]', `1. npm ls ${name} 으로 현재 설치 버전과 경로를 확인해 줘.`)
  if (indirect) L.push(`2. 상위 패키지가 허용하는 버전 범위 안에서 ${name}을(를) 목표 버전으로 올릴 수 있는지 확인해 줘. 안 되면 ${upDeprecated ? '상위 패키지가 사용 중단 상태이니 업데이트보다 ' : '상위 패키지 업데이트, '}package.json의 overrides, 상위 패키지 교체 중에서 비교해 추천하고 각 방법의 영향을 알려줘. overrides를 쓸 때는 다른 패키지가 쓰는 ${name} 버전까지 바뀌지 않도록 해당 상위 패키지 아래로 범위를 좁혀 줘.`)
  else L.push(`2. package.json의 ${name} 버전 범위를 확인하고, 목표 버전으로 올릴 때 코드에서 바꿔야 할 부분이 있는지 변경 기록을 보고 알려줘.`)
  L.push('3. 내가 확인하면 적용하고 npm install로 lock 파일을 갱신해 줘.')
  L.push(`4. 빌드와 테스트를 실행해 줘. package.json에 build·test 스크립트가 없으면 없다고 알려주고, 앱이 실행되는지 확인해 줘. 그다음 npm ls ${name} 으로 최종 설치 버전을 확인해 줘. overridden 같은 표시가 아니라 실제 버전 번호로 확인해 줘.`)
  if (fix.status !== 'all') L.push('5. 수정 정보가 없던 취약점이 해결됐는지 확인할 방법을 알려줘.')
  L.push('', '[지켜 줄 것]',
    '- 위에 없는 버전 번호를 추측해서 쓰지 마. 필요하면 npm view로 실제 값을 확인해.',
    '- npm audit fix --force처럼 여러 패키지를 한꺼번에 바꾸는 명령은 실행 전에 물어봐.',
    '- package-lock.json을 손으로 직접 고치지 마.',
    '- 경고를 없애려고 패키지를 지우거나 검사를 끄지 마.',
    `- 이 검사는 코드에서 ${name}을(를) 실제로 쓰는지 분석하지 않았어. 안 쓴다고 단정하지 마.`)
  L.push('', '[끝나면 알려줘]', '- 바꾼 파일과 내용, 최종 설치 버전', '- 빌드·테스트 결과', '- 해결하지 못한 취약점과 그 이유')
  return L.join('\n')
}
