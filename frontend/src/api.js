// FastAPI 호출 모음. 모든 경로는 vite 프록시를 통해 /api 로 나간다.

const BASE = '/api'

async function request(path, options) {
  const response = await fetch(BASE + path, options)
  const text = await response.text()
  let body = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = { detail: text }
    }
  }
  if (!response.ok) {
    const error = new Error(describe(body, response.status))
    error.status = response.status
    error.body = body
    throw error
  }
  return body
}

function describe(body, status) {
  const detail = body && body.detail
  if (typeof detail === 'string') return detail
  if (detail && typeof detail === 'object') return detail.message || JSON.stringify(detail)
  return `요청이 실패했습니다 (HTTP ${status})`
}

export function createScan(packageJson, packageLock) {
  const form = new FormData()
  form.append('package_json', packageJson, 'package.json')
  form.append('package_lock', packageLock, 'package-lock.json')
  return request('/scans', { method: 'POST', body: form })
}

export const getScan = (scanId) => request(`/scans/${scanId}`)
export const getDependencyPaths = (scanId, findingId) => request(`/scans/${scanId}/findings/${findingId}/dependency-paths`)
// 서버의 페이지 상한은 유지하고 전체 페이지를 모은다. 일부 페이지만 성공하면 오류로 표시한다.
async function getAll(scanId, resource) {
  const items = []
  let page
  do {
    page = await request(`/scans/${scanId}/${resource}?limit=500&offset=${items.length}`)
    if (!Array.isArray(page.items) || !Number.isInteger(page.total) || page.total < 0) {
      throw new Error('목록 응답이 올바르지 않습니다. 다시 불러와 주세요.')
    }
    if (page.items.length === 0 && items.length < page.total) {
      throw new Error('전체 목록을 가져오지 못했습니다. 다시 불러와 주세요.')
    }
    items.push(...page.items)
  } while (items.length < page.total)
  return { ...page, offset: 0, items }
}

export const getPackages = (scanId) => getAll(scanId, 'packages')
export const getMaintenance = (scanId) => getAll(scanId, 'maintenance')
export const getFindings = (scanId) => getAll(scanId, 'findings')

// SBOM 미생성은 404로 오지만 오류가 아니다. available:false 로 바꿔서 돌려준다.
export async function getSbomInfo(scanId) {
  try {
    return await request(`/scans/${scanId}/sbom/info`)
  } catch (error) {
    if (error.status === 404 && error.body && error.body.detail && error.body.detail.reason) {
      return { available: false, syft: error.body.detail.syft }
    }
    throw error
  }
}

// AI 설명. 생성되지 않았으면 서버가 status:'not_generated'로 돌려준다.
export const getAiReport = (scanId) => request(`/scans/${scanId}/ai/report`)
export const generateAiReport = (scanId) => request(`/scans/${scanId}/ai/report`, { method: 'POST' })
export const getAiFindings = (scanId) => request(`/scans/${scanId}/ai/findings`)
export const getAiFinding = (scanId, findingId) => request(`/scans/${scanId}/ai/findings/${findingId}`)
export const generateAiFinding = (scanId, findingId) => request(`/scans/${scanId}/ai/findings/${findingId}`, { method: 'POST' })

export const sbomDownloadUrl = (scanId) => `${BASE}/scans/${scanId}/sbom`

export async function downloadSbom(scanId) {
  const response = await fetch(sbomDownloadUrl(scanId))
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(describe(body, response.status))
  }
  return response.blob()
}

// 패키지 단위 AI 설명. 이름에 @scope/가 들어갈 수 있어 쿼리 문자열로 보낸다.
const packageQuery = (name, version) => `?name=${encodeURIComponent(name)}&version=${encodeURIComponent(version)}`
export const getAiPackage = (scanId, name, version) => request(`/scans/${scanId}/ai/package${packageQuery(name, version)}`)
export const generateAiPackage = (scanId, name, version) => request(`/scans/${scanId}/ai/package${packageQuery(name, version)}`, { method: 'POST' })
