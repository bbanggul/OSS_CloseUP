export const COMPARISON_LABELS = {
  new: '새로 발견', persisting: '계속 발견', not_detected: '현재 미발견', not_comparable: '비교 불가',
}
export function findingText(data, side, ids) {
  return ids.map(id => {
    const finding = data.finding_catalog[side][id]
    return finding ? `${finding.identifiers.join(', ') || id} (${finding.severity || '심각도 미확인'})` : id
  }).join(' / ') || '관측 없음'
}
export function comparisonRows(data) {
  const installations = new Map(data.installations.map(item => [item.installation_id, item]))
  return data.items.map(item => {
    const installation = installations.get(item.installation_id)
    return {
      id: item.item_id, name: installation?.name || '설치 대응 확인 필요', status: item.status,
      reason: item.reason, conflict: item.unit === 'identifier_conflict',
      basePath: installation?.base?.lockfile_path || '—', targetPath: installation?.target?.lockfile_path || '—',
      baseVersion: installation?.base?.installed_version || '—', targetVersion: installation?.target?.installed_version || '—',
      baseFindings: findingText(data, 'base', item.base_finding_ids),
      targetFindings: findingText(data, 'target', item.target_finding_ids),
    }
  })
}
export function comparisonError(error) {
  const code = error.body?.detail?.code
  return ({ scan_not_found: '검사를 찾을 수 없습니다. 이력을 새로고침해 주세요.',
    same_scan: '서로 다른 두 검사를 선택해 주세요.', different_project: '같은 프로젝트의 검사만 비교할 수 있습니다.',
    scan_processing: '검사가 진행 중입니다. 완료 후 새로고침해 주세요.',
    comparison_limit_exceeded: '비교할 자료가 처리 한도를 초과했습니다.',
    database_unavailable: '서버에 연결할 수 없습니다. 잠시 후 다시 시도해 주세요.',
    comparison_invariant_failed: '비교 결과를 만들지 못했습니다. 다시 시도해 주세요.',
  })[code] || error.message
}

export function comparisonReason(reason) {
  return ({ matched_identity: '두 검사에서 같은 취약점을 확인했습니다.',
    version_unknown: '설치 버전을 확인할 수 없습니다.',
    base_incomplete: '이전 검사의 자료가 충분하지 않습니다.',
    target_incomplete: '현재 검사의 자료가 충분하지 않습니다.',
    base_unlinked_findings: '이전 검사에 패키지와 연결되지 않은 취약점이 있습니다.',
    target_unlinked_findings: '현재 검사에 패키지와 연결되지 않은 취약점이 있습니다.',
    identifier_review_required: '취약점 식별자의 대응 관계를 검토해야 합니다.',
    identifier_missing: '비교에 필요한 취약점 식별자가 없습니다.',
    package_added: '현재 검사에 추가된 패키지입니다.',
    package_removed: '현재 검사에서 제거된 패키지입니다.',
    version_changed: '두 검사의 설치 버전이 다릅니다.',
    same_version: '같은 설치 버전의 검사 결과가 달라졌습니다.',
  })[reason] || reason
}
