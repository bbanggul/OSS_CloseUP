# 패키지 묶음 API v1 — 화면 연동 계약

작성일: 2026-10-26. 구현 및 검토용 계약이며 팀의 최종 합의·운영 배포 완료를 뜻하지 않는다.

기존 설치별 `/packages`와 취약점 `/findings`는 유지한다. 이 API는 같은 검사에서 생태계·패키지명·설치 버전이 같은 설치를 한 묶음으로 조회한다. 현재 저장된 취약점과 우선순위 결과만 사용하며 조회 중에 병합·계산·DB 수정을 수행하지 않는다.

## 1. 경로

| 요청 | 용도 |
| --- | --- |
| `GET /scans/{scan_id}/vulnerable-packages` | 취약 패키지 묶음 목록·검색·필터·전체 순위 |
| `GET /scans/{scan_id}/vulnerable-packages/{package_group_id}` | 묶음 기본 정보·모든 설치·전체 관련 취약점과 수정 근거 |
| `GET /scans/{scan_id}/unlinked-vulnerabilities` | affected 관계의 비루트 설치에 연결되지 않은 취약점 |
| `GET /scans/{scan_id}/findings/{finding_ref}` | 현재 취약점 상세 및 기록된 병합 전 식별자 해석 |

`scan_id`는 UUID다. 없는 검사는 404이며 잘못된 UUID·쿼리 값은 422다. DB 조회 실패는 503으로 반환하며 정상 빈 목록으로 대체하지 않는다.

## 2. 묶음과 집계

- 같은 검사·생태계·이름·설치 버전은 하나의 묶음이다. `package_group_id`는 이 값들의 SHA-256 기반 식별자이며 검색·필터·페이지·우선순위 재평가로 달라지지 않는다.
- 버전이 NULL인 설치는 `package_id`별로 분리한다. 서로 같은 버전이라고 추정하지 않는다.
- 프로젝트 루트는 묶음에서 제외한다. 취약점의 `affected` 연결만 취약 패키지 집계에 사용한다.
- 같은 묶음의 설치 경로·직접/간접 관계·라이선스·purl·저장소 정보는 `installations` 배열에 각각 유지한다.
- 같은 취약점이 여러 설치에 연결돼도 묶음의 `finding_count`에는 한 번만 센다. `severity_counts` 합은 `finding_count`와 같다. NULL 심각도는 UNKNOWN으로 표시한다.
- 동일성 판단은 저장된 Findings를 따른다. 이 API가 CVE/GHSA 별칭을 임의로 다시 병합하지 않는다. 중복 병합 규칙 수정은 PR #3의 별도 범위다.

| 공통 집계 필드 | 의미 |
| --- | --- |
| `total` | 해당 목록에서 필터 적용 후, 페이지 분할 전 개수 |
| `total_unfiltered` | 검사 전체 취약 패키지 묶음 수. 상세·미연결 응답에서도 같은 의미 |
| `unique_finding_count` | 검사 전체 고유 취약점 수. license/maintenance 항목 제외 |
| `linked_unique_finding_count` | 최소 하나의 묶음에 연결된 고유 취약점 수 |
| `unlinked_finding_count` | 적격 설치 연결이 없는 고유 취약점 수 |
| `ranked_total` | 전체 묶음 중 숫자 순위가 부여된 수 |

`unique_finding_count = linked_unique_finding_count + unlinked_finding_count`다. 여러 묶음에 하나의 취약점이 연결될 수 있으므로 패키지별 `finding_count` 합을 검사 전체 건수로 쓰지 않는다.

`unlinked-vulnerabilities`의 `total`은 미연결 취약점 수다. 루트에만 연결되거나 `entry_point`/`dependency`만 있는 항목도 이 목록에 포함한다. 기존 연결은 `installation_links`로 보존하고 사유는 `no_affected_non_root_installation`로 명시한다.

## 3. 전체 순위 및 검색·필터

대표 P등급은 저장된 최신 유효 평가의 연결별 등급 중 가장 긴급한 값이다. 전체 묶음을 아래 순서로 정렬하고 **검색·필터·페이지 분할 전에** 1부터 `global_rank`를 부여한다.

1. P0 → P1 → P2 → P3.
2. 대표 등급의 취약점에 수정 후보가 있는 묶음 우선.
3. 대표 등급에 해당하는 고유 취약점 수 내림차순.
4. 패키지 이름 → 설치 버전 문자열 → 안정적인 묶음 ID 순.

동률이어도 마지막 기준으로 순서를 정해 서로 다른 정수 순위를 부여한다. SemVer 정렬을 새로 도입하지 않는다. 화면은 `global_rank`에 “위”를 붙여 표시할 수 있다. 검색 결과의 첫 행이 전체 7위라면 그대로 7위다.

- UNKNOWN만 있는 묶음은 알려진 등급 뒤에서 이름·버전·ID 순으로 표시하고 `global_rank=null`이다. 후보 유무로 UNKNOWN의 위험 순위를 만들지 않는다.
- 알려진 등급과 UNKNOWN이 섞인 묶음은 알려진 등급으로 대표값·순위를 정하고 UNKNOWN 수는 보존한다.
- 최신 계산이 실패·미실행·무효이면 모든 순위와 대표 등급은 NULL이다. 과거 등급이나 `offset+1`로 가짜 순위를 만들지 않는다.
- 부분 검사에서도 유효한 평가가 있으면 확보된 결과 기준으로 순위를 제공하되 `result_state=partial`, `incomplete=true`다.
- 하위 등급에만 있는 수정 후보는 대표 등급의 후보 여부나 정렬을 바꾸지 않는다.

목록 쿼리:

| 쿼리 | 규칙 |
| --- | --- |
| `limit`, `offset` | 기본 100/0. limit 1~500, offset ≥0 |
| `q` | 패키지명 부분 일치, 대소문자 무시, 최대 200자 |
| `priority` | P0/P1/P2/P3 중 하나 |
| `severity` | CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN. 해당 심각도 취약점이 하나 이상 있는 묶음 |
| `relationship` | direct/indirect/unknown. 해당 관계 설치가 하나 이상 있는 묶음 |
| `snapshot_id` | 이전 응답과 같은 결과인지 확인할 선택적 토큰 |

여러 필터는 AND로 적용한다. UNKNOWN 필터는 알려진 등급과 UNKNOWN이 섞인 묶음도 포함한다.

## 4. 상세 화면과 수정 근거

목록의 각 `items[]`와 상세의 `item`은 다음 정보를 공유한다.

- `package_group_id`, `ecosystem`, `name`, `installed_version`, `installations`
- `priority`, `priority_status`, `global_rank`
- `finding_ids`, `finding_count`, `severity_counts`
- `representative_finding_ids`, `representative_finding_count`, `has_fix_candidate_at_priority`, `representative_links`
- `full_remediation_status=not_evaluated`, `incomplete`

상세 `item.findings[]`에는 **대표 등급뿐 아니라 모든 관련 취약점**을 포함한다. 각 취약점의 식별자·심각도·출처·검토 상태·정규화 원문을 보존하고 `installation_links[]`에 해당 묶음의 설치별 `finding_id`, `package_id`, 경로, 관계, 수정 후보, 원문 출처와 연결 근거를 제공한다.

수정 후보 객체를 한 문자열로 합치지 않는다. `fixed_version_candidates`의 value/raw/source_tool/json_pointer 등 저장된 객체를 그대로 반환한다. 패키지 단위 수정 프롬프트는 이 전체 근거를 사용하면 된다. 프롬프트 생성이나 모든 취약점을 해결하는 공통 버전 계산은 이번 API에 포함하지 않는다.

UNKNOWN만 있는 유효 평가에서는 대표 ID·연결은 빈 배열, 대표 건수 0, 후보 여부 false다. 평가 자체를 사용할 수 없으면 해당 대표 필드들은 모두 NULL이다. 이를 정상 빈 결과와 구분한다.

## 5. 준비·실패·빈 결과

| `result_state` | 의미와 처리 |
| --- | --- |
| `processing` | 검사 queued/running이며 검증된 정규화 결과 준비 전 |
| `ready` | 패키지 저장 완료 + normalization completed + roundtrip_verified=true |
| `partial` | 패키지 저장 완료 + normalization partial + roundtrip_verified=true |
| `failed` | 정규화 실패 또는 검증된 결과 없이 검사 실패 |
| `unavailable` | 종료된 검사이나 정규화 검증·패키지 저장 근거가 부족 |

`security_status`는 저장된 정규화 결과의 completed/partial/failed이며 아직 없으면 NULL이다. 전체 `scan_status`와 구분한다. 우선순위 실패는 유효한 취약점 결과 자체를 숨기지 않는다. `priority_evaluation`으로 계산 상태를 따로 확인한다.

processing/failed/unavailable 목록은 `items=[]`, `total`과 전체 집계는 NULL이다. 이 상태에서 상세 요청은 409 `results_not_ready`다. 정상 0건은 **`zero_findings_confirmed=true`일 때만** 표시한다. 이 값은 ready이고 전체 고유 취약점이 0개일 때만 true다. 미연결 취약점만 있어도 정상 0건이 아니다.

`empty_reason`: 결과가 있으면 NULL. 그 외 processing/failed/unavailable, no_vulnerabilities, partial_no_findings, no_matches, page_out_of_range로 구분한다. 검색 결과 0개 또는 마지막 페이지 밖의 요청은 전체 검사 0건과 다르다.

## 6. 스냅샷 일관성

한 요청은 repeatable-read 읽기 전용 트랜잭션으로 검사 상태·패키지·취약점·연결·평가를 읽는다. 응답의 `snapshot_id`는 이 조회 자료와 응답 버전에 기반한 토큰이다.

첫 목록의 토큰을 검색·필터·다음 페이지·상세·미연결·취약점 조회에 전달한다. 원본 자료 또는 평가 상태가 바뀌었으면 409 `snapshot_changed`와 현재 토큰을 반환한다. 화면은 목록을 새로 받아야 한다. 이 토큰은 과거 스냅샷을 서버에 보관하는 기능이 아니다. 생략하면 요청 시점 최신 결과를 반환한다.

`global_rank`는 동일 스냅샷에서 유지된다. 재평가로 원래 순위가 바뀌면 새 토큰에서 새 순위를 보여준다. 평가가 참조한 연결 집합·취약점 수·심각도·수정 후보·취약점 근거와 현재 자료가 맞지 않으면 평가 사용 불가로 처리한다.

## 7. 중복 검토 완료 조건

자동 병합 적용 정보는 `automatic_deduplication`으로 전달한다. 병합 기록이 없으면 NULL이며, 이를 중복 검토 완료로 해석하지 않는다.

`deduplication_status`는 결과 미준비 시 not_ready, 검토 완료 근거가 없으면 review_pending이다. completed는 아래 조건을 모두 만족할 때만 반환한다.

- result_state=ready, 수동 검토 필요 취약점 0개.
- 저장된 normalization fingerprint가 존재.
- `scan_runs.tool_status.deduplication_review`의 status=completed이며 normalization_fingerprint가 현재 결과와 일치.
- reviewed_by, reviewed_at, evidence_ref가 비어 있지 않은 문자열로 기록돼 있음.

이 PR은 위 검토 근거를 **읽는 계약**을 제공한다. 검토 완료를 기록하는 편집 API·화면은 포함하지 않는다. 해당 기록이 없는 기존 검사들은 review_pending으로 유지된다. 실제 74건·71건 문제도 근거 없이 완료로 표시하지 않는다.

## 8. 병합 전 취약점 ID

`findings/{finding_ref}`는 현재 DB UUID 또는 현재 정규화 Finding ID를 직접 조회할 수 있다. 저장된 `evidence.normalized.merge_basis.kind=explicit_ghsa_identity`와 `source_finding_ids`에 명시된 이전 정규화 ID는 최종 DB UUID로 해석한다.

응답은 200이며 `requested_finding_id`, `canonical_finding_id`, `resolution=direct|merged`, `item`을 포함한다. 임의 CVE/GHSA로 추측하지 않는다. 같은 이전 ID가 여러 최종 항목에 대응하면 409 ambiguous_finding_alias, 기록이 없으면 404다.

PR #3은 기존 검사 결과를 덮어쓰지 않고 새 검사에 적용한다. 기존 검사의 DB UUID는 기존 scan_id에서 조회하며 다른 검사로 자동 연결하지 않는다. 이전 DB UUID→새 DB UUID 이력을 새로 만들어내지 않는다. 현재 병합 근거는 정규화 ID 기준이다.

## 9. 구현 범위와 반영

DB 스키마 변경 없이 신규 GET 경로와 읽기 전용 집계 모듈을 추가한다. 기존 API·화면·우선순위 계산기는 변경하지 않는다. PR #3과 같은 기준 커밋에서 분리했으며, PR #3이 반영되면 저장된 병합 근거도 자동으로 읽는다.

현재는 전체 검사 데이터를 읽어 메모리에서 묶음·순위를 구성한다. 대규모 검사의 조회 비용을 줄이는 사전 집계·캐시는 포함하지 않는다. 검증 범위와 실제 응답 예시는 [재실행 안내](../verification/package-api/README.md)에 정리한다.
