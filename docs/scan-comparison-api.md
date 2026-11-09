# 이전·현재 검사 비교 API v1

2026-11-09 구현. 기준 브랜치 `feat/design-refresh`, 기준 커밋 `dec0417`.
11월 1일 비교 상세안의 상태·집계·출처 확인 규칙을 저장 자료 조회와 HTTP API로 구현합니다.

## 호출

```http
GET /scans/{target_scan_id}/compare?base={base_scan_id}
```

사이트에서는 기존과 같이 `/api` 접두사를 사용합니다. 기존 사이트 인증 계층을 그대로 사용합니다.
`base`는 이전 쪽, 경로의 `target_scan_id`는 현재 쪽입니다. 같은 프로젝트의 서로 다른 두 검사만 받습니다.
선택한 방향을 바꾸지 않으며, base가 더 나중 검사라면 `base_after_target` 경고를 반환합니다.

비교 요청은 새 검사·정규화·우선순위 계산·AI 생성·DB 갱신을 실행하지 않습니다.
두 검사의 자료는 하나의 `REPEATABLE READ, READ ONLY` 트랜잭션에서 읽습니다.
조회가 끝나면 연결을 닫고 순수 비교 함수를 실행합니다.

## 응답과 화면 연결

- [정확한 응답 Schema](../backend/app/schemas/compare-response.schema.json)
- [오류 Schema](../backend/app/schemas/compare-error.schema.json)
- [독립 작성된 17개 정상·경계 예시](../backend/tests/fixtures/scan_compare/examples/)
- [7개 도메인 오류 예시](../backend/tests/fixtures/scan_compare/errors/)
- `/openapi.json`과 `/docs`에도 200·오류 응답 구조가 포함됩니다.

주요 필드:

| 필드 | 용도 |
| --- | --- |
| `base`, `target` | 검사 시각·입력 lock 해시·완전성·원본 실행 근거·도구/DB 버전 |
| `installations` | 취약점 유무와 무관한 외부 npm 설치 목록의 대응·추가·제거·검토 상태 |
| `items` | 설치별 취약점 비교 또는 식별자 검토 묶음 |
| `summary` | 네 상태의 **비교 항목 수**. 합계는 `items.length`와 같음 |
| `finding_catalog` | 각 검사에서 관측한 finding의 표시 자료. 원문 설명·서버 경로·로그는 제외 |
| `finding_counts` | 각 검사의 **저장 finding 수**. 비교 항목 수와 다른 단위 |
| `unlinked_findings` | 외부 affected 설치에 연결되지 않은 finding. summary와 별도 표시 |
| `context_changes` | 확인 가능한 도구·DB 버전 차이. 변화의 원인이라고 단정하지 않음 |
| `comparison_complete`, `warnings` | 전체 범위 확인 여부와 제한 사유 |

화면의 네 상태는 다음 문구를 사용합니다.

| API 상태 | 화면 표시 | 판정 |
| --- | --- | --- |
| `new` | 새로 발견 | 현재 관측이 있으며 이전 검사의 부재 확인 근거가 충분함 |
| `persisting` | 계속 발견 | 대응 설치에서 명확한 1:1 취약점 관측이 양쪽에 존재함 |
| `not_detected` | 이번 검사에서 미검출 | 이전 관측이 있으며 현재 검사의 부재 확인 근거가 충분함 |
| `not_comparable` | 비교 불가 | 식별자 충돌·정보 부족·일부 실패 등으로 판정을 보류함 |

`not_detected`를 수정 완료나 안전 보장으로 표현하지 않습니다.
부분 실패라도 명확한 양쪽 관측은 `persisting`입니다. 실패한 쪽에서 빈 배열이 나왔다고
`new`/`not_detected`로 판단하지 않습니다. 확인할 수 없는 finding 수는 `null`이며 정상적인 `0`과 다릅니다.

`not_comparable_units.identifier_conflict`는 검토 묶음 수입니다. 1:2 충돌이면 비교 불가 1묶음이며,
`base_finding_ids` 1개와 `target_finding_ids` 2개를 모두 보존합니다. 취약점 1개로 표시하면 안 됩니다.
같은 finding이 두 설치에 연결되면 비교 항목은 2개지만 저장 finding 수는 1개입니다.

선택 대상이 바뀌면 이전 요청을 취소하거나 늦게 도착한 응답을 무시해야 합니다.
한 응답의 summary와 items를 함께 교체합니다. `comparison_id`는 방향과 정책·자료 지문을 포함합니다.
`base.snapshot_id`/`target.snapshot_id`는 비교 전용이며 기존 패키지 API의 snapshot과 교환하지 않습니다.

## 대응 규칙

1. 설치는 `(ecosystem, name, lockfile_path)`가 같은 것을 먼저 연결합니다. 버전 변화는 별도로 기록합니다.
2. 버전이 없으면 해당 관측을 보존하고 비교를 보류합니다. 빈 값끼리 정상 연결하지 않습니다.
3. 양쪽 설치 목록이 완전하고 같은 이름의 남은 설치가 각각 하나일 때만 위치 이동을 추정합니다.
4. 취약점은 같은 단일 GHSA → primary 근거가 있는 공유 CVE → 같은 단일 NSWG 수동 레코드 순으로 후보를 만듭니다.
5. 전체 후보 그래프를 먼저 확인합니다. 명확한 1:1만 확정하며 1:N/N:M 충돌은 검토 묶음으로 보존합니다.
6. 서로 다른 GHSA의 공유 CVE는 자동 동일성 근거가 아닙니다. 참조 URL 일치는 검토 후보에만 사용합니다.

공유 CVE가 있어도 primary 근거를 선택할 수 없으면 검토 대상으로 보존합니다.
이 근거 부족을 곧바로 서로 다른 새 항목과 미검출 항목으로 해석하지 않습니다.

설치 버전의 증감은 기존 공용 SemVer 함수를 사용합니다. 빌드 메타데이터만 달라진 버전은
문자열 변경을 유지하면서 방향은 `equivalent`로 표시합니다. 파싱할 수 없는 비어 있지 않은 버전은
설치 대응에 사용할 수 있지만 증감 방향은 `unknown`입니다.

## 출처와 부재 확인

`scan_tool_runs`에서 **현재 attempt**만 사용합니다. 정규화에 기록된 `source_artifacts`의 실행 ID,
artifact ID, SHA-256, attempt와 실제 저장 메타데이터를 대조합니다. 과거 성공 실행을 가져와 현재 실패를 덮지 않습니다.
`roundtrip_verified`, 정규화 fingerprint, 공개된 finding/연결 수와 원본 evidence의 일치도 확인합니다.

출처 연결이 없는 예전 자료는 `legacy_unverified`이며 부재 확인 근거로 쓰지 않습니다.
기존 결과를 자동 수정하거나 재정규화하지 않습니다. 보관 기한으로 원문 파일이 삭제됐어도 저장된 provenance
메타데이터는 비교할 수 있으며, 이 GET은 원문 파일을 다시 읽거나 외부 URL을 방문하지 않습니다.

도구 버전·DB 버전은 실제 실행 행에 기록된 값을 반환합니다. DB 버전을 알 수 없으면 `null`입니다.
`cached` 같은 실행 요약을 DB 버전으로 대체하지 않습니다. OSV 실행 완료 시각을 `queried_at`으로 표시하며
DB 버전과 구분합니다. GitHub 수집·우선순위 단계의 실패만으로 보안 검사 완료를 부정하지 않습니다.

## 오류와 처리 상한

| HTTP | `detail.code` |
| --- | --- |
| 404 | `scan_not_found` |
| 422 | `same_scan`, `different_project`, `comparison_limit_exceeded` |
| 409 | `scan_processing` |
| 503 | `database_unavailable` |
| 500 | `comparison_invariant_failed` |

잘못된 UUID와 필수 query 누락은 기존 FastAPI 422 validation 배열을 유지합니다.
나머지는 `{detail: {code, message, scan_ids, limit}}` 형식입니다.
검사 순서는 입력 검증 → 같은 ID → 존재 여부 → 같은 프로젝트 → 진행 상태 → 크기·자료 검증입니다.

두 검사의 합계로 설치 10,000개, 유효 affected 연결 50,000개, 미연결 finding 10,000개를 허용합니다.
전체 응답을 반환하며 조용히 일부만 자르지 않습니다.

구현에서 **후보 쌍 100,000개 상한**을 추가했습니다. 적은 설치 안에 다수의 같은 식별자가 모이면
입력 행 상한만으로 후보 그래프의 크기를 제한할 수 없기 때문입니다. 초과 시 기존 422 오류를 사용하고
`limit.dimension=candidate_pairs`를 반환합니다. 오류 Schema에 이 dimension을 추가한 것이 상세안 대비 보완 사항입니다.

## 범위와 팀 연결점

이 변경은 공통 조회 분리·순수 비교 모듈·비교 GET·Schema·테스트입니다. 기존 패키지 화면과 AI 설명의
공통 조회 projection을 유지하여 비교 메타데이터 추가만으로 기존 snapshot을 바꾸지 않습니다.
DB 구조 변경은 필요하지 않습니다.

같은 프로젝트로 업로드하는 `POST /scans`의 `project_id` 옵션, 프로젝트별 검사 목록, 비교 화면,
도구/DB 버전 수집 보완은 시연님 담당 연결점입니다. 기존에 서로 다른 프로젝트로 저장된 검사를 자동으로 묶지 않습니다.
이번 구현·검증은 로컬 격리 환경 기준이며 배포 서버에 적용하지 않았습니다.

검증 방법과 결과는 [검증 기록](../verification/scan-compare/README.md)을 참고하세요.
