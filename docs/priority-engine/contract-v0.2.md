# D01~D06 승인 반영 계약 v0.2

기준일: 2026-10-18. 사용자에게 전달된 팀원 검토 의견을 반영했다.
현재 호출 계약은 이 문서이며 `contract-v0.1.md`는 이전 설계 기록이다.
구현 위치는 `worker/app/priority.py`, `normalizer.py`, `review_policy.py`다.
모두 DB·네트워크·AI 호출 없이 동작하며 DB 저장·API·화면 연결 구현은 별도다.

## 버전과 호출

| 구분 | 현재 값 | 의미 |
| --- | --- | --- |
| 보안 입출력 | `priority-io-v2` | 후보 검증 강화, 원문·대표 연결·집계·시험 표시 추가 |
| 보안 계산 규칙 | `priority-v1` | 등급 매핑과 정렬 규칙은 기존과 동일하므로 유지 |
| 라이선스 표시 | `license-review-v1` | D05 내부 확인 정책 |
| 활동 정보 표시 | `activity-facts-v1` | D03 날짜 기반 자동 위험 분류 없음 |
| 정규화 | `normalization-v1` | 기존 필드 유지, 지원 여부와 계산 적격 표시 추가 |

```python
from app.priority import calculate_priorities
from app.review_policy import evaluate_activity, evaluate_license

security = calculate_priorities(payload)
license_review = evaluate_license("MIT OR GPL-3.0-only", project_license="MIT")
activity = evaluate_activity({
    "github_status": "ok", "archived": False,
    "last_commit_at": "2026-01-27T00:00:00Z", "last_release_at": None,
}, as_of="2026-09-27T00:00:00Z")
# activity: Facts only / 활동 정보, commit_elapsed_days=243,
# release_display=정보 없음. license_review: alternative_selection_review.
```

## 보안 입력 계약

`calculate_priorities(payload, *, allow_test_data=False)`는 새 객체를 반환한다.
입력과 반환의 중첩 원문 객체는 독립 복사되어 반환값을 편집해도 입력이 변하지 않는다.

| 필드 | 형식 |
| --- | --- |
| `schema_version` | `priority-io-v2` 필수. v1 자동 변환 없음 |
| `scan_id` | UUID 문자열 |
| `security_status` | completed / partial / failed |
| `tool_status` | trivy·osv 각각 비어 있지 않은 status 문자열을 가진 객체 |
| `test_only` | 선택 boolean, 기본 false. 합성 자료는 true 필수 |
| `packages` | package_id(UUID), name(문자열), installed_version(문자열/null), relationship(direct/indirect/unknown) |
| `findings` | finding_id(UUID), severity(CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN) |
| `finding_packages` | finding_id, package_id, fix_information, fixed_version_candidates |

어댑터는 보안 Finding과 affected 연결만 전달한다. 정규화 ID를 실제 DB UUID로 매핑하고
모든 행의 검사 소속을 확인한다. 같은 UUID의 다른 문자열 표기는 동일한 ID로 검증한다.
이름·버전이 같아도 서로 다른 package_id는 별도 설치 인스턴스다.

## D01 — 등급과 표시 순서

CRITICAL=P0, HIGH=P1, MEDIUM=P2, LOW=P3. UNKNOWN은 null/severity_unknown.
severity와 priority는 별도 필드다. 직접·간접·관계 불명은 등급·동률 정렬에 영향을 주지 않는다.
수정 후보는 같은 알려진 등급 안에서만 먼저 정렬하는 데 사용한다.
UNKNOWN은 후보 유무를 정렬에 사용하지 않고 별도 ‘심각도 확인 필요’ 구역에 표시한다.
목록 뒤에 있다는 이유로 낮은 위험으로 설명하지 않는다.

## D02 — 정규화와 검토 대상

- MODERATE→MEDIUM. 원문 `severity_observations[].raw`, source_tool, source와 evidence를 보존한다.
- 누락/null/빈 라벨은 UNKNOWN. CVSS 벡터를 계산해 등급을 추정하지 않는다.
- 확인된 식별자 연결의 알려진 등급이 충돌하면 최고 등급을 대표값으로 삼고
  `severity_conflict=true`와 모든 관측값을 남긴다. UNKNOWN+HIGH는 알려진 등급 충돌이 아니다.
- 등급이 같다는 이유만으로 다른 취약점을 병합하지 않는다. 기존 식별자 병합 제한을 유지한다.
- 정규화 관측에 `normalization_status=supported/missing/unsupported`를 추가한다.
  INFO 등 지원 밖 라벨은 원문을 보존하고 `priority_input_eligible=false`,
  `review_status=needs_review`, `review_reasons`에 `unsupported_severity_label`을 남긴다.
  정규화의 UNKNOWN은 표시용 자리값이며 자동 계산·이관 허가가 아니다.
- 어댑터는 해당 Finding을 검토 대상으로 분리하고 적격성·관측값을 누락하지 않는다.
  계산기는 false 적격성 또는 지원 밖 원문 관측을 받으면 `SEVERITY_REVIEW_REQUIRED`를 발생시킨다.
  원래 severity=INFO/MODERATE 자체도 계약 밖이므로 `INVALID_VALUE`다.
  과거 DB에서 INFO를 이미 UNKNOWN으로 바꿨다면 원시 근거를 다시 확인해야 한다.
  어댑터가 검토 대상을 분리했다면 그 건수와 원문을 별도로 유지하고, 미검토 항목이 남아 있는 검사를
  적격 입력 배열이 비었다는 이유만으로 전체 ‘탐지 0건’으로 표시하지 않는다.

## D03 — 활동 정보

`evaluate_activity(facts, *, as_of)`는 커밋·릴리즈·Archived를 별도로 반환한다.
날짜로 Active/Low를 자동 분류하지 않으며 `automatic_risk_classification=false`다.

입력 facts는 github_status, archived(bool/null), last_commit_at, last_release_at,
선택 deprecated, field_status, field_errors를 가진다. 원본 전체는 반환 evidence에 보존한다.
github_status=ok면 기본적으로 조회 성공, 그 밖은 확인 불가다.
field_status는 archived/last_commit_at/last_release_at별 ok/failed/unknown을 지정할 수 있다.
명시적 필드 상태가 우선하므로 부분 조회의 성공한 필드를 유지할 수 있다.
오류 근거는 같은 키의 field_errors에서 해당 *_error 및 evidence로 보존한다.

| Archived 확인 결과 | maintenance_status | display_label |
| --- | --- | --- |
| 성공 + true | Archived | Archived |
| 성공 + false | Facts only | 활동 정보 |
| 실패·미확인·boolean 이외 | Unknown | 확인 불가 |

각 날짜는 `last_*_at` 원문, `commit/release_status`, `*_display`, `*_elapsed_days`로 반환한다.
성공 조회의 null은 missing/정보 없음, 실패는 unavailable/확인 불가다.
날짜가 없다는 이유로 릴리즈 없음·활동 중단을 단정하지 않는다.
as_of는 시간대가 있는 고정 ISO 시각 필수이며 UTC 경과 초를 86400으로 나누어 내림한다.
시간대 없는 관측 시각·파싱 실패는 invalid/입력 이상, 미래는 future/입력 이상이며 경과일은 null이다.
한 날짜가 오래됐거나 최근이라는 사실이 다른 날짜를 덮어쓰지 않는다. deprecated도 독립 근거다.

## D04 — 수정 정보

| fix_information | 의미 |
| --- | --- |
| candidates_available | 실제 출처에서 보고한 비어 있지 않은 후보 원문이 존재 |
| not_reported | 성공한 유효 결과에 후보가 보고되지 않음 |
| unknown | 출처·조회 상태 확인 불가 |
| failed | 수정 정보 조회 실패의 명시적 근거 있음 |

어댑터가 출처·조회 근거로 상태를 정한다. 후보가 있는 상태와 배열의 비어 있음이 충돌하면 거부한다.
후보 객체는 비어 있지 않은 value 또는 raw 문자열 및 비어 있지 않은 source_tool이 필수다.
advisory_id, kind, range와 그 밖의 원문 필드는 존재하는 대로 보존하고 출처·식별자를 만들지 않는다.
source_tool은 출처 이름이며 임의 문자열이 진짜 출처인지 검증하는 책임은 어댑터에 있다.
failed 근거는 연결 evidence에 전달해 link_evidence로 보존한다.
유효한 다른 도구의 후보를 한 도구의 실패로 지우지 않는다.
후보 없는 세 상태끼리는 추가 정렬 가중치가 없다.

fixed_version=null이어도 복수·범위형 후보는 후보 있음이다. 후보를 단일 버전으로 선택하거나
recommended_fixed_version·업데이트 명령을 만들지 않는다. 후보 있음은 호환성 확인을 뜻하지 않는다.
Finding의 review_status/review_reasons/manual_review_required와 evidence를 finding_context로 복사한다.
연결의 evidence는 link_evidence로 유지한다. NSWG-ECO-516 수동 검토 경고를 제거하지 않는다.

시험 자료는 payload.test_only=true이며 시험 후보에도 test_only=true를 붙인다.
기본 호출은 시험 payload/후보를 `TEST_DATA_NOT_ALLOWED`로 거부한다.
오직 테스트에서 allow_test_data=True와 payload.test_only=true를 함께 지정할 수 있다.
이 경우 결과에도 test_only=true가 남는다. 저장·API 어댑터는 이를 운영 결과로 저장하거나
실제 수정 버전으로 노출해서는 안 된다. 마커가 제거된 후보의 진위를 계산기가 추측하지는 못한다.
reported만 있고 원문 후보가 없는 입력은 시험의 1.1.0으로 보충하지 않는다.

## D05 — 라이선스 내부 확인 표시

`evaluate_license(raw_license, *, project_license=None)`는 원문과 프로젝트 라이선스를 유지한다.
MIT/Apache-2.0/BSD-3-Clause/ISC 단일 식별자는 일반/listed_general_license다.
일반은 의무 없음·법적 적합성을 의미하지 않으며 적용 조건 확인 문구를 반환한다.
GPL/AGPL/LGPL 계열은 copyleft_review, 누락은 license_missing,
표 밖 식별자는 license_not_in_policy로 확인 필요 표시다. only/or-later 및 옛 표기를 고치지 않는다.

단순 `식별자 OR 식별자` 또는 `식별자 AND 식별자`만 구조를 반환한다.
OR의 reason_code는 alternative_selection_review(실제 적용 대안 선택 확인),
AND는 combined_terms_review(각 조건 함께 적용 여부 확인)다.
expression.operator/operands와 원문을 함께 보존하며 automatic_selection=null이다.
복합·괄호·WITH·잘못된 표현식은 expression_unparsed와 원문을 유지한다.
일반 목적 SPDX 판정기나 법률 판정이 아니다. 보안 priority에 영향을 주지 않는다.

## D06 — 결과, 집계와 화면의 대상 일치

최상위 결과는 schema_version, scan_id, priority_rule_version, security_status, test_only,
link_results, package_results, unmapped_finding_ids, summary를 가진다.

각 link_results는 finding_id/package_id, package_name/installed_version, priority/priority_status,
has_fix_candidate, priority_rule_version, fix_information, fixed_version_candidates,
finding_context, link_evidence를 가진다. **패키지명·priority·수정 후보는 반드시 이 동일 연결 행의 값으로 표시한다.**
Finding 하나가 여러 설치에 연결되어도 다른 설치의 후보를 끌어오지 않는다.

각 package_results는 package_id/package_name/installed_version, priority/priority_status,
representative_finding_ids, has_fix_candidate_at_priority, unknown_finding_count, incomplete,
representative_links를 가진다. 대표값은 가장 긴급한 알려진 P값이며 동률 대표 ID 전부를 보존한다.
**패키지 대표 행의 후보는 같은 package_id·같은 대표 priority인 representative_links에서만 표시한다.**
낮은 등급 후보를 대표 후보로 섞지 않는다. 여러 대표 연결의 후보는 finding_id별로 구분한다.
전체 상세에서는 link_results의 다른 등급 후보도 그 등급·Finding과 함께 표시할 수 있다.

| summary 필드 | 단위·포함 범위 |
| --- | --- |
| finding_count | 고유 입력 Finding, 미연결 포함 |
| unknown_finding_count | 고유 UNKNOWN Finding, 미연결 포함 |
| package_count | 검사 입력의 설치 패키지 수 |
| affected_package_count | 하나 이상 Finding 연결이 있는 설치 패키지 수 |
| unknown_package_count | UNKNOWN 연결이 하나 이상 있는 설치 패키지 수 |
| link_count | Finding–패키지 연결 행 수 |

상단 UNKNOWN에는 summary.unknown_finding_count를 사용한다. 패키지별 UNKNOWN 합을 사용하지 않는다.
미연결 Finding은 unmapped_finding_ids로 보존하고 가짜 연결을 만들지 않는다.
알려진 값과 UNKNOWN 혼재 시 알려진 대표값과 패키지별 UNKNOWN 수를 함께 유지한다.
모두 UNKNOWN이면 대표 ID와 representative_links는 빈 배열, 대표 후보 여부는 false다.

정렬은 알려진 등급→UNKNOWN→no_findings→unavailable이다. 상태 구역은 화면에서 분리한다.
알려진 연결은 등급→후보 있음 우선→패키지명→버전→finding_id→package_id,
패키지는 등급→대표 등급 후보 있음 우선→패키지명→버전→package_id다.
UNKNOWN은 후보 여부를 제외한다. 문자열은 대소문자 구별 사전순, null 버전은 빈 문자열 키이며 semver 순위가 아니다.

## 상태와 이번 범위 밖의 저장 연결

기존 completed/partial/failed 계산 의미는 유지한다. completed의 연결 0건은 no_findings,
partial/failed의 연결 0건은 unavailable이며 partial/failed는 incomplete=true다.
알려진 Finding이 있으면 partial에서도 해당 P등급을 유지한다. failed인데 Finding이 있으면 입력 오류다.
queued/running은 호출부의 not_computed이며 severity_unknown과 구분한다.
검사 전체 0건은 completed 및 summary.finding_count=0일 때만 표시한다.
security_status와 tool_status의 의미 일치는 어댑터가 확인한다.

오류는 PriorityInputError.code/field_path로 전달하고 계산 부분 결과는 반환하지 않는다.
기존 오류 코드에 EMPTY_FIX_CANDIDATE, TEST_DATA_NOT_ALLOWED, SEVERITY_REVIEW_REQUIRED를 추가했다.
이 규칙은 **잘못된 우선순위 결과 저장을 차단**하기 위한 것으로, 검사 원문·유효한 검사 결과·오류 근거를
폐기하라는 뜻이 아니다. D07의 상세 저장 경계와 DB 트랜잭션 구현은 이번 D01~D06 작업에 포함하지 않는다.

DB·API·화면은 규칙 버전과 상태를 포함해 결과를 그대로 반영하고 AI는 결과를 설명한다.
AI가 등급·UNKNOWN·원문·수동 확인 경고를 수정하거나 축들을 합산해 새 점수를 만들지 않는다.

## v1에서 연결할 때

1. 입력 schema_version을 v2로 바꾸고 후보 원문·출처와 시험 표시를 확인한다.
2. 정규화의 priority_input_eligible 및 severity_observations를 보존하고 지원 밖 입력을 검토 대상으로 분리한다.
3. 반환의 summary와 representative_links를 사용해 집계·표시 대상을 맞춘다.
4. 과거 priority-v1 보안 등급을 일괄 변경할 필요는 없다. 새 메타데이터·검토 표시는 원문에서 다시 계산한다.
5. 기존 INFO를 자동 이관하지 않는다. 저장 코드·마이그레이션·실제 화면 연결은 별도 통합 검증한다.

전체 보안 예시는 example-input.json/example-expected.json이다. 둘 다 명시적 시험 자료이며
실제 검사·DB 저장 증거가 아니다. 29개 원본 ID의 의미는 accepted-cases.json과 해당 테스트에서 추적한다.
