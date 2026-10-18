# 우선순위 모듈 연동 전달 자료

대상 저장소: **bbanggul/OSS_CloseUP**.
PR 기준 브랜치: **fix/week3-results**, 확인한 기준 커밋은
`63de27fbc0383f590e0628e1c3aa8735c163fd95`다.
제출 브랜치: `JenmrR/OSS_CloseUP:codex/priority-d01-d07`.

## 구현·미구현 구분

| 구분 | 상태 |
| --- | --- |
| D01~D06 계산·정규화·표시 정책 | 구현 및 단위 테스트 완료 |
| D07 검사 근거 선저장·우선순위 오류 격리 순서 | run_priority_stage와 저장 인터페이스 구현 |
| D07 저장 경계 검증 | 임시 SQLite에서 실제 커밋·롤백·별도 연결 재조회 테스트 |
| 팀 PostgreSQL 우선순위 저장 어댑터 | **미구현** — 세 저장 메서드 구현 및 실제 DB 검증 필요 |
| 실행 worker에서 모듈 호출 | **미연결** — 이 PR은 기존 worker 호출부를 변경하지 않음 |
| 실제 API·화면·AI 연동 검증 | 미실행. 기존 소비 코드 유지 |

현재 DB에는 finding_packages.priority와 priority_rule_version 컬럼이 있으나,
이번 모듈을 추가하는 것만으로 DB에 우선순위가 저장되지는 않는다.
계산 함수는 DB·네트워크·AI를 호출하지 않는다. 모듈 결과를 저장한 뒤 화면과 AI가 읽도록 연결해야 한다.

## 버전

- 입력·출력: `priority-io-v2`
- 보안 계산: `priority-v1` — CRITICAL=P0, HIGH=P1, MEDIUM=P2, LOW=P3, UNKNOWN=null
- 라이선스 확인 표시: `license-review-v1`
- 활동 정보 표시: `activity-facts-v1`
- 저장 단계 처리: `priority-stage-v1`
- 계약: [D01~D06 v0.2](contract-v0.2.md), [D07 v0.3](contract-v0.3.md)

priority-io-v1 입력을 그대로 전달하면 거부한다. 특히 후보 원문과 source_tool, 시험용 표시,
정규화의 priority_input_eligible·severity_observations를 새 계약에 맞춰 전달해야 한다.

## 호출 방법과 재현

저장소 루트에서 모듈 검증을 실행한다. Python 표준 라이브러리만 필요하다.

```sh
python3 scripts/validate_priority.py --include-regression
```

이 명령은 모듈·29개 사례·정규화·검사 실행 테스트를 실행하고
`docs/priority-engine/validation-v0.3/`에 결과·로그·예시 실제 출력·소스 해시를 쓴다.
프로젝트의 별도 pytest 기반 worker 테스트를 대체하지는 않는다.

worker 패키지 경로가 설정된 환경에서 호출한다(저장소 루트에서는 `PYTHONPATH=worker`).

```python
from app.priority import calculate_priorities, PriorityInputError
from app.review_policy import evaluate_activity, evaluate_license

# payload는 실제 DB UUID와 유효한 검사 결과에서 구성한 priority-io-v2 객체다.
result = calculate_priorities(payload)
license_review = evaluate_license("MIT OR GPL-3.0-only", project_license="MIT")
activity = evaluate_activity({
    "github_status": "ok", "archived": False,
    "last_commit_at": "2026-01-27T00:00:00Z", "last_release_at": None,
}, as_of="2026-09-27T00:00:00Z")
```

라이선스 예시는 확인 필요/alternative_selection_review를 반환하고 대안을 자동 선택하지 않는다.
활동 예시는 활동 정보/Facts only, 커밋 경과일 243, 릴리즈 정보 없음이다.

전체 보안 JSON은 [example-input.json](example-input.json)과
[example-expected.json](example-expected.json)에 있다. HIGH 후보 없음 + MEDIUM 후보 있음 + UNKNOWN의
예시이며 대표값은 P1, 대표 후보 여부는 false, 고유 UNKNOWN 건수는 1이다.

이 JSON은 `test_only=true`인 시험 자료다. 다음 호출은 재현 테스트에서만 사용한다.

```python
import json
from pathlib import Path
from app.priority import calculate_priorities

sample = json.loads(Path("docs/priority-engine/example-input.json").read_text())
actual = calculate_priorities(sample, allow_test_data=True)
```

시험 결과와 예시의 1.1.0은 운영 DB·실제 수정 버전에 사용하지 않는다.
운영 호출과 run_priority_stage는 시험 입력을 기본 거부한다.

## DB 입력 구성

1. 동일 검사에서 type=vulnerability Finding, root를 제외한 설치 패키지, role=affected 연결을 읽는다.
2. 정규화 finding_*/pkg_*를 그대로 쓰지 말고 저장기가 매핑한 실제 DB UUID를 사용한다.
3. severity는 정규화된 값을 쓰되 원문 관측과 적격성을 보존한다. INFO 등은 검토 대상으로 유지하고
   UNKNOWN으로 숨겨 자동 계산하지 않는다. 새 정규화 결과의 적격성은 Finding의
   `evidence.normalized.priority_input_eligible`, 관측값은 `evidence.normalized.severity_observations`에서 얻을 수 있다.
4. 수정 후보 원문과 출처, 수정 정보 4상태 및 기존 수동 경고를 전달한다. 후보 미보고를 임의 후보로 채우지 않는다.
5. security_status는 전체 scan_runs.status를 복사하지 않고 Trivy/OSV의 출력 해석·정규화 성공 여부로 정한다.
   2개 성공=completed, 1개=partial, 0개=failed. 도구 프로세스 종료 성공만으로 판단하지 않는다.

normalizer는 D02 메타데이터를 추가한다. 기존 finding_storage는 정규화 문서 fingerprint를 비교하므로
예전 결과가 저장된 검사를 새 코드로 무조건 재저장하면 변경된 fingerprint로 거부될 수 있다.
기존 원문을 보존하고 새 검사 또는 명시적인 이관 경로를 사용한다. 이 PR에 데이터 마이그레이션은 없다.

## 저장과 D07

`run_priority_stage`는 실제 저장 드라이버를 주입받는다.

```python
from app.priority_stage import run_priority_stage

outcome = run_priority_stage(
    scan_id=scan_id, attempt_id=attempt_id,
    raw_results=raw_results, valid_results=validated_scan_results,
    tool_status=tool_status, build_payload=build_priority_input,
    store=application_store,
)
```

application_store에 다음 세 메서드를 구현한다.

1. save_scan_evidence: 검사 원문·유효 결과·도구 오류 근거를 먼저 별도 커밋한다.
2. save_priority_result: 모든 연결 우선순위·대표 집계·성공 상태를 한 트랜잭션으로 반영한다.
3. save_priority_error: 입력·계산·저장 오류를 별도 커밋하고 이번 평가를 사용 불가로 표시한다.

저장 시 link_results의 priority/rule_version은 해당 finding_packages 행의
priority/priority_rule_version에 대응한다. package_results와 summary의 저장·API 노출 위치는
어댑터에서 정해야 하며 packages.priority 컬럼을 가정하지 않는다.
source evidence에 계산 메타데이터를 병합한다면 기존 finding_storage의 전체 evidence round-trip 비교도
원본과 추가 메타데이터를 구분하도록 함께 조정해야 한다.

입력 오류가 있어도 원문·유효 Finding은 유지한다. 잘못된 우선순위 계산 묶음만 저장하지 않는다.
이전 정상 우선순위는 이력으로 남기되 최신 평가가 실패하면 current_result_available=false를 노출한다.
UI가 과거 priority 컬럼 값만 읽으면 최신 실패를 놓칠 수 있으므로 평가 상태·시도 ID를 함께 읽어야 한다.
상세 코드·필드 경로·오류 근거는 error에 남는다. 모든 단계를 하나의 외부 트랜잭션으로 묶지 않는다.

## 화면·AI에 전달할 값

- 패키지 행의 이름·priority·수정 후보는 같은 package_id와 대표 등급의 representative_links에서 가져온다.
- 상단 고유 UNKNOWN 수는 summary.unknown_finding_count를 사용한다. 패키지별 건수를 더하지 않는다.
- severity_unknown, no_findings, unavailable, 미실행 not_computed와 계산 입력 실패를 구분한다.
- 정상 0건은 completed와 전체 고유 Finding 0건을 함께 확인한다. 검토 대상이 격리되어 비어 있는 입력은 0건의 증거가 아니다.
- AI는 저장된 결과와 확인 이유를 설명한다. 새 등급·단일 수정 권장 버전·통합 위험 점수를 생성하지 않는다.

기준 브랜치의 AI 코드는 DB priority를 소비하도록 되어 있다. 이번 PR은 계산값을 실제 DB에 쓰는 연결까지
완료한 PR이 아니므로, 병합만으로 화면·AI에 새 우선순위가 자동 표시된다고 가정하지 않는다.
