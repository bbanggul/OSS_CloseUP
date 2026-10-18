# D01~D07 구현·테스트·연동 안내

2026-10-18 팀원 검토 의견을 코드·테스트·계약에 반영했다.
현재 D07 저장 계약은 [contract-v0.3.md](contract-v0.3.md), D01~D06 계약은 [contract-v0.2.md](contract-v0.2.md)이다. 팀 연결 순서는 [INTEGRATION.md](INTEGRATION.md)를 따른다.

## 적용 내용

| 항목 | 구현 |
| --- | --- |
| D01 | 직접성·후보 부재로 등급을 낮추지 않음. 후보는 같은 알려진 등급 내 정렬에만 사용. UNKNOWN 별도 상태 |
| D02 | MODERATE 원문·출처 보존, 최고 알려진 충돌 등급 유지. INFO 등은 검토 표시 및 계산 입력 거부 |
| D03 | evaluate_activity: 커밋·릴리즈·Archived 독립 표시. 자동 Active/Low 분류 없음. UTC 경과일, 미래·부분 실패 표시 |
| D04 | 수정 정보 4상태 보존, 비어 있는 후보·출처 누락 거부, 시험 후보 기본 차단, 범위·복수·수동 검토 근거 보존 |
| D05 | evaluate_license: 내부 일반/확인 필요 표시. OR/AND 구조·서로 다른 이유 유지, 대안 자동 선택 없음 |
| D06 | 고유 Finding·설치 패키지·연결 건수 분리. 같은 패키지·대표 등급의 연결과 후보를 함께 반환 |
| D07 | 검사 원문·유효 결과 선저장 → 우선순위 계산 묶음 검증·원자적 저장 → 실패 시 우선순위만 차단하고 오류 별도 기록 |

입출력은 **priority-io-v2**, 보안 등급 규칙은 변경 없이 **priority-v1**이다.
새 축의 버전은 **activity-facts-v1 / license-review-v1**, 저장 경계 처리 버전은 **priority-stage-v1**이다.

## 호출과 예시

worker를 Python 모듈 경로에 넣어 호출한다. 추가 라이브러리가 필요하지 않다.

```python
from app.priority import calculate_priorities, PriorityInputError
from app.review_policy import evaluate_activity, evaluate_license

security = calculate_priorities(payload)  # 실제 DB UUID와 정규화된 입력
license_review = evaluate_license("MIT OR GPL-3.0-only", project_license="MIT")
activity = evaluate_activity({
    "github_status": "ok", "archived": False,
    "last_commit_at": "2026-01-27T00:00:00Z", "last_release_at": None,
}, as_of="2026-09-27T00:00:00Z")
```

전체 보안 예시: [입력](example-input.json), [기대 출력](example-expected.json).
예시의 시험 후보는 실제 수정 버전이 아니다. 예시를 실행할 때만
`calculate_priorities(sample, allow_test_data=True)`를 사용한다.
기본 호출은 시험용 입력을 거부하며 시험 실행 결과에도 `test_only=true`가 남는다.

화면 연결 시 패키지 대표 행은 `package_results[].representative_links`의 후보를 사용하고,
상단 UNKNOWN 고유 건수는 `summary.unknown_finding_count`를 사용한다.
AI는 이 결과와 확인 이유를 설명하며 새 등급을 만들지 않는다.

## 검증 실행

저장소 루트에서 실행한다.

```sh
python3 scripts/validate_priority.py --include-regression
```

기본 출력은 `docs/priority-engine/validation-v0.3/`다.
[결과 JSON](validation-v0.3/results.json)에 실제 실행 수·통과 ID·오류·소스 해시를 기록한다.
[테스트 로그](validation-v0.3/unittest.txt)와 [실제 예시 출력](validation-v0.3/example-actual.json)도 생성한다.
D01~D06의 기존 검증은 113개 테스트이며, D07 저장 경계 테스트 14개를 추가했다.
최신 전체 실행의 통과 여부·개수는 결과 JSON과 로그에 기록한다.
구성은 승인 사례 29, 정규화 24, 기존 priority 34, 후속 priority 6, 저장 경계 14, 표시 정책 10, 검사 실행 10이다.
심각도·직접성·수정 상태 조합과 표현식·날짜 변형은 메서드 내부의 하위 검사이며 개수를 중복 합산하지 않는다.
`--include-regression`을 빼면 priority·저장 경계·표시 정책·29개 사례 테스트를 실행한다.

[accepted-cases.json](accepted-cases.json)은 기존 29개 ID와 원본 입력·제안 기대값을 보존한 검토 기준이다.
`test_accepted_cases.py`가 이를 모듈 수준에서 검증한다. reported만 있던 후보는 시험 표시를 붙인
합성 후보로, 추상적인 활동 기간은 고정 시각의 합성 날짜로 구체화한다.
X03~X05는 기존 상태 동작의 회귀 검사다. D07 저장 보존은 `test_priority_stage.py`에서 별도 검증한다.
임시 파일 SQLite에서 실제 커밋·롤백을 실행하고 별도 연결로 근거와 오류의 보존을 확인한다.
실제 PostgreSQL 어댑터·worker·API/UI 통합을 검증한 것은 아니다.
실측 NSWG-ECO-516 원문은 별도 fixture로 보존하고 수동 경고·범위 후보를 재검증한다.

## 파일

- `worker/app/priority.py`: 검증·등급·대표값·정렬·원문 전달·집계.
- `worker/app/priority_stage.py`: 검사 근거 선저장, 계산·저장 오류 격리, 독립 오류 기록 처리.
- `worker/tests/test_priority_stage.py`: D07 저장 경계·실제 테스트 DB 트랜잭션 검증.
- `worker/app/normalizer.py`: 원문·출처·충돌·지원 밖 심각도 검토 표시.
- `worker/app/review_policy.py`: 라이선스와 활동 정보의 독립 순수 함수.
- `worker/tests/test_priority.py`, `test_priority_review.py`: 보안 계약과 후속 경계 조건.
- `worker/tests/test_review_policy.py`, `test_accepted_cases.py`: 표시 정책과 승인 사례.
- `worker/tests/test_normalizer.py`, `test_scanner.py`: 기존 정규화·검사 실행 회귀.

## 연결 상태

로컬 계산·표시 모듈과 D07 저장 경계 조정 함수, 테스트·계약을 구현했다.
실제 PostgreSQL 저장 어댑터, 검사 worker 호출 연결, API·화면·AI 보고서 연결 및 원격 GitHub 게시까지
완료된 것은 아니다. `PriorityStageStore`의 세 메서드를 팀 저장기에 구현해 연결해야 한다.
검사 근거 저장과 우선순위 저장을 하나의 외부 트랜잭션으로 묶지 않는다.
정규화 ID→DB UUID, 검사 소속 검증, 지원 밖 입력의 검토 분리, 시험 결과 저장 차단은
연결 어댑터에서 지켜야 한다. 저장된 기존 priority만으로 새 원문·대표 연결 필드를 복원할 수는 없다.

제출 기준은 bbanggul/OSS_CloseUP의 fix/week3-results, 63de27fbc0383f590e0628e1c3aa8735c163fd95다.
원본 저장소의 기존 worker·DB 저장기·화면은 유지하고 계산·표시 정책·저장 경계 모듈을 추가했다.
검증 결과의 source_base_commit은 제출 전 기준 커밋이며 실제 검증 파일은 source_sha256으로 식별한다.
