# D07 저장 경계 보완 계약 v0.3

기준일: 2026-10-18. 이 문서의 D07이 이전 계약의 저장 중단 문구를 대체한다.
D01~D06 계산·표시·입출력은 [contract-v0.2.md](contract-v0.2.md)를 유지한다.
보안 입출력 priority-io-v2와 등급 규칙 priority-v1은 변경하지 않는다.
이번에 추가된 저장 경계 처리 함수의 버전은 priority-stage-v1이다.

## D07 확정 문구

**입력 오류 시 잘못된 우선순위 결과의 저장을 차단한다. 확보한 검사 원문,
독립적으로 검증된 유효한 검사 결과, 도구 상태와 오류 근거는 보존한다.**

차단 단위는 이번 호출의 우선순위 계산 묶음이다. ID 오류나 후보 상태 불일치가 있으면
해당 묶음의 link_results·package_results·priority 집계를 부분 저장하지 않는다.
이는 검사 결과 전체를 폐기하거나 저장을 모두 중단한다는 뜻이 아니다.
유효한 검사 결과란 scanner/normalizer 자체 검증을 통과한 결과이며,
오류가 있는 priority payload에서 임의로 골라낸 부분 계산 결과가 아니다.

## 저장 경계

| 단계 | 저장할 내용 | 실패 시 동작 |
| --- | --- | --- |
| A. 검사 근거 | 확보한 원문/원본 파일, 유효 검사 결과, 도구 상태·오류 근거 | 기존 원본 파일을 유지한다. 새 저장 성공을 주장하지 않고 상위 호출부에 오류를 전달한다 |
| B. 우선순위 입력·계산 | 계산 입력 전체 검증 후 정상 결과만 C로 전달 | A를 유지하고 D에 입력 오류와 원인을 기록한다. 빈 정상 결과·기본 P등급으로 대체하지 않는다 |
| C. 우선순위 게시 | 연결 결과·패키지 집계·성공 상태를 한 트랜잭션으로 반영 | 우선순위 트랜잭션만 롤백하고 A를 유지한다. D에 저장 오류를 기록한다 |
| D. 오류 기록 | 평가 ID, 검사·시도 ID, 단계, 코드, 필드 경로, 메시지, 구성된 입력 | C와 별도 트랜잭션으로 커밋한다. 기록도 실패하면 호출부에 기록 객체와 명시적 예외를 전달한다 |

**A의 커밋을 확인한 뒤 B를 시작한다. A~D를 하나의 외부 트랜잭션으로 감싸지 않는다.**
이미 원본을 artifact 저장소에 보존한 구현은 해당 원본과 해시·위치를 유지하면서 A에서 관련 근거를
별도 커밋할 수 있다. JSON으로 해석되지 않은 검사 출력도 기존 파일·로그로 보존해야 한다.

오류 근거 기록이 실패하는 저장소 장애에서는 영속 보존을 보장할 수 없다.
함수는 저장 성공을 반환하지 않고 `PriorityStagePersistenceError`를 발생시키며,
호출부가 로그·재시도에 사용할 record와 scan_evidence_saved를 제공한다.
이를 정상 완료·탐지 0건으로 처리하지 않는다.

## 구현 API

`worker/app/priority_stage.py`의 `run_priority_stage(...)`는 다음 순서를 구현한다.

```python
from app.priority_stage import run_priority_stage

outcome = run_priority_stage(
    scan_id=scan_id,          # worker가 확인한 검사 UUID
    attempt_id=attempt_id,    # worker가 관리하는 검사 시도 UUID
    raw_results=raw_results,
    valid_results=validated_scan_results,
    tool_status=tool_status,
    build_payload=build_priority_input,
    store=application_store,
)
```

build_priority_input은 커밋된 근거의 복사본을 받아 DB UUID 기반 priority-io-v2 입력을 구성한다.
예상한 입력 구성 오류는 `PriorityInputError(code, field_path, message)`로 전달한다.
입력 구성의 예기치 않은 예외도 빈 배열로 대체하지 않고 실패로 기록한다.
priority payload의 scan_id는 worker가 전달한 scan_id와 일치해야 한다.
패키지·Finding의 실제 DB 검사 소속, 원본 리비전과 작업자 유효성은 저장 어댑터가 확인한다.
같은 검사에 대한 동시 실행·오래된 시도의 덮어쓰기는 실제 worker의 잠금/시도 검증으로 차단한다.

application_store는 `PriorityStageStore` 프로토콜의 다음 세 메서드를 구현해야 한다.

- `save_scan_evidence(record)`: 근거 저장을 별도 커밋한 뒤 반환한다.
- `save_priority_result(record)`: 계산 결과 전체와 성공 기록을 원자적으로 게시한다.
  예외 시 이번 우선순위 쓰기를 모두 롤백한 뒤 예외를 전파한다.
- `save_priority_error(record)`: 오류 기록을 별도 커밋한다. 이전 정상 결과는 이력으로 유지하되
  이번 평가의 current_result_available=false를 반영한다.

각 호출에 독립 evaluation_id를 생성한다. 스캔 재시도와 같은 시도의 재계산도 이력으로 구분한다.
raw_results/valid_results/tool_status와 계산 입력·결과는 복사해 전달하므로
입력 구성 함수나 어댑터의 객체 변경이 호출자 데이터에 전파되지 않는다.
운영 단계 함수에는 allow_test_data 옵션이 없으며 시험용 후보·입력은 기본 계산기에서 거부한다.

**이 모듈은 저장 순서를 실행하는 조정 함수다. 실제 PostgreSQL 어댑터나 worker 연결 구현은 아니다.**
제출 기준 팀 브랜치에는 실행 worker와 저장기가 있으며 이번 변경에서 해당 호출부를 교체하지 않았다.
팀 DB에 연결할 때 세 메서드의 독립 커밋·원자성·시도 검증을 구현하고 실제 DB에서 검증해야 한다.

## 결과와 오류 상태

| 필드 | 의미 |
| --- | --- |
| stage_version | priority-stage-v1 |
| evaluation_id / scan_id / attempt_id | 평가·검사·검사 시도 식별자 |
| started_at | 평가 시작 UTC 시각 |
| schema_version / priority_rule_version | 시도한 계약·규칙. 성공 여부는 status와 함께 판단 |
| status | completed / invalid_input / failed |
| current_result_available | 이번 평가의 유효한 결과 사용 가능 여부 |
| result | 성공 시 계산기 전체 결과, 오류 시 null |
| error | 오류 단계·code·field_path·message·exception_type, 성공 시 null |
| attempted_payload | 오류 때 이미 구성된 입력. 구성 전 실패는 null |
| scan_evidence_saved | 호출 반환 시 근거 커밋 확인 여부 |
| priority_saved / error_saved | 이번 호출에서 확인한 저장 결과 |

입력 검증 오류는 기존 PriorityInputError 코드와 필드 경로를 유지한다.
추가 코드는 SCAN_SCOPE_MISMATCH, PRIORITY_INPUT_BUILD_FAILED,
PRIORITY_CALCULATION_FAILED, PRIORITY_WRITE_FAILED다.
오류의 stage는 input_build / calculation / priority_storage로 구분한다.
잘못된 결과의 일부나 임의 P등급은 반환·게시하지 않는다.

이 단계의 completed는 우선순위 평가·저장 성공을 뜻하며 **보안 검사 전체 성공과 다르다**.
보안 검사 상태는 result.security_status와 도구 근거로 판단한다.
completed/partial/failed, no_findings/unavailable, incomplete 및 UNKNOWN 의미는 기존 계약을 유지한다.
예를 들어 보안 검사 failed의 빈 유효 입력을 평가하면 단계는 completed여도
result.security_status=failed, 패키지 상태는 unavailable이다. 탐지 0건으로 표시하지 않는다.

## 재계산·화면·AI

- 입력 오류가 발생해도 예전 정상 priority를 삭제하거나 null/기본 등급으로 덮어쓰지 않는다.
- 예전 결과는 이전 evaluation_id/attempt_id에 속한 이력이다. 새 평가가 실패했으면
  current_result_available=false로 표시하고 예전 값을 이번 결과처럼 보여주지 않는다.
- 계산 입력 오류는 ‘우선순위 계산 입력 확인 필요’, 계산·저장 실패는 ‘우선순위 확인 불가’로 안내한다.
  보안 검사 원문·유효 Finding·도구 실패 상태와 오류 상세는 계속 확인할 수 있어야 한다.
- severity_unknown은 유효한 UNKNOWN 계산 결과다. 입력 오류 또는 미실행 not_computed와 섞지 않는다.
- 우선순위 실패가 검사 전체 status를 임의로 바꾸거나 유효한 Findings를 숨기게 하지 않는다.
- AI는 저장된 유효 결과와 실패 근거를 설명한다. 실패한 평가를 정상 0건으로 설명하거나
  예전 priority를 최신으로 간주해 설명하지 않는다.

## 검증 범위

`test_priority_stage.py`는 임시 파일 SQLite 어댑터에서 실제 커밋·롤백을 실행한다.
별도 연결로 저장 결과를 다시 읽어 원문·유효 결과·오류의 영속 보존을 확인한다.
중간 우선순위 쓰기 실패, 입력 오류, 입력 구성 실패, 시험 입력, 다른 검사 ID,
과거 정상 결과 이력, 정상 재시도, 근거·오류 저장소 장애를 검증한다.
이는 저장 경계 프로토콜의 실행 검증이며 팀 PostgreSQL 저장기·운영 worker·API/UI 통합 통과를 뜻하지 않는다.


## PostgreSQL 구현 보완 — 2026-10-26

`PostgresPriorityStore.save_priority_error`는 오류 상태·구조화된 오류 정보와
`attempted_payload`를 같은 오류 기록 트랜잭션에 저장한다. 입력 구성 전에 실패하면
`attempted_payload`는 SQL NULL이고, 구성 후 검증·게시 실패 시에는 계산 전에 복사한
입력을 JSONB로 보존한다. 이 필드는 오류 진단 자료이며 검증된 계산 결과가 아니다.
기존 `evidence_snapshot`과 검사 원문은 별도로 유지한다.

DB의 `error.message`에는 예외 원문 대신 단계별 고정 설명을 저장하고,
`error.message_policy=safe-stage-summary-v1`로 표시한다. DB 접속정보 등이 포함될 수 있는
임의 예외 문자열을 저장하지 않는다. 구체적인 오류 구분은 기존 code·field_path·exception_type을
함께 확인한다. 조정 함수가 반환하는 메모리상의 record와 DB의 정제된 메시지는 다를 수 있다.
입력 전체는 내부 진단 테이블에 저장하며 공개 API 응답에 추가하지 않는다.

적용 전에 `db/oss_closeup_v2_2_priority.sql`을 실행하여 `attempted_payload JSONB` 열을
추가해야 한다. 기존 테이블·평가 이력은 유지되며 반복 실행할 수 있다.
기존 이력에 당시 입력을 소급 생성하지 않는다. 스키마 반영 후 수정된 worker를 배포한다.
이는 로컬 구현 보완이며 원격 저장소·운영 DB 반영 또는 팀의 별도 승인 완료를 뜻하지 않는다.
