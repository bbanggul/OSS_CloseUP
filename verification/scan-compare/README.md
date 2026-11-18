# 검사 비교 구현 검증

검증일: 2026-11-09. 기준 코드: `feat/design-refresh`의 `dec0417`.
별도 복제본·`codex/scan-comparison-api` 브랜치에서 구현했으며 원래 검증 자료와 배포 서버는 변경하지 않았습니다.

## 최종 결과

| 검사 | 결과 |
| --- | --- |
| 백엔드 | 263 통과, Python 하위 검증 8 통과 |
| 기존 worker 전체 | 240 통과, Python 하위 검증 153 통과 |
| 기존 프런트엔드 로직 | 138 통과 |
| 합계 | 테스트 **641개 통과**, Python 하위 검증 **161개 별도 통과** |
| 실패·건너뜀 | 0 |

새 비교 테스트는 백엔드에 포함된 91개입니다: 순수 비교·HTTP 경계 64개, 실제 PostgreSQL 27개.
JUnit의 test 수에는 Python 하위 검증이 포함되므로 위 합계와 다시 합산하지 않습니다.
기존 Starlette/httpx 테스트 클라이언트 사용 중단 예고 경고가 있으나 테스트 실패는 없습니다.

## 검증한 내용

- 11월 1일 독립 작성된 17개 예시: 저장 자료 입력 → 비교 함수 → Schema·건수·상태·참조 대조.
- 같은 17개를 실제 PostgreSQL에 저장하고 등록된 HTTP 경로로 조회. 반복 요청과 DB 행 불변 확인.
- 비교 방향 반전 시 new/not_detected 반전, 방향별 comparison_id 분리.
- DB 행 순서를 바꿔도 응답·ID 동일. 의미 있는 원본 evidence 배열 순서는 지문에 반영.
- 버전 변경·추가·제거·무취약 설치·여러 설치 위치·버전 미상·빈 식별자.
- GHSA와 CVE-only 후보 충돌, 다중 식별자, NSWG 검토 유지, 참조 URL만 같은 검토 후보.
- primary 근거 없는 공유 CVE를 새로 발견/미검출로 단정하지 않음.
- 부분 실패에서도 양쪽 명확한 관측 유지. 실패·출처 미확인·이전 attempt·artifact 불일치의 부재 판정 제한.
- 잘못된 scan/package/finding 연결, 중복 연결, 정규화 근거와 설치 정보 불일치 거부.
- 같은 finding의 여러 설치와 식별자 충돌 묶음에서 누락·중복 소비 없음.
- 조회 도중 다른 연결에서 프로젝트와 현재 검사 자료를 갱신해도 두 조회가 한 읽기 전용 스냅샷을 유지.
- 기존 패키지 API의 projection과 snapshot을 이전 방식으로 직접 계산한 값과 대조.
- 기록된 poc77 원문을 실제 normalizer와 persist 함수로 다시 저장한 두 검사의 53개 finding 비교.
- 실제 설치 합계 10,000개 허용, 10,001개는 evidence를 읽기 전에 422 거부.
- 후보 그래프 상한 초과 시 부분 성공 응답을 반환하지 않음.
- 이전 기능의 전체 worker·패키지 API·AI 입력 순위·수정 후보 안내 회귀 검증.

## 환경과 범위

Python 3.12, 저장소의 고정 백엔드 의존성, 별도 임시 PostgreSQL 16 컨테이너를 사용했습니다.
각 DB 테스트는 고유 schema를 만들고 종료 시 제거합니다. 테스트 DB는 운영 데이터와 무관합니다.
프런트엔드는 기존 Node 테스트를 실행했으며 화면 코드는 변경하지 않았습니다.

기록된 scanner 결과의 재생과 합성 경계 사례를 검증했습니다. 최신 취약점 DB 재검사,
my-vibe-app 실제 코드 수정, 외부 AI 호출, 비교 화면 조작, 배포 서버 적용은 이번 검증에 포함되지 않습니다.
따라서 641개 통과를 배포 환경 시연 완료로 표현하지 않습니다.

## 재실행

저장소 루트에서 격리된 Python 환경에 다음 의존성을 설치합니다.

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt -r verification/scan-compare/requirements.txt
```

일회용 PostgreSQL 데이터베이스를 준비하고 `COMPARISON_TEST_DSN`, `PRIORITY_TEST_DSN`에 그 주소를 설정합니다.
운영 DB를 지정하지 않습니다. 이번 테스트의 DB 초기화는 매 테스트의 고유 schema 안에서만 수행합니다.

```sh
PYTHONPATH=.:backend .venv/bin/python -m pytest backend/tests -q
PYTHONPATH=.:worker:worker/tests .venv/bin/python -m pytest worker/tests -q
node --test frontend/tests/*.test.js
```

DSN이 없으면 PostgreSQL 테스트는 건너뜁니다. 이번 기록은 두 DSN을 모두 지정하고 건너뜀 없이 실행한 결과입니다.
DB 테스트를 실행하려면 해당 임시 DB 사용자에게 schema 생성·제거 권한이 필요합니다.

## 근거 파일

- [기계 판독 요약](evidence/summary.json)
- [백엔드 실행 기록](evidence/backend.txt), [JUnit](evidence/backend.xml)
- [worker 실행 기록](evidence/worker.txt), [JUnit](evidence/worker.xml)
- [프런트엔드 실행 기록](evidence/frontend.txt)
- [실제 비교 함수로 생성한 합성 응답](evidence/implemented-version-change.json)
- [17개 사례 대조표](evidence/contract-results.json)

API의 응답 단위와 연결 방법은 [API 문서](../../docs/scan-comparison-api.md)를 참고하세요.
