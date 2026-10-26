# 검토용 검증 근거와 재실행

[수정·검증 요약](../../docs/week5-deduplication-verification.md)

## 실행

Docker와 Docker Compose가 필요하다. 저장소 루트에서 실행한다.

```sh
sh verification/week5-dedup-d07/run.sh
```

처음 실행할 때 Python/PostgreSQL 이미지와 테스트 의존성을 내려받는다. 실행은 별도 Compose 프로젝트와 임시 DB에서 이루어지고 호스트 포트를 열지 않는다. 실행 종료 시 해당 컨테이너·임시 DB를 정리한다. 결과는 무시되는 `results/`에 남으며 커밋된 `evidence/`를 덮어쓰지 않는다. 같은 체크아웃에서는 한 번에 하나만 실행한다.

전체 worker 테스트 → 29사례 DB/API 재현 → D07 장애·동일 검사 정렬 검증 순서다. 실패 시 종료 코드도 실패하며 로그가 남는다. 운영 DB 접속 설정이나 `.env`를 사용하지 않는다. compose의 계정 정보는 격리된 임시 DB 전용이다.

## 커밋된 근거

| 파일 | 내용 |
| --- | --- |
| [summary.json](evidence/summary.json) | 29사례·38변형·340대조, D07 8시나리오·72대조, 순서19대조 집계 |
| [worker-tests.txt](evidence/worker-tests.txt) / [worker-junit.xml](evidence/worker-junit.xml) | 전체 테스트 로그·기계 판독 결과 |
| [service-results.json](evidence/service-results.json) | 모든 사례의 합성 입력, 저장 행, 실제 HTTP 응답, 기대값·실측값 |
| [d07-results.json](evidence/d07-results.json) | 장애별 DB·HTTP·별도 연결 보존 확인 및 오류 진단 |
| [cross-case-order.json](evidence/cross-case-order.json) | 같은 검사 안의 상대 순위 대조 |
| [recorded-fixture-regression.json](evidence/recorded-fixture-regression.json) | 기존 저장 검사 4종의 수정 전후 문서 동일성 |
| [synthetic-before.json](evidence/synthetic-before.json) / [synthetic-after.json](evidence/synthetic-after.json) | 합성 입력의 3→1 병합 재현; 실제 74건 검사와 별개 |
| [source-manifest.json](evidence/source-manifest.json) | 검증 소스·스크립트의 SHA-256 |

큰 JSON은 전체 근거를 유지하면서 공백만 줄였다. 샘플 이름·EXAMPLE 식별자·수정 후보는 테스트용이며 실제 조치 권고가 아니다. D07의 `attempted_payload_persisted=true`는 구성 전 실패에서는 NULL이 정확하게 저장됐다는 뜻이다. 오류 저장소가 실패하는 경우에는 신규 진단 기록을 보장하지 않는다.

자동 테스트 통과는 운영 배포 또는 실제 74건·71건 분석 완료를 뜻하지 않는다. 화면 검증과 EC2 업로드 전체 흐름은 별도다.
