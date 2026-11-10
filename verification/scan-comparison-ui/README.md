# 이전 검사 비교 화면 연결 검증

기준: PR #7 `b61712a`, 대상: `feat/design-refresh` `dec0417`.

## 재실행

```bash
PYTHONPATH=backend python -m pytest backend/tests -q
node --test frontend/tests/*.test.js
npm --prefix frontend run lint
npm --prefix frontend run build
```

프런트 159개 통과. 백엔드 241개 통과, PostgreSQL 환경을 지정하지 않아 기존 DB 테스트 27개 건너뜀, 하위 검증 8개 통과. 빌드와 lint 통과.
추가 검증은 동일 프로젝트 재업로드, 잘못된/없는 프로젝트 거부, 검사 이력 범위·페이지 분할, API 방향·취소 신호, 17개 비교 계약 예시의 상태·집계·식별자 보존입니다. 백엔드 추가 테스트는 DB 연결 모의 객체를 사용합니다.

## 브라우저 확인 준비

Vite를 127.0.0.1:5173으로 띄우고 Playwright가 설치된 환경에서:

```bash
node verification/scan-comparison-ui/browser.mjs
```

필요하면 `PLAYWRIGHT_MODULE`(모듈 경로), `CHROMIUM_PATH`(브라우저 경로)를 지정합니다. 이 스크립트는 실제 계약 JSON을 모의 API로 제공하여 충돌·부분 결과·늦은 응답·모바일 가로 넘침·프로젝트 재업로드 전달을 확인합니다. 실서버 검증은 아닙니다.
현재 작업 환경에서는 Chromium이 socket 생성 제한으로 시작하지 못해 이 브라우저 검증은 **미실행**입니다. EC2 배포 및 업로드→worker 실행→비교의 실제 서버 검증도 미실행입니다.

PR #7의 DB 검증 수치를 이번 변경의 재검증 결과로 합산하지 않습니다. worker 탐지 로직과 도구/DB 버전 수집은 변경하지 않았습니다.

## Scan names and layout update

Scan history now supports editing an optional name (80 characters maximum), stored in scan_runs.display_name via PATCH /scans/{id}. Empty names reset to the default label. Apply db/oss_closeup_v2_4_scan_names.sql before deploying the updated backend. Existing scan IDs and results are preserved.

Removed the requested comparison notice; severity distribution stretches to the sidebar width and the rescan banner uses shorter labels.
Validation: frontend 159 tests, build and lint passed; backend 248 tests and 8 subtests passed, 27 PostgreSQL tests skipped. Browser/EC2 visual verification remains outstanding.
