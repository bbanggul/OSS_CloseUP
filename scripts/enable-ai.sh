#!/usr/bin/env bash
# Run from project root: bash scripts/enable-ai.sh <backend-compose-service>
set -euo pipefail
set +x
cd "$(dirname "$0")/.."
service="${1:-}"
if [[ -z "$service" ]] || ! docker compose config --services | grep -Fxq -- "$service"; then
  echo '백엔드 서비스 이름을 인수로 지정하세요. 현재 서비스:'
  docker compose config --services
  echo '예: bash scripts/enable-ai.sh api'
  exit 1
fi
if [[ ! "$service" =~ ^[a-zA-Z0-9_-]+$ ]]; then exit 1; fi
read -r -p '사용할 OpenAI 모델 ID: ' OPENAI_MODEL
read -r -s -p 'OpenAI API 키 (화면에 표시되지 않음): ' OPENAI_API_KEY
printf '\n'
[[ -n "$OPENAI_MODEL" && -n "$OPENAI_API_KEY" ]] || { echo '모델과 키가 필요합니다.'; exit 1; }
export OPENAI_MODEL OPENAI_API_KEY
override=$(mktemp)
trap 'rm -f -- "$override"; unset OPENAI_API_KEY OPENAI_MODEL' EXIT
printf 'services:\n  %s:\n    environment:\n      OPENAI_API_KEY: ${OPENAI_API_KEY:?}\n      OPENAI_MODEL: ${OPENAI_MODEL:?}\n' "$service" > "$override"
# .env 의 COMPOSE_FILE(예: 배포용 docker-compose.prod.yml 포함)을 그대로 이어서 사용
files="${COMPOSE_FILE:-$(grep -E '^COMPOSE_FILE=' .env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\"'")}"
args=()
IFS=: read -r -a list <<< "${files:-docker-compose.yml}"
for f in "${list[@]}"; do [[ -n "$f" ]] && args+=(-f "$f"); done
docker compose "${args[@]}" -f "$override" up -d --build "$service"
echo '설정을 전달했습니다. 화면의 AI 설명 생성 버튼으로 검사 1건을 확인하세요.'
echo '나중에 기본 compose 명령으로 컨테이너를 다시 만들면 설정이 사라질 수 있습니다. 이 스크립트를 다시 실행하세요.'
