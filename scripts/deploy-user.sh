#!/usr/bin/env bash
# 데모 사이트 접속 계정 추가·비밀번호 변경: bash scripts/deploy-user.sh <아이디>
# 비밀번호는 화면에 표시되지 않고, 파일에는 bcrypt 해시만 저장됨.
set -euo pipefail
set +x
cd "$(dirname "$0")/.."
user="${1:-}"
[[ "$user" =~ ^[a-zA-Z0-9_-]{2,32}$ ]] || { echo '사용법: bash scripts/deploy-user.sh <아이디: 영문·숫자·_- 2~32자>'; exit 1; }
read -r -s -p '비밀번호 (12자 이상, 화면에 표시되지 않음): ' pw1; printf '\n'
read -r -s -p '비밀번호 확인: ' pw2; printf '\n'
[[ "$pw1" == "$pw2" ]] || { echo '두 비밀번호가 다릅니다.'; exit 1; }
(( ${#pw1} >= 12 )) || { echo '12자 이상으로 정하세요.'; exit 1; }
hash=$(printf '%s\n' "$pw1" | docker run --rm -i caddy:2.11-alpine caddy hash-password)
unset pw1 pw2
[[ "$hash" == \$2* ]] || { echo '해시 생성에 실패했습니다.'; exit 1; }
file=deploy/users.caddy
umask 077
touch "$file"
grep -v -E "^${user} " "$file" > "$file.tmp" || true
printf '%s %s\n' "$user" "$hash" >> "$file.tmp"
mv "$file.tmp" "$file"
chmod 600 "$file"
echo "계정 '$user' 를 저장했습니다. 적용: docker compose restart web"
