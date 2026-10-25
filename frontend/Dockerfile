# 배포용 화면 이미지: 빌드한 정적 파일을 Caddy가 제공 (docker-compose.prod.yml 의 web)
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM caddy:2.11-alpine
COPY --from=build /app/dist /srv
