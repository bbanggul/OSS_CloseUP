#!/bin/sh
set -eu
cd "$(dirname "$0")"
review_project="oss-package-api-review-$$"
mkdir -p results
cleanup() { docker compose -p "$review_project" -f compose.yaml down; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker compose -p "$review_project" -f compose.yaml build check
docker compose -p "$review_project" -f compose.yaml up -d --no-build db api
docker compose -p "$review_project" -f compose.yaml run --rm check
