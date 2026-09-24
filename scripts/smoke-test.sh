#!/usr/bin/env bash
set -euo pipefail

BASE="${FACEID_BASE:-http://127.0.0.1:8094}"
LAN_BASE="${FACEID_LAN_BASE:-http://10.0.0.73:8094}"

check() {
  local name="$1" url="$2" expected="$3"
  local code
  code="$(curl -sS -o /tmp/faceid-smoke.out -w '%{http_code}' "$url")"
  if [[ "$code" != "$expected" ]]; then
    echo "FAIL $name expected=$expected got=$code"
    cat /tmp/faceid-smoke.out || true
    exit 1
  fi
  echo "PASS $name ($code)"
}

check "ready" "$BASE/readyz" "200"
check "dashboard" "$BASE/" "200"
check "dashboard-data" "$BASE/v1/dashboard" "200"
check "subjects" "$BASE/v1/subjects" "200"
check "events" "$BASE/v1/events?limit=5" "200"
check "registrations" "$BASE/v1/registrations?status=pending" "200"
check "audit" "$BASE/v1/audit?limit=5" "200"
check "camera-onvif" "$BASE/v1/cameras/ezviz-main/onvif" "200"
check "camera-snapshot" "$BASE/v1/cameras/ezviz-main/snapshot" "200"
check "lan-registration" "$LAN_BASE/register" "200"
check "lan-admin-denied" "$LAN_BASE/" "403"

echo "FACE-ID smoke test: PASS"
