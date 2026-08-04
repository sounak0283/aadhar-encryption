#!/usr/bin/env bash
# Proves the per-hit audit-report fix: submit an Aadhaar number once, decrypt
# it twice, then confirm GET /api/admin/audit-report returns 3 separate rows
# for the same reference_id — each with its own distinct request_datetime —
# instead of 1 row frozen at the original submission time.
#
# Requires an already-registered admin (run Flow B in the Postman collection
# first if you don't have one). Edit the four variables below, then run:
#   bash docs/postman/verify_per_hit_audit.sh
set -euo pipefail

BASE_URL="http://localhost:8103"     # match frontend/.env's VITE_API_BASE_URL
ADMIN_USER="admin"
ADMIN_PASS="at-least-12-characters"
read -rp "Live 6-digit TOTP code for $ADMIN_USER (type it fresh, then press Enter): " TOTP_NOW

USER_JAR=$(mktemp)
ADMIN_JAR=$(mktemp)
trap 'rm -f "$USER_JAR" "$ADMIN_JAR"' EXIT

echo "== 1. Sign up + log in a throwaway regular user =="
TEST_USER="test-hits-$(date +%s)"
curl -s -c "$USER_JAR" -X POST "$BASE_URL/api/auth/signup" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$TEST_USER\",\"password\":\"a-strong-password-1\"}" >/dev/null

curl -s -c "$USER_JAR" -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$TEST_USER\",\"password\":\"a-strong-password-1\"}" >/dev/null

echo "== 2. Submit one Aadhaar number =="
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SUBMIT=$(curl -s -b "$USER_JAR" -X POST "$BASE_URL/api/aadhaar" \
  -H "Content-Type: application/json" \
  -d "{\"aadhaar_number\":\"102938475615\",\"consent\":true,\"ts\":\"$NOW\"}")
echo "Submit response: $SUBMIT"
REF_ID=$(echo "$SUBMIT" | python -c "import sys,json; print(json.load(sys.stdin)['reference_id'])")
echo "reference_id = $REF_ID"

echo "== 3. Log in as admin =="
curl -s -c "$ADMIN_JAR" -X POST "$BASE_URL/api/admin/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\",\"totp_code\":\"$TOTP_NOW\"}" >/dev/null

echo "== 4. Decrypt the SAME record twice =="
curl -s -b "$ADMIN_JAR" -X POST "$BASE_URL/api/admin/submissions/$REF_ID/decrypt"; echo
curl -s -b "$ADMIN_JAR" -X POST "$BASE_URL/api/admin/submissions/$REF_ID/decrypt"; echo

echo "== 5. Today's audit report — expect 3 rows for $REF_ID, distinct timestamps =="
TODAY=$(date -u +"%Y-%m-%d")
curl -s -b "$ADMIN_JAR" "$BASE_URL/api/admin/audit-report?from_date=$TODAY&to_date=$TODAY" | python -m json.tool

echo "== 6. Today's full audit log — expect user_login, submit, admin_login, decrypt x2 =="
curl -s -b "$ADMIN_JAR" "$BASE_URL/api/admin/audit-log?from_date=$TODAY&to_date=$TODAY" | python -m json.tool
