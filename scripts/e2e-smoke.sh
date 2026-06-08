#!/usr/bin/env bash
#
# e2e-smoke.sh — hard end-to-end acceptance test against a running stack.
#
# Exercises real transactions through the live HTTP API and verifies:
#   * health / readiness
#   * order creation + validation rules (state machine, payment, currency, PII)
#   * idempotency (replay, key-reuse rejection, missing-key rejection)
#   * idempotency under CONCURRENCY (N parallel identical requests => 1 order)
#   * RBAC/ABAC-safe responses, PII masking
#   * order state machine (legal + illegal transitions)
#   * PII encryption-at-rest (raw DB column must not contain plaintext)
#   * transactional outbox -> Kafka delivery
#   * Prometheus metrics + security headers
#
# Prereqs: stack up via `make up`; tools: curl, jq, docker compose.
# Usage:   ./scripts/e2e-smoke.sh   (from project root)
#
set -uo pipefail

BASE="${BASE:-http://localhost:8080}"
METRICS="${METRICS:-http://localhost:9090}"
COMPOSE="docker compose -f deploy/docker/docker-compose.yml"

PASS=0
FAIL=0
RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; CYN=$'\e[36m'; BLD=$'\e[1m'; RST=$'\e[0m'

section() { echo; echo "${CYN}${BLD}== $* ==${RST}"; }
ok()      { echo "  ${GRN}✓${RST} $*"; PASS=$((PASS+1)); }
bad()     { echo "  ${RED}✗${RST} $*"; FAIL=$((FAIL+1)); }

# assert_eq <expected> <actual> <message>
assert_eq() {
  if [[ "$1" == "$2" ]]; then ok "$3 (=$2)"; else bad "$3 (expected '$1', got '$2')"; fi
}
# assert_contains <haystack> <needle> <message>
assert_contains() {
  if [[ "$1" == *"$2"* ]]; then ok "$3"; else bad "$3 (missing '$2')"; fi
}
# assert_not_contains <haystack> <needle> <message>
assert_not_contains() {
  if [[ "$1" != *"$2"* ]]; then ok "$3"; else bad "$3 (UNEXPECTED '$2' present)"; fi
}

# http_code METHOD PATH [JSON_BODY] [EXTRA_HEADER...]
# echoes the numeric status code; body saved to $BODY_FILE
BODY_FILE="$(mktemp)"
http_code() {
  local method="$1" path="$2" body="${3:-}"; shift || true; shift || true; shift || true
  local args=(-s -o "$BODY_FILE" -w '%{http_code}' -X "$method" "$BASE$path"
              -H 'Content-Type: application/json')
  for h in "$@"; do args+=(-H "$h"); done
  [[ -n "$body" ]] && args+=(-d "$body")
  curl "${args[@]}"
}

CUST="11111111-1111-1111-1111-111111111111"
# Unique per-run id so each execution creates a FRESH order (idempotency keys
# are permanent by design, so a fixed key would replay a finished order).
RUN_ID="$(date +%s)-$$-$RANDOM"
CREATE_KEY="e2e-create-$RUN_ID"

order_body() {
  # $1 = optional override for payment_method / items etc not needed; fixed valid body
  cat <<JSON
{
  "customer_id": "$CUST",
  "payment_method": "CARD",
  "contact": {"full_name":"Ada Lovelace","email":"ada@example.com","phone":"+1 415 555 1234"},
  "shipping_address": {"line1":"1 Main St","city":"London","postal_code":"EC1","country":"GB"},
  "items": [{"sku":"SKU-1","name":"Widget","quantity":2,"unit_price":1500,"currency":"USD"}]
}
JSON
}

# ---------------------------------------------------------------------------
section "1. Health & readiness"
code=$(http_code GET /healthz); assert_eq 200 "$code" "GET /healthz"
code=$(http_code GET /readyz);  assert_eq 200 "$code" "GET /readyz (pg+redis up)"
ready=$(jq -r '.ready' < "$BODY_FILE"); assert_eq true "$ready" "readyz reports ready"

# ---------------------------------------------------------------------------
section "2. Create order (happy path) + total computed"
code=$(http_code POST /v1/orders "$(order_body)" "Idempotency-Key: $CREATE_KEY")
assert_eq 201 "$code" "POST /v1/orders -> 201"
OID=$(jq -r '.id' < "$BODY_FILE")
total=$(jq -r '.total_price' < "$BODY_FILE")
status=$(jq -r '.status' < "$BODY_FILE")
assert_eq 3000 "$total" "total_price computed (2*1500)"
assert_eq PENDING "$status" "new order is PENDING"
email=$(jq -r '.contact.email' < "$BODY_FILE")
assert_eq "ada@example.com" "$email" "creator sees own PII unmasked"
echo "    order id: $OID"

# ---------------------------------------------------------------------------
section "3. Idempotency"
code=$(http_code POST /v1/orders "$(order_body)" "Idempotency-Key: $CREATE_KEY")
OID2=$(jq -r '.id' < "$BODY_FILE")
assert_eq "$OID" "$OID2" "replay with same key returns SAME order"

code=$(http_code POST /v1/orders '{"customer_id":"'"$CUST"'","payment_method":"PAYPAL","contact":{"full_name":"X Y","email":"x@y.com"},"shipping_address":{"line1":"a","city":"b","postal_code":"c","country":"GB"},"items":[{"sku":"S","name":"n","quantity":1,"unit_price":1,"currency":"USD"}]}' "Idempotency-Key: $CREATE_KEY")
assert_eq 422 "$code" "same key + different body -> 422 key reuse"

code=$(http_code POST /v1/orders "$(order_body)")
assert_eq 400 "$code" "missing Idempotency-Key -> 400"

# ---------------------------------------------------------------------------
section "4. Idempotency under CONCURRENCY (race) — 20 parallel identical POSTs"
KEY="e2e-race-$RANDOM"
TMPD="$(mktemp -d)"
for i in $(seq 1 20); do
  ( curl -s -o "$TMPD/r$i.json" -w '%{http_code}\n' -X POST "$BASE/v1/orders" \
      -H 'Content-Type: application/json' -H "Idempotency-Key: $KEY" \
      -d "$(order_body)" > "$TMPD/c$i.txt" ) &
done
wait
# collect distinct order ids that came back (201 or replayed 200)
ids=$(grep -hoE '"id":"[0-9a-f-]+"' "$TMPD"/r*.json 2>/dev/null | sort -u | wc -l | tr -d ' ')
created=$(grep -h '^201' "$TMPD"/c*.txt | wc -l | tr -d ' ')
conflicts=$(grep -h '^409' "$TMPD"/c*.txt | wc -l | tr -d ' ')
echo "    201-created=$created  409-inflight=$conflicts  distinct-ids=$ids"
assert_eq 1 "$ids" "exactly ONE distinct order created under 20x race"
rm -rf "$TMPD"

# ---------------------------------------------------------------------------
section "5. Validation rules (business invariants -> 422/400)"
bad_body() { http_code POST /v1/orders "$1" "Idempotency-Key: val-$RANDOM-$RANDOM"; }

code=$(bad_body '{"customer_id":"'"$CUST"'","payment_method":"CARD","contact":{"full_name":"A B","email":"a@b.com"},"shipping_address":{"line1":"a","city":"b","postal_code":"c","country":"GB"},"items":[]}')
assert_eq 422 "$code" "empty items -> 422"

code=$(bad_body '{"customer_id":"'"$CUST"'","payment_method":"BITCOIN","contact":{"full_name":"A B","email":"a@b.com"},"shipping_address":{"line1":"a","city":"b","postal_code":"c","country":"GB"},"items":[{"sku":"S","name":"n","quantity":1,"unit_price":1,"currency":"USD"}]}')
assert_eq 422 "$code" "invalid payment_method -> 422"

code=$(bad_body '{"customer_id":"'"$CUST"'","payment_method":"CARD","contact":{"full_name":"A B","email":"a@b.com"},"shipping_address":{"line1":"a","city":"b","postal_code":"c","country":"GB"},"items":[{"sku":"S","name":"n","quantity":1,"unit_price":100,"currency":"USD"},{"sku":"T","name":"m","quantity":1,"unit_price":100,"currency":"EUR"}]}')
assert_eq 422 "$code" "mixed currency -> 422"

code=$(bad_body '{"customer_id":"'"$CUST"'","payment_method":"CARD","contact":{"full_name":"A B","email":"a@b.com"},"shipping_address":{"line1":"a","city":"b","postal_code":"c","country":"GB"},"items":[{"sku":"S","name":"n","quantity":0,"unit_price":100,"currency":"USD"}]}')
assert_eq 422 "$code" "zero quantity -> 422"

code=$(bad_body '{"customer_id":"not-a-uuid","payment_method":"CARD","contact":{"full_name":"A B","email":"a@b.com"},"shipping_address":{"line1":"a","city":"b","postal_code":"c","country":"GB"},"items":[{"sku":"S","name":"n","quantity":1,"unit_price":1,"currency":"USD"}]}')
assert_eq 400 "$code" "invalid customer uuid -> 400"

# ---------------------------------------------------------------------------
section "6. Read paths"
code=$(http_code GET "/v1/orders/$OID"); assert_eq 200 "$code" "GET existing order -> 200"
code=$(http_code GET "/v1/orders/99999999-9999-9999-9999-999999999999"); assert_eq 404 "$code" "GET missing order -> 404"
code=$(http_code GET "/v1/orders?limit=5"); assert_eq 200 "$code" "list orders -> 200"
cnt=$(jq -r '.count' < "$BODY_FILE"); echo "    listed count=$cnt"

# ---------------------------------------------------------------------------
section "7. Order state machine (legal + illegal transitions)"
patch() { http_code PATCH "/v1/orders/$OID/status" "{\"status\":\"$1\"}"; }

code=$(patch SHIPPED);   assert_eq 409 "$code" "PENDING -> SHIPPED illegal (409)"
code=$(patch PAID);      assert_eq 200 "$code" "PENDING -> PAID legal (200)"
ver=$(jq -r '.version' < "$BODY_FILE"); assert_eq 2 "$ver" "version bumped to 2 after PAID"
code=$(patch PENDING);   assert_eq 409 "$code" "PAID -> PENDING illegal (409)"
code=$(patch SHIPPED);   assert_eq 200 "$code" "PAID -> SHIPPED legal (200)"
code=$(patch CANCELLED); assert_eq 409 "$code" "SHIPPED is terminal -> 409"

# ---------------------------------------------------------------------------
section "8. PII encryption AT REST (raw DB column must be ciphertext)"
contact_enc=$($COMPOSE exec -T postgres psql -U order -d orders -tA \
  -c "select contact_enc from orders where id='$OID';" 2>/dev/null | tr -d '\r')
if [[ -n "$contact_enc" ]]; then
  assert_not_contains "$contact_enc" "ada@example.com" "email NOT stored in plaintext"
  assert_not_contains "$contact_enc" "Lovelace" "name NOT stored in plaintext"
  echo "    contact_enc (db) = ${contact_enc:0:48}..."
else
  bad "could not read contact_enc from DB"
fi

# Verify decrypt round-trips through the API.
code=$(http_code GET "/v1/orders/$OID")
dec_email=$(jq -r '.contact.email' < "$BODY_FILE")
assert_eq "ada@example.com" "$dec_email" "API decrypts PII correctly on read"

# ---------------------------------------------------------------------------
section "9. Transactional outbox -> Kafka delivery"
sleep 3  # let the relay drain
msgs=$($COMPOSE exec -T kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic orders.events \
  --from-beginning --timeout-ms 6000 2>/dev/null || true)
assert_contains "$msgs" "order.created" "order.created event in Kafka"
assert_contains "$msgs" "order.paid" "order.paid event in Kafka"
assert_contains "$msgs" "order.shipped" "order.shipped event in Kafka"
assert_contains "$msgs" "$OID" "events carry the order id (partition key)"
assert_not_contains "$msgs" "ada@example.com" "NO PII leaked into Kafka events"

# ---------------------------------------------------------------------------
section "10. Observability & hardening"
m=$(curl -s "$METRICS/metrics")
assert_contains "$m" "http_requests_total" "metrics: http_requests_total exposed"
assert_contains "$m" "events_published_total" "metrics: events_published_total exposed"
assert_contains "$m" "outbox_pending_events" "metrics: outbox gauge exposed"

hdrs=$(curl -s -D - -o /dev/null "$BASE/healthz")
assert_contains "$hdrs" "X-Content-Type-Options: nosniff" "security header: nosniff"
assert_contains "$hdrs" "Content-Security-Policy" "security header: CSP"
assert_contains "$hdrs" "X-Frame-Options: DENY" "security header: frame-deny"

# ---------------------------------------------------------------------------
echo
echo "${BLD}=================== RESULT ===================${RST}"
echo "  ${GRN}PASS: $PASS${RST}    ${RED}FAIL: $FAIL${RST}"
rm -f "$BODY_FILE"
if [[ $FAIL -eq 0 ]]; then
  echo "  ${GRN}${BLD}ALL CHECKS GREEN ✅${RST}"; exit 0
else
  echo "  ${RED}${BLD}SOME CHECKS FAILED ❌${RST}"; exit 1
fi
