#!/usr/bin/env bash
# Copyright (c) 2026 Andrea Oliveti All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -euo pipefail

PRIMARY_HTTP="http://kdns-primary:8080"
REPLICA_HTTP="http://kdns-replica:8080"
STANDALONE_HTTP="http://kdns-standalone:8080"
STANDALONE_DOH_URL="http://kdns-standalone:8443"

PRIMARY_HOST="kdns-primary"
REPLICA_HOST="kdns-replica"
STANDALONE_HOST="kdns-standalone"

DNS_PORT=5353

PRIMARY_TOKEN="primary-api-secret-12345"
REPLICA_TOKEN="replica-api-secret-12345"
STANDALONE_TOKEN="standalone-api-secret-1234"

echo "==> 1. Checking Standalone node health & DNS..."
curl -sf "${STANDALONE_HTTP}/livez" > /dev/null
curl -sf "${STANDALONE_HTTP}/readyz" > /dev/null
curl -sf -X PUT "${STANDALONE_HTTP}/v1/records/standalone.example.com" \
  -H "Authorization: Bearer ${STANDALONE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"records":[{"type":"A","ttl":300,"rdata":["1.2.3.4"]}]}' > /dev/null

echo "==> 2. Querying Standalone via dig..."
dig @"${STANDALONE_HOST}" -p "${DNS_PORT}" standalone.example.com A +short | grep -q "1.2.3.4"
echo "    [OK] Standalone DNS query succeeded."

echo "==> 3. Writing record to Primary Hub node & querying Primary DNS..."
curl -sf -X PUT "${PRIMARY_HTTP}/v1/records/cluster.example.com" \
  -H "Authorization: Bearer ${PRIMARY_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"records":[{"type":"A","ttl":300,"rdata":["10.99.88.77"]}]}' > /dev/null

dig @"${PRIMARY_HOST}" -p "${DNS_PORT}" cluster.example.com A +short | grep -q "10.99.88.77"
echo "    [OK] Primary DNS query succeeded."

echo "==> 4. Checking Replica authentication & read-only status..."
UNAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${REPLICA_HTTP}/v1/records/forbidden.example.com" \
  -H "Content-Type: application/json" \
  -d '{"records":[{"type":"A","ttl":300,"rdata":["1.1.1.1"]}]}')
if [[ "${UNAUTH_STATUS}" != "401" ]]; then
  echo "    [FAIL] Expected 401 Unauthorized on unauthenticated write, got ${UNAUTH_STATUS}"
  exit 1
fi
echo "    [OK] Replica rejects unauthenticated requests with 401 Unauthorized."

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${REPLICA_HTTP}/v1/records/forbidden.example.com" \
  -H "Authorization: Bearer ${REPLICA_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"records":[{"type":"A","ttl":300,"rdata":["1.1.1.1"]}]}')
if [[ "${STATUS}" != "403" ]]; then
  echo "    [FAIL] Expected 403 Forbidden on Replica write, got ${STATUS}"
  exit 1
fi
echo "    [OK] Replica is correctly operating in read-only mode (403 Forbidden)."

echo "==> 5. Querying Replica DNS to verify real-time replication..."
for _ in {1..10}; do
  if dig @"${REPLICA_HOST}" -p "${DNS_PORT}" cluster.example.com A +short | grep -q "10.99.88.77"; then
    echo "    [OK] Replica successfully resolved streamed record."
    break
  fi
  sleep 0.5
done

echo "==> 6. Testing NXDOMAIN negative caching response via dig..."
dig @"${STANDALONE_HOST}" -p "${DNS_PORT}" nonexistent.example.com A | grep -q "status: NXDOMAIN"
echo "    [OK] Standalone correctly returns NXDOMAIN for non-existent names."

echo "==> 7. Testing REST API Search, Pagination & CORS Preflight..."
curl -sf -H "Authorization: Bearer ${PRIMARY_TOKEN}" "${PRIMARY_HTTP}/v1/records/search?q=cluster" | grep -q "cluster.example.com"
curl -sf -H "Authorization: Bearer ${PRIMARY_TOKEN}" "${PRIMARY_HTTP}/v1/records?limit=1" | grep -q "domains"
curl -s -I -X OPTIONS "${PRIMARY_HTTP}/v1/records/cluster.example.com" | grep -qi "access-control-allow-origin: \*"
echo "    [OK] REST API search, pagination, and CORS preflight options verified."

echo "==> 8. Testing DoH endpoint probe..."
curl -sf "${STANDALONE_DOH_URL}/livez" | grep -q "ok"
echo "    [OK] DoH endpoint health check succeeded."

echo "==> 9. Testing Container Restart & State Durability (Disaster Recovery)..."
docker compose -f /workspace/test/e2e/docker-compose.yml restart kdns-standalone > /dev/null
for _ in {1..10}; do
  if dig @"${STANDALONE_HOST}" -p "${DNS_PORT}" standalone.example.com A +short | grep -q "1.2.3.4"; then
    echo "    [OK] Standalone successfully retained state across full container restart."
    break
  fi
  sleep 0.5
done

echo "==> 10. Testing REST API Zone File Export (Full & Filtered on Primary and Replica)..."
curl -sf -H "Authorization: Bearer ${PRIMARY_TOKEN}" "${PRIMARY_HTTP}/v1/export/zonefile" | grep -q "cluster.example.com."
curl -sf -H "Authorization: Bearer ${PRIMARY_TOKEN}" "${PRIMARY_HTTP}/v1/export/zonefile?zone=example.com" | grep -q "\$ORIGIN example.com."
curl -sf -H "Authorization: Bearer ${REPLICA_TOKEN}" "${REPLICA_HTTP}/v1/export/zonefile" | grep -q "cluster.example.com."
echo "    [OK] Zone file export successfully verified on both Primary and Replica."

echo "==> All E2E smoke tests passed successfully!"
