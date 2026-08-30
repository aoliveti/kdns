# REST API and telemetry reference

The control plane runs on HTTP port `:8080`, exposing record management, zone export, health checks, and Prometheus metrics.

A formal **OpenAPI 3.0 specification** describing all endpoints is available in [`api/openapi.yaml`](../api/openapi.yaml).

---

## 1. Authentication

Write endpoints require an authentication token via either:
- **Authorization header:** `Authorization: Bearer <API_TOKEN>`
- **API key header:** `X-API-Key: <API_TOKEN>`

For local testing, you can disable authentication using `--allow-unauthenticated-api`.

---

## 2. Health and readiness probes

KDNS provides standard Kubernetes `-z` probe endpoints on both `:8080` and `:8443`:

| Endpoint | Probe type | Description | Return codes |
| :--- | :--- | :--- | :--- |
| `GET /livez` | Liveness | Checks process liveness and deadlock avoidance. | `200 OK` (`ok\n`) |
| `GET /startupz` | Startup | Verifies snapshot loading and initial WAL replay have finished. | `200 OK` (`ok\n`) |
| `GET /readyz` | Readiness | Checks whether the node is ready to answer queries. In Replica mode, returns 503 until the first snapshot sync completes. | `200 OK` (`ok\n`)<br/>`503 Service Unavailable` (`syncing\n`) |

---

## 3. Record management

### `GET /v1/records/{domain}`
Returns all records configured for `{domain}`.

**Response `200 OK`:**
```json
{
  "domain": "example.com",
  "records": [
    {
      "type": "A",
      "ttl": 300,
      "rdata": ["192.0.2.1"]
    },
    {
      "type": "TXT",
      "ttl": 300,
      "rdata": ["v=spf1 -all"]
    }
  ]
}
```

---

### `PUT /v1/records/{domain}`
Replaces all records for `{domain}` atomically.

**Request body:**
```json
{
  "records": [
    {
      "type": "A",
      "ttl": 300,
      "rdata": ["192.0.2.50", "192.0.2.51"]
    },
    {
      "type": "AAAA",
      "ttl": 300,
      "rdata": ["2001:db8::50"]
    }
  ]
}
```

---

### `DELETE /v1/records/{domain}`
Removes all records for `{domain}`.

**Response `204 No Content`**

---

### `GET /v1/records/search?q={query}`
Performs a fast substring scan across all domain names in memory.

---

### `GET /v1/export/zonefile[?zone={domain}]`
Streams records formatted as a standard RFC 1035 Master Zone File (BIND format).

- **`?zone=example.com`:** Filters export to records under `example.com`. If omitted, all hosted zones are exported.
- **Headers:** `Content-Type: text/dns; charset=utf-8`
- Works on both **Primary** and **Replica** nodes.

**Example output:**
```text
$ORIGIN example.com.
$TTL 3600

example.com.                  3600    IN      SOA     ns1.example.com. hostmaster.example.com. 2026082701 7200 3600 1209600 300
example.com.                  3600    IN      NS      ns1.example.com.
example.com.                  3600    IN      A       192.0.2.1
www.example.com.              300     IN      A       192.0.2.10
mail.example.com.             3600    IN      MX      10 mail.example.com.
```

---

## 4. Supported record types

KDNS supports standard RFC types:
- `A` (IPv4 address, RFC 1035)
- `AAAA` (IPv6 address, RFC 3596)
- `CNAME` (Canonical name alias, RFC 1035)
- `MX` (Mail exchange: `{"preference": 10, "exchange": "mail.example.com"}`, RFC 1035)
- `TXT` (Text strings, RFC 1035)
- `NS` (Name server delegation and apex records, RFC 1035)
- `SOA` (Start of authority, RFC 1035)
- `SRV` (Service locator: `{"priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com"}`, RFC 2782)
- `CAA` (Certification authority authorization, RFC 8659)
- `PTR` (Pointer domain name for reverse lookups, RFC 1035)
- `DS` (Delegation signer for DNSSEC, RFC 4034)
- `DNSKEY` (Zone public keys for DNSSEC, RFC 4034)
- `RRSIG` (Cryptographic signatures, RFC 4034)
- `NSEC` / `NSEC3` (Authenticated denial of existence, RFC 4034 / RFC 5155)
- `ZONEMD` (Zone message digest, RFC 8976)

---

## 5. Prometheus metrics (`GET /metrics`)

KDNS exports Prometheus metrics (version 0.0.4) on `GET /metrics`:

| Metric name | Type | Description |
| :--- | :---: | :--- |
| `kdns_server_info` | Gauge | Operational mode (`standalone`, `primary`, `replica`), feature flags (`ha_enabled`, `dnssec_enabled`, `rrl_enabled`, `tls_enabled`, `doh_enabled`), and `server_id`. |
| `kdns_start_time_seconds` | Gauge | Process start timestamp in Unix seconds. |
| `kdns_uptime_seconds` | Gauge | Total server uptime in seconds. |
| `kdns_build_info` | Gauge | Build metadata (`version`, `commit`, `build_time`). |
| `kdns_queries_total` | Counter | Total incoming DNS queries partitioned by `proto` (`udp`, `tcp`, `dot`, `doh`). |
| `kdns_queries_by_type_total` | Counter | Total incoming DNS queries partitioned by `type` (`A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`, `SOA`, `SRV`, `CAA`, `PTR`, `DS`, `DNSKEY`, `OTHER`). |
| `kdns_responses_total` | Counter | Total DNS responses partitioned by `rcode` (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, `NOTIMP`, `OTHER`). |
| `kdns_network_receive_bytes_total` | Counter | Total network bytes received partitioned by `proto` (`udp`, `tcp`, `dot`, `doh`). |
