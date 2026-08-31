# Configuration, CLI flags and environment variables

KDNS is configured via command-line flags or environment variables. CLI flags take precedence over environment variables.

---

## 1. Options reference

### Network and transports

| CLI flag | Environment variable | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--address` | `KDNS_ADDRESS` | `string` | `:5353` | UDP/TCP listen address for standard authoritative DNS queries (RFC 1034/1035). |
| `--dot-addr` | `KDNS_DOT_ADDR` | `string` | `:853` (with TLS) | TCP listen address for DNS-over-TLS (DoT, RFC 7858). Enabled when TLS certificates are set. |
| `--doh-addr` | `KDNS_DOH_ADDR` | `string` | `:8443` | HTTP/HTTPS listen address for DNS-over-HTTPS (DoH, RFC 8484). |
| `--tls-cert` | `KDNS_TLS_CERT` | `string` | `""` | Path to TLS certificate PEM file for DoT and HTTPS listeners. |
| `--tls-key` | `KDNS_TLS_KEY` | `string` | `""` | Path to TLS private key PEM file for DoT and HTTPS listeners. |
| `--server-id` | `KDNS_SERVER_ID` | `string` | `""` | Custom identity string for CHAOS class queries (`id.server`, `hostname.bind`). Defaults to hostname. |

---

### HTTP management and control plane

| CLI flag | Environment variable | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--http-addr` | `KDNS_HTTP_ADDR` | `string` | `:8080` | Bind address for REST management API, health probes, and Prometheus `/metrics`. |
| `--api-token` | `KDNS_API_TOKEN` | `string` | *(Required)* | Secret Bearer authentication token for REST API mutations (minimum 16 characters). |
| `--http-cors` | `KDNS_HTTP_CORS` | `bool` | `true` | Enable CORS headers and `OPTIONS` preflight handling on the REST API. |
| `--http-cors-origin` | `KDNS_HTTP_CORS_ORIGIN` | `string` | `*` | Allowed origin for CORS requests (e.g. `*` or `https://app.example.com`). |

---

### High availability and cluster replication

| CLI flag | Environment variable | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--mode` | `KDNS_MODE` | `string` | `standalone` | Operation mode: `standalone`, `primary` (streams WAL mutations), or `replica` (read-only state sync). |
| `--cluster-addr` | `KDNS_CLUSTER_ADDR` | `string` | `:8081` | Bind address for HA WAL replication and snapshot transfer endpoints. |
| `--cluster-token` | `KDNS_CLUSTER_TOKEN` | `string` | `""` | Shared Bearer token for cluster replication authentication between nodes. |
| `--primary-url` | `KDNS_PRIMARY_URL` | `string` | `""` | HTTP/HTTPS URL of the primary node (required in replica mode, e.g. `http://primary:8081`). |
| `--cluster-tls-cert` | `KDNS_CLUSTER_TLS_CERT` | `string` | `""` | Path to TLS certificate PEM file for primary cluster replication listener. |
| `--cluster-tls-key` | `KDNS_CLUSTER_TLS_KEY` | `string` | `""` | Path to TLS private key PEM file for primary cluster replication listener. |
| `--cluster-ca-cert` | `KDNS_CLUSTER_CA_CERT` | `string` | `""` | Path to Root CA PEM file to verify primary TLS certificate in replica mode. |

---

### Storage and persistence

| CLI flag | Environment variable | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--storage-dir` | `KDNS_STORAGE_DIR` | `string` | `./data` | Directory for persistent Write-Ahead Log (`mutations.wal`) and compressed snapshots (`state.snap`). |
| `--zone-file` | `KDNS_ZONE_FILE` | `string` | `""` | Path to an initial RFC 1035 master zone file to preload records on first startup. |
| `--compaction-threshold` | `KDNS_COMPACTION_THRESHOLD` | `uint64` | `10000` | Mutation count threshold before triggering background WAL compaction (min `100`). |
| `--compaction-interval` | `KDNS_COMPACTION_INTERVAL` | `duration` | `30m` | Time interval between background WAL compactions (min `1m`). |

---

### Security, TSIG and DNSSEC

| CLI flag | Environment variable | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--tsig-keys` | `KDNS_TSIG_KEYS` | `string` | `""` | Comma-separated TSIG keys for RFC 2136 dynamic updates (syntax: `name:algo:secret` or `name:secret`). |
| `--dnssec` | `KDNS_DNSSEC` | `bool` | `false` | Enable on-the-fly DNSSEC signing and dynamic NSEC authenticated denial proofs. |
| `--dnssec-keys` | `KDNS_DNSSEC_KEYS` | `string` | `""` | Comma-separated DNSSEC signing keys per zone (syntax: `zone:algo`, e.g. `example.com:13,example.org:15`). |

---

### Response rate limiting (BCP 140 / RRL)

| CLI flag | Environment variable | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--rrl` | `KDNS_RRL` | `bool` | `true` | Enable Response Rate Limiting to mitigate DNS amplification and reflection attacks. |
| `--rrl-rate` | `KDNS_RRL_RATE` | `int` | `50` | Maximum responses per second per client subnet prefix. |
| `--rrl-error-rate` | `KDNS_RRL_ERROR_RATE` | `int` | `10` | Maximum error responses per second per client subnet prefix. |
| `--rrl-slip` | `KDNS_RRL_SLIP` | `int` | `2` | RRL slip rate: 1 out of every N dropped responses is sent with `TC=1` to force TCP retry. |
| `--rrl-table-size` | `KDNS_RRL_TABLE_SIZE` | `int` | `65536` | Total slot capacity of the sharded RRL tracking table. |
| `--rrl-ipv4-prefix` | `KDNS_RRL_IPV4_PREFIX` | `int` | `24` | IPv4 client subnet prefix length for rate aggregation. |
| `--rrl-ipv6-prefix` | `KDNS_RRL_IPV6_PREFIX` | `int` | `56` | IPv6 client subnet prefix length for rate aggregation. |

---

### Logging and diagnostics

| CLI flag | Environment variable | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--log-format` | `KDNS_LOG_FORMAT` | `string` | `json` | Structured log format: `json` (cloud-native default) or `text` (console development). |
| `--debug` | `KDNS_DEBUG` | `bool` | `false` | Enable verbose debug logging output. |

---

## 2. Cryptographic algorithm specifications

### TSIG HMAC algorithms (RFC 2845 & RFC 8945)

TSIG keys are specified using `--tsig-keys` or `KDNS_TSIG_KEYS` with the syntax:
`name:algorithm:secret` or `name:secret` (defaults to `hmac-sha256`).

| Identifier | Specification | Key length | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `hmac-sha256` | RFC 4635 / RFC 8945 | 256 bits | **Recommended** | Standard default algorithm for dynamic DNS updates. |
| `hmac-sha512` | RFC 4635 / RFC 8945 | 512 bits | Supported | High-security HMAC authentication. |
| `hmac-sha1` | RFC 2845 | 160 bits | Supported | Maintained for legacy DNS client compatibility. |
| `hmac-md5` | RFC 2845 | 128 bits | Supported | Maintained for legacy BIND / RFC 2845 compatibility. |

**Example configuration:**
```bash
--tsig-keys="dhcp-updater:hmac-sha256:c2VjcmV0S2V5MTIzNA==,legacy-client:hmac-md5:b2xkU2VjcmV0NTY3OA=="
```

---

### DNSSEC signing algorithms (RFC 4034, RFC 6605, RFC 8080)

Zone signing keys are specified using `--dnssec-keys` or `KDNS_DNSSEC_KEYS` with the syntax:
`zone:algorithm` (e.g. `example.com:13,example.org:15`). If the algorithm code is omitted, it defaults to `13`.

| Algorithm code | Cryptographic suite | Specification | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `13` | **ECDSA Curve P-256 with SHA-256** | RFC 6605 | **Recommended** | Fast signing, short signatures (64 bytes), universal resolver support. |
| `15` | **Ed25519 (Edwards-curve DSA)** | RFC 8080 | Supported | Ultra-high performance modern elliptic curve cryptography. |

**Example configuration:**
```bash
--dnssec=true \
--dnssec-keys="example.com:13,secure.internal:15"
```

---

## 3. Common configuration recipes

### Standalone server with persistent storage

```bash
kdns \
  --address=":5353" \
  --http-addr=":8080" \
  --api-token="secret-token-min-16-chars" \
  --storage-dir="/var/lib/kdns/data" \
  --zone-file="/etc/kdns/example.com.zone"
```

### High availability primary node

```bash
kdns \
  --mode="primary" \
  --address=":5353" \
  --http-addr=":8080" \
  --api-token="primary-control-token" \
  --cluster-addr=":8081" \
  --cluster-token="cluster-shared-secret" \
  --storage-dir="/var/lib/kdns/primary-data"
```

### High availability read-only replica node

```bash
kdns \
  --mode="replica" \
  --address=":5353" \
  --http-addr=":8080" \
  --api-token="replica-read-token" \
  --primary-url="http://primary.internal:8081" \
  --cluster-token="cluster-shared-secret" \
  --storage-dir="/var/lib/kdns/replica-data"
```

### Encrypted DoT and DoH with TLS

```bash
kdns \
  --address=":5353" \
  --dot-addr=":853" \
  --doh-addr=":8443" \
  --tls-cert="/etc/letsencrypt/live/ns1.example.com/fullchain.pem" \
  --tls-key="/etc/letsencrypt/live/ns1.example.com/privkey.pem" \
  --api-token="secret-token-min-16-chars"
```

### On-the-fly DNSSEC signing

```bash
kdns \
  --address=":5353" \
  --api-token="secret-token-min-16-chars" \
  --dnssec=true \
  --dnssec-keys="example.com:13,example.org:15"
```
