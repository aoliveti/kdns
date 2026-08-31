<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/kdns-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/kdns-logo-light.svg">
    <img alt="KDNS Logo" src="assets/kdns-logo-light.svg" width="380">
  </picture>
</p>

<p align="center">
  <strong>A high-performance authoritative DNS server written in Go from scratch.</strong>
</p>

<p align="center">
  <a href="https://github.com/aoliveti/kdns/releases/latest"><img src="https://img.shields.io/github/v/release/aoliveti/kdns?logo=github&color=blue" alt="Latest Release"></a>
  <a href="https://github.com/aoliveti/kdns/actions/workflows/ci.yml"><img src="https://github.com/aoliveti/kdns/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
  <a href="https://github.com/aoliveti/kdns/actions/workflows/codeql.yml"><img src="https://github.com/aoliveti/kdns/actions/workflows/codeql.yml/badge.svg" alt="CodeQL Analysis"></a>
  <a href="https://pkg.go.dev/github.com/aoliveti/kdns"><img src="https://pkg.go.dev/badge/github.com/aoliveti/kdns.svg" alt="Go Reference"></a>
  <a href="https://hub.docker.com/r/aoliveti/kdns"><img src="https://img.shields.io/docker/v/aoliveti/kdns?label=Docker%20Hub&logo=docker" alt="Docker Hub"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BSD--3--Clause-blue.svg" alt="License"></a>
</p>

---

> **Note on AI collaboration:**  
> KDNS is an educational project built from scratch to explore low-level networking, high-performance Go, and distributed state—developed in pair-programming with an AI agent. If you don't like AI-assisted projects, feel free to skip this repository. Constructive technical feedback and contributions are always welcome; purist gatekeeping is not.

---

## Overview

KDNS is a lightweight, zero-dependency authoritative DNS server designed for fast responses, low memory usage, and simple operations.

```
       +-------------------------------------------------------------------+
       |                               KDNS                                |
       |                                                                   |
       |  +-------------------------------------------------------------+  |
       |  |                         Data Plane                          |  |
       |  |    UDP / TCP :5353       DoT :853       DoH :8443 (/query)  |  |
       |  +------------------------------+------------------------------+  |
       |                                 |                                 |
       |                            [Read Path]                            |
       |                                 v                                 |
       |  +-------------------------------------------------------------+  |
       |  |                      In-Memory Engine                       |  |
       |  |          Radix tree (routing)   +   Sharded LRU cache       |  |
       |  +------------------------------^------------------------------+  |
       |                                 |                                 |
       |                      [Mutations & Snapshots]                      |
       |                                 |                                 |
       |  +------------------------------v------------------------------+  |
       |  |                       Storage Engine                        |  |
       |  |    mutations.wal (Group Commit)  <->  state.snap (Deflate)  |  |
       |  +------------------------------^------------------------------+  |
       |                                 |                                 |
       |                         [Cluster & Mgmt]                          |
       |                                 |                                 |
       |  +------------------------------+------------------------------+  |
       |  |                    Control & Replication                    |  |
       |  |    REST API :8080        RFC 2136       Cluster :8081 (HA)  |  |
       |  +-------------------------------------------------------------+  |
       +-------------------------------------------------------------------+
```

---

## Key highlights

- **Zero heap allocations on resolution:** Reuses buffer pools and serves pre-packed wire payloads to keep the garbage collector out of the query hot path.
- **Reverse-label radix tree:** Domains are indexed from right to left (`.` &rarr; `com` &rarr; `example` &rarr; `www`). Lookups take only 2 to 4 steps, with automatic wildcard fallbacks (`*.example.com`) and zone delegations.
- **Durability with WAL and compressed snapshots:** Mutations are written sequentially to `mutations.wal` with CRC32 checksums. Periodic background compaction compresses the state into `state.snap` (-94% disk footprint).
- **Primary / replica streaming:** Zero-dependency replication where replica nodes stream mutations over HTTP (`:8081`), writing to local disk and updating memory in a single pass.
- **DNSSEC, TSIG & rate limiting:** On-the-fly RRSIG signing (ECDSA P-256 / Ed25519) with NSEC denial proofs when requested (`DO=1`), HMAC TSIG authentication for RFC 2136 dynamic updates, and response rate limiting (RRL).
- **Management API & metrics:** REST endpoints on port `8080`, RFC 1035 zone exporter, native Prometheus `/metrics`, and Kubernetes probes (`/livez`, `/readyz`, `/startupz`).

---

## What KDNS is not (by design)

To keep things simple, fast, and maintainable, a few features are deliberately left out:

- **It is not a recursive resolver:** KDNS only serves the zones you configure. It won't resolve arbitrary internet domains or act as a caching DNS forwarder for your home network.
- **It does not chase CNAMEs:** Following the original RFC 1034 separation of concerns (like NSD and Knot DNS), KDNS returns the CNAME in the Answer section and lets the recursive resolver follow it.
- **No legacy AXFR/IXFR transfers:** Zone replication between nodes uses authenticated HTTP streaming on port `8081` instead of plaintext transfers over port 53. If you need standard zone files, use the `/v1/export/zonefile` endpoint.
- **No plugins or scripting engines:** KDNS compiles into a single, self-contained static binary without dynamic `.so` plugins or external scripting hooks.

---

## Standards & RFC compliance

| Standard / RFC | Category | Implementation & Details |
| :--- | :--- | :--- |
| **RFC 1034 & 1035** | Core DNS | Binary wire parser/packer, pointer compression, multiline master zone file parser. |
| **RFC 1034 §4.3.2** | Zone cuts | Radix tree interception returning delegation referrals (`NOERROR`, `AA=0`, Authority `NS`, glue in Additional). |
| **RFC 2136** | Dynamic updates | Complete `Opcode 5 UPDATE` engine verifying 5 prerequisite rules and applying 4 update operations to WAL. |
| **RFC 2308** | Negative caching | Authority section contains enclosing zone SOA with calculated `MINIMUM` TTL on `NXDOMAIN` and `NODATA`. |
| **RFC 2845 & 8945** | TSIG auth | HMAC-SHA256, HMAC-SHA512, HMAC-SHA1, HMAC-MD5 with timing-attack resistant signature verification. |
| **RFC 4034 & 4035** | DNSSEC | On-the-fly `RRSIG` signing (ECDSA P-256 / Ed25519), apex `DNSKEY`/`DS`, and windowed `NSEC` type bitmaps (`DO=1`). |
| **RFC 4592** | Wildcards | Exact-match precedence over wildcards with proper Empty Non-Terminal (ENT) synthesis. |
| **RFC 6891** | EDNS0 | Buffer size negotiation (capped at 1232 bytes), DO bit extraction, duplicate OPT rejection (`FORMERR`). |
| **RFC 7766** | TCP framing | Length-prefixed asynchronous TCP pipelining supporting full 64KB message payloads. |
| **RFC 7858 & 9539** | DNS-over-TLS | Native listener on port `853` with zero-downtime certificate hot-reloading (`SIGHUP`). |
| **RFC 8484** | DNS-over-HTTPS | Dedicated listener on `:8443` (`GET` base64url & `POST`) with dynamic `Cache-Control: max-age=<TTL>` headers. |
| **RFC 8482** | Minimal ANY | **Anti-DDoS defense:** Rather than returning all records for `TypeANY` (`255`)—a common vector for 100x amplification attacks—KDNS returns a single minimal RRSet, neutralizing DDoS reflection exploits. |
| **RFC 1035 §4.1.1** | Anti-reflection | Incoming packets with `QR=1` (response bit set) are silently dropped to prevent reflection loops. |
| **BCP 140 / RRL** | Rate limiting | Token bucket rate limiting with subnet aggregation (`/24` IPv4, `/56` IPv6) and SLIP (`TC=1`) truncation. |

---

## Network & port topology

| Port | Protocol | Plane | Description |
| :--- | :--- | :--- | :--- |
| **`5353`** | UDP / TCP | Data | Authoritative DNS query resolution (RFC 1034 / 1035) and RFC 2136 dynamic updates. |
| **`853`** | TCP (TLS) | Data | DNS-over-TLS (DoT, RFC 7858) with zero-downtime certificate hot-reloading (`SIGHUP`). |
| **`8443`** | HTTP / TLS | Data | Dedicated DNS-over-HTTPS (DoH, RFC 8484) endpoint on `/dns-query` and health probes. |
| **`8080`** | HTTP | Control | Management REST API (`/v1/records`), zone exporter, and Prometheus `/metrics`. |
| **`8081`** | HTTP / TLS | Cluster | Primary / replica asynchronous WAL streaming (`/v1/cluster/stream`) and snapshot sync. |

---

## Supported platforms

| Platform | Architectures | Packages |
| :--- | :--- | :--- |
| **Linux** | `amd64`, `arm64` | Standalone archive (`.tar.gz`) & Distroless OCI container |
| **FreeBSD** | `amd64`, `arm64` | Standalone archive (`.tar.gz`) |
| **OpenBSD** | `amd64`, `arm64` | Standalone archive (`.tar.gz`) |
| **NetBSD** | `amd64`, `arm64` | Standalone archive (`.tar.gz`) |

---

## Quick start

### Run with Docker

```bash
docker run -d \
  --name kdns \
  -p 5353:5353/udp \
  -p 5353:5353/tcp \
  -p 8443:8443/tcp \
  -p 8080:8080/tcp \
  -e KDNS_API_TOKEN="supersecrettoken12345" \
  -v kdns_data:/data \
  aoliveti/kdns:latest
```

### Build from source

Requires Go 1.27+:

```bash
git clone https://github.com/aoliveti/kdns.git
cd kdns

# Build static binary into bin/kdns
make build

# Start standalone daemon
./bin/kdns \
  --address :5353 \
  --http-addr :8080 \
  --api-token "supersecrettoken12345" \
  --storage-dir ./data
```

---

## Operational examples

### 1. Insert a DNS record via REST API
```bash
curl -X PUT http://127.0.0.1:8080/v1/records/app.example.com \
  -H "Authorization: Bearer supersecrettoken12345" \
  -H "Content-Type: application/json" \
  -d '{
    "records": [
      {
        "type": "A",
        "ttl": 300,
        "rdata": ["192.0.2.1"]
      }
    ]
  }'
```

### 2. Query the server
```bash
dig @127.0.0.1 -p 5353 app.example.com A +short
# Output: 192.0.2.1
```

### 3. Check health probes
```bash
curl -i http://127.0.0.1:8443/livez
# HTTP/1.1 200 OK
# ok
```

---

## Documentation & API specifications

Detailed architectural deep dives, implementation guides, and API contracts are available in [`docs/`](docs/) and [`api/`](api/):

| Guide | Subsystem | Topics Covered |
| :--- | :--- | :--- |
| **[Configuration & Flags](docs/configuration.md)** | Operations | Complete reference for command-line flags and environment variables, precedence rules, cryptographic algorithm support, and deployment recipes. |
| **[Architecture & Design](docs/architecture.md)** | System Design | CQRS concurrency model, physical port isolation (`:5353`, `:853`, `:8443`, `:8080`, `:8081`), zero-allocation data plane pipeline, POSIX signal handling (`SIGHUP`/`SIGTERM`). |
| **[REST API Reference](docs/api-reference.md)** | Control Plane | Endpoints (`/v1/records`, `/search`), streaming zone file export (`/v1/export/zonefile`), Kubernetes probes (`/livez`, `/readyz`, `/startupz`), Prometheus `/metrics`. |
| **[OpenAPI 3.0 Spec](api/openapi.yaml)** | API Contracts | Formal OpenAPI 3.0 specification covering Control Plane (`:8080`), DoH Data Plane (`:8443`), and Cluster Replication (`:8081`). |
| **[Clustering & HA](docs/clustering-ha.md)** | High Availability | Primary / replica asynchronous WAL streaming (`:8081`), real-time dual disk/memory ingestion, safe atomic state replacement on compaction, read-only replica mode. |
| **[Storage & WAL Internals](docs/storage-and-wal.md)** | Persistence | Group-commit write batching, big-endian binary framing, Deflate compressed snapshots (`state.snap`, -94%), atomic compaction guardrails. |
| **[Radix Tree Implementation](docs/radix-tree.md)** | Routing Engine | Reverse-label domain hierarchy, Copy-on-Write concurrency (100% lock-free reads), RFC 4592 wildcard synthesis, ENT suppression, CNAME transparency. |
| **[DNSSEC & TSIG Security](docs/dnssec.md)** | Cryptography | On-the-fly RRSIG signing (ECDSA P-256 / Ed25519) on `DO=1`, windowed NSEC denial bitmaps, apex DNSKEY/DS generation, TSIG transaction authentication. |
| **[Transports & Protocols](docs/transports.md)** | Networking | UDP/TCP length-prefixed pipelining, DoT on `:853`, DoH on `:8443` with dynamic `Cache-Control`, BCP 140 Response Rate Limiting (RRL), CHAOS diagnostics. |

---

## Engineering standards & verification

```bash
# Run test suite with race detector (24 packages, 0 data races)
go test -race -count=1 ./...

# Run strict linter suite (29 linters strictly enforced)
golangci-lint run ./...

# Run benchmark suite
go test -bench=. -benchmem ./...

# Run fuzz testing battery (100k iterations per target)
make fuzz
```

---

## Contributing & Security

- **Contributing:** Feedback, ideas, and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for code conventions.
- **Security:** Please report security vulnerabilities responsibly via [GitHub Security Advisories](https://github.com/aoliveti/kdns/security/advisories/new) as detailed in [SECURITY.md](SECURITY.md).

---

## License

KDNS is open-source software licensed under the [BSD 3-Clause License](LICENSE).
