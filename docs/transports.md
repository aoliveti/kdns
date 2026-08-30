# Transports, dynamic updates and security

KDNS supports standard UDP/TCP transports as well as encrypted DoT/DoH and network rate limiting.

---

## 1. Supported network protocols

```
       +-----------------------------------------------------------+
       |                     Supported transports                  |
       |                                                           |
       |  [UDP :5353]   [TCP :5353]   [DoT :853]   [DoH :8443]     |
       |    RFC 1035     RFC 7766      RFC 7858     RFC 8484       |
       +-----------------------------------------------------------+
```

| Transport | Port | Framing | Highlights |
| :--- | :--- | :--- | :--- |
| **DNS UDP** | `5353` | Raw datagrams (Capped at 1232B EDNS0) | Anti-reflection drop (`QR=1`), RRL slip |
| **DNS TCP** | `5353` | 2-byte length prefix | Pipelined async queries up to 64KB |
| **DNS-over-TLS (DoT)** | `853` | TLS 1.2 / 1.3 over TCP | Zero-downtime certificate reload (`SIGHUP`) |
| **DNS-over-HTTPS (DoH)**| `8443`| HTTP/2 `/dns-query` | Binary POST and base64url GET |

---

## 2. DNS-over-HTTPS (DoH RFC 8484)

The DoH server runs on a dedicated listener (`:8443`), separated from the management API:

- **POST queries:** Accepts `application/dns-message` in the request body.
- **GET queries:** Accepts base64url encoded queries (`?dns=<base64url>`).
- **CDN caching:** Calculates the lowest TTL among records in the response and sets `Cache-Control: max-age=<MIN_TTL>`.

---

## 3. Dynamic updates (RFC 2136) & TSIG (RFC 8945)

KDNS supports wire-format `Opcode 5 UPDATE` requests:

1. **TSIG authentication:** Constant-time HMAC verification (`hmac-sha256`, `hmac-sha512`, `hmac-sha1`, `hmac-md5`) with clock skew checks ($\pm 300$ seconds).
2. **Prerequisites:** Validates existence and non-existence rules before touching state.
3. **Commit:** Approved updates are written straight to `mutations.wal` and applied in memory.

---

## 4. Response rate limiting (BCP 140 / RRL)

To mitigate DNS amplification and reflection attacks:

- **Token bucket decay:** Tracks query frequencies per client subnet in fixed memory slots.
- **Subnet masks:** Aggregates by `/24` prefix for IPv4 and `/56` for IPv6.
- **SLIP truncation:** Sends a truncated response (`TC=1`) every $N$ dropped queries (`--rrl-slip`) to force valid clients to retry over TCP while dropping malicious UDP traffic.
- **Configurable rates:** Separate thresholds for valid answers (`--rrl-rate`) and error codes (`--rrl-error-rate`).

---

## 5. CHAOS class diagnostics (RFC 4892)

Queries in Class `CH` (`3`) return operational metadata:

| Query name | Record type | Returned value | Description |
| :--- | :--- | :--- | :--- |
| `id.server` | `TXT` | `--server-id` / system hostname / `"none"` | Node ID in Anycast pools |
| `hostname.bind` | `TXT` | `--server-id` / system hostname / `"none"` | Server hostname |
| `version.bind` | `TXT` | `kdns-<version>` | KDNS build version |
| `version.server` | `TXT` | `kdns-<version>` | KDNS version alias |
| `authors.bind` | `TXT` | `"Andrea Oliveti"` | Author string |
