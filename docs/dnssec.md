# DNSSEC signing and denial proofs

KDNS signs DNS records and generates authenticated denial proofs on the fly on the query hot path.

---

## 1. Dynamic signing vs pre-signing

Traditional DNSSEC tools require pre-signing entire zone files offline, creating large static `RRSIG` records that must be re-signed before expiration.

KDNS signs records dynamically:
1. When a client sends a query with **EDNS0 `DO=1` (DNSSEC OK)**, KDNS computes the `RRSIG` signature on demand using the zone's private key.
2. Signatures are cached in the sharded LRU cache to avoid recomputing them for frequent queries.
3. Queries without the `DO` bit skip cryptographic operations entirely.

---

## 2. Supported algorithms

KDNS supports elliptic curve cryptographic suites:

| Algorithm number | Mnemonic | Standard | Key parameters | Characteristics |
| :--- | :--- | :--- | :--- | :--- |
| **13** (Default) | `ECDSAP256SHA256` | RFC 6605 | NIST P-256 (secp256r1) | Hardware-accelerated on modern CPUs |
| **15** | `ED25519` | RFC 8080 | Ed25519 (Curve25519) | Constant-time execution, compact signatures |

---

## 3. Denial of existence (`NSEC`, RFC 4034 / 5155)

To cryptographically prove that a domain (`NXDOMAIN`) or record type (`NODATA`) does not exist, KDNS builds dynamic **NSEC** records with windowed bitmaps:

```
+-------------------------------------------------------------+
|                     NSEC record layout                      |
|                                                             |
|  [Next domain name] -> Lexicographical successor in radix   |
|  [Window block 0]   -> Types 0..255 (e.g. A, AAAA, SOA, NS) |
|  [Bitmap bytes]     -> Windowed bitfield flags              |
+-------------------------------------------------------------+
```

- **NXDOMAIN:** The Authority section includes the enclosing SOA, the synthetic `NSEC` record, and its accompanying `RRSIG(NSEC)`.
- **NODATA:** Returns `NOERROR` with an `NSEC` record showing which record types exist for the name, signed with `RRSIG(NSEC)`.

---

## 4. Apex DNSKEY and DS records

When DNSSEC is enabled for a zone, KDNS serves:
- **`DNSKEY` (Type 48):** Public keys (ZSK/KSK) at the zone apex.
- **`DS` (Type 43):** SHA-256 delegation signer hashes for the parent registrar.
