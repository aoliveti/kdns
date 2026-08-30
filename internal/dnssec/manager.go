// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnssec

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	defaultValidityPast   = 1 * time.Hour
	defaultValidityFuture = 24 * time.Hour
	defaultNSECTTL        = 300
	defaultDNSKEYTTL      = 3600
)

// Manager holds multiple DNSSEC signing keys indexed by zone name and coordinates
// on-the-fly RRSIG signature generation and authenticated denial of existence.
type Manager struct {
	keys map[string][]*Key
}

// NewManager creates an empty DNSSEC Key Manager.
func NewManager() *Manager {
	return &Manager{
		keys: make(map[string][]*Key),
	}
}

// Add registers a cryptographic signing key for its associated zone.
func (m *Manager) Add(k *Key) {
	if k == nil {
		return
	}
	zone := canonicalZone(k.Zone)
	m.keys[zone] = append(m.keys[zone], k)
}

// HasKeys reports whether active signing keys exist for the zone.
func (m *Manager) HasKeys(zone string) bool {
	return len(m.keys[canonicalZone(zone)]) > 0
}

// Keys returns all active signing keys for the exact canonical zone name.
func (m *Manager) Keys(zone string) []*Key {
	return m.keys[canonicalZone(zone)]
}

// KeysForZone returns signing keys for the most specific enclosing zone cut
// matching the query name.
func (m *Manager) KeysForZone(name string) []*Key {
	curr := canonicalZone(name)
	for {
		if keys := m.Keys(curr); len(keys) > 0 {
			return keys
		}
		if curr == "." {
			break
		}
		dotIdx := strings.IndexByte(curr, '.')
		if dotIdx == -1 {
			curr = "."
			continue
		}
		curr = curr[dotIdx+1:]
	}
	return nil
}

// DNSKEY builds the apex DNSKEY RRSet containing all public keys registered for the zone.
func (m *Manager) DNSKEY(zone string, ttl uint32) (dns.RRSet, bool) {
	keys := m.Keys(zone)
	if len(keys) == 0 {
		return dns.RRSet{}, false
	}

	rdatas := make([][]byte, len(keys))
	for i, k := range keys {
		rdatas[i] = k.DNSKEYWire
	}

	return dns.RRSet{
		Type:  dns.TypeDNSKEY,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: rdatas,
	}, true
}

// DS synthesizes a Delegation Signer record for parental zone delegation (RFC 4034 §5.1, RFC 4509).
func (m *Manager) DS(zone string, ksk *Key) (dns.RRSet, error) {
	zoneWire := dns.EncodeDomainName(zone)

	h := sha256.New()
	h.Write(zoneWire)
	h.Write(ksk.DNSKEYWire)
	digest := h.Sum(nil)

	dsWire := make([]byte, 4+len(digest))
	binary.BigEndian.PutUint16(dsWire[0:2], ksk.KeyTag)
	dsWire[2] = ksk.Algorithm
	dsWire[3] = DigestSHA256
	copy(dsWire[4:], digest)

	return dns.RRSet{
		Type:  dns.TypeDS,
		Class: dns.ClassIN,
		TTL:   300,
		RData: [][]byte{dsWire},
	}, nil
}

// SignResult decorates a DNS resolution outcome with RRSIG signatures and NSEC records when the DO bit is set.
func (m *Manager) SignResult(qName string, qType dns.Type, res *dns.Result, now time.Time) {
	if m == nil || res == nil {
		return
	}

	canonicalQName := canonicalZone(qName)

	// RFC 4034 §2: Synthesize apex DNSKEY response if requested and keys are configured.
	if qType == dns.TypeDNSKEY && (!res.HasAnswer() || res.Answer.Type != dns.TypeDNSKEY) {
		if m.synthesizeDNSKEY(canonicalQName, res, now) {
			return
		}
	}

	keys := m.findMatchingKeys(canonicalQName)
	if len(keys) == 0 {
		return
	}
	key := keys[0]

	inception := now.Add(-defaultValidityPast)
	expiration := now.Add(defaultValidityFuture)

	// RFC 4035 §3.1: Sign positive answer records with active ZSK.
	if res.RCode == dns.RCodeSuccess && res.HasAnswer() {
		if res.Answer.Type != dns.TypeRRSIG {
			if rrSig, err := Sign(canonicalQName, res.Answer, key, inception, expiration); err == nil {
				res.AnswerRRSIG = rrSig
			}
		}
		return
	}

	// RFC 4035 §3.1.3 & RFC 5155: Provide authenticated denial of existence for NXDOMAIN and NODATA.
	switch res.RCode {
	case dns.RCodeNameError:
		apex := canonicalZone(key.Zone)
		nsecRecord, err := NSEC(canonicalQName, apex, nil, defaultNSECTTL)
		if err == nil {
			if sig, signErr := Sign(canonicalQName, nsecRecord, key, inception, expiration); signErr == nil {
				res.Authority = nsecRecord
				res.AuthorityRRSIG = sig
				res.AuthorityName = canonicalQName
			}
		}

	case dns.RCodeSuccess:
		apex := canonicalZone(key.Zone)
		nsecRecord, err := NSEC(canonicalQName, apex, []dns.Type{dns.TypeSOA, dns.TypeNS}, defaultNSECTTL)
		if err == nil {
			if sig, signErr := Sign(canonicalQName, nsecRecord, key, inception, expiration); signErr == nil {
				res.Authority = nsecRecord
				res.AuthorityRRSIG = sig
				res.AuthorityName = canonicalQName
			}
		}
	}
}

func (m *Manager) findMatchingKeys(domain string) []*Key {
	curr := canonicalZone(domain)
	for {
		if keys := m.Keys(curr); len(keys) > 0 {
			return keys
		}
		if curr == "." {
			break
		}
		dotIdx := strings.IndexByte(curr, '.')
		if dotIdx == -1 {
			curr = "."
			continue
		}
		curr = curr[dotIdx+1:]
	}
	return nil
}

// synthesizeDNSKEY builds and signs a synthetic DNSKEY answer for zone apex queries.
func (m *Manager) synthesizeDNSKEY(canonicalQName string, res *dns.Result, now time.Time) bool {
	dnsKeySet, ok := m.DNSKEY(canonicalQName, defaultDNSKEYTTL)
	if !ok {
		return false
	}
	res.RCode = dns.RCodeSuccess
	res.Answer = dnsKeySet
	keys := m.Keys(canonicalQName)
	if len(keys) > 0 {
		inception := now.Add(-defaultValidityPast)
		expiration := now.Add(defaultValidityFuture)
		if rrSig, err := Sign(canonicalQName, dnsKeySet, keys[0], inception, expiration); err == nil {
			res.AnswerRRSIG = rrSig
		}
	}
	return true
}
