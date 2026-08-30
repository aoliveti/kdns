// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnssec

import (
	"testing"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

func BenchmarkSign_ECDSA(b *testing.B) {
	key, err := NewECDSAKey("example.com.", FlagZSK)
	if err != nil {
		b.Fatal(err)
	}

	record := dns.NewRRSet(dns.TypeA, 300, "1.2.3.4")

	now := time.Now()
	inception := now.Add(-1 * time.Hour)
	expiration := now.Add(24 * time.Hour)

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		_, err := Sign("example.com.", record, key, inception, expiration)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_Ed25519(b *testing.B) {
	key, err := NewEd25519Key("example.com.", FlagZSK)
	if err != nil {
		b.Fatal(err)
	}

	record := dns.NewRRSet(dns.TypeA, 300, "1.2.3.4")

	now := time.Now()
	inception := now.Add(-1 * time.Hour)
	expiration := now.Add(24 * time.Hour)

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		_, err := Sign("example.com.", record, key, inception, expiration)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNSEC(b *testing.B) {
	types := []dns.Type{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeCAA}

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		_, err := NSEC("a.example.com.", "z.example.com.", types, 300)
		if err != nil {
			b.Fatal(err)
		}
	}
}
