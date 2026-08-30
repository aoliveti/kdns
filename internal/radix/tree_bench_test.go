// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"fmt"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

func BenchmarkTree_Resolve(b *testing.B) {
	tree := New()
	rA, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{rA}}}
	target := "target.example.com"

	loader := func(onRecord func(domain string, records dns.RRSets)) error {
		for i := range 1000 {
			domain := fmt.Sprintf("node-%d.example.com", i)
			onRecord(domain, records)
		}
		onRecord(target, records)
		return nil
	}
	_ = tree.ReloadZone(loader)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = tree.Resolve(target, dns.TypeA)
	}
}

func BenchmarkTree_Resolve_Parallel(b *testing.B) {
	tree := New()
	rA, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{rA}}}
	target := "target.example.com"

	loader := func(onRecord func(domain string, records dns.RRSets)) error {
		for i := range 1000 {
			domain := fmt.Sprintf("node-%d.example.com", i)
			onRecord(domain, records)
		}
		onRecord(target, records)
		return nil
	}
	_ = tree.ReloadZone(loader)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = tree.Resolve(target, dns.TypeA)
		}
	})
}

func BenchmarkTree_Wildcard_Resolve(b *testing.B) {
	tree := New()
	rA, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{rA}}}
	tree.Upsert("*.wild.example.com", records)

	target := "deep.sub.wild.example.com"

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = tree.Resolve(target, dns.TypeA)
	}
}

func BenchmarkTree_ScaleResolve(b *testing.B) {
	tree := New()
	const numDomains = 1_000_000
	rA, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{rA}}}

	queries := make([]string, numDomains)
	for i := range numDomains {
		queries[i] = fmt.Sprintf("host-%d.zone-%d.com", i, i%100)
	}

	loader := func(onRecord func(domain string, records dns.RRSets)) error {
		for _, domain := range queries {
			onRecord(domain, records)
		}
		return nil
	}
	_ = tree.ReloadZone(loader)

	b.ReportAllocs()
	b.ResetTimer()

	var i int
	for b.Loop() {
		idx := i % numDomains
		_ = tree.Resolve(queries[idx], dns.TypeA)
		i++
	}
}

func BenchmarkTree_Get(b *testing.B) {
	tree := New()
	target := "target.example.com"
	rA, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	rTxt, _ := dns.PackRData(dns.TypeTXT, "v=spf1 -all")
	rIP, _ := dns.PackRData(dns.TypeA, "10.0.0.1")

	tree.Upsert(target, dns.RRSets{
		{Type: dns.TypeA, TTL: 300, RData: [][]byte{rA}},
		{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{rTxt}},
	})

	for i := range 1000 {
		domain := fmt.Sprintf("node-%d.example.com", i)
		tree.Upsert(domain, dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{rIP}}})
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = tree.Get(target)
	}
}

func BenchmarkTree_Upsert(b *testing.B) {
	tree := New()
	rA, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{rA}}}

	b.ReportAllocs()
	b.ResetTimer()

	var i int
	for b.Loop() {
		i++
		domain := fmt.Sprintf("upsert-host-%d.example.com", i)
		tree.Upsert(domain, records)
	}
}

func BenchmarkTree_ScaleReload(b *testing.B) {
	rA, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{rA}}}
	const numDomains = 1_000_000
	domains := make([]string, numDomains)
	for i := range numDomains {
		domains[i] = fmt.Sprintf("host-%d.zone-%d.com", i, i%100)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		b.StopTimer()
		tree := New()
		loader := func(onRecord func(domain string, records dns.RRSets)) error {
			for _, domain := range domains {
				onRecord(domain, records)
			}
			return nil
		}
		b.StartTimer()
		_ = tree.ReloadZone(loader)
	}
}

func BenchmarkTree_Search_NoMatch(b *testing.B) {
	tree := New()
	rLocal, _ := dns.PackRData(dns.TypeA, "127.0.0.1")
	records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{rLocal}}}

	for i := range 10000 {
		tree.Upsert(fmt.Sprintf("host-%d.example.com", i), records)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		for domain, rrs := range tree.Search("missing-domain-query") {
			_, _ = domain, rrs
		}
	}
}

func BenchmarkTree_Seek_Pagination(b *testing.B) {
	tree := New()
	rLocal, _ := dns.PackRData(dns.TypeA, "127.0.0.1")
	records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{rLocal}}}

	for i := range 10000 {
		tree.Upsert(fmt.Sprintf("host-%d.example.com", i), records)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		limit := 10
		for range tree.Seek("host-5000.example.com") {
			if limit == 0 {
				break
			}
			limit--
		}
	}
}
