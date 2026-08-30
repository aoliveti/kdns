// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snapshot

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
)

func BenchmarkSnapshot_Save(b *testing.B) {
	tree := radix.New()
	r1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	r2, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{r1, r2}}}

	for i := range 10_000 {
		domain := fmt.Sprintf("host-%d.example.com", i)
		tree.Upsert(domain, records)
	}

	var buf bytes.Buffer
	if err := Save(&buf, tree); err != nil {
		b.Fatalf("failed to calculate snapshot size: %v", err)
	}
	b.SetBytes(int64(buf.Len()))
	b.ReportMetric(float64(buf.Len()), "bytes/snap")

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = Save(io.Discard, tree)
	}
}

func BenchmarkSnapshot_Load(b *testing.B) {
	tree := radix.New()
	r1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	r2, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{r1, r2}}}

	for i := range 10_000 {
		domain := fmt.Sprintf("host-%d.example.com", i)
		tree.Upsert(domain, records)
	}

	var buf bytes.Buffer
	if err := Save(&buf, tree); err != nil {
		b.Fatalf("failed to prepare snapshot buffer: %v", err)
	}
	data := buf.Bytes()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		r := bytes.NewReader(data)
		_ = Load(r, func(_ string, _ dns.RRSets) {})
	}
}

func BenchmarkSnapshot_RestoreIntoRadix(b *testing.B) {
	tree := radix.New()
	r1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	r2, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{r1, r2}}}

	for i := range 10_000 {
		domain := fmt.Sprintf("host-%d.example.com", i)
		tree.Upsert(domain, records)
	}

	var buf bytes.Buffer
	if err := Save(&buf, tree); err != nil {
		b.Fatalf("failed to prepare snapshot buffer: %v", err)
	}
	data := buf.Bytes()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		r := bytes.NewReader(data)
		target := radix.New()
		_ = target.ReloadZone(func(onRecord func(string, dns.RRSets)) error {
			return Load(r, onRecord)
		})
	}
}
