// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"fmt"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/state"
)

func BenchmarkStore_Upsert(b *testing.B) {
	tmpDir := b.TempDir()
	st := state.New(1024)
	s, err := Open(tmpDir, st, WithCompactionThreshold(1_000_000_000), WithLogger(discardLogger))
	if err != nil {
		b.Fatalf("failed to open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	r1, _ := dns.PackRData(dns.TypeA, "192.0.2.10")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{r1}},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; b.Loop(); i++ {
		domain := fmt.Sprintf("host-%d.example.com", i)
		_ = s.Upsert(domain, records)
	}
}
