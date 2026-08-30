// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package state

import (
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
)

func BenchmarkState_Resolve_CacheHit(b *testing.B) {
	st := New(10000)
	tree := radix.New()
	tree.Upsert("bench.example.com", dns.RRSets{
		dns.NewRRSet(dns.TypeA, 300, "1.2.3.4"),
	})
	st.Swap(tree)

	// Warmup cache
	_ = st.Resolve("bench.example.com", dns.TypeA)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = st.Resolve("bench.example.com", dns.TypeA)
		}
	})
}
