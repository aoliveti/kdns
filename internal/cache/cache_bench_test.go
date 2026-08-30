// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cache

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

// BenchmarkCache_Set_SteadyState measures write throughput and allocations when the cache
// is fully saturated, verifying zero-allocation node recycling in steady state.
func BenchmarkCache_Set_SteadyState(b *testing.B) {
	const capacity = 100_000
	c := New(capacity)
	wireA, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

	// Pre-fill the cache to 100% capacity to trigger steady-state eviction
	for i := range capacity {
		c.Set(Key{Name: fmt.Sprintf("prefill-%d.com", i), Type: dns.TypeA}, record, time.Hour)
	}

	const keySpace = 500_000
	keys := make([]Key, keySpace)
	for i := range keySpace {
		keys[i] = Key{Name: fmt.Sprintf("steady-%d.com", i), Type: dns.TypeA}
	}

	b.ReportAllocs()
	b.ResetTimer()

	var i int
	for b.Loop() {
		c.Set(keys[i%keySpace], record, 5*time.Minute)
		i++
	}
}

// BenchmarkCache_Get_HotKey measures lookup latency on the most frequently accessed domain,
// verifying the fast-path bypass of LRU pointer manipulation.
func BenchmarkCache_Get_HotKey(b *testing.B) {
	c := New(100_000)
	wireA, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

	hotKey := Key{Name: "apex.example.com", Type: dns.TypeA}
	c.Set(hotKey, record, time.Hour)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = c.Get(hotKey)
	}
}

// BenchmarkCache_Get_ColdKey measures lookup latency on non-head elements
// to establish the cost of full doubly linked list pointer updates.
func BenchmarkCache_Get_ColdKey(b *testing.B) {
	const capacity = 1000
	c := New(capacity)
	wireA, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

	targetShard := &c.shards[0]
	var keysInSameShard []Key
	for i := 0; len(keysInSameShard) < 10; i++ {
		k := Key{Name: fmt.Sprintf("cold-%d.com", i), Type: dns.TypeA}
		if c.getShard(k) == targetShard {
			keysInSameShard = append(keysInSameShard, k)
			c.Set(k, record, time.Hour)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	var i int
	for b.Loop() {
		// Alternate between tail and intermediate keys to force full LRU list restructuring
		key := keysInSameShard[i%len(keysInSameShard)]
		_, _ = c.Get(key)
		i++
	}
}

// BenchmarkCache_SetSequential establishes a single-core baseline for insertions.
func BenchmarkCache_SetSequential(b *testing.B) {
	c := New(100_000)
	wireA, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

	const keySpace = 100_000
	keys := make([]Key, keySpace)
	for i := range keySpace {
		keys[i] = Key{Name: fmt.Sprintf("d-%d.com", i), Type: dns.TypeA}
	}

	b.ReportAllocs()
	b.ResetTimer()

	var i int
	for b.Loop() {
		c.Set(keys[i%keySpace], record, 5*time.Minute)
		i++
	}
}

// BenchmarkCache_GetSequential establishes a single-core baseline for lookups.
func BenchmarkCache_GetSequential(b *testing.B) {
	c := New(100_000)
	wireA, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

	key := Key{Name: "target.com", Type: dns.TypeA}
	c.Set(key, record, 5*time.Minute)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		c.Get(key)
	}
}

// BenchmarkCache_SetParallel evaluates concurrent write throughput across partitioned shards.
func BenchmarkCache_SetParallel(b *testing.B) {
	c := New(100_000)
	wireA, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

	const keySpace = 100_000
	keys := make([]Key, keySpace)
	for i := range keySpace {
		keys[i] = Key{Name: fmt.Sprintf("domain-%d.com", i), Type: dns.TypeA}
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		// #nosec G404
		i := rand.IntN(keySpace)
		for pb.Next() {
			c.Set(keys[i], record, 5*time.Minute)
			i++
			if i >= keySpace {
				i = 0
			}
		}
	})
}

// BenchmarkCache_GetParallel evaluates concurrent read throughput and LRU promotions.
func BenchmarkCache_GetParallel(b *testing.B) {
	c := New(100_000)
	wireA, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

	const keySpace = 50_000
	keys := make([]Key, keySpace)
	for i := range keySpace {
		keys[i] = Key{Name: fmt.Sprintf("domain-%d.com", i), Type: dns.TypeA}
		c.Set(keys[i], record, 5*time.Minute)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		// #nosec G404
		i := rand.IntN(keySpace)
		for pb.Next() {
			c.Get(keys[i])
			i++
			if i >= keySpace {
				i = 0
			}
		}
	})
}

// BenchmarkCache_MixedParallel simulates an authoritative DNS workload (90% lookups, 10% insertions).
func BenchmarkCache_MixedParallel(b *testing.B) {
	c := New(100_000)
	wireA, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

	const keySpace = 100_000
	keys := make([]Key, keySpace)
	for i := range keySpace {
		keys[i] = Key{Name: fmt.Sprintf("domain-%d.com", i), Type: dns.TypeA}
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		// #nosec G404
		i := rand.IntN(keySpace)
		opCount := 0
		for pb.Next() {
			key := keys[i]
			if opCount%10 == 0 {
				c.Set(key, record, 5*time.Minute)
			}
			if opCount%10 != 0 {
				c.Get(key)
			}

			i++
			if i >= keySpace {
				i = 0
			}
			opCount++
		}
	})
}
