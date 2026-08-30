// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rrl

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

// BenchmarkLimiter_Check evaluates baseline sequential throughput on a single CPU core.
func BenchmarkLimiter_Check(b *testing.B) {
	limiter := New(DefaultConfig())
	ip := netip.MustParseAddr("192.0.2.10")
	domain := "bench.example.com"

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		_ = limiter.Check(ip, domain, dns.RCodeSuccess)
	}
}

// BenchmarkLimiter_CheckParallel_SingleSubnetContention measures worst-case lock contention.
// All goroutines query the identical IP and domain, forcing all CPU cores to synchronize on a single shard mutex.
func BenchmarkLimiter_CheckParallel_SingleSubnetContention(b *testing.B) {
	limiter := New(DefaultConfig())
	ip := netip.MustParseAddr("192.0.2.10")
	domain := "bench.example.com"

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = limiter.Check(ip, domain, dns.RCodeSuccess)
		}
	})
}

// BenchmarkLimiter_CheckParallel_DistributedSubnets evaluates multi-core throughput across distinct subnets.
// Queries are partitioned across all 64 memory shards to demonstrate zero-allocation scalability and lock striping.
func BenchmarkLimiter_CheckParallel_DistributedSubnets(b *testing.B) {
	limiter := New(DefaultConfig())
	domain := "bench.example.com"
	var counter atomic.Uint32

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := counter.Add(1)
			// #nosec G115
			ip := netip.AddrFrom4([4]byte{192, byte(id >> 8), byte(id), 1})
			_ = limiter.Check(ip, domain, dns.RCodeSuccess)
		}
	})
}
