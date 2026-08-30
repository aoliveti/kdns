// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/metrics"
)

func BenchmarkServer_Resolve(b *testing.B) {
	res := newPopulatedFakeResolver()
	queryBytes := buildQuery(b, "example.com", dns.TypeA)

	b.Run("WithMetrics", func(b *testing.B) {
		srv := New(res, WithMetrics(metrics.New()))
		respBuf := make([]byte, dns.MaxUDPSize)
		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			_, _, _, _ = srv.resolve(queryBytes, respBuf, dns.MaxUDPSize)
		}
	})

	b.Run("WithNopMetrics", func(b *testing.B) {
		srv := New(res)
		respBuf := make([]byte, dns.MaxUDPSize)
		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			_, _, _, _ = srv.resolve(queryBytes, respBuf, dns.MaxUDPSize)
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		srv := New(res, WithMetrics(metrics.New()))
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			buf := make([]byte, dns.MaxUDPSize)
			for pb.Next() {
				_, _, _, _ = srv.resolve(queryBytes, buf, dns.MaxUDPSize)
			}
		})
	})
}
