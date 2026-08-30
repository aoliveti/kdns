// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"io"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

func BenchmarkMetrics_IncQueriesParallel(b *testing.B) {
	m := New()
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.IncQueriesUDP()
			m.IncResponses(dns.RCodeSuccess)
		}
	})
}

func BenchmarkMetrics_WriteTo(b *testing.B) {
	m := New(WithBuildInfo("1.0.0", "abc1234", "2026-08-13"))
	m.IncQueriesUDP()
	m.IncResponses(dns.RCodeSuccess)
	m.SetDomains(7364)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = m.WriteTo(io.Discard)
	}
}
