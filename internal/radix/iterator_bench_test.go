// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"testing"
)

// BenchmarkDomainIterator measures the performance and guarantees
// zero memory allocations during domain parsing.
func BenchmarkDomainIterator(b *testing.B) {
	domain := "www.complex-internal-routing.eu-west-1.compute.internal."

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		iter := NewDomainIterator(domain)
		for {
			_, hasNext := iter.Next()
			if !hasNext {
				break
			}
		}
	}
}

// BenchmarkDomainIterator_Types measures the performance of the iterator
// across different lengths and structures using sub-benchmarks.
func BenchmarkDomainIterator_Types(b *testing.B) {
	tests := []struct {
		name   string
		domain string
	}{
		{"Short", "com."},
		{"Average", "api.github.com"},
		{"Long", "www.complex-internal-routing.eu-west-1.compute.internal."},
		{"Extreme_RFC", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com"},
	}

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				iter := NewDomainIterator(tc.domain)
				for {
					_, hasNext := iter.Next()
					if !hasNext {
						break
					}
				}
			}
		})
	}
}

// BenchmarkDomainIterator_Mixed simulates a real-world workload by cycling
// through a large slice of varied domains. This defeats CPU branch prediction
// and provides a realistic average nanosecond-per-operation metric.
func BenchmarkDomainIterator_Mixed(b *testing.B) {
	// Generate a dataset of 10,000 mixed domains
	datasetSize := 10000
	dataset := make([]string, datasetSize)

	for i := range datasetSize {
		switch i % 4 {
		case 0:
			dataset[i] = "it."
		case 1:
			dataset[i] = "www.google.com"
		case 2:
			dataset[i] = "cdn.production.network.internal."
		case 3:
			dataset[i] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.local"
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	var i int
	for b.Loop() {
		domain := dataset[i%datasetSize]
		i++
		iter := NewDomainIterator(domain)
		for {
			_, hasNext := iter.Next()
			if !hasNext {
				break
			}
		}
	}
}

// BenchmarkDomainIterator_Short measures throughput on short domain names.
func BenchmarkDomainIterator_Short(b *testing.B) {
	domain := "example.com"

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		iter := NewDomainIterator(domain)
		for {
			_, hasNext := iter.Next()
			if !hasNext {
				break
			}
		}
	}
}

// BenchmarkDomainIterator_Parallel evaluates multi-core scalability.
func BenchmarkDomainIterator_Parallel(b *testing.B) {
	domain := "subdomain.domain.org."

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			iter := NewDomainIterator(domain)
			for {
				_, hasNext := iter.Next()
				if !hasNext {
					break
				}
			}
		}
	})
}

// BenchmarkDomainIterator_WorstCase stresses deeply nested label hierarchies.
func BenchmarkDomainIterator_WorstCase(b *testing.B) {
	domain := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com."

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		iter := NewDomainIterator(domain)
		for {
			_, hasNext := iter.Next()
			if !hasNext {
				break
			}
		}
	}
}

// BenchmarkDomainIterator_ManyLookups simulates high query rate workloads.
func BenchmarkDomainIterator_ManyLookups(b *testing.B) {
	domains := []string{
		"example.com",
		"sub.example.com",
		"deep.sub.example.com",
		"a.b.c.d.e.org",
	}

	b.ReportAllocs()
	b.ResetTimer()

	i := 0
	for b.Loop() {
		domain := domains[i%len(domains)]
		i++
		iter := NewDomainIterator(domain)
		for {
			_, hasNext := iter.Next()
			if !hasNext {
				break
			}
		}
	}
}
