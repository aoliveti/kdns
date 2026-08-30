// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

func FuzzTree_Operations(f *testing.F) {
	f.Add("example.com")
	f.Add("*.example.com")
	f.Add("sub.example.com")
	f.Add(".")
	f.Add("a.b.c.d.e.f.com")
	f.Add("..invalid..dots..")

	r1, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r1}},
	}

	f.Fuzz(func(_ *testing.T, domain string) {
		tree := New()
		tree.Upsert(domain, records)
		_ = tree.Resolve(domain, dns.TypeA)
		_, _ = tree.Get(domain)
		tree.DeleteDomain(domain)
		_ = tree.Resolve(domain, dns.TypeA)
	})
}
