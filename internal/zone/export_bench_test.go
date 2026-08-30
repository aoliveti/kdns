// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zone

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"strings"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

func BenchmarkZone_FormatSmall(b *testing.B) {
	records := map[string]dns.RRSets{
		"example.com": {
			dns.NewRRSet(dns.TypeSOA, 3600, "ns1.example.com. hostmaster.example.com. 2026082701 7200 3600 1209600 300"),
			dns.NewRRSet(dns.TypeNS, 3600, "ns1.example.com.", "ns2.example.com."),
			dns.NewRRSet(dns.TypeA, 3600, "192.0.2.1"),
			dns.NewRRSet(dns.TypeTXT, 3600, "v=spf1 include:_spf.example.com ~all"),
			dns.NewRRSet(dns.TypeCAA, 3600, `0 issue "letsencrypt.org"`),
		},
		"www.example.com": {
			dns.NewRRSet(dns.TypeA, 300, "192.0.2.10"),
		},
		"mail.example.com": {
			dns.NewRRSet(dns.TypeMX, 3600, "10 mail.example.com."),
		},
	}

	var buf bytes.Buffer
	if err := FormatZone(&buf, "example.com", maps.All(records)); err != nil {
		b.Fatalf("failed setup: %v", err)
	}
	b.SetBytes(int64(buf.Len()))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = FormatZone(io.Discard, "example.com", maps.All(records))
	}
}

func BenchmarkZone_Format10kRecords(b *testing.B) {
	records := make(map[string]dns.RRSets, 10000)
	soaWire, _ := dns.PackRData(dns.TypeSOA, "ns1.example.com. hostmaster.example.com. 2026082701 7200 3600 1209600 300")
	nsWire, _ := dns.PackRData(dns.TypeNS, "ns1.example.com.")

	records["example.com"] = dns.RRSets{
		{
			Type:  dns.TypeSOA,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: [][]byte{soaWire},
		},
		{
			Type:  dns.TypeNS,
			Class: dns.ClassIN,
			TTL:   3600,
			RData: [][]byte{nsWire},
		},
	}

	for i := range 10000 {
		domain := fmt.Sprintf("host%d.example.com", i)
		aWire, _ := dns.PackRData(dns.TypeA, fmt.Sprintf("192.0.2.%d", (i%250)+1))
		records[domain] = dns.RRSets{
			{
				Type:  dns.TypeA,
				Class: dns.ClassIN,
				TTL:   300,
				RData: [][]byte{aWire},
			},
		}
	}

	var sample bytes.Buffer
	if err := Format(io.MultiWriter(&sample, io.Discard), maps.All(records)); err != nil {
		b.Fatalf("failed setup: %v", err)
	}
	b.SetBytes(int64(sample.Len()))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Format(io.Discard, maps.All(records))
	}
}

func BenchmarkZone_FormatFilteredSingleZone(b *testing.B) {
	records := make(map[string]dns.RRSets, 10000)
	for i := range 5000 {
		domainA := fmt.Sprintf("host%d.example.com", i)
		domainB := fmt.Sprintf("host%d.othercorp.org", i)
		aWire, _ := dns.PackRData(dns.TypeA, "192.0.2.1")
		records[domainA] = dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{aWire}}}
		records[domainB] = dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{aWire}}}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = FormatZone(io.Discard, "example.com", maps.All(records))
	}
}

func BenchmarkZone_FormatAndParseRoundTrip(b *testing.B) {
	records := map[string]dns.RRSets{
		"example.com": {
			dns.NewRRSet(dns.TypeSOA, 3600, "ns1.example.com. hostmaster.example.com. 2026082701 7200 3600 1209600 300"),
			dns.NewRRSet(dns.TypeNS, 3600, "ns1.example.com.", "ns2.example.com."),
			dns.NewRRSet(dns.TypeA, 3600, "192.0.2.1"),
		},
		"www.example.com": {
			dns.NewRRSet(dns.TypeA, 300, "192.0.2.10"),
		},
	}

	var buf bytes.Buffer
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		buf.Reset()
		_ = FormatZone(&buf, "example.com", maps.All(records))
		_ = Parse(strings.NewReader(buf.String()), func(_ string, _ dns.RRSets) {})
	}
}
