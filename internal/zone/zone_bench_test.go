// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zone

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

func BenchmarkZone_ParseSmall(b *testing.B) {
	zoneData := `
	$TTL 3600
	$ORIGIN example.com.
	@       IN  SOA ns1.example.com. admin.example.com. 2026010101 7200 3600 1209600 3600
	@       IN  NS  ns1.example.com.
	www     IN  A   192.0.2.10
	`

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Parse(strings.NewReader(zoneData), func(_ string, _ dns.RRSets) {})
	}
}

func BenchmarkZone_Parse10kRecords(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("$TTL 3600\n$ORIGIN example.com.\n")
	for i := range 10000 {
		_, _ = fmt.Fprintf(&sb, "host%d IN A 192.0.2.%d\n", i, i%255)
	}
	data := sb.String()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Parse(strings.NewReader(data), func(_ string, _ dns.RRSets) {})
	}
}

func BenchmarkZone_ParseRootZone(b *testing.B) {
	testdataRoot, err := os.OpenRoot("testdata")
	if err != nil {
		b.Fatalf("failed to open testdata root: %v", err)
	}
	defer func() { _ = testdataRoot.Close() }()

	data, err := testdataRoot.ReadFile("root.zone")
	if err != nil {
		b.Fatalf("failed to read testdata/root.zone: %v", err)
	}

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = Parse(bytes.NewReader(data), func(_ string, _ dns.RRSets) {})
	}
}

func BenchmarkZone_Parse_DNSSEC(b *testing.B) {
	zoneData := `
	$TTL 1d
	$ORIGIN secure.example.com.
	@ IN SOA ns1.secure.example.com. admin.secure.example.com. 2026081601 7200 3600 1209600 3600
	@ IN NS ns1.secure.example.com.
	@ IN DNSKEY 256 3 8 AwEAAag=
	@ IN DS 60999 8 2 2BB1832F
	@ IN RRSIG A 8 2 300 20260901000000 20260801000000 60999 secure.example.com. AwEAAag=
	@ IN NSEC next.secure.example.com. A AAAA RRSIG NSEC
	@ IN NSEC3 1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3
	@ IN ZONEMD 2026081201 1 1 09BE1F9856A15F431C8B9A2E12345678
	`

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = Parse(strings.NewReader(zoneData), func(_ string, _ dns.RRSets) {})
	}
}
