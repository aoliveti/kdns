// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zone

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

func FuzzZone_Parse(f *testing.F) {
	f.Add([]byte("$TTL 3600\n$ORIGIN example.com.\nwww IN A 192.0.2.1\n"))
	f.Add([]byte("example.com. IN SOA ns1.example.com. admin.example.com. ( 2026081201 7200 3600 1209600 3600 )\n"))
	f.Add([]byte("example.com. IN DNSKEY 256 3 8 AwEAAag=\n"))
	f.Add([]byte("example.com. IN DS 60999 8 2 2BB1832F\n"))
	f.Add([]byte("example.com. IN RRSIG A 8 2 300 20260901000000 20260801000000 60999 example.com. AwEAAag=\n"))
	f.Add([]byte("example.com. IN NSEC next.example.com. A AAAA RRSIG NSEC\n"))
	f.Add([]byte("example.com. IN NSEC3 1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3\n"))
	f.Add([]byte("example.com. IN ZONEMD 2026081201 1 1 09BE1F9856A15F431C8B9A2E12345678\n"))
	f.Add([]byte("malformed line without spaces"))
	f.Add([]byte("$ORIGIN \n"))
	f.Add([]byte(strings.Repeat("a", 300) + " IN A 192.0.2.1\n"))
	f.Add([]byte("; comment only\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_ = Parse(r, func(_ string, _ dns.RRSets) {})
	})
}
