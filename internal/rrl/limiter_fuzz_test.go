// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rrl

import (
	"net/netip"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

func FuzzLimiter_Check(f *testing.F) {
	f.Add([]byte{192, 0, 2, 1}, "example.com", uint8(0), uint32(1700000000))
	f.Add([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "sub.domain.org", uint8(3), uint32(1700000001))
	f.Add([]byte{127, 0, 0, 1}, "", uint8(2), uint32(0))
	f.Add([]byte{10, 0, 0, 5}, "*.wildcard.test", uint8(1), uint32(4294967295))

	limiter := New(DefaultConfig())

	f.Fuzz(func(t *testing.T, ipBytes []byte, domain string, rCode uint8, timestamp uint32) {
		ip, ok := netip.AddrFromSlice(ipBytes)
		if !ok {
			return
		}

		action := limiter.checkAt(ip, domain, dns.RCode(rCode), timestamp)
		if action != ActionAllow && action != ActionDrop && action != ActionSlip {
			t.Fatalf("unexpected action: %v", action)
		}
	})
}
