// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnssec

import (
	"slices"

	"github.com/aoliveti/kdns/internal/dns"
)

// NSEC creates a Next Secure record with RFC 4034 §4 windowed type bitmaps.
func NSEC(owner, nextOwner string, types []dns.Type, ttl uint32) (dns.RRSet, error) {
	_ = owner
	nextWire := dns.EncodeDomainName(nextOwner)

	allTypes := make([]dns.Type, 0, len(types)+2)
	allTypes = append(allTypes, types...)
	if !slices.Contains(allTypes, dns.TypeRRSIG) {
		allTypes = append(allTypes, dns.TypeRRSIG)
	}
	if !slices.Contains(allTypes, dns.TypeNSEC) {
		allTypes = append(allTypes, dns.TypeNSEC)
	}

	bitmaps := encodeWindowedBitmaps(allTypes)

	wire := make([]byte, len(nextWire)+len(bitmaps))
	copy(wire, nextWire)
	copy(wire[len(nextWire):], bitmaps)

	return dns.RRSet{
		Type:  dns.TypeNSEC,
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: [][]byte{wire},
	}, nil
}

func encodeWindowedBitmaps(types []dns.Type) []byte {
	// RFC 4034 §4.1.2: Group types into 256-type window blocks.
	windows := make(map[byte][]byte)

	for _, t := range types {
		window := byte(t >> 8)
		typeLow := byte(t & 0xFF)
		byteIndex := typeLow / 8
		bitIndex := 7 - (typeLow % 8)

		bm := windows[window]
		if int(byteIndex) >= len(bm) {
			newBM := make([]byte, byteIndex+1)
			copy(newBM, bm)
			bm = newBM
		}
		bm[byteIndex] |= 1 << bitIndex
		windows[window] = bm
	}

	windowNums := make([]byte, 0, len(windows))
	for w := range windows {
		windowNums = append(windowNums, w)
	}
	slices.Sort(windowNums)

	var out []byte
	for _, w := range windowNums {
		bm := windows[w]
		out = append(out, w, byte(len(bm))) //nolint:gosec // bitmap length is at most 32 bytes
		out = append(out, bm...)
	}

	return out
}
