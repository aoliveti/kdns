// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "testing"

// BenchmarkMessage_PackResponse evaluates the CPU efficiency and zero-allocation performance of the serializer.
func BenchmarkMessage_PackResponse(b *testing.B) {
	msg := Message{
		Header: Header{
			ID: 5678,
		},
		Questions: []Question{
			{
				Name:  "high-traffic-domain.com",
				Type:  TypeA,
				Class: ClassIN,
			},
		},
		EDNS0Size: 4096,
	}

	r1, _ := PackRData(TypeA, "203.0.113.5")
	r2, _ := PackRData(TypeA, "203.0.113.6")
	record := RRSet{
		Type:  TypeA,
		Class: ClassIN,
		TTL:   60,
		RData: [][]byte{r1, r2},
	}

	res := Result{
		RCode:  RCodeSuccess,
		Answer: record,
	}

	buf := make([]byte, 4096)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = msg.PackResponse(buf, res, 4096)
	}
}
