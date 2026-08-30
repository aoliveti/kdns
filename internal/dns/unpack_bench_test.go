// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "testing"

// BenchmarkMessage_Unpack evaluates the CPU efficiency and zero-allocation performance of wire query unpacking.
func BenchmarkMessage_Unpack(b *testing.B) {
	payload := validQuery()
	var m Message

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = m.Unpack(payload)
	}
}
