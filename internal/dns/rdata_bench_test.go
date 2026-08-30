// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "testing"

func BenchmarkPackRData_A(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = PackRData(TypeA, "192.0.2.1")
	}
}

func BenchmarkPackRData_SOA(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = PackRData(TypeSOA, "ns1.example.com admin.example.com 2026081201 7200 3600 1209600 3600")
	}
}

func BenchmarkUnpackRData_A(b *testing.B) {
	wire, _ := PackRData(TypeA, "192.0.2.1")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = UnpackRData(TypeA, wire)
	}
}
