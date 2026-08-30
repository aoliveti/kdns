// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snapshot

import (
	"bytes"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
)

// FuzzSnapshot_Load tests the resilience of the snapshot decoder against arbitrary
// or malformed byte sequences, ensuring it handles corruption safely without panicking.
func FuzzSnapshot_Load(f *testing.F) {
	tree := radix.New()
	r1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	r2, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{r1, r2}}}
	tree.Upsert("example.com", records)

	var buf bytes.Buffer
	if err := Save(&buf, tree); err != nil {
		f.Fatalf("failed to prepare seed snapshot: %v", err)
	}
	f.Add(buf.Bytes())

	f.Fuzz(func(_ *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_ = Load(r, func(_ string, _ dns.RRSets) {
			// No-op consumption during fuzzing.
		})
	})
}
