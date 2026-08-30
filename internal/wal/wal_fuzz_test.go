// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wal

import (
	"bytes"
	"os"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

// FuzzWAL_Replay tests that Replay never panics on arbitrary,
// corrupted, or truncated binary streams.
func FuzzWAL_Replay(f *testing.F) {
	r1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	seedRecords := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r1}},
	}

	root, err := os.OpenRoot(f.TempDir())
	if err == nil {
		defer func() { _ = root.Close() }()
		file, openErr := root.OpenFile("seed.wal", os.O_CREATE|os.O_RDWR, 0o600)
		if openErr == nil {
			w := NewWriter(file)
			_ = w.AppendUpsert("example.com", seedRecords)
			_ = w.AppendDelete("example.com")
			_ = w.Flush()
			_ = file.Close()

			data, readErr := root.ReadFile("seed.wal")
			if readErr == nil {
				f.Add(data)
			}
		}
	}

	f.Add([]byte{OpUpsert, 0x00, 0x01, 0xFF})
	f.Add([]byte{OpDelete, 0x00, 0x10, 'a', 'b', 'c'})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		reader := bytes.NewReader(data)

		_ = Replay(
			reader,
			func(_ string, _ dns.RRSets) {},
			func(_ string) {},
		)
	})
}
