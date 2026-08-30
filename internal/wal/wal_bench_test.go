// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wal

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func BenchmarkWAL_AppendUpsert(b *testing.B) {
	file := createBenchTempFile(b)
	w := NewWriter(file)

	r1, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	r2, _ := dns.PackRData(dns.TypeA, "10.0.0.2")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r1, r2}},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		err := w.AppendUpsert("example.com", records)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWAL_AppendDelete(b *testing.B) {
	file := createBenchTempFile(b)
	w := NewWriter(file)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		err := w.AppendDelete("example.com")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWAL_ReplayThroughput(b *testing.B) {
	root, err := os.OpenRoot(b.TempDir())
	require.NoError(b, err)
	defer func() { _ = root.Close() }()

	file, err := root.OpenFile("bench_replay.wal", os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(b, err)
	defer func() {
		_ = file.Close()
	}()

	w := NewWriter(file)
	r1, _ := dns.PackRData(dns.TypeA, "192.168.1.100")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r1}},
	}

	const recordCount = 10000
	for range recordCount {
		err = w.AppendUpsert("benchmark-domain.com", records)
		require.NoError(b, err)
	}
	require.NoError(b, w.Flush())

	data, err := root.ReadFile("bench_replay.wal")
	require.NoError(b, err)

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		reader := bytes.NewReader(data)
		err := Replay(
			reader,
			func(_ string, _ dns.RRSets) {},
			func(_ string) {},
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWAL_Replay_Mixed(b *testing.B) {
	root, err := os.OpenRoot(b.TempDir())
	require.NoError(b, err)
	defer func() { _ = root.Close() }()

	file, err := root.OpenFile("bench_mixed.wal", os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(b, err)
	defer func() {
		_ = file.Close()
	}()

	w := NewWriter(file)
	r1, _ := dns.PackRData(dns.TypeA, "1.2.3.4")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r1}},
	}

	const totalOperations = 5000
	for i := range totalOperations {
		domain := fmt.Sprintf("mixed-node-%d.example.com", i)
		if i%3 == 0 {
			require.NoError(b, w.AppendDelete(domain))
			continue
		}
		require.NoError(b, w.AppendUpsert(domain, records))
	}
	require.NoError(b, w.Flush())

	data, err := root.ReadFile("bench_mixed.wal")
	require.NoError(b, err)

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		reader := bytes.NewReader(data)
		err := Replay(
			reader,
			func(_ string, _ dns.RRSets) {},
			func(_ string) {},
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func createBenchTempFile(b *testing.B) *os.File {
	b.Helper()
	root, err := os.OpenRoot(b.TempDir())
	require.NoError(b, err)
	file, err := root.OpenFile("bench.wal", os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(b, err)
	b.Cleanup(func() {
		_ = file.Close()
		_ = root.Close()
	})
	return file
}
