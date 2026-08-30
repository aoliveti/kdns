// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/state"
)

func TestStore_Compaction(t *testing.T) {
	t.Parallel()

	t.Run("ManualCompaction", func(t *testing.T) {
		t.Parallel()
		storeDir := t.TempDir()
		st := state.New(1024)
		s, err := Open(storeDir, st, WithLogger(discardLogger))
		require.NoError(t, err)

		records := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.0.2.1")}}}
		require.NoError(t, s.Upsert("compact1.example.com", records))
		require.NoError(t, s.Upsert("compact2.example.com", records))
		require.NoError(t, s.walWriter.Flush())

		walPath := filepath.Join(storeDir, walFileName)
		infoBefore, err := os.Stat(walPath)
		require.NoError(t, err)
		sizeBefore := infoBefore.Size()

		require.NoError(t, s.Compact("manual_test"))

		infoAfter, err := os.Stat(walPath)
		require.NoError(t, err)
		sizeAfter := infoAfter.Size()

		assert.Less(t, sizeAfter, sizeBefore)
		assert.Equal(t, int64(0), sizeAfter)

		res := st.Resolve("compact1.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
		require.NoError(t, s.Close())
	})

	t.Run("ThresholdTrigger", func(t *testing.T) {
		t.Parallel()
		st := state.New(1024)
		s, err := Open(t.TempDir(), st, WithCompactionThreshold(100), WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		records := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.0.2.1")}}}

		for i := range 100 {
			domain := fmt.Sprintf("host%d.example.com", i)
			require.NoError(t, s.Upsert(domain, records))
		}

		time.Sleep(100 * time.Millisecond)

		s.mu.RLock()
		count := s.mutationsCount
		s.mu.RUnlock()
		assert.Equal(t, uint64(0), count)
	})

	t.Run("CompactionLoop", func(t *testing.T) {
		t.Parallel()
		st := state.New(1024)
		s, err := Open(
			t.TempDir(),
			st,
			WithCompactionThreshold(1_000_000),
			WithLogger(discardLogger),
		)
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		var wg sync.WaitGroup
		wg.Go(func() {
			s.compactionLoop(ctx, 10*time.Millisecond)
		})

		require.NoError(t, s.Upsert("loop.example.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}},
		}))

		time.Sleep(50 * time.Millisecond)
		cancel()
		wg.Wait()
	})
}

func TestStore_CompactDoesNotBlockMutations(t *testing.T) {
	t.Parallel()

	s, err := Open(t.TempDir(), state.New(100), WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	go func() { _ = s.Compact("test") }()
	time.Sleep(10 * time.Millisecond) // Let it acquire locks

	start := time.Now()
	_ = s.Upsert("test.com", dns.RRSets{})
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("Upsert was blocked by Compact disk I/O")
	}
}

func TestStore_CleanStaleTempFilesOnStartup(t *testing.T) {
	t.Parallel()

	storeDir := t.TempDir()
	staleFile1 := filepath.Join(storeDir, "state-snap-12345.tmp")
	staleFile2 := filepath.Join(storeDir, "state-snap-67890.tmp")
	keepFile := filepath.Join(storeDir, "keep-me.txt")

	require.NoError(t, os.WriteFile(staleFile1, []byte("stale1"), 0o600))
	require.NoError(t, os.WriteFile(staleFile2, []byte("stale2"), 0o600))
	require.NoError(t, os.WriteFile(keepFile, []byte("keep"), 0o600))

	st := state.New(1024)
	s, err := Open(storeDir, st, WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	assert.NoFileExists(t, staleFile1, "stale temp file 1 must be cleaned up on Open")
	assert.NoFileExists(t, staleFile2, "stale temp file 2 must be cleaned up on Open")
	assert.FileExists(t, keepFile, "unrelated files must not be touched")
}

func TestStore_CompactionUniqueTempFiles(t *testing.T) {
	t.Parallel()

	storeDir := t.TempDir()
	st := state.New(1024)
	s, err := Open(storeDir, st, WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	records := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.0.2.1")}}}
	require.NoError(t, s.Upsert("unique-temp.example.com", records))

	require.NoError(t, s.Compact("test_unique"))

	entries, err := os.ReadDir(storeDir)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, filepath.Ext(entry.Name()) == ".tmp", "no leftover .tmp files should exist after compaction: %s", entry.Name())
	}
}
