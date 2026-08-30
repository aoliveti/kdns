// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/state"
)

var discardLogger = slog.New(slog.DiscardHandler)

func TestStore_BootstrapAndLifecycle(t *testing.T) {
	t.Parallel()

	zoneContent := `
$TTL 3600
$ORIGIN example.com.
@       IN  SOA ns1.example.com. admin.example.com. 2026010101 7200 3600 1209600 3600
www     IN  A   192.0.2.10
`

	t.Run("NilStateReturnsError", func(t *testing.T) {
		t.Parallel()
		storeDir := t.TempDir()
		_, err := Open(storeDir, nil, WithLogger(discardLogger))
		require.ErrorIs(t, err, ErrNilState)
	})

	t.Run("BootstrapFromZoneFile", func(t *testing.T) {
		t.Parallel()
		storeDir := filepath.Join(t.TempDir(), "store_zone")
		require.NoError(t, os.MkdirAll(storeDir, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(storeDir, "test.zone"), []byte(zoneContent), 0o600))

		st := state.New(1024)
		s, err := Open(storeDir, st, WithZoneFile("test.zone"), WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		res := st.Resolve("www.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)

		_, err = os.Stat(filepath.Join(storeDir, snapFileName))
		assert.NoError(t, err)
	})

	t.Run("CompactionThresholdTooLow", func(t *testing.T) {
		t.Parallel()
		storeDir := filepath.Join(t.TempDir(), "store_low_thresh")
		st := state.New(1024)
		_, err := Open(storeDir, st, WithCompactionThreshold(50))
		require.ErrorIs(t, err, ErrCompactionThresholdTooLow)
	})

	t.Run("CompactionIntervalTooLow", func(t *testing.T) {
		t.Parallel()
		storeDir := filepath.Join(t.TempDir(), "store_low_interval")
		st := state.New(1024)
		_, err := Open(storeDir, st, WithCompactionInterval(10*time.Second))
		require.ErrorIs(t, err, ErrCompactionIntervalTooLow)
	})

	t.Run("BootstrapFromOfficialRootZone", func(t *testing.T) {
		t.Parallel()
		testdataRoot, err := os.OpenRoot(filepath.Join("..", "zone", "testdata"))
		require.NoError(t, err)
		defer func() { _ = testdataRoot.Close() }()

		rootZoneData, err := testdataRoot.ReadFile("root.zone")
		require.NoError(t, err)

		storeDir := filepath.Join(t.TempDir(), "store_root_zone")
		require.NoError(t, os.MkdirAll(storeDir, 0o750))
		storeRoot, err := os.OpenRoot(storeDir)
		require.NoError(t, err)
		defer func() { _ = storeRoot.Close() }()

		require.NoError(t, storeRoot.WriteFile("root.zone", rootZoneData, 0o600))

		st := state.New(1024)
		s, err := Open(storeDir, st, WithZoneFile("root.zone"), WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		res := st.Resolve(".", dns.TypeNS)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)

		resCom := st.Resolve("com.", dns.TypeNS)
		assert.Equal(t, dns.RCodeSuccess, resCom.RCode)
	})

	t.Run("BootstrapFromExternalZoneFilePath", func(t *testing.T) {
		t.Parallel()
		externalDir := filepath.Join(t.TempDir(), "external_zone")
		require.NoError(t, os.MkdirAll(externalDir, 0o750))
		externalFile := filepath.Join(externalDir, "external.zone")
		require.NoError(t, os.WriteFile(externalFile, []byte(zoneContent), 0o600))

		storeDir := filepath.Join(t.TempDir(), "store_external")
		require.NoError(t, os.MkdirAll(storeDir, 0o750))

		st := state.New(1024)
		s, err := Open(storeDir, st, WithZoneFile(externalFile), WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		res := st.Resolve("www.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
	})

	t.Run("LoadFromSnapshotIgnoringZoneFile", func(t *testing.T) {
		t.Parallel()
		storeDir := filepath.Join(t.TempDir(), "store_snap")
		require.NoError(t, os.MkdirAll(storeDir, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(storeDir, "test.zone"), []byte(zoneContent), 0o600))

		st1 := state.New(1024)
		s1, err := Open(storeDir, st1, WithZoneFile("test.zone"), WithLogger(discardLogger))
		require.NoError(t, err)
		require.NoError(t, s1.Close())

		st2 := state.New(1024)
		s2, err := Open(storeDir, st2, WithZoneFile("nonexistent.zone"), WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s2.Close() }()

		res := st2.Resolve("www.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
	})

	t.Run("UncleanStateRejection", func(t *testing.T) {
		t.Parallel()
		storeDir := filepath.Join(t.TempDir(), "store_unclean")
		require.NoError(t, os.MkdirAll(storeDir, 0o750))
		walPath := filepath.Join(storeDir, walFileName)
		require.NoError(t, os.WriteFile(walPath, []byte("fake-wal-data"), 0o600))

		st := state.New(1024)
		_, err := Open(storeDir, st, WithLogger(discardLogger))
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUncleanState)
	})

	t.Run("WALCrashRecoveryWithTruncatedTail", func(t *testing.T) {
		t.Parallel()
		storeDir := filepath.Join(t.TempDir(), "store_crash")
		require.NoError(t, os.MkdirAll(storeDir, 0o750))

		st1 := state.New(1024)
		s1, err := Open(storeDir, st1, WithLogger(discardLogger))
		require.NoError(t, err)

		records := dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.0.2.1")}},
		}

		require.NoError(t, s1.Upsert("survived.example.com", records))
		require.NoError(t, s1.Upsert("doomed.example.com", records))
		require.NoError(t, s1.Close())

		storeRoot, err := os.OpenRoot(storeDir)
		require.NoError(t, err)
		defer func() { _ = storeRoot.Close() }()

		walData, err := storeRoot.ReadFile(walFileName)
		require.NoError(t, err)

		if len(walData) > 5 {
			require.NoError(t, storeRoot.WriteFile(walFileName, walData[:len(walData)-5], 0o600))
		}

		st2 := state.New(1024)
		s2, err := Open(storeDir, st2, WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s2.Close() }()

		res := st2.Resolve("survived.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)

		resDoomed := st2.Resolve("doomed.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resDoomed.RCode)
	})

	t.Run("FunctionalOptions", func(t *testing.T) {
		t.Parallel()
		storeDir := t.TempDir()
		st := state.New(1024)
		s, err := Open(
			storeDir,
			st,
			WithCompactionInterval(5*time.Minute),
			WithCompactionThreshold(500),
			WithLogger(discardLogger),
		)
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		require.NoError(t, s.Upsert("test.example.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}},
		}))

		res := st.Resolve("test.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.True(t, res.HasAnswer())
	})
}

func TestStore_ReloadState(t *testing.T) {
	t.Parallel()

	t.Run("ZoneFileReloadAndCacheInvalidation", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		zonePath := filepath.Join(dir, "example.zone")
		require.NoError(t, os.WriteFile(zonePath, []byte("example.com. 300 IN A 1.2.3.4\n"), 0o600))

		st := state.New(1024)
		s, err := Open(dir, st, WithZoneFile("example.zone"), WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		res1 := st.Resolve("example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res1.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.2.3.4"), res1.Answer.RData[0])

		// Modify zone file on disk
		require.NoError(t, os.WriteFile(zonePath, []byte("example.com. 300 IN A 5.6.7.8\nnew.com. 300 IN A 9.9.9.9\n"), 0o600))

		// Trigger reload
		require.NoError(t, s.ReloadState())

		// Verify cache was purged and new record is returned
		res2 := st.Resolve("example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res2.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "5.6.7.8"), res2.Answer.RData[0])

		res3 := st.Resolve("new.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res3.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "9.9.9.9"), res3.Answer.RData[0])
	})

	t.Run("SnapshotAndWALReload", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		st := state.New(1024)
		s, err := Open(dir, st, WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		require.NoError(t, s.Upsert("snap.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}},
		}))
		require.NoError(t, s.Compact("manual"))

		require.NoError(t, s.Upsert("wal.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.2")}},
		}))

		require.NoError(t, s.ReloadState())

		resSnap := st.Resolve("snap.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, resSnap.RCode)

		resWAL := st.Resolve("wal.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, resWAL.RCode)
	})

	t.Run("ConcurrentCompactionAndReload", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		zonePath := filepath.Join(dir, "example.zone")
		require.NoError(t, os.WriteFile(zonePath, []byte("example.com. 300 IN A 1.2.3.4\n"), 0o600))

		st := state.New(1024)
		s, err := Open(dir, st, WithZoneFile("example.zone"), WithLogger(discardLogger))
		require.NoError(t, err)
		defer func() { _ = s.Close() }()

		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()

		var wg sync.WaitGroup
		wg.Go(func() {
			for ctx.Err() == nil {
				_ = s.Compact("concurrent")
			}
		})
		wg.Go(func() {
			for ctx.Err() == nil {
				_ = s.ReloadState()
			}
		})
		wg.Go(func() {
			for ctx.Err() == nil {
				_ = st.Resolve("example.com", dns.TypeA)
			}
		})
		wg.Wait()
	})
}

func TestStore_LeakAfterClose(t *testing.T) {
	t.Parallel()

	s, err := Open(t.TempDir(), state.New(100), WithLogger(discardLogger))
	require.NoError(t, err)
	_ = s.Close()
	done := make(chan error, 1)
	go func() { done <- s.Upsert("example.com", dns.RRSets{}) }()

	select {
	case <-done: // Success or immediate error
	case <-time.After(500 * time.Millisecond):
		t.Fatal("goroutine leaked due to Upsert blocking after Close")
	}
}

func TestStore_SnapshotChecksum(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	st := state.New(100)
	s, err := Open(dir, st, WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	chk, err := s.SnapshotChecksum()
	require.NoError(t, err)
	assert.NotZero(t, chk)
}

func TestStore_Options(t *testing.T) {
	t.Parallel()

	logger := slog.Default()

	opts := &options{}
	WithZoneFile("example.zone")(opts)
	WithLogger(logger)(opts)
	WithCompactionInterval(10 * time.Minute)(opts)
	WithCompactionThreshold(5000)(opts)
	WithReplicaMode(true)(opts)
	WithClusterHub(nil)(opts)
	WithMetrics(nil)(opts)

	assert.Equal(t, "example.zone", opts.zoneFileName)
	assert.Equal(t, logger, opts.logger)
	assert.Equal(t, 10*time.Minute, opts.compactionInterval)
	assert.Equal(t, uint64(5000), opts.compactionThreshold)
	assert.True(t, opts.isReplica)
}

type fakeHub struct {
	flushes     atomic.Int64
	compactions atomic.Int64
}

func (f *fakeHub) NotifyFlush()      { f.flushes.Add(1) }
func (f *fakeHub) NotifyCompaction() { f.compactions.Add(1) }

func TestStore_ClusterHubAndReaders(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	st := state.New(100)
	s, err := Open(dir, st, WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	hub := &fakeHub{}
	s.SetClusterHub(hub)

	// Perform Upsert -> should trigger NotifyFlush on hub
	err = s.Upsert("example.com", dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{{1, 2, 3, 4}}},
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return hub.flushes.Load() >= 1
	}, time.Second, 10*time.Millisecond)

	// Test OpenWALReader
	walReader, err := s.OpenWALReader()
	require.NoError(t, err)
	require.NotNil(t, walReader)
	_ = walReader.Close()

	// Perform Compaction -> should trigger NotifyCompaction on hub
	err = s.Compact("test")
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return hub.compactions.Load() >= 1
	}, time.Second, 10*time.Millisecond)

	// Test OpenSnapshotReader
	snapReader, err := s.OpenSnapshotReader()
	require.NoError(t, err)
	require.NotNil(t, snapReader)
	_ = snapReader.Close()

	// Test SetClusterHub(nil)
	s.SetClusterHub(nil)
}

func TestStore_OperationsOnClosedStore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	st := state.New(10)
	s, err := Open(dir, st, WithLogger(discardLogger))
	require.NoError(t, err)

	require.NoError(t, s.Close())

	// Upsert on closed store returns error
	err = s.Upsert("test.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{{1, 2, 3, 4}}}})
	require.ErrorIs(t, err, ErrClosed)

	// DeleteDomain on closed store returns error
	err = s.DeleteDomain("test.com")
	require.ErrorIs(t, err, ErrClosed)
}

func TestNopImplementations_NoPanic(t *testing.T) {
	t.Parallel()

	// Verify nopCollector and nopHub execute without panic
	var m nopCollector
	m.SetDomains(10)
	m.IncMutations()
	m.IncCompactions()
	m.SetSnapshotBytes(1024)
	m.SetWALBytes(2048)
	m.SetCompactionDuration(time.Second)
	m.SetMutationsPending(5)

	var h nopHub
	h.NotifyFlush()
	h.NotifyCompaction()
}
