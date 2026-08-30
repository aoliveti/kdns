// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package replica

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/cluster/hub"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/metrics"
	"github.com/aoliveti/kdns/internal/state"
	"github.com/aoliveti/kdns/internal/store"
)

type forwardingHub struct {
	hub store.ClusterHub
}

func (f *forwardingHub) NotifyFlush() {
	if f.hub != nil {
		f.hub.NotifyFlush()
	}
}

func (f *forwardingHub) NotifyCompaction() {
	if f.hub != nil {
		f.hub.NotifyCompaction()
	}
}

func TestClient_SnapshotSync(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	fhub := &forwardingHub{}

	primaryStore, err := store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	require.NoError(t, err)

	// Insert initial data on primary
	domain := "snapshot-init.com."
	rrs := dns.RRSets{
		{
			Type:  dns.TypeA,
			TTL:   300,
			RData: [][]byte{[]byte("5.6.7.8")},
		},
	}
	require.NoError(t, primaryStore.Upsert(domain, rrs))

	// Close primary store to flush and trigger compaction/snapshot
	_ = primaryStore.Close()

	// Reopen primary store to establish clean snapshot
	primaryStore, err = store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "snap-token"
	m := metrics.New()
	srv := hub.New("127.0.0.1:0", token, primaryStore, hub.WithLogger(logger), hub.WithMetrics(m))
	fhub.hub = srv

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	replicaDir := t.TempDir()
	stReplica := state.New(100)
	client := New("http://"+addr, token, replicaDir, stReplica, WithLogger(logger), WithMetrics(m))

	go func() {
		_ = client.Start(ctx)
	}()

	// Verify that replica received the snapshot and populated stReplica
	require.Eventually(t, func() bool {
		records, ok := stReplica.Get(domain)
		return ok && len(records) > 0
	}, 3*time.Second, 50*time.Millisecond)
}

func TestClient_ForeignSnapshotRejection(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	fhub := &forwardingHub{}

	primaryStore, err := store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	// Add data on primary
	domain := "primary-domain.com."
	rrs := dns.RRSets{
		{
			Type:  dns.TypeA,
			TTL:   300,
			RData: [][]byte{[]byte("1.1.1.1")},
		},
	}
	require.NoError(t, primaryStore.Upsert(domain, rrs))

	token := "foreign-test-token"
	m := metrics.New()
	srv := hub.New("127.0.0.1:0", token, primaryStore, hub.WithLogger(logger), hub.WithMetrics(m))
	fhub.hub = srv

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	// Create replica directory with a fake/foreign snapshot
	replicaDir := t.TempDir()
	foreignSnapPath := filepath.Join(replicaDir, "state.snap")
	// #nosec G306
	require.NoError(t, os.WriteFile(foreignSnapPath, []byte("INVALID_SNAPSHOT_DATA_12345678"), 0o600))

	stReplica := state.New(100)
	client := New("http://"+addr, token, replicaDir, stReplica, WithLogger(logger), WithMetrics(m))

	go func() {
		_ = client.Start(ctx)
	}()

	// Verify that replica rejected the fake snapshot, resynced with primary, and loaded the primary domain
	require.Eventually(t, func() bool {
		records, ok := stReplica.Get(domain)
		return ok && len(records) > 0
	}, 3*time.Second, 50*time.Millisecond)
}

func TestClient_WALCompactionResync(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	fhub := &forwardingHub{}

	primaryStore, err := store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	require.NoError(t, err)

	token := "compaction-resync-tok"
	m := metrics.New()
	srv := hub.New("127.0.0.1:0", token, primaryStore, hub.WithLogger(logger), hub.WithMetrics(m))
	fhub.hub = srv

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	replicaDir := t.TempDir()
	stReplica := state.New(100)
	client := New("http://"+addr, token, replicaDir, stReplica, WithLogger(logger), WithMetrics(m))

	go func() {
		_ = client.Start(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	// 1. Initial replication check
	d1 := "before-compaction.com."
	require.NoError(t, primaryStore.Upsert(d1, dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{[]byte("1.2.3.4")}}}))

	require.Eventually(t, func() bool {
		_, ok := stReplica.Get(d1)
		return ok
	}, 3*time.Second, 50*time.Millisecond)

	// 2. Trigger compaction by saving snapshot and truncating WAL on primary
	_ = primaryStore.Close()
	primaryStore, err = store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	srv.SetStore(primaryStore)
	fhub.hub = srv
	srv.NotifyCompaction()

	// 3. Insert new record after compaction
	d2 := "after-compaction.com."
	require.NoError(t, primaryStore.Upsert(d2, dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{[]byte("9.8.7.6")}}}))

	// 4. Verify replica reconnects, resyncs snapshot/WAL, and receives d2
	require.Eventually(t, func() bool {
		_, ok := stReplica.Get(d2)
		return ok
	}, 5*time.Second, 50*time.Millisecond)
}

func TestClient_RateLimit429Handling(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cluster/stream", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
	})
	mux.HandleFunc("GET /v1/cluster/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
	})

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	stReplica := state.New(100)
	replicaDir := t.TempDir()

	client := New("http://"+listener.Addr().String(), "tok", replicaDir, stReplica, WithLogger(logger))

	// sync should return ErrRateLimited on 429
	syncErr := client.sync(ctx)
	require.ErrorIs(t, syncErr, ErrRateLimited)
}

func TestClient_SnapshotChecksumMismatch(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	// Add a dummy record so snapshot has data
	require.NoError(t, primaryStore.Upsert("example.com.", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{[]byte("1.1.1.1")}}}))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cluster/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		f, openErr := primaryStore.OpenSnapshotReader()
		if openErr != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = f.Close() }()

		// Send invalid bogus checksum header
		w.Header().Set("X-Snapshot-Checksum", "deadbeef")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	})

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	stReplica := state.New(100)
	replicaDir := t.TempDir()

	client := New("http://"+listener.Addr().String(), "tok", replicaDir, stReplica, WithLogger(logger))

	downloadErr := client.downloadSnapshot(ctx)
	require.ErrorIs(t, downloadErr, ErrChecksumMismatch)
}

func TestClient_WALTruncatedHandling_SafePreservation(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	var snapshotAvailable atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cluster/stream", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Requested Range Not Satisfiable", http.StatusRequestedRangeNotSatisfiable)
	})
	mux.HandleFunc("GET /v1/cluster/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		if !snapshotAvailable.Load() {
			http.Error(w, "Snapshot Unavailable", http.StatusInternalServerError)
			return
		}
		f, snapErr := primaryStore.OpenSnapshotReader()
		if snapErr != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = f.Close() }()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	})

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	stReplica := state.New(100)
	replicaDir := t.TempDir()

	// Pre-create initial valid local snap and wal files
	snapPath := filepath.Join(replicaDir, "state.snap")
	walPath := filepath.Join(replicaDir, "mutations.wal")
	require.NoError(t, os.WriteFile(snapPath, []byte("prev-snap-data"), 0o600))
	require.NoError(t, os.WriteFile(walPath, []byte("prev-wal-data"), 0o600))

	client := New("http://"+listener.Addr().String(), "tok", replicaDir, stReplica, WithLogger(logger))

	// 1. Primary returns 416 and snapshot download fails: local files MUST NOT be deleted
	syncErr := client.sync(ctx)
	require.Error(t, syncErr)
	assert.FileExists(t, snapPath, "previous snapshot must be preserved on download failure")
	assert.FileExists(t, walPath, "previous wal must be preserved on download failure")

	// 2. Primary snapshot becomes available: atomic replacement succeeds
	snapshotAvailable.Store(true)
	require.NoError(t, client.sync(ctx))
	assert.FileExists(t, snapPath)
	assert.NoFileExists(t, walPath, "wal should be reset after snapshot replacement")
}

func TestClient_RetryAndReconnectOnTransientFailure(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var attempts atomic.Int32

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "valid-token-12345"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cluster/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		current := attempts.Add(1)
		if current < 3 {
			// Fail the first 2 attempts with a transient 503 error
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		// Attempt 3 succeeds
		f, openErr := primaryStore.OpenSnapshotReader()
		if openErr != nil {
			http.Error(w, "open snapshot error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = f.Close() }()

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	})

	mux.HandleFunc("GET /v1/cluster/stream", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-ctx.Done()
	})

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	stReplica := state.New(100)
	replicaDir := t.TempDir()

	client := New("http://"+listener.Addr().String(), token, replicaDir, stReplica, WithLogger(logger))

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- client.Start(ctx)
	}()

	// Wait for attempts to reach >= 3 (verifying retry occurred)
	require.Eventually(t, func() bool {
		return attempts.Load() >= 3
	}, 5*time.Second, 50*time.Millisecond)

	// Stop replica
	cancel()
	select {
	case err := <-doneCh:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("replica did not terminate cleanly upon context cancel")
	}
}

func TestClient_WithHTTPClientOption(t *testing.T) {
	t.Parallel()

	customClient := &http.Client{Timeout: 12 * time.Second}
	st := state.New(10)
	c := New("http://127.0.0.1:9999", "tok", t.TempDir(), st, WithHTTPClient(customClient))
	require.NotNil(t, c)
	require.Equal(t, customClient, c.client)
}
func TestClient_Options(t *testing.T) {
	t.Parallel()

	st := state.New(10)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	c := New("https://127.0.0.1:9999", "tok", t.TempDir(), st,
		WithTLSConfig(tlsCfg),
		WithTLSConfig(nil),
		WithMetrics(nil),
		WithLogger(slog.Default()),
		WithHTTPClient(&http.Client{}),
	)
	require.NotNil(t, c)
}

func TestComputeBackoff(t *testing.T) {
	t.Parallel()

	baseDelay := 500 * time.Millisecond

	// Negative attempt clamped to attempt 0: [250ms, 500ms]
	for range 20 {
		d := computeBackoff(-5, baseDelay)
		require.GreaterOrEqual(t, d, 250*time.Millisecond)
		require.LessOrEqual(t, d, 500*time.Millisecond)
	}

	// Attempt 0 should be in [base/2, base] -> [250ms, 500ms]
	for range 20 {
		d := computeBackoff(0, baseDelay)
		require.GreaterOrEqual(t, d, 250*time.Millisecond)
		require.LessOrEqual(t, d, 500*time.Millisecond)
	}

	// Attempt 1: [500ms, 1s]
	for range 20 {
		d := computeBackoff(1, baseDelay)
		require.GreaterOrEqual(t, d, 500*time.Millisecond)
		require.LessOrEqual(t, d, 1*time.Second)
	}

	// High attempt should be capped at maxBackoff (with jitter in [max/2, max]) -> [15s, 30s]
	for range 20 {
		d := computeBackoff(10, baseDelay)
		require.GreaterOrEqual(t, d, 15*time.Second)
		require.LessOrEqual(t, d, 30*time.Second)
	}

	// Very large attempt count (overflow protection) -> [15s, 30s]
	for range 20 {
		d := computeBackoff(1000, baseDelay)
		require.GreaterOrEqual(t, d, 15*time.Second)
		require.LessOrEqual(t, d, 30*time.Second)
	}

	// Zero or negative base delay
	zeroDelay := computeBackoff(0, 0)
	require.Equal(t, time.Duration(0), zeroDelay)
}

func TestClient_CleanStaleTempFilesOnStartup(t *testing.T) {
	t.Parallel()

	replicaDir := t.TempDir()
	staleFile1 := filepath.Join(replicaDir, "state-snap-1111.tmp")
	staleFile2 := filepath.Join(replicaDir, "state-snap-2222.tmp")
	keepFile := filepath.Join(replicaDir, "keep-me.txt")

	require.NoError(t, os.WriteFile(staleFile1, []byte("stale1"), 0o600))
	require.NoError(t, os.WriteFile(staleFile2, []byte("stale2"), 0o600))
	require.NoError(t, os.WriteFile(keepFile, []byte("keep"), 0o600))

	st := state.New(10)
	c := New("http://127.0.0.1:9999", "tok", replicaDir, st)
	require.NotNil(t, c)

	assert.NoFileExists(t, staleFile1, "stale temp file 1 must be cleaned up on New")
	assert.NoFileExists(t, staleFile2, "stale temp file 2 must be cleaned up on New")
	assert.FileExists(t, keepFile, "unrelated files must not be touched")
}

func TestClient_SnapshotDownloadUniqueTempFiles(t *testing.T) {
	t.Parallel()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	require.NoError(t, primaryStore.Upsert("example.com.", dns.RRSets{
		{Type: dns.TypeA, TTL: 300, RData: [][]byte{[]byte("1.1.1.1")}},
	}))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cluster/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		f, openErr := primaryStore.OpenSnapshotReader()
		if openErr != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = f.Close() }()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	})

	var lc net.ListenConfig
	listener, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	stReplica := state.New(100)
	replicaDir := t.TempDir()
	client := New("http://"+listener.Addr().String(), "tok", replicaDir, stReplica)

	require.NoError(t, client.downloadSnapshot(t.Context()))

	entries, err := os.ReadDir(replicaDir)
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, filepath.Ext(entry.Name()) == ".tmp", "no leftover .tmp files should exist after downloadSnapshot: %s", entry.Name())
	}
}

func TestClient_DownloadSnapshotErrors(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cluster/snapshot", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Test-Case") {
		case "500":
			http.Error(w, "server error", http.StatusInternalServerError)
		case "429":
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	var lc net.ListenConfig
	listener, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	stReplica := state.New(100)
	replicaDir := t.TempDir()
	client := New("http://"+listener.Addr().String(), "tok", replicaDir, stReplica)

	// Test 404
	err = client.downloadSnapshot(t.Context())
	require.ErrorIs(t, err, ErrSnapshotNotFound)
}
