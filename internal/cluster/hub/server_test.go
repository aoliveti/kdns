// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hub

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/metrics"
	"github.com/aoliveti/kdns/internal/state"
	"github.com/aoliveti/kdns/internal/store"
)

func TestServer_Authentication(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "secret123"
	m := metrics.New()
	srv := New("127.0.0.1:0", token, primaryStore, WithLogger(logger), WithMetrics(m))

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	client := &http.Client{Timeout: 2 * time.Second}

	// Request without authorization header
	noAuthReq, noAuthErr := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/cluster/snapshot", http.NoBody)
	require.NoError(t, noAuthErr)
	resp, err := client.Do(noAuthReq)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Request with invalid token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/cluster/stream?offset=0", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err = client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestServer_HTTPMethodsAndOffsets(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "secret123"
	m := metrics.New()
	srv := New("127.0.0.1:0", token, primaryStore, WithLogger(logger), WithMetrics(m))

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	client := &http.Client{Timeout: 2 * time.Second}

	// Method Not Allowed
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/v1/cluster/snapshot", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

	// Invalid offset (negative or not a number)
	for _, invalidOffset := range []string{"-1", "invalid", ""} {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/cluster/stream?offset="+invalidOffset, http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err = client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}

	// Out of range offset (no WAL or offset beyond WAL size)
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/cluster/stream?offset=999999", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusRequestedRangeNotSatisfiable, resp.StatusCode)
}

func TestServer_MaxStreamsLimit(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "secret123"
	m := metrics.New()
	// Configure maxStreams = 2
	srv := New("127.0.0.1:0", token, primaryStore,
		WithLogger(logger),
		WithMetrics(m),
		WithMaxStreams(2),
	)

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	client := &http.Client{Timeout: 5 * time.Second}

	// Connect 2 stream clients
	var wg sync.WaitGroup
	var activeStreams atomic.Int64
	streamCtx, cancelStreams := context.WithCancel(ctx)
	defer cancelStreams()

	for range 2 {
		wg.Go(func() {
			req, rErr := http.NewRequestWithContext(streamCtx, http.MethodGet, "http://"+addr+"/v1/cluster/stream?offset=0", http.NoBody)
			if rErr != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)
			resp, doErr := client.Do(req)
			if doErr != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusOK {
				activeStreams.Add(1)
				buf := make([]byte, 1024)
				for {
					_, readErr := resp.Body.Read(buf)
					if readErr != nil {
						break
					}
				}
			}
		})
	}

	require.Eventually(t, func() bool {
		return activeStreams.Load() == 2
	}, 3*time.Second, 50*time.Millisecond)

	// Attempt 3rd connection: should be rejected with 429 Too Many Requests
	req3, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/cluster/stream?offset=0", http.NoBody)
	require.NoError(t, err)
	req3.Header.Set("Authorization", "Bearer "+token)
	resp3, err := client.Do(req3)
	require.NoError(t, err)
	_ = resp3.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp3.StatusCode)

	cancelStreams()
	wg.Wait()
}

func TestServer_SnapshotDownloadSuccess(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "secret123"
	m := metrics.New()
	srv := New("127.0.0.1:0", token, primaryStore, WithLogger(logger), WithMetrics(m))

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/cluster/snapshot", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))
	assert.NotEmpty(t, resp.Header.Get("X-Snapshot-Checksum"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
}

func TestServer_NotifyFlushAndCompaction(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "secret123"
	m := metrics.New()
	srv := New("127.0.0.1:0", token, primaryStore, WithLogger(logger), WithMetrics(m))
	primaryStore.SetClusterHub(srv)

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	// Stream connection
	client := &http.Client{Timeout: 5 * time.Second}
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, "http://"+addr+"/v1/cluster/stream?offset=0", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Write data to store -> Store automatically notifies srv
	err = primaryStore.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{{1, 2, 3, 4}}}})
	require.NoError(t, err)

	// Read streamed bytes safely
	buf := make([]byte, 1024)
	type readRes struct {
		err error
		n   int
	}
	readCh := make(chan readRes, 1)
	go func() {
		n, rErr := resp.Body.Read(buf)
		readCh <- readRes{err: rErr, n: n}
	}()

	select {
	case res := <-readCh:
		require.NoError(t, res.err)
		assert.Positive(t, res.n)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for streamed data")
	}

	// Notify compaction to disconnect streaming client
	srv.NotifyCompaction()

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		for {
			_, rErr := resp.Body.Read(buf)
			if rErr != nil {
				return
			}
		}
	}()

	select {
	case <-doneCh:
		// Clean disconnection
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not disconnect after compaction")
	}
}

func TestServer_StreamClientEarlyClose(t *testing.T) {
	t.Parallel()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "tok-early-close"
	srv := New("127.0.0.1:0", token, primaryStore)
	primaryStore.SetClusterHub(srv)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() { _ = srv.Start(ctx) }()
	<-srv.Ready()
	addr := srv.Addr()

	client := &http.Client{Timeout: 5 * time.Second}
	streamReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/cluster/stream?offset=0", http.NoBody)
	require.NoError(t, err)
	streamReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(streamReq)
	require.NoError(t, err)

	// Close client connection immediately
	_ = resp.Body.Close()

	// Write mutations to trigger flush to closed client
	for i := range 5 {
		_ = primaryStore.Upsert(fmt.Sprintf("early-%d.com.", i), dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{{1, 2, 3, 4}}},
		})
	}
}

func TestServer_Options(t *testing.T) {
	t.Parallel()

	// WithTLSConfig accepts a pre-built tls.Config
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	s := New("127.0.0.1:0", "tok", nil, WithTLSConfig(tlsCfg))
	require.NotNil(t, s)
	require.Equal(t, tlsCfg, s.tlsConfig)

	// WithTLS must return an error for missing certificate files (BUG-3 fix)
	_, tlsErr := WithTLS("nonexistent.crt", "nonexistent.key")
	require.Error(t, tlsErr)

	// Test SetStore
	s.SetStore(nil)
}

func TestServer_SnapshotNotFoundAndNilStore(t *testing.T) {
	t.Parallel()

	// 1. Test nil store -> 503
	token := "secret123"
	srv1 := New("127.0.0.1:0", token, nil)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() { _ = srv1.Start(ctx) }()
	<-srv1.Ready()
	addr1 := srv1.Addr()

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr1+"/v1/cluster/snapshot", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	// 2. Test missing snapshot file on disk -> 404
	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	// Remove state.snap
	_ = os.Remove(filepath.Join(primaryDir, "state.snap"))

	srv2 := New("127.0.0.1:0", token, primaryStore)
	go func() { _ = srv2.Start(ctx) }()
	<-srv2.Ready()
	addr2 := srv2.Addr()

	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr2+"/v1/cluster/snapshot", http.NoBody)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)

	resp2, err := client.Do(req2)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

func TestServer_AuthorizeEdgeCases(t *testing.T) {
	t.Parallel()

	srv := New("127.0.0.1:0", "valid-token", nil)

	// Missing authorization header
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	assert.False(t, srv.authorize(req))

	// Invalid prefix
	req.Header.Set("Authorization", "Basic 12345")
	assert.False(t, srv.authorize(req))

	// Empty token after bearer
	req.Header.Set("Authorization", "Bearer ")
	assert.False(t, srv.authorize(req))

	// Wrong token
	req.Header.Set("Authorization", "Bearer wrong-token")
	assert.False(t, srv.authorize(req))

	// Valid token
	req.Header.Set("Authorization", "Bearer valid-token")
	assert.True(t, srv.authorize(req))
}

type nonFlusherWriter struct {
	header http.Header
	code   int
}

func (n *nonFlusherWriter) Header() http.Header {
	if n.header == nil {
		n.header = make(http.Header)
	}
	return n.header
}

func (n *nonFlusherWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (n *nonFlusherWriter) WriteHeader(statusCode int) {
	n.code = statusCode
}

func TestServer_HandleStreamEdgeCases(t *testing.T) {
	t.Parallel()

	// 1. Nil store -> 503
	srvNilStore := New("127.0.0.1:0", "tok", nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/cluster/stream?offset=0", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	srvNilStore.handleStream(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	// 2. Non-flusher writer -> 500
	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	srv := New("127.0.0.1:0", "tok", primaryStore)
	nonFlusher := &nonFlusherWriter{}
	srv.handleStream(nonFlusher, req)
	assert.Equal(t, http.StatusInternalServerError, nonFlusher.code)

	// 3. Invalid offset (negative or not integer) -> 400
	reqBadOffset := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/cluster/stream?offset=-5", http.NoBody)
	reqBadOffset.Header.Set("Authorization", "Bearer tok")
	recBadOffset := httptest.NewRecorder()
	srv.handleStream(recBadOffset, reqBadOffset)
	assert.Equal(t, http.StatusBadRequest, recBadOffset.Code)

	reqNaN := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/cluster/stream?offset=invalid", http.NoBody)
	reqNaN.Header.Set("Authorization", "Bearer tok")
	recNaN := httptest.NewRecorder()
	srv.handleStream(recNaN, reqNaN)
	assert.Equal(t, http.StatusBadRequest, recNaN.Code)

	// 4. Offset beyond WAL size -> 416
	reqOutOfBounds := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/cluster/stream?offset=999999", http.NoBody)
	reqOutOfBounds.Header.Set("Authorization", "Bearer tok")
	recOutOfBounds := httptest.NewRecorder()
	srv.handleStream(recOutOfBounds, reqOutOfBounds)
	assert.Equal(t, http.StatusRequestedRangeNotSatisfiable, recOutOfBounds.Code)

	// 5. Empty WAL file (fresh store with no mutations) and offset > 0 -> 416
	emptyStoreDir := t.TempDir()
	emptyStore, err := store.Open(emptyStoreDir, state.New(10))
	require.NoError(t, err)
	defer func() { _ = emptyStore.Close() }()
	srvEmpty := New("127.0.0.1:0", "tok", emptyStore)
	recEmpty := httptest.NewRecorder()
	srvEmpty.handleStream(recEmpty, reqOutOfBounds)
	assert.Equal(t, http.StatusRequestedRangeNotSatisfiable, recEmpty.Code)
}

func TestServer_StreamWALToClient_InitialNilWALAndCompaction(t *testing.T) {
	t.Parallel()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	primaryStore, err := store.Open(primaryDir, stPrimary)
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "secret123"
	srv := New("127.0.0.1:0", token, primaryStore)
	primaryStore.SetClusterHub(srv)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() { _ = srv.Start(ctx) }()
	<-srv.Ready()
	addr := srv.Addr()

	client := &http.Client{Timeout: 5 * time.Second}
	streamReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/cluster/stream?offset=0", http.NoBody)
	require.NoError(t, err)
	streamReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(streamReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Write to primary store -> WAL is flushed, Store automatically notifies srv
	err = primaryStore.Upsert("stream.test.", dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{{1, 2, 3, 4}}},
	})
	require.NoError(t, err)

	// Read streamed bytes safely
	buf := make([]byte, 1024)
	type readRes struct {
		err error
		n   int
	}
	readCh := make(chan readRes, 1)
	go func() {
		n, rErr := resp.Body.Read(buf)
		readCh <- readRes{err: rErr, n: n}
	}()

	select {
	case res := <-readCh:
		require.NoError(t, res.err)
		assert.Positive(t, res.n)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for streamed WAL bytes from server")
	}

	// Trigger compaction -> srv.NotifyCompaction() -> stream must be closed by server
	srv.NotifyCompaction()

	// Subsequent read must hit EOF / closed body within deadline
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		for {
			_, readErr := resp.Body.Read(buf)
			if readErr != nil {
				return
			}
		}
	}()

	select {
	case <-doneCh:
		// Successfully disconnected on compaction!
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not terminate after compaction notification")
	}
}
