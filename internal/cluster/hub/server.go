// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hub implements the Primary node replication HTTP streaming server for KDNS.
package hub

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aoliveti/kdns/internal/store"
)

const defaultMaxStreams = 64

type metricsCollector interface {
	IncClusterStream()
	DecClusterStream()
	IncClusterSnapshotSent()
}

type nopMetrics struct{}

func (nopMetrics) IncClusterStream()       {}
func (nopMetrics) DecClusterStream()       {}
func (nopMetrics) IncClusterSnapshotSent() {}

// Option configures functional parameters for the replication Server.
type Option func(*options)

type options struct {
	logger     *slog.Logger
	metrics    metricsCollector
	tlsConfig  *tls.Config
	maxStreams int
}

// WithLogger sets the structured logger for the Hub Server.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithMetrics sets the telemetry metrics collector for the Hub Server.
func WithMetrics(m metricsCollector) Option {
	return func(o *options) {
		if m != nil {
			o.metrics = m
		}
	}
}

// WithMaxStreams sets the maximum number of concurrent active streaming replicas.
func WithMaxStreams(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.maxStreams = n
		}
	}
}

// WithTLSConfig sets the TLS configuration for the Hub listener.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *options) {
		o.tlsConfig = cfg
	}
}

// WithTLS enables TLS using cert and key files.
// It returns an error if the certificate or key cannot be loaded, preventing
// silent fallback to plaintext HTTP.
func WithTLS(certFile, keyFile string) (Option, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("hub: load TLS keypair %q / %q: %w", certFile, keyFile, err)
	}
	return func(o *options) {
		o.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}, nil
}

// Server manages active cluster replication streams for replicas.
// It implements store.ClusterHub to receive WAL flush and compaction signals.
type Server struct {
	logger        *slog.Logger
	store         *store.Store
	cond          *sync.Cond
	httpServer    *http.Server
	tlsConfig     *tls.Config
	ready         chan struct{}
	metrics       metricsCollector
	addr          string
	token         string
	gen           uint64
	maxStreams    int
	activeStreams atomic.Int64
	mu            sync.Mutex
	stopped       bool
}

// New creates a new replication Hub Server.
func New(addr, token string, st *store.Store, opts ...Option) *Server {
	cfg := &options{
		logger:     slog.Default(),
		metrics:    nopMetrics{},
		maxStreams: defaultMaxStreams,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	s := &Server{
		addr:       addr,
		token:      token,
		logger:     cfg.logger,
		store:      st,
		metrics:    cfg.metrics,
		tlsConfig:  cfg.tlsConfig,
		maxStreams: cfg.maxStreams,
		ready:      make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Addr returns the network address the server is listening on.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Ready returns a channel that is closed when the server listener is active and ready to accept connections.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// SetStore dynamically updates the backing storage engine reference.
func (s *Server) SetStore(st *store.Store) {
	s.mu.Lock()
	s.store = st
	s.mu.Unlock()
}

// NotifyFlush broadcasts to all waiting streaming connections that new WAL entries are available.
func (s *Server) NotifyFlush() {
	s.cond.Broadcast()
}

// NotifyCompaction signals all active streaming connections that a WAL compaction occurred.
func (s *Server) NotifyCompaction() {
	s.mu.Lock()
	s.gen++ // Increment generation so waiting streams know to disconnect
	s.mu.Unlock()
	s.cond.Broadcast()
}

// Start launches the HTTP server for replica streaming.
func (s *Server) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on replication hub address %q: %w", s.addr, err)
	}
	defer func() { _ = ln.Close() }()

	s.mu.Lock()
	s.addr = ln.Addr().String()
	s.mu.Unlock()
	close(s.ready)

	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cluster/snapshot", s.handleSnapshot)
	mux.HandleFunc("GET /v1/cluster/stream", s.handleStream)

	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	s.logger.Info(
		"starting cluster replication hub",
		slog.String("addr", s.addr),
		slog.Bool("tls", s.tlsConfig != nil),
	)
	errCh := make(chan error, 1)

	go func() {
		if serveErr := s.httpServer.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.mu.Lock()
		s.stopped = true
		s.mu.Unlock()
		s.cond.Broadcast()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("cluster hub shutdown: %w", err)
		}
		return nil
	case serveErr := <-errCh:
		return serveErr
	}
}

func (s *Server) authorize(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := auth[len("Bearer "):]
	if token == "" || s.token == "" {
		return false
	}
	expectedHash := sha256.Sum256([]byte(s.token))
	providedHash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) == 1
}
