// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package doh implements a zero-allocation, RFC 8484 compliant DNS-over-HTTPS (DoH) server.
package doh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	defaultAddr              = ":8443"
	defaultReadTimeout       = 5 * time.Second
	defaultReadHeaderTimeout = 3 * time.Second
	defaultWriteTimeout      = 5 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	maxWirePayloadSize       = 4096
)

var dohBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxWirePayloadSize)
		return &b
	},
}

// Resolver defines the domain resolution capability required by the DoH server.
type Resolver interface {
	Resolve(domain string, qType dns.Type) dns.Result
}

type metricsCollector interface {
	IncQueriesDoH()
	IncQueryType(qType dns.Type)
	AddBytesInDoH(n uint64)
	AddBytesOutDoH(n uint64)
}

// Option configures functional parameters for the DoH server.
type Option func(*options)

type options struct {
	tlsConfig *tls.Config
	logger    *slog.Logger
	metrics   metricsCollector
	addr      string
}

// WithAddress sets the listening network address.
func WithAddress(addr string) Option {
	return func(o *options) {
		if addr != "" {
			o.addr = addr
		}
	}
}

// WithTLSConfig sets the TLS configuration for HTTPS serving.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *options) {
		if cfg != nil {
			o.tlsConfig = cfg
		}
	}
}

// WithLogger sets the structured logger for the server.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithMetrics attaches telemetry metrics collection to the server.
func WithMetrics(m metricsCollector) Option {
	return func(o *options) {
		if m != nil {
			o.metrics = m
		}
	}
}

// Server provides the RFC 8484 DNS-over-HTTPS data-plane endpoint.
type Server struct {
	resolver   Resolver
	metrics    metricsCollector
	logger     *slog.Logger
	httpServer *http.Server
	tlsConfig  *tls.Config
	addr       string
}

// New constructs a new DoH Server instance.
func New(r Resolver, opts ...Option) *Server {
	cfg := &options{
		addr:   defaultAddr,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	s := &Server{
		resolver:  r,
		metrics:   cfg.metrics,
		logger:    cfg.logger,
		tlsConfig: cfg.tlsConfig,
		addr:      cfg.addr,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /dns-query", s.handleDoH)
	mux.HandleFunc("POST /dns-query", s.handleDoH)
	mux.HandleFunc("GET /livez", s.handleProbe)
	mux.HandleFunc("GET /readyz", s.handleProbe)
	mux.HandleFunc("GET /startupz", s.handleProbe)

	s.httpServer = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		TLSConfig:         s.tlsConfig,
	}

	return s
}

// Handler returns the underlying http.Handler used by the server.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// hasTLS returns true if TLS configuration is attached to the DoH server.
func (s *Server) hasTLS() bool {
	return s.tlsConfig != nil
}

// Start runs the DoH HTTP/HTTPS server and blocks until the context is canceled.
func (s *Server) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on DoH address %q: %w", s.addr, err)
	}
	defer func() { _ = ln.Close() }()

	scheme := "http"
	if s.hasTLS() {
		ln = tls.NewListener(ln, s.tlsConfig)
		scheme = "https"
	}
	s.logger.Info("doh "+scheme+" server listening", slog.String("addr", s.addr))

	errCh := make(chan error, 1)
	go func() {
		if serveErr := s.httpServer.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}
