// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package api provides the control-plane HTTP REST API and telemetry exporter.
//
// Concurrency Model:
//   - Reads (GET /v1/records, /search): Lock-free lookups against the Reader (state.State).
//   - Writes (PUT, POST, DELETE): Enqueued to the Mutator (store.Store).
//   - Read-Only Mode: If mutator is nil, mutation routes return 403 Forbidden.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	defaultHTTPAddr          = ":8080"
	defaultCORSOrigin        = "*"
	defaultPageLimit         = 50
	maxPageLimit             = 1000
	defaultMaxBodyBytes      = 4 * 1024 * 1024
	defaultReadHeaderTimeout = 3 * time.Second
	defaultReadTimeout       = 5 * time.Second
	defaultWriteTimeout      = 0 // 0 allows unlimited duration for streaming large zone file exports
	defaultIdleTimeout       = 60 * time.Second
	defaultMaxHeaderBytes    = 1024 * 1024
)

// ErrNilViewer indicates that the provided Viewer instance is nil.
var ErrNilViewer = errors.New("api: viewer cannot be nil")

// Getter handles point lookups of domain record sets.
type Getter = dns.Getter

// Seeker handles cursor-based pagination starting after a specific domain.
type Seeker = dns.Seeker

// Walker handles sequential traversal over all stored domain records.
type Walker = dns.Walker

// Searcher handles substring searching over stored domain records.
type Searcher = dns.Searcher

// Viewer aggregates all read-only query and traversal operations over in-memory state.
type Viewer = dns.Viewer

// Upserter handles inserting or updating domain record sets.
type Upserter = dns.Upserter

// Deleter handles domain deletion.
type Deleter = dns.Deleter

// UpsertDeleter aggregates domain mutation operations.
type UpsertDeleter = dns.UpsertDeleter

// Option configures the HTTP API Server.
type Option func(*options)

type options struct {
	logger        *slog.Logger
	metrics       io.WriterTo
	upsertDeleter UpsertDeleter
	addr          string
	apiToken      string
	corsOrigin    string
	corsOriginSet bool
	maxBodyBytes  int64
}

// WithAddress sets the listening TCP address for the HTTP server.
func WithAddress(addr string) Option {
	return func(o *options) {
		if addr != "" {
			o.addr = addr
		}
	}
}

// WithUpsertDeleter attaches a persistent UpsertDeleter instance for domain record modifications.
// If omitted, the API server runs in read-only replica mode.
func WithUpsertDeleter(ud UpsertDeleter) Option {
	return func(o *options) {
		o.upsertDeleter = ud
	}
}

// WithLogger sets the structured logger for the HTTP server.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithMetrics sets the Prometheus metrics exporter.
func WithMetrics(m io.WriterTo) Option {
	return func(o *options) {
		o.metrics = m
	}
}

// WithAPIToken sets the required Bearer / X-API-Key authentication token.
func WithAPIToken(token string) Option {
	return func(o *options) {
		o.apiToken = strings.TrimSpace(token)
	}
}

// WithMaxBodyBytes sets the maximum allowed HTTP request body size in bytes.
func WithMaxBodyBytes(limit int64) Option {
	return func(o *options) {
		if limit > 0 {
			o.maxBodyBytes = limit
		}
	}
}

// WithCORSOrigin sets the value of the Access-Control-Allow-Origin response header.
// Defaults to "*" when not explicitly configured.
func WithCORSOrigin(origin string) Option {
	return func(o *options) {
		o.corsOrigin = origin
		o.corsOriginSet = true
	}
}

// WithoutCORS explicitly disables CORS headers and OPTIONS preflight handling.
func WithoutCORS() Option {
	return func(o *options) {
		o.corsOrigin = ""
		o.corsOriginSet = true
	}
}

type nopWriterTo struct{}

func (nopWriterTo) WriteTo(io.Writer) (int64, error) {
	return 0, nil
}

// Server manages the HTTP management plane, exposing health checks, metrics, and REST endpoints.
type Server struct {
	httpServer    *http.Server
	logger        *slog.Logger
	handler       http.Handler
	metricsWriter io.WriterTo
	viewer        Viewer
	upsertDeleter UpsertDeleter
	addr          string
	apiToken      string
	corsOrigin    string
	maxBodyBytes  int64
}

// New instantiates and configures a new HTTP API Server.
// viewer provides read access to the in-memory domain state (state.State).
// Pass WithUpsertDeleter(ud) to enable write operations; without it, the server runs in read-only replica mode.
func New(viewer Viewer, opts ...Option) *Server {
	cfg := &options{
		addr:   defaultHTTPAddr,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	mux := http.NewServeMux()

	m := cfg.metrics
	if m == nil {
		m = nopWriterTo{}
	}

	limit := cfg.maxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}

	corsOrigin := cfg.corsOrigin
	if !cfg.corsOriginSet {
		corsOrigin = defaultCORSOrigin
	}

	s := &Server{
		addr:          cfg.addr,
		logger:        cfg.logger,
		metricsWriter: m,
		viewer:        viewer,
		upsertDeleter: cfg.upsertDeleter,
		apiToken:      cfg.apiToken,
		maxBodyBytes:  limit,
		corsOrigin:    corsOrigin,
	}

	s.registerRoutes(mux)
	s.handler = s.wrapMiddleware(mux)

	s.httpServer = &http.Server{
		Addr:              s.addr,
		Handler:           s.handler,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
	}

	return s
}

// Start runs the HTTP server listening on the configured TCP address until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if s.viewer == nil {
		return ErrNilViewer
	}

	if s.apiToken == "" {
		s.logger.Warn("control plane API authentication is disabled")
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("starting http management server", slog.String("addr", s.httpServer.Addr))
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("listen and serve: %w", err)
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("http server shutdown: %w", err)
		}
		s.logger.Info("http management server stopped gracefully")
		return nil
	case err := <-errCh:
		return err
	}
}

// Handler returns the fully initialized and wrapped http.Handler.
func (s *Server) Handler() http.Handler {
	return s.handler
}

type syncStatusProvider interface {
	ReplicaSyncStatus() int64
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /livez", s.livez)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /startupz", s.startupz)
	mux.HandleFunc("GET /metrics", s.metrics)

	mux.HandleFunc("GET /v1/records", s.listRecords)
	mux.HandleFunc("GET /v1/records/search", s.searchRecords)
	mux.HandleFunc("GET /v1/records/{domain...}", s.getDomain)
	mux.HandleFunc("PUT /v1/records/{domain...}", s.upsertDomain)
	mux.HandleFunc("POST /v1/records/{domain...}", s.upsertDomain)
	mux.HandleFunc("DELETE /v1/records/{domain...}", s.deleteDomain)
	mux.HandleFunc("GET /v1/export/zonefile", s.exportZoneFile)
}

func (s *Server) wrapMiddleware(handler http.Handler) http.Handler {
	return s.recoverPanic(
		s.securityHeaders(
			s.cors(
				s.authenticate(
					s.logRequests(handler),
				),
			),
		),
	)
}

func (s *Server) livez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) startupz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.upsertDeleter == nil {
		if provider, ok := s.metricsWriter.(syncStatusProvider); ok && provider.ReplicaSyncStatus() != 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("syncing\n"))
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := s.metricsWriter.WriteTo(w); err != nil {
		s.logger.Error("failed to write prometheus metrics", slog.Any("error", err))
	}
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic recovered in http handler",
					slog.Any("panic", rec),
					slog.String("path", r.URL.Path),
				)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.corsOrigin == "" {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", s.corsOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// canUpdate returns true if a persistent storage backend is attached (Primary writable mode).
func (s *Server) canUpdate() bool {
	return s.upsertDeleter != nil
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if s.apiToken == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		token := extractToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		expectedHash := sha256.Sum256([]byte(s.apiToken))
		providedHash := sha256.Sum256([]byte(token))

		if subtle.ConstantTimeCompare(expectedHash[:], providedHash[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func isPublicPath(path string) bool {
	switch path {
	case "/livez", "/readyz", "/startupz", "/metrics":
		return true
	default:
		return false
	}
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
	bytesCount int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytesCount += n
	return n, err
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		duration := time.Since(start)
		fields := []any{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.statusCode),
			slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
			slog.String("remote_addr", r.RemoteAddr),
			slog.Int("bytes", rec.bytesCount),
		}

		switch {
		case rec.statusCode >= 500:
			s.logger.Error("http request error", fields...)
		case rec.statusCode >= 400:
			s.logger.Warn("http client error", fields...)
		default:
			s.logger.Info("http request", fields...)
		}
	})
}
