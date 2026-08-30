// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package replica implements the read-only Replica node synchronization client for KDNS.
package replica

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aoliveti/kdns/internal/snapshot"
	"github.com/aoliveti/kdns/internal/state"
)

const (
	initialBackoff   = 500 * time.Millisecond
	maxBackoff       = 30 * time.Second
	rateLimitBackoff = 5 * time.Second
	snapshotTimeout  = 60 * time.Second
	keepAlivePeriod  = 15 * time.Second
	connectTimeout   = 10 * time.Second
)

var (
	// ErrRateLimited indicates that the primary rejected the streaming connection with HTTP 429.
	ErrRateLimited = errors.New("replica: primary rate limited (429 too many requests)")

	// ErrChecksumMismatch indicates that the downloaded snapshot checksum did not match the primary header.
	ErrChecksumMismatch = errors.New("replica: snapshot checksum mismatch")

	// ErrSnapshotNotFound indicates that the remote snapshot was not found on the primary (HTTP 404).
	ErrSnapshotNotFound = errors.New("replica: remote snapshot not found")

	// ErrUnexpectedStatus indicates that the primary returned an unexpected HTTP status code.
	ErrUnexpectedStatus = errors.New("replica: unexpected http status")
)

type metricsCollector interface {
	SetReplicaSyncStatus(status int64)
	IncReplicaSnapshotRecv()
	SetReplicaLastSync(unix int64)
}

type nopMetrics struct{}

func (nopMetrics) SetReplicaSyncStatus(int64) {}
func (nopMetrics) IncReplicaSnapshotRecv()    {}
func (nopMetrics) SetReplicaLastSync(int64)   {}

// Option configures functional parameters for the Replica Client.
type Option func(*options)

type options struct {
	logger     *slog.Logger
	metrics    metricsCollector
	httpClient *http.Client
}

// WithLogger sets the structured logger for the Replica Client.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithMetrics sets the telemetry metrics collector for the Replica Client.
func WithMetrics(m metricsCollector) Option {
	return func(o *options) {
		if m != nil {
			o.metrics = m
		}
	}
}

// WithHTTPClient sets the HTTP client used for replication requests.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		if c != nil {
			o.httpClient = c
		}
	}
}

func newHTTPClient(tlsCfg *tls.Config) *http.Client {
	dialer := &net.Dialer{
		Timeout:   connectTimeout,
		KeepAlive: keepAlivePeriod,
	}
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   false,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   0,
	}
}

// WithTLSConfig explicitly sets the tls.Config for the replica HTTP client.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *options) {
		if cfg != nil {
			o.httpClient = newHTTPClient(cfg)
		}
	}
}

// Client connects to a Primary hub and streams mutations to keep the local state synchronized.
type Client struct {
	logger     *slog.Logger
	st         *state.State
	client     *http.Client
	metrics    metricsCollector
	root       *os.Root
	primaryURL string
	token      string
	storageDir string
}

// New creates a new replication Client.
func New(primaryURL, token, storageDir string, st *state.State, opts ...Option) *Client {
	cfg := &options{
		logger:     slog.Default(),
		metrics:    nopMetrics{},
		httpClient: newHTTPClient(nil),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	snapshot.CleanStaleTemp(storageDir)

	_ = os.MkdirAll(storageDir, 0o750)
	root, _ := os.OpenRoot(storageDir)

	return &Client{
		primaryURL: primaryURL,
		token:      token,
		storageDir: storageDir,
		st:         st,
		logger:     cfg.logger,
		metrics:    cfg.metrics,
		client:     cfg.httpClient,
		root:       root,
	}
}

// Close releases local resources held by the replica client.
func (c *Client) Close() error {
	if c.root != nil {
		return c.root.Close()
	}
	return nil
}

// Start launches the background replication loop with exponential backoff and jitter.
func (c *Client) Start(ctx context.Context) error {
	snapshot.CleanStaleTemp(c.storageDir)
	c.logger.Info("starting cluster replica client", slog.String("primary_url", c.primaryURL))

	var attempt int
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err := c.sync(ctx)
		// When sync completes cleanly (e.g., streaming disconnection or snapshot downloaded),
		// reset backoff attempt and immediately reconnect to resume streaming.
		if err == nil {
			attempt = 0
			continue
		}

		if errors.Is(err, context.Canceled) {
			return nil
		}

		if errors.Is(err, ErrRateLimited) {
			delay := computeBackoff(attempt, rateLimitBackoff)
			c.logger.Warn("stream rate limited by primary, backing off",
				slog.Duration("delay", delay),
				slog.Int("attempt", attempt),
			)
			attempt++
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return nil
			}
		}

		delay := computeBackoff(attempt, initialBackoff)
		c.logger.Error("replication sync failed, retrying",
			slog.Any("error", err),
			slog.Duration("delay", delay),
			slog.Int("attempt", attempt),
		)
		attempt++

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil
		}
	}
}

func computeBackoff(attempt int, baseDelay time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	shift := min(attempt, 6)
	backoff := min(baseDelay*(1<<shift), maxBackoff)
	half := backoff / 2
	if half <= 0 {
		return baseDelay
	}
	// #nosec G404 -- non-cryptographic jitter for network backoff
	jitter := rand.N(half)
	return half + jitter
}
