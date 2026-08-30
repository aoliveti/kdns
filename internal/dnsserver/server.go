// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnsserver implements the high-performance DNS Data Plane server, handling UDP, TCP,
// and DoT connections, connection lifecycles, and protocol limits on port 53 and 853.
package dnsserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/dnssec"
	"github.com/aoliveti/kdns/internal/rrl"
	"github.com/aoliveti/kdns/internal/tsig"
)

const (
	defaultAddr         = ":53"
	udpBufferSize       = 4096
	udpReadTimeout      = 1 * time.Second
	tcpReadWriteTimeout = 5 * time.Second
)

var (
	// ErrNilResolver indicates that the provided resolver implementation is nil.
	ErrNilResolver = errors.New("resolver cannot be nil")

	// ErrMalformedQuery indicates that the query payload is invalid or cannot be parsed.
	ErrMalformedQuery = errors.New("malformed query payload")

	// ErrResponsePacket indicates an incoming packet has QR=1 (response packet) and is dropped to prevent loops.
	ErrResponsePacket = errors.New("incoming packet has response bit set")

	// ErrSerialization indicates an internal failure while encoding the DNS response.
	ErrSerialization = errors.New("failed to serialize dns response")

	// ErrSocketWrite indicates a failure while writing to the network socket.
	ErrSocketWrite = errors.New("failed to write response to socket")
)

type metricsCollector interface {
	IncQueriesUDP()
	IncQueriesTCP()
	IncQueriesDoT()
	IncQueryType(qType dns.Type)
	IncResponses(rCode dns.RCode)
	IncRRLDrop()
	IncRRLSlip()
	IncDNSSECSignatures()
	IncDNSSECQueries()
	IncTSIG(status string)
	IncRFC2136(status string)
	AddBytesInUDP(n uint64)
	AddBytesInTCP(n uint64)
	AddBytesInDoT(n uint64)
	AddBytesOutUDP(n uint64)
	AddBytesOutTCP(n uint64)
	AddBytesOutDoT(n uint64)
	IncTCPConnection()
	DecTCPConnection()
}

type nopCollector struct{}

func (nopCollector) IncQueriesUDP()         {}
func (nopCollector) IncQueriesTCP()         {}
func (nopCollector) IncQueriesDoT()         {}
func (nopCollector) IncQueryType(dns.Type)  {}
func (nopCollector) IncResponses(dns.RCode) {}
func (nopCollector) IncRRLDrop()            {}
func (nopCollector) IncRRLSlip()            {}
func (nopCollector) IncDNSSECSignatures()   {}
func (nopCollector) IncDNSSECQueries()      {}
func (nopCollector) IncTSIG(string)         {}
func (nopCollector) IncRFC2136(string)      {}
func (nopCollector) AddBytesInUDP(uint64)   {}
func (nopCollector) AddBytesInTCP(uint64)   {}
func (nopCollector) AddBytesInDoT(uint64)   {}
func (nopCollector) AddBytesOutUDP(uint64)  {}
func (nopCollector) AddBytesOutTCP(uint64)  {}
func (nopCollector) AddBytesOutDoT(uint64)  {}
func (nopCollector) IncTCPConnection()      {}
func (nopCollector) DecTCPConnection()      {}

// resolver defines the data-plane resolution capability required by the Server.
type resolver interface {
	Resolve(domain string, qType dns.Type) dns.Result
}

type options struct {
	logger        *slog.Logger
	metrics       metricsCollector
	rrl           *rrl.Limiter
	tlsConfig     *tls.Config
	upsertDeleter dns.UpsertDeleter
	tsigKeys      *tsig.KeyRing
	dnssecMgr     *dnssec.Manager
	addr          string
	dotAddr       string
	version       string
	identity      string
}

// Option configures Server parameters via the functional options pattern.
type Option func(*options)

// WithAddress overrides the default network binding address.
func WithAddress(addr string) Option {
	return func(o *options) {
		if addr != "" {
			o.addr = addr
		}
	}
}

// WithDoTAddress sets the address for the DNS-over-TLS (DoT) listener.
func WithDoTAddress(addr string) Option {
	return func(o *options) {
		if addr != "" {
			o.dotAddr = addr
		}
	}
}

// WithTLSConfig configures the TLS settings required for DoT.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *options) {
		o.tlsConfig = cfg
	}
}

// WithLogger overrides the default standard logger.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithMetrics attaches a telemetry metrics collector to the DNS server.
func WithMetrics(m metricsCollector) Option {
	return func(o *options) {
		o.metrics = m
	}
}

// WithRRL attaches a response rate limiter to the DNS server.
func WithRRL(r *rrl.Limiter) Option {
	return func(o *options) {
		o.rrl = r
	}
}

// WithUpsertDeleter attaches a persistent UpsertDeleter backend for Dynamic DNS Updates (RFC 2136).
func WithUpsertDeleter(ud dns.UpsertDeleter) Option {
	return func(o *options) {
		o.upsertDeleter = ud
	}
}

// WithVersion sets the version string returned for CHAOS version.bind queries.
func WithVersion(v string) Option {
	return func(o *options) {
		if v != "" {
			o.version = v
		}
	}
}

// WithIdentity sets the server ID / hostname returned for CHAOS id.server / hostname.bind queries.
func WithIdentity(id string) Option {
	return func(o *options) {
		if id != "" {
			o.identity = id
		}
	}
}

// WithTSIG configures authorized TSIG keys for request verification and response signing.
func WithTSIG(kr *tsig.KeyRing) Option {
	return func(o *options) {
		o.tsigKeys = kr
	}
}

// WithTSIGKeyRing is an alias for WithTSIG.
func WithTSIGKeyRing(kr *tsig.KeyRing) Option {
	return WithTSIG(kr)
}

// WithDNSSEC configures the DNSSEC key manager for on-the-fly RRSIG and NSEC synthesis.
func WithDNSSEC(m *dnssec.Manager) Option {
	return func(o *options) {
		o.dnssecMgr = m
	}
}

// Server encapsulates the DNS transport layer and connection management.
type Server struct {
	udpPool       sync.Pool
	tcpPool       sync.Pool
	res           resolver
	getter        dns.Getter
	upsertDeleter dns.UpsertDeleter
	tsigKeys      *tsig.KeyRing
	dnssecMgr     *dnssec.Manager
	logger        *slog.Logger
	metrics       metricsCollector
	rrl           *rrl.Limiter
	tlsConfig     *tls.Config
	cancel        context.CancelFunc
	addr          string
	dotAddr       string
	versionWire   [][]byte
	identityWire  [][]byte
	authorsWire   [][]byte
	wg            sync.WaitGroup
	mu            sync.Mutex
}

// New constructs a DNS Server instance initialized with the given options.
func New(res resolver, opts ...Option) *Server {
	cfg := &options{
		addr:     defaultAddr,
		logger:   slog.Default(),
		version:  "dev",
		identity: "none",
	}

	if host, err := os.Hostname(); err == nil && host != "" {
		cfg.identity = host
	}

	for _, opt := range opts {
		opt(cfg)
	}

	m := cfg.metrics
	if m == nil {
		m = nopCollector{}
	}

	var getter dns.Getter
	if g, ok := res.(dns.Getter); ok {
		getter = g
	}

	versionRData, _ := dns.PackRData(dns.TypeTXT, cfg.version)
	identityRData, _ := dns.PackRData(dns.TypeTXT, cfg.identity)
	authorsRData, _ := dns.PackRData(dns.TypeTXT, "Andrea Oliveti")

	return &Server{
		addr:          cfg.addr,
		dotAddr:       cfg.dotAddr,
		tlsConfig:     cfg.tlsConfig,
		res:           res,
		getter:        getter,
		upsertDeleter: cfg.upsertDeleter,
		tsigKeys:      cfg.tsigKeys,
		dnssecMgr:     cfg.dnssecMgr,
		logger:        cfg.logger,
		metrics:       m,
		rrl:           cfg.rrl,
		versionWire:   [][]byte{versionRData},
		identityWire:  [][]byte{identityRData},
		authorsWire:   [][]byte{authorsRData},
		udpPool: sync.Pool{
			New: func() any {
				b := make([]byte, udpBufferSize)
				return &b
			},
		},
		tcpPool: sync.Pool{
			New: func() any {
				b := make([]byte, dns.MaxTCPSize)
				return &b
			},
		},
	}
}

// canUpdate returns true if the server is equipped to process RFC 2136 Dynamic DNS Updates.
func (s *Server) canUpdate() bool {
	return s.getter != nil && s.upsertDeleter != nil && s.tsigKeys != nil
}

// canSign returns true if DNSSEC on-the-fly signing is active.
func (s *Server) canSign() bool {
	return s.dnssecMgr != nil
}

// hasDoT returns true if DNS-over-TLS listener is configured.
func (s *Server) hasDoT() bool {
	return s.tlsConfig != nil && s.dotAddr != ""
}

// hasRRL returns true if Response Rate Limiting is active.
func (s *Server) hasRRL() bool {
	return s.rrl != nil
}

// Close triggers context cancellation to initiate a graceful shutdown.
func (s *Server) Close() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// ResolveWireTo executes a binary DNS query and writes the wire response to the provided io.Writer.
// It leverages the 64KB TCP pool to guarantee zero allocations, making it ideal for DoH integration.
func (s *Server) ResolveWireTo(req []byte, w io.Writer) error {
	if s.res == nil {
		return ErrNilResolver
	}

	buf := s.tcpPool.Get().(*[]byte)
	defer s.tcpPool.Put(buf)

	written, _, _, err := s.resolve(req, *buf, dns.MaxTCPSize)
	if err != nil {
		return err
	}

	_, err = w.Write((*buf)[:written])
	return err
}
