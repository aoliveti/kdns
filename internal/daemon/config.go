// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package daemon orchestrates the lifecycle, services, and execution runtime of kdns.
package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aoliveti/kdns/internal/dnssec"
	"github.com/aoliveti/kdns/internal/metrics"
	"github.com/aoliveti/kdns/internal/rrl"
	"github.com/aoliveti/kdns/internal/store"
	"github.com/aoliveti/kdns/internal/tsig"
)

const (
	// MinAPITokenLength is the minimum required character length for the control plane API token.
	MinAPITokenLength = 16
)

var (
	// ErrIncompleteTLS indicates that only one of the TLS certificate or private key paths was provided.
	ErrIncompleteTLS = errors.New("incomplete tls configuration: both cert and key are required")

	// ErrDoTRequiresTLS indicates that DoT address was specified without TLS certificate credentials.
	ErrDoTRequiresTLS = errors.New("dot address specified but no tls certificates provided")

	// ErrAPITokenRequired indicates that the HTTP management API was enabled without an authentication token.
	ErrAPITokenRequired = errors.New("control plane API token is required (set --api-token or KDNS_API_TOKEN)")

	// ErrAPITokenTooShort indicates that the provided API token does not meet the minimum length requirements.
	ErrAPITokenTooShort = errors.New("api token must be at least 16 characters long")

	// ErrAPITokenInvalid indicates that the API token contains illegal whitespace or control characters.
	ErrAPITokenInvalid = errors.New("api token must not contain whitespace or control characters")

	// ErrEmptyCORSOrigin indicates that CORS is enabled but the allowed origin is empty.
	ErrEmptyCORSOrigin = errors.New("cors origin cannot be empty when cors is enabled; use -http-cors=false to disable cors")

	// ErrReplicaZoneFileForbidden indicates that a zone file was provided to a replica node.
	ErrReplicaZoneFileForbidden = errors.New("cluster: --zone-file cannot be specified in replica mode; replica state is synchronized exclusively from the primary node")

	// ErrClusterTokenRequired indicates that cluster-token is missing in primary or replica mode.
	ErrClusterTokenRequired = errors.New("cluster: cluster-token is required in primary and replica mode")

	// ErrClusterPrimaryURLRequired indicates that primary-url is missing in replica mode.
	ErrClusterPrimaryURLRequired = errors.New("cluster: primary-url is required in replica mode")

	// ErrClusterStandaloneFlagsForbidden indicates that cluster options were provided in standalone mode.
	ErrClusterStandaloneFlagsForbidden = errors.New("cluster: cluster options cannot be specified in standalone mode")

	// ErrClusterPrimaryFlagsForbidden indicates that replica-only options were provided in primary mode.
	ErrClusterPrimaryFlagsForbidden = errors.New("cluster: replica options (primary-url, ca-cert) cannot be specified in primary mode")

	// ErrClusterReplicaFlagsForbidden indicates that primary-only options were provided in replica mode.
	ErrClusterReplicaFlagsForbidden = errors.New("cluster: primary options (cluster-tls-cert, cluster-tls-key) cannot be specified in replica mode")

	// ErrClusterTLSIncomplete indicates that only one of cluster-tls-cert or cluster-tls-key was specified.
	ErrClusterTLSIncomplete = errors.New("cluster: both cluster-tls-cert and cluster-tls-key must be specified")

	// ErrClusterUnknownMode indicates that an unknown or invalid cluster mode was specified.
	ErrClusterUnknownMode = errors.New("cluster: unknown mode")
)

// --- Category 1: Network & Transports (DNS, DoT, DoH, TLS) ---

// NetworkConfig defines listening addresses for DNS transports and operational server identity.
type NetworkConfig struct {
	// Address is the UDP/TCP network address to listen on for standard authoritative DNS queries (e.g. ":5353").
	Address string

	// DoTAddr is the TCP network address to listen on for DNS-over-TLS (RFC 7858, defaults to ":853" when TLS is configured).
	DoTAddr string

	// DoHAddr is the HTTP/HTTPS network address to listen on for DNS-over-HTTPS (RFC 8484, defaults to ":8443").
	DoHAddr string

	// ServerID is the operational server identity returned for CHAOS class queries (id.server / hostname.bind).
	ServerID string
}

// HasDoT reports whether a DNS-over-TLS listening address is configured.
func (n NetworkConfig) HasDoT() bool {
	return n.DoTAddr != ""
}

// HasDoH reports whether a DNS-over-HTTPS listening address is configured.
func (n NetworkConfig) HasDoH() bool {
	return n.DoHAddr != ""
}

// TLSConfig defines the file paths for DNS-over-TLS and DNS-over-HTTPS certificates and private keys.
type TLSConfig struct {
	// CertPath is the filesystem path to the PEM-encoded X.509 TLS certificate file.
	CertPath string

	// KeyPath is the filesystem path to the PEM-encoded TLS private key file.
	KeyPath string
}

// HasCert reports whether a TLS certificate file path is specified.
func (t TLSConfig) HasCert() bool {
	return t.CertPath != ""
}

// HasKey reports whether a TLS private key file path is specified.
func (t TLSConfig) HasKey() bool {
	return t.KeyPath != ""
}

// IsConfigured reports whether at least one TLS parameter is specified.
func (t TLSConfig) IsConfigured() bool {
	return t.CertPath != "" || t.KeyPath != ""
}

// IsComplete reports whether both certificate and private key file paths are specified.
func (t TLSConfig) IsComplete() bool {
	return t.CertPath != "" && t.KeyPath != ""
}

// --- Category 2: HTTP Management & Control Plane API ---

// HTTPConfig defines configuration and security parameters for the HTTP management Control Plane.
type HTTPConfig struct {
	// Addr is the TCP address to bind the HTTP management server (e.g. ":8080").
	Addr string

	// APIToken is the mandatory Bearer authentication token for REST API endpoints (minimum 16 characters).
	APIToken string

	// CORSOrigin is the allowed Access-Control-Allow-Origin header (default "*").
	CORSOrigin string

	// CORS controls whether CORS preflight and response headers are enabled (default true).
	CORS bool
}

// IsEnabled reports whether the HTTP management server address is configured.
func (h HTTPConfig) IsEnabled() bool {
	return h.Addr != ""
}

// --- Category 3: High Availability & Cluster Replication ---

// ClusterMode defines the operation mode of a KDNS node in a cluster deployment.
type ClusterMode string

const (
	// ModeStandalone runs KDNS as an independent authoritative server.
	ModeStandalone ClusterMode = "standalone"

	// ModePrimary runs KDNS as the cluster primary node, serving and streaming WAL mutations to replicas.
	ModePrimary ClusterMode = "primary"

	// ModeReplica runs KDNS as a read-only replica node, streaming and applying mutations from the primary.
	ModeReplica ClusterMode = "replica"
)

// ClusterConfig defines settings for High Availability primary/replica clustering.
type ClusterConfig struct {
	// Mode specifies the cluster role (standalone, primary, replica).
	Mode ClusterMode

	// PrimaryURL is the HTTP/HTTPS URL of the primary node (required for replica mode).
	PrimaryURL string

	// Token is the shared bearer token authenticating replication streams between primary and replicas.
	Token string

	// Addr is the HTTP/HTTPS listening address for the cluster sync endpoints (default ":8081").
	Addr string

	// TLSCert is the optional PEM certificate file path for primary cluster HTTPS replication.
	TLSCert string

	// TLSKey is the optional PEM private key file path for primary cluster HTTPS replication.
	TLSKey string

	// CACert is the optional PEM Root CA certificate file path to verify the primary TLS certificate on replicas.
	CACert string
}

// --- Category 4: Storage & Durability (WAL, Zone File, Compaction) ---

// StorageConfig encapsulates durable storage, snapshotting, and background compaction parameters.
type StorageConfig struct {
	// Dir is the directory path for persistent Write-Ahead Log (WAL) and state snapshot storage.
	Dir string

	// ZoneFile is an optional path to an RFC 1035 master zone file to preload records on first startup.
	ZoneFile string

	// CompactionInterval is the duration between periodic background WAL snapshot compactions (min 1m, default 30m).
	CompactionInterval time.Duration

	// CompactionThreshold is the number of mutations before triggering background WAL compaction (min 100, default 10000).
	CompactionThreshold uint64
}

// HasZoneFile reports whether an initial RFC 1035 zone file is specified.
func (s StorageConfig) HasZoneFile() bool {
	return s.ZoneFile != ""
}

// --- Category 5: Security & Cryptography (TSIG & DNSSEC) ---

// TSIGKey specifies a TSIG key name, algorithm, and secret for authenticated Dynamic DNS Updates (RFC 2136 / RFC 8945).
type TSIGKey struct {
	// Name is the TSIG key domain identifier (e.g. "update-key.example.com.").
	Name string

	// Algorithm is the HMAC algorithm identifier (e.g. "hmac-sha256", "hmac-sha512").
	Algorithm string

	// Secret is the shared secret key (base64 or raw string).
	Secret string
}

// TSIGConfig defines authentication keys for Dynamic DNS Updates (RFC 2136 / RFC 8945).
type TSIGConfig struct {
	// Keys is the slice of registered TSIG authentication keys.
	Keys []TSIGKey
}

// IsEnabled reports whether any TSIG keys are registered.
func (t TSIGConfig) IsEnabled() bool {
	return len(t.Keys) > 0
}

// DNSSECKey specifies a zone and algorithm for DNSSEC on-the-fly signing.
type DNSSECKey struct {
	// Zone is the DNS zone apex domain name for this key (e.g. "example.com.").
	Zone string

	// Algorithm is the cryptographic algorithm number or name (e.g. "13" / "ecdsa-p256", "15" / "ed25519").
	Algorithm string
}

// DNSSECConfig encapsulates DNSSEC on-the-fly signing settings and cryptographic keys.
type DNSSECConfig struct {
	// Keys is the slice of zone signing key specifications.
	Keys []DNSSECKey

	// Enabled controls whether on-the-fly DNSSEC signing and dynamic NSEC authenticated denial are active.
	Enabled bool
}

// --- Category 6: Response Rate Limiting (BCP 140 / RRL) ---

// RRLConfig encapsulates Response Rate Limiting (BCP 140) parameters.
type RRLConfig struct {
	rrl.Config

	// Enabled controls whether Response Rate Limiting is active.
	Enabled bool
}

// --- Category 7: Main Daemon Runtime Configuration ---

// Config specifies the runtime configuration for a kdns daemon instance.
type Config struct {
	// Network defines DNS listening addresses, transports, and server identity.
	Network NetworkConfig

	// TLS defines TLS certificate credentials for DoT/DoH transport encryption.
	TLS TLSConfig

	// HTTP defines configuration for the HTTP management REST API control plane.
	HTTP HTTPConfig

	// Cluster defines high-availability primary/replica replication settings.
	Cluster ClusterConfig

	// Storage defines persistent storage, WAL, and compaction parameters.
	Storage StorageConfig

	// TSIG defines RFC 2136 dynamic DNS update authentication keys.
	TSIG TSIGConfig

	// DNSSEC defines DNSSEC on-the-fly signing parameters and keys.
	DNSSEC DNSSECConfig

	// RRL defines BCP 140 Response Rate Limiting settings.
	RRL RRLConfig

	// Debug enables verbose debug level logging.
	Debug bool
}

// HasTLS reports whether complete TLS credentials are configured.
func (c Config) HasTLS() bool {
	return c.TLS.IsComplete()
}

// HasDoT reports whether a DNS-over-TLS listening address is configured.
func (c Config) HasDoT() bool {
	return c.Network.HasDoT()
}

// HasDoH reports whether a DNS-over-HTTPS listening address is configured.
func (c Config) HasDoH() bool {
	return c.Network.HasDoH()
}

// HasHTTP reports whether an HTTP management and API address is configured.
func (c Config) HasHTTP() bool {
	return c.HTTP.IsEnabled()
}

// HasZoneFile reports whether an initial RFC 1035 zone file is specified.
func (c Config) HasZoneFile() bool {
	return c.Storage.HasZoneFile()
}

// HasTSIG reports whether any TSIG keys are configured.
func (c Config) HasTSIG() bool {
	return c.TSIG.IsEnabled()
}

// HasDNSSEC reports whether DNSSEC on-the-fly signing is enabled.
func (c Config) HasDNSSEC() bool {
	return c.DNSSEC.Enabled
}

// HasRRL reports whether Response Rate Limiting is active.
func (c Config) HasRRL() bool {
	return c.RRL.Enabled
}

// Validate checks the consistency and validity of all configuration parameters.
func (c Config) Validate() error {
	if c.TLS.IsConfigured() && !c.TLS.IsComplete() {
		return ErrIncompleteTLS
	}

	if c.HasDoT() && !c.HasTLS() {
		return fmt.Errorf("%w: %s", ErrDoTRequiresTLS, c.Network.DoTAddr)
	}

	if err := c.validateHTTP(); err != nil {
		return err
	}

	if err := c.validateCluster(); err != nil {
		return err
	}

	return c.validateStorage()
}

// validateHTTP validates control plane HTTP REST API configuration parameters.
func (c Config) validateHTTP() error {
	if !c.HasHTTP() {
		return nil
	}
	if c.HTTP.APIToken == "" {
		return ErrAPITokenRequired
	}
	if len(c.HTTP.APIToken) < MinAPITokenLength {
		return fmt.Errorf("%w: got %d characters, required at least %d", ErrAPITokenTooShort, len(c.HTTP.APIToken), MinAPITokenLength)
	}
	if strings.ContainsAny(c.HTTP.APIToken, " \t\r\n") {
		return ErrAPITokenInvalid
	}
	if c.HTTP.CORS && strings.TrimSpace(c.HTTP.CORSOrigin) == "" {
		return ErrEmptyCORSOrigin
	}
	return nil
}

// validateCluster validates clustering configuration constraints based on the chosen mode.
func (c Config) validateCluster() error {
	switch c.Cluster.Mode {
	case ModeStandalone, "":
		if c.Cluster.Token != "" || c.Cluster.PrimaryURL != "" || c.Cluster.TLSCert != "" ||
			c.Cluster.TLSKey != "" || c.Cluster.CACert != "" {
			return ErrClusterStandaloneFlagsForbidden
		}

	case ModePrimary:
		if c.Cluster.Token == "" {
			return ErrClusterTokenRequired
		}
		if c.Cluster.PrimaryURL != "" || c.Cluster.CACert != "" {
			return ErrClusterPrimaryFlagsForbidden
		}
		if (c.Cluster.TLSCert != "" && c.Cluster.TLSKey == "") || (c.Cluster.TLSCert == "" && c.Cluster.TLSKey != "") {
			return ErrClusterTLSIncomplete
		}

	case ModeReplica:
		if c.Cluster.PrimaryURL == "" {
			return ErrClusterPrimaryURLRequired
		}
		if c.Cluster.Token == "" {
			return ErrClusterTokenRequired
		}
		if c.HasZoneFile() {
			return ErrReplicaZoneFileForbidden
		}
		if c.Cluster.TLSCert != "" || c.Cluster.TLSKey != "" {
			return ErrClusterReplicaFlagsForbidden
		}

	default:
		return fmt.Errorf("%w %q", ErrClusterUnknownMode, c.Cluster.Mode)
	}
	return nil
}

// validateStorage validates storage engine and background compaction guardrail thresholds.
func (c Config) validateStorage() error {
	if c.Storage.CompactionThreshold > 0 && c.Storage.CompactionThreshold < store.MinCompactionThreshold {
		return fmt.Errorf("invalid compaction threshold %d: %w", c.Storage.CompactionThreshold, store.ErrCompactionThresholdTooLow)
	}

	if c.Storage.CompactionInterval > 0 && c.Storage.CompactionInterval < store.MinCompactionInterval {
		return fmt.Errorf("invalid compaction interval %s: %w", c.Storage.CompactionInterval, store.ErrCompactionIntervalTooLow)
	}

	return nil
}

// ReplicaTLSConfig builds the tls.Config for the replica client, loading any CA certificate file safely using os.OpenRoot.
func (c Config) ReplicaTLSConfig() (*tls.Config, error) {
	if !strings.HasPrefix(c.Cluster.PrimaryURL, "https://") && c.Cluster.CACert == "" {
		return nil, nil
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if c.Cluster.CACert != "" {
		cleanPath := filepath.Clean(c.Cluster.CACert)
		dir, file := filepath.Split(cleanPath)
		if dir == "" {
			dir = "."
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, fmt.Errorf("open ca cert dir: %w", err)
		}
		defer func() { _ = root.Close() }()

		caData, err := root.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read ca cert file: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caData)
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

// StoreOptions builds the slice of store.Option based on the daemon configuration.
func (c Config) StoreOptions(logger *slog.Logger, m *metrics.Metrics) []store.Option {
	storageLogger := logger.With(slog.String("component", "storage"))
	opts := []store.Option{
		store.WithLogger(storageLogger),
		store.WithMetrics(m),
	}
	if c.HasZoneFile() {
		opts = append(opts, store.WithZoneFile(c.Storage.ZoneFile))
	}
	if c.Storage.CompactionThreshold > 0 {
		opts = append(opts, store.WithCompactionThreshold(c.Storage.CompactionThreshold))
	}
	if c.Storage.CompactionInterval > 0 {
		opts = append(opts, store.WithCompactionInterval(c.Storage.CompactionInterval))
	}
	if c.Cluster.Mode == ModeReplica {
		opts = append(opts, store.WithReplicaMode(true))
	}
	return opts
}

// KeyRing builds a tsig.KeyRing from the configured TSIG keys.
// Returns nil if no TSIG keys are configured.
func (c Config) KeyRing() *tsig.KeyRing {
	if !c.HasTSIG() {
		return nil
	}
	kr := tsig.NewKeyRing()
	for _, k := range c.TSIG.Keys {
		secretBytes, err := base64.StdEncoding.DecodeString(k.Secret)
		if err != nil {
			secretBytes = []byte(k.Secret)
		}
		kr.Add(tsig.Key{
			Name:      k.Name,
			Algorithm: k.Algorithm,
			Secret:    secretBytes,
		})
	}
	return kr
}

// DNSSECManager builds a dnssec.Manager if DNSSEC on-the-fly signing is enabled.
// Returns nil if DNSSEC is disabled.
func (c Config) DNSSECManager() (*dnssec.Manager, error) {
	if !c.DNSSEC.Enabled {
		return nil, nil
	}
	mgr := dnssec.NewManager()
	if len(c.DNSSEC.Keys) == 0 {
		key, err := dnssec.NewECDSAKey(".", dnssec.FlagZSK)
		if err != nil {
			return nil, fmt.Errorf("failed to create default root dnssec key: %w", err)
		}
		mgr.Add(key)
		return mgr, nil
	}
	for _, k := range c.DNSSEC.Keys {
		var (
			key *dnssec.Key
			err error
		)
		switch k.Algorithm {
		case "ed25519", "15":
			key, err = dnssec.NewEd25519Key(k.Zone, dnssec.FlagZSK)
		default:
			key, err = dnssec.NewECDSAKey(k.Zone, dnssec.FlagZSK)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create dnssec key for zone %q (algorithm %s): %w", k.Zone, k.Algorithm, err)
		}
		mgr.Add(key)
	}
	return mgr, nil
}

// Limiter instantiates an RRL Limiter based on the daemon configuration.
// Returns nil if RRL is disabled.
func (c Config) Limiter() *rrl.Limiter {
	if !c.HasRRL() {
		return nil
	}
	return rrl.New(c.RRL.Config)
}
