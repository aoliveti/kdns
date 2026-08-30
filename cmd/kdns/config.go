// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aoliveti/kdns/internal/daemon"
	"github.com/aoliveti/kdns/internal/rrl"
	"github.com/aoliveti/kdns/internal/store"
)

type cliConfig struct {
	// Network & Transports
	address   string
	dotAddr   string
	dohAddr   string
	tlsCert   string
	tlsKey    string
	serverID  string
	logFormat string

	// HTTP Control Plane
	httpAddr       string
	apiToken       string
	httpCORSOrigin string

	// High Availability & Cluster
	mode           string
	clusterAddr    string
	clusterToken   string
	primaryURL     string
	clusterTLSCert string
	clusterTLSKey  string
	clusterCACert  string

	// Storage & Durability
	storageDir string
	zoneFile   string

	// Security (TSIG & DNSSEC)
	tsigKeys   string
	dnssecKeys string

	// 8-byte integers / durations
	compactionThreshold uint64
	compactionInterval  time.Duration

	// 4-byte integers (Response Rate Limiting)
	rrlRate       int
	rrlErrorRate  int
	rrlSlip       int
	rrlTableSize  int
	rrlIPv4Prefix int
	rrlIPv6Prefix int

	// Boolean flags
	debug         bool
	dnssecEnabled bool
	httpCORS      bool
	rrlEnabled    bool
}

func parseCLI(args []string, output io.Writer) (*cliConfig, error) {
	fs := flag.NewFlagSet("kdns", flag.ContinueOnError)
	fs.SetOutput(output)

	cfg := &cliConfig{}

	// 1. Network & Transports
	fs.StringVar(&cfg.address, "address", getEnv("KDNS_ADDRESS", ":5353"), "UDP/TCP network address to listen on for standard authoritative DNS queries (default :5353)")
	fs.StringVar(&cfg.dotAddr, "dot-addr", getEnv("KDNS_DOT_ADDR", ""), "TCP network address to listen on for DNS-over-TLS (defaults to :853 when TLS certificates are configured)")
	fs.StringVar(&cfg.dohAddr, "doh-addr", getEnv("KDNS_DOH_ADDR", ":8443"), "HTTP/HTTPS network address to listen on for DNS-over-HTTPS (DoH RFC 8484, default :8443)")
	fs.StringVar(&cfg.tlsCert, "tls-cert", getEnv("KDNS_TLS_CERT", ""), "Path to the TLS certificate file (PEM) for DoT/DoH transport encryption")
	fs.StringVar(&cfg.tlsKey, "tls-key", getEnv("KDNS_TLS_KEY", ""), "Path to the TLS private key file (PEM) for DoT/DoH transport encryption")
	fs.StringVar(&cfg.serverID, "server-id", getEnv("KDNS_SERVER_ID", ""), "Custom server identity string returned for CHAOS class queries (id.server / hostname.bind)")

	// 2. HTTP Management & Control Plane
	fs.StringVar(&cfg.httpAddr, "http-addr", getEnv("KDNS_HTTP_ADDR", ":8080"), "HTTP management server address for REST API, Prometheus metrics, and health probes (default :8080)")
	fs.StringVar(&cfg.apiToken, "api-token", getEnv("KDNS_API_TOKEN", ""), "Bearer token for control plane REST API authentication (required, minimum 16 characters)")
	fs.BoolVar(&cfg.httpCORS, "http-cors", getEnvBool("KDNS_HTTP_CORS", true), "Enable CORS headers and preflight handling on the HTTP management API (default true)")
	fs.StringVar(&cfg.httpCORSOrigin, "http-cors-origin", getEnv("KDNS_HTTP_CORS_ORIGIN", "*"), "Allowed CORS origin for REST API (e.g. '*' or 'https://app.example.com', default *)")

	// 3. High Availability & Cluster Replication
	fs.StringVar(&cfg.mode, "mode", getEnv("KDNS_MODE", "standalone"), "Cluster operation mode: standalone (default), primary (streams WAL mutations), or replica (read-only state sync)")
	fs.StringVar(&cfg.clusterAddr, "cluster-addr", getEnv("KDNS_CLUSTER_ADDR", ":8081"), "HTTP/HTTPS network address for cluster WAL replication sync endpoints (default :8081)")
	fs.StringVar(&cfg.clusterToken, "cluster-token", getEnv("KDNS_CLUSTER_TOKEN", ""), "Shared bearer authentication token for cluster replication between primary and replicas")
	fs.StringVar(&cfg.primaryURL, "primary-url", getEnv("KDNS_PRIMARY_URL", ""), "HTTP/HTTPS URL of the primary node (required in replica mode, e.g. http://primary:8081)")
	fs.StringVar(&cfg.clusterTLSCert, "cluster-tls-cert", getEnv("KDNS_CLUSTER_TLS_CERT", ""), "Path to the TLS certificate file (PEM) for primary cluster replication listener")
	fs.StringVar(&cfg.clusterTLSKey, "cluster-tls-key", getEnv("KDNS_CLUSTER_TLS_KEY", ""), "Path to the TLS private key file (PEM) for primary cluster replication listener")
	fs.StringVar(&cfg.clusterCACert, "cluster-ca-cert", getEnv("KDNS_CLUSTER_CA_CERT", ""), "Path to the Root CA certificate file (PEM) to verify the primary TLS certificate in replica mode")

	// 4. Storage & Durability
	fs.StringVar(&cfg.storageDir, "storage-dir", getEnv("KDNS_STORAGE_DIR", "./data"), "Directory path for persistent storage (Write-Ahead Log and compressed snapshots, default ./data)")
	fs.StringVar(&cfg.zoneFile, "zone-file", getEnv("KDNS_ZONE_FILE", ""), "Path to an initial RFC 1035 master zone file to preload records on first startup")
	fs.Uint64Var(&cfg.compactionThreshold, "compaction-threshold", getEnvUint64("KDNS_COMPACTION_THRESHOLD", store.DefaultCompactionThreshold), "Number of mutations before triggering background WAL compaction (min 100, default 10000)")
	fs.DurationVar(&cfg.compactionInterval, "compaction-interval", getEnvDuration("KDNS_COMPACTION_INTERVAL", store.DefaultCompactionInterval), "Time interval between periodic background WAL compactions (min 1m, default 30m)")

	// 5. Security & Cryptography (TSIG & DNSSEC)
	fs.StringVar(&cfg.tsigKeys, "tsig-keys", getEnv("KDNS_TSIG_KEYS", ""), "Comma-separated TSIG keys for RFC 2136 dynamic DNS updates (format: name:algo:secret or name:secret)")
	fs.BoolVar(&cfg.dnssecEnabled, "dnssec", getEnvBool("KDNS_DNSSEC", false), "Enable DNSSEC on-the-fly signing and dynamic NSEC authenticated denial of existence")
	fs.StringVar(&cfg.dnssecKeys, "dnssec-keys", getEnv("KDNS_DNSSEC_KEYS", ""), "Comma-separated DNSSEC signing keys per zone (format: example.com:13,example.org:15 where 13=ECDSA-P256, 15=Ed25519)")

	// 6. Response Rate Limiting (BCP 140 / RRL)
	fs.BoolVar(&cfg.rrlEnabled, "rrl", getEnvBool("KDNS_RRL", true), "Enable Response Rate Limiting to mitigate DNS amplification attacks (default true)")
	fs.IntVar(&cfg.rrlRate, "rrl-rate", getEnvInt("KDNS_RRL_RATE", rrl.DefaultResponsesPerSecond), "Maximum identical DNS responses per second per client subnet (default 50)")
	fs.IntVar(&cfg.rrlErrorRate, "rrl-error-rate", getEnvInt("KDNS_RRL_ERROR_RATE", rrl.DefaultErrorsPerSecond), "Maximum error responses per second per client subnet (default 10)")
	fs.IntVar(&cfg.rrlSlip, "rrl-slip", getEnvInt("KDNS_RRL_SLIP", rrl.DefaultSlipRate), "RRL slip rate: 1 out of every N dropped responses is sent with TC=1 to force TCP retry (default 2)")
	fs.IntVar(&cfg.rrlTableSize, "rrl-table-size", getEnvInt("KDNS_RRL_TABLE_SIZE", rrl.DefaultTableSize), "Total slot capacity of the sharded RRL tracking table (default 65536)")
	fs.IntVar(&cfg.rrlIPv4Prefix, "rrl-ipv4-prefix", getEnvInt("KDNS_RRL_IPV4_PREFIX", rrl.DefaultIPv4Prefix), "IPv4 client subnet prefix length for rate limiting aggregation (default 24)")
	fs.IntVar(&cfg.rrlIPv6Prefix, "rrl-ipv6-prefix", getEnvInt("KDNS_RRL_IPV6_PREFIX", rrl.DefaultIPv6Prefix), "IPv6 client subnet prefix length for rate limiting aggregation (default 56)")

	// 7. Logging & Diagnostics
	fs.StringVar(&cfg.logFormat, "log-format", getEnv("KDNS_LOG_FORMAT", "json"), "Log output format: json (cloud-native default) or text (console development)")
	fs.BoolVar(&cfg.debug, "debug", getEnvBool("KDNS_DEBUG", false), "Enable verbose debug logging (default false)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *cliConfig) toDaemonConfig() daemon.Config {
	return daemon.Config{
		Network: daemon.NetworkConfig{
			Address:  c.address,
			DoTAddr:  c.dotAddr,
			DoHAddr:  c.dohAddr,
			ServerID: c.serverID,
		},
		TLS: daemon.TLSConfig{
			CertPath: c.tlsCert,
			KeyPath:  c.tlsKey,
		},
		HTTP: daemon.HTTPConfig{
			Addr:       c.httpAddr,
			APIToken:   c.apiToken,
			CORS:       c.httpCORS,
			CORSOrigin: c.httpCORSOrigin,
		},
		Cluster: daemon.ClusterConfig{
			Mode:       daemon.ClusterMode(c.mode),
			PrimaryURL: c.primaryURL,
			Token:      c.clusterToken,
			Addr:       c.clusterAddr,
			TLSCert:    c.clusterTLSCert,
			TLSKey:     c.clusterTLSKey,
			CACert:     c.clusterCACert,
		},
		Storage: daemon.StorageConfig{
			Dir:                 c.storageDir,
			ZoneFile:            c.zoneFile,
			CompactionInterval:  c.compactionInterval,
			CompactionThreshold: c.compactionThreshold,
		},
		TSIG: daemon.TSIGConfig{
			Keys: parseTSIGKeys(c.tsigKeys),
		},
		DNSSEC: daemon.DNSSECConfig{
			Enabled: c.dnssecEnabled,
			Keys:    parseDNSSECKeys(c.dnssecKeys),
		},
		RRL: daemon.RRLConfig{
			Enabled: c.rrlEnabled,
			Config: rrl.Config{
				ResponsesPerSecond: c.rrlRate,
				ErrorsPerSecond:    c.rrlErrorRate,
				SlipRate:           c.rrlSlip,
				TableSize:          c.rrlTableSize,
				IPv4Prefix:         c.rrlIPv4Prefix,
				IPv6Prefix:         c.rrlIPv6Prefix,
			},
		},
		Debug: c.debug,
	}
}

func parseDNSSECKeys(raw string) []daemon.DNSSECKey {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var res []daemon.DNSSECKey
	for p := range strings.SplitSeq(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		zone, algo, found := strings.Cut(p, ":")
		if !found || algo == "" {
			algo = "13"
		}
		res = append(res, daemon.DNSSECKey{
			Zone:      zone,
			Algorithm: algo,
		})
	}
	return res
}

func parseTSIGKeys(raw string) []daemon.TSIGKey {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var keys []daemon.TSIGKey
	for entry := range strings.SplitSeq(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		first, rest, found := strings.Cut(entry, ":")
		if !found {
			continue
		}
		second, third, hasThird := strings.Cut(rest, ":")
		name := first
		algo := "hmac-sha256"
		secret := second
		if hasThird {
			algo = second
			secret = third
		}
		keys = append(keys, daemon.TSIGKey{
			Name:      name,
			Algorithm: algo,
			Secret:    secret,
		})
	}
	return keys
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	return val == "true" || val == "1" || val == "yes"
}

func getEnvInt(key string, fallback int) int {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	if n, err := strconv.Atoi(val); err == nil {
		return n
	}
	return fallback
}

func getEnvUint64(key string, fallback uint64) uint64 {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	if n, err := strconv.ParseUint(val, 10, 64); err == nil {
		return n
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	if d, err := time.ParseDuration(val); err == nil {
		return d
	}
	return fallback
}
