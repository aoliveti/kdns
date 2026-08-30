// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package daemon

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/rrl"
	"github.com/aoliveti/kdns/internal/store"
)

func TestTLSConfig_Methods(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()

		cfg := TLSConfig{}
		assert.False(t, cfg.HasCert())
		assert.False(t, cfg.HasKey())
		assert.False(t, cfg.IsConfigured())
		assert.False(t, cfg.IsComplete())
	})

	t.Run("OnlyCert", func(t *testing.T) {
		t.Parallel()

		cfg := TLSConfig{CertPath: "cert.pem"}
		assert.True(t, cfg.HasCert())
		assert.False(t, cfg.HasKey())
		assert.True(t, cfg.IsConfigured())
		assert.False(t, cfg.IsComplete())
	})

	t.Run("OnlyKey", func(t *testing.T) {
		t.Parallel()

		cfg := TLSConfig{KeyPath: "key.pem"}
		assert.False(t, cfg.HasCert())
		assert.True(t, cfg.HasKey())
		assert.True(t, cfg.IsConfigured())
		assert.False(t, cfg.IsComplete())
	})

	t.Run("Complete", func(t *testing.T) {
		t.Parallel()

		cfg := TLSConfig{CertPath: "cert.pem", KeyPath: "key.pem"}
		assert.True(t, cfg.HasCert())
		assert.True(t, cfg.HasKey())
		assert.True(t, cfg.IsConfigured())
		assert.True(t, cfg.IsComplete())
	})
}

func TestConfig_Predicates(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Network: NetworkConfig{
			Address: ":5353",
			DoTAddr: ":853",
		},
		HTTP: HTTPConfig{
			Addr:     ":8080",
			APIToken: "test-token-12345678",
		},
		Storage: StorageConfig{
			ZoneFile: "example.zone",
			Dir:      "/tmp/data",
		},
		TLS: TLSConfig{CertPath: "cert.pem", KeyPath: "key.pem"},
		RRL: RRLConfig{
			Enabled: true,
			Config: rrl.Config{
				ResponsesPerSecond: 50,
				ErrorsPerSecond:    10,
				SlipRate:           2,
				TableSize:          1024,
				IPv4Prefix:         24,
				IPv6Prefix:         56,
			},
		},
	}

	assert.True(t, cfg.HasTLS())
	assert.True(t, cfg.HasDoT())
	assert.True(t, cfg.HasHTTP())
	assert.True(t, cfg.HasZoneFile())
	assert.True(t, cfg.HasRRL())
	require.NoError(t, cfg.Validate())
	assert.NotNil(t, cfg.Limiter())
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	t.Run("IncompleteTLSCertOnly", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			TLS: TLSConfig{CertPath: "cert.pem"},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrIncompleteTLS)
	})

	t.Run("IncompleteTLSKeyOnly", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			TLS: TLSConfig{KeyPath: "key.pem"},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrIncompleteTLS)
	})

	t.Run("DoTWithoutTLS", func(t *testing.T) {
		t.Parallel()
		cfg := Config{
			Network: NetworkConfig{DoTAddr: ":853"},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrDoTRequiresTLS)
	})

	t.Run("HTTPWithoutToken_FailsFast", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			HTTP: HTTPConfig{Addr: ":8080"},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrAPITokenRequired)
	})

	t.Run("HTTPTokenTooShort_FailsFast", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			HTTP: HTTPConfig{
				Addr:     ":8080",
				APIToken: "short-token",
			},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrAPITokenTooShort)
	})

	t.Run("HTTPTokenWithWhitespace_FailsFast", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			HTTP: HTTPConfig{
				Addr:     ":8080",
				APIToken: "token with spaces 123",
			},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrAPITokenInvalid)
	})

	t.Run("HTTPWithoutToken_Fails", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			HTTP: HTTPConfig{
				Addr: ":8080",
			},
		}
		require.ErrorIs(t, cfg.Validate(), ErrAPITokenRequired)
	})

	t.Run("CompactionThresholdTooLow", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Storage: StorageConfig{CompactionThreshold: 50},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, store.ErrCompactionThresholdTooLow)
	})

	t.Run("CompactionIntervalTooLow", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Storage: StorageConfig{CompactionInterval: 30 * time.Second},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, store.ErrCompactionIntervalTooLow)
	})

	t.Run("ValidCompactionSettings", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Storage: StorageConfig{
				CompactionThreshold: 10000,
				CompactionInterval:  30 * time.Minute,
			},
		}
		require.NoError(t, cfg.Validate())
	})

	t.Run("ClusterReplica_MissingPrimaryURL", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Cluster: ClusterConfig{
				Mode:  "replica",
				Token: "cluster-token-123",
			},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrClusterPrimaryURLRequired)
	})

	t.Run("ClusterReplica_MissingToken", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Cluster: ClusterConfig{
				Mode:       "replica",
				PrimaryURL: "http://127.0.0.1:8081",
			},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrClusterTokenRequired)
	})

	t.Run("ClusterPrimary_MissingToken", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Cluster: ClusterConfig{
				Mode: "primary",
			},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrClusterTokenRequired)
	})

	t.Run("Cluster_InvalidMode", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Cluster: ClusterConfig{
				Mode: "invalid-mode",
			},
		}
		err := cfg.Validate()
		require.ErrorIs(t, err, ErrClusterUnknownMode)
	})

	t.Run("Cluster_ValidPrimaryAndReplica", func(t *testing.T) {
		t.Parallel()

		primaryCfg := Config{
			Cluster: ClusterConfig{
				Mode:    "primary",
				Token:   "token-1234",
				TLSCert: "cert.pem",
				TLSKey:  "key.pem",
			},
		}
		require.NoError(t, primaryCfg.Validate())

		replicaCfg := Config{
			Cluster: ClusterConfig{
				Mode:       "replica",
				PrimaryURL: "https://primary:8081",
				Token:      "token-1234",
				CACert:     "ca.pem",
			},
		}
		require.NoError(t, replicaCfg.Validate())
	})

	t.Run("ClusterStandalone_RejectsClusterFlags", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Cluster: ClusterConfig{
				Mode:  "standalone",
				Token: "token-1234",
			},
		}
		require.ErrorIs(t, cfg.Validate(), ErrClusterStandaloneFlagsForbidden)

		cfg2 := Config{
			Cluster: ClusterConfig{
				PrimaryURL: "http://primary:8081",
			},
		}
		require.ErrorIs(t, cfg2.Validate(), ErrClusterStandaloneFlagsForbidden)
	})

	t.Run("ClusterPrimary_ValidationRules", func(t *testing.T) {
		t.Parallel()

		// Missing token
		cfg1 := Config{
			Cluster: ClusterConfig{Mode: "primary"},
		}
		require.ErrorIs(t, cfg1.Validate(), ErrClusterTokenRequired)

		// Replica option forbidden
		cfg2 := Config{
			Cluster: ClusterConfig{
				Mode:       "primary",
				Token:      "token-1234",
				PrimaryURL: "http://other:8081",
			},
		}
		require.ErrorIs(t, cfg2.Validate(), ErrClusterPrimaryFlagsForbidden)

		// Incomplete TLS (cert only)
		cfg3 := Config{
			Cluster: ClusterConfig{
				Mode:    "primary",
				Token:   "token-1234",
				TLSCert: "cert.pem",
			},
		}
		require.ErrorIs(t, cfg3.Validate(), ErrClusterTLSIncomplete)

		// Incomplete TLS (key only)
		cfg4 := Config{
			Cluster: ClusterConfig{
				Mode:   "primary",
				Token:  "token-1234",
				TLSKey: "key.pem",
			},
		}
		require.ErrorIs(t, cfg4.Validate(), ErrClusterTLSIncomplete)
	})

	t.Run("ClusterReplica_ValidationRules", func(t *testing.T) {
		t.Parallel()

		// Missing primary URL
		cfg1 := Config{
			Cluster: ClusterConfig{
				Mode:  "replica",
				Token: "token-1234",
			},
		}
		require.ErrorIs(t, cfg1.Validate(), ErrClusterPrimaryURLRequired)

		// Missing token
		cfg2 := Config{
			Cluster: ClusterConfig{
				Mode:       "replica",
				PrimaryURL: "http://primary:8081",
			},
		}
		require.ErrorIs(t, cfg2.Validate(), ErrClusterTokenRequired)

		// Primary TLS option forbidden on replica
		cfg3 := Config{
			Cluster: ClusterConfig{
				Mode:       "replica",
				PrimaryURL: "http://primary:8081",
				Token:      "token-1234",
				TLSCert:    "cert.pem",
			},
		}
		require.ErrorIs(t, cfg3.Validate(), ErrClusterReplicaFlagsForbidden)
	})

	t.Run("ClusterReplica_ZoneFileForbidden", func(t *testing.T) {
		t.Parallel()

		replicaCfg := Config{
			Cluster: ClusterConfig{
				Mode:       "replica",
				PrimaryURL: "http://primary:8081",
				Token:      "token-1234",
			},
			Storage: StorageConfig{
				ZoneFile: "zone.txt",
			},
		}
		err := replicaCfg.Validate()
		require.ErrorIs(t, err, ErrReplicaZoneFileForbidden)
	})
}

func TestConfig_StoreOptions(t *testing.T) {
	t.Parallel()

	logger := slog.Default()

	t.Run("WithoutZoneFile", func(t *testing.T) {
		t.Parallel()

		cfg := Config{Storage: StorageConfig{Dir: "/tmp"}}
		opts := cfg.StoreOptions(logger, nil)
		assert.Len(t, opts, 2)
	})

	t.Run("WithZoneFile", func(t *testing.T) {
		t.Parallel()

		cfg := Config{Storage: StorageConfig{Dir: "/tmp", ZoneFile: "example.zone"}}
		opts := cfg.StoreOptions(logger, nil)
		assert.Len(t, opts, 3)
	})

	t.Run("WithCompactionSettings", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			Storage: StorageConfig{
				Dir:                 "/tmp",
				ZoneFile:            "example.zone",
				CompactionThreshold: 10000,
				CompactionInterval:  30 * time.Minute,
			},
		}
		opts := cfg.StoreOptions(logger, nil)
		assert.Len(t, opts, 5)
	})
}

func TestConfig_LimiterDisabled(t *testing.T) {
	t.Parallel()

	cfg := Config{
		RRL: RRLConfig{Enabled: false},
	}
	assert.False(t, cfg.HasRRL())
	assert.Nil(t, cfg.Limiter())
}

func TestConfig_TSIGAndDNSSEC(t *testing.T) {
	t.Parallel()

	t.Run("TSIGDisabled", func(t *testing.T) {
		t.Parallel()

		cfg := Config{}
		assert.False(t, cfg.HasTSIG())
		assert.Nil(t, cfg.KeyRing())
	})

	t.Run("TSIGEnabled", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			TSIG: TSIGConfig{
				Keys: []TSIGKey{
					{ //nolint:gosec // dummy test credentials
						Name:      "test-key.",
						Algorithm: "hmac-sha256",
						Secret:    "c2VjcmV0MTIz",
					},
				},
			},
		}
		assert.True(t, cfg.HasTSIG())
		kr := cfg.KeyRing()
		require.NotNil(t, kr)
		k, ok := kr.Key("test-key.")
		require.True(t, ok)
		assert.Equal(t, "test-key.", k.Name)
	})

	t.Run("DNSSECDisabled", func(t *testing.T) {
		t.Parallel()

		cfg := Config{}
		assert.False(t, cfg.HasDNSSEC())
		mgr, err := cfg.DNSSECManager()
		require.NoError(t, err)
		assert.Nil(t, mgr)
	})

	t.Run("DNSSECEnabledWithCustomKeys", func(t *testing.T) {
		t.Parallel()

		cfg := Config{
			DNSSEC: DNSSECConfig{
				Enabled: true,
				Keys: []DNSSECKey{
					{Zone: "example.com", Algorithm: "13"},
					{Zone: "example.org", Algorithm: "15"},
				},
			},
		}
		assert.True(t, cfg.HasDNSSEC())
		mgr, err := cfg.DNSSECManager()
		require.NoError(t, err)
		require.NotNil(t, mgr)
		assert.True(t, mgr.HasKeys("example.com"))
		assert.True(t, mgr.HasKeys("example.org"))
	})

	t.Run("ReplicaTLSConfig", func(t *testing.T) {
		t.Parallel()

		// Plaintext HTTP returns nil tls.Config
		plainCfg := Config{
			Cluster: ClusterConfig{
				PrimaryURL: "http://127.0.0.1:8081",
			},
		}
		tlsCfg, err := plainCfg.ReplicaTLSConfig()
		require.NoError(t, err)
		assert.Nil(t, tlsCfg)

		// HTTPS without CACert returns default TLS 1.3 config
		httpsCfg := Config{
			Cluster: ClusterConfig{
				PrimaryURL: "https://127.0.0.1:8081",
			},
		}
		tlsCfg, err = httpsCfg.ReplicaTLSConfig()
		require.NoError(t, err)
		require.NotNil(t, tlsCfg)
		assert.Nil(t, tlsCfg.RootCAs)

		// Invalid CACert path returns error
		invalidCaCfg := Config{
			Cluster: ClusterConfig{
				PrimaryURL: "https://127.0.0.1:8081",
				CACert:     "/nonexistent/ca.pem",
			},
		}
		_, err = invalidCaCfg.ReplicaTLSConfig()
		require.Error(t, err)
	})
}
