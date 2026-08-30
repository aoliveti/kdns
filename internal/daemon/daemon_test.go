// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/rrl"
)

func TestDaemon_Lifecycle(t *testing.T) {
	t.Run("InvalidConfig", func(t *testing.T) {
		cfg := Config{
			Network: NetworkConfig{DoTAddr: ":853"},
		}
		err := Run(t.Context(), cfg)
		require.ErrorIs(t, err, ErrDoTRequiresTLS)
	})

	t.Run("InvalidStorageDir", func(t *testing.T) {
		invalidFilePath := filepath.Join(t.TempDir(), "invalid-file")
		require.NoError(t, os.WriteFile(invalidFilePath, []byte("not-a-directory"), 0o600))

		cfg := Config{
			Network: NetworkConfig{Address: "127.0.0.1:0"},
			Storage: StorageConfig{Dir: invalidFilePath},
		}
		err := Run(t.Context(), cfg)
		require.Error(t, err)
	})

	t.Run("FullServerLifecycle", func(t *testing.T) {
		storageDir := filepath.Join(t.TempDir(), "data")
		require.NoError(t, os.MkdirAll(storageDir, 0o750))

		zoneFilePath := filepath.Join(storageDir, "example.zone")
		require.NoError(t, os.WriteFile(zoneFilePath, []byte("example.com. 300 IN A 1.2.3.4\n"), 0o600))

		var stdout bytes.Buffer

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		cfg := Config{
			Network: NetworkConfig{
				Address: "127.0.0.1:0",
				DoHAddr: "127.0.0.1:0",
			},
			HTTP: HTTPConfig{
				Addr:     "127.0.0.1:0",
				APIToken: "test-token-12345678",
			},
			Storage: StorageConfig{
				Dir:      storageDir,
				ZoneFile: "example.zone",
			},
			Debug: true,
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

		errCh := make(chan error, 1)
		go func() {
			errCh <- Run(ctx, cfg,
				WithOutput(&stdout),
				WithBuildInfo("1.0.0", "abc1234", "2026-08-18"),
			)
		}()

		time.Sleep(150 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("daemon did not shut down within timeout")
		}

		assert.Contains(t, stdout.String(), "starting kdns server")
		assert.Contains(t, stdout.String(), "shutdown complete")
	})

	t.Run("WithLoggerCustomOption", func(t *testing.T) {
		storageDir := filepath.Join(t.TempDir(), "data")
		require.NoError(t, os.MkdirAll(storageDir, 0o750))

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		cfg := Config{
			Network: NetworkConfig{Address: "127.0.0.1:0"},
			Storage: StorageConfig{Dir: storageDir},
		}

		customLogger := slog.New(slog.DiscardHandler)
		errCh := make(chan error, 1)
		go func() {
			errCh <- Run(ctx, cfg, WithLogger(customLogger))
		}()

		time.Sleep(100 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("daemon did not shut down within timeout")
		}
	})

	t.Run("SIGHUP_TriggersHotReload", func(t *testing.T) {
		storageDir := filepath.Join(t.TempDir(), "data")
		require.NoError(t, os.MkdirAll(storageDir, 0o750))

		zoneFilePath := filepath.Join(storageDir, "example.zone")
		require.NoError(t, os.WriteFile(zoneFilePath, []byte("example.com. 300 IN A 1.2.3.4\n"), 0o600))

		var stdout bytes.Buffer
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		cfg := Config{
			Network: NetworkConfig{Address: "127.0.0.1:0"},
			Storage: StorageConfig{
				Dir:      storageDir,
				ZoneFile: "example.zone",
			},
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- Run(ctx, cfg, WithOutput(&stdout))
		}()

		time.Sleep(150 * time.Millisecond)

		// Send SIGHUP to self
		require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGHUP))

		time.Sleep(150 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("daemon did not shut down within timeout")
		}

		assert.Contains(t, stdout.String(), "received SIGHUP signal, initiating hot-reload")
		assert.Contains(t, stdout.String(), "store state reloaded successfully")
	})

	t.Run("BootConfigurations", func(t *testing.T) {
		tests := []struct {
			cfgFn func(dir string) Config
			name  string
		}{
			{
				name: "PrimaryCluster",
				cfgFn: func(dir string) Config {
					return Config{
						Network: NetworkConfig{Address: "127.0.0.1:0"},
						Cluster: ClusterConfig{
							Mode:  "primary",
							Addr:  "127.0.0.1:0",
							Token: "cluster-secret",
						},
						Storage: StorageConfig{Dir: dir},
					}
				},
			},
			{
				name: "ReplicaCluster",
				cfgFn: func(dir string) Config {
					return Config{
						Network: NetworkConfig{Address: "127.0.0.1:0"},
						Cluster: ClusterConfig{
							Mode:       "replica",
							PrimaryURL: "http://127.0.0.1:59999",
							Token:      "cluster-secret",
						},
						Storage: StorageConfig{Dir: dir},
					}
				},
			},
			{
				name: "DNSSEC",
				cfgFn: func(dir string) Config {
					return Config{
						Network: NetworkConfig{Address: "127.0.0.1:0"},
						DNSSEC: DNSSECConfig{
							Enabled: true,
						},
						Storage: StorageConfig{Dir: dir},
					}
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				storageDir := filepath.Join(t.TempDir(), tt.name)
				require.NoError(t, os.MkdirAll(storageDir, 0o750))

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				errCh := make(chan error, 1)
				go func() {
					errCh <- Run(ctx, tt.cfgFn(storageDir))
				}()

				time.Sleep(100 * time.Millisecond)
				cancel()

				select {
				case err := <-errCh:
					require.NoError(t, err)
				case <-time.After(3 * time.Second):
					t.Fatalf("%s daemon did not shut down within timeout", tt.name)
				}
			})
		}
	})

	t.Run("TLSErrorHandling", func(t *testing.T) {
		cfg := Config{
			Network: NetworkConfig{
				Address: "127.0.0.1:0",
				DoTAddr: "127.0.0.1:0",
			},
			TLS: TLSConfig{
				CertPath: "nonexistent.crt",
				KeyPath:  "nonexistent.key",
			},
			Storage: StorageConfig{Dir: t.TempDir()},
		}

		err := Run(t.Context(), cfg)
		require.ErrorIs(t, err, ErrTLSInitFailed)
	})
}

func TestDaemon_ServerIDResolution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configured string
		wantPrefix string
	}{
		{
			name:       "ExplicitServerID",
			configured: "ns1.example.com",
			wantPrefix: `server_id="ns1.example.com"`,
		},
		{
			name:       "ExplicitNone",
			configured: "none",
			wantPrefix: `server_id="none"`,
		},
		{
			name:       "DefaultEmptyFallsBackToHostnameOrNone",
			configured: "",
			wantPrefix: `server_id=`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := Config{
				Network: NetworkConfig{
					ServerID: tt.configured,
				},
			}

			d, err := New(cfg)
			require.NoError(t, err)
			require.NotNil(t, d)

			var buf bytes.Buffer
			_, err = d.telemetry.WriteTo(&buf)
			require.NoError(t, err)
			assert.Contains(t, buf.String(), tt.wantPrefix)
		})
	}
}
