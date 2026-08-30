// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/daemon"
)

func TestCLIConfig_Parse(t *testing.T) {
	t.Run("Defaults", func(t *testing.T) {
		var buf bytes.Buffer
		cfg, err := parseCLI([]string{}, &buf)
		require.NoError(t, err)

		assert.Equal(t, ":5353", cfg.address)
		assert.Equal(t, "", cfg.dotAddr)
		assert.Equal(t, ":8443", cfg.dohAddr)
		assert.Equal(t, ":8080", cfg.httpAddr)
		assert.Equal(t, "", cfg.apiToken)
		assert.Equal(t, "json", cfg.logFormat)
		assert.Equal(t, "", cfg.zoneFile)
		assert.Equal(t, "./data", cfg.storageDir)
		assert.Equal(t, "", cfg.tlsCert)
		assert.Equal(t, "", cfg.tlsKey)
		assert.Equal(t, uint64(10000), cfg.compactionThreshold)
		assert.Equal(t, 30*time.Minute, cfg.compactionInterval)
		assert.False(t, cfg.debug)
		assert.True(t, cfg.rrlEnabled)
		assert.Equal(t, 50, cfg.rrlRate)
		assert.Equal(t, 10, cfg.rrlErrorRate)
		assert.Equal(t, 2, cfg.rrlSlip)
		assert.Equal(t, 65536, cfg.rrlTableSize)
		assert.Equal(t, 24, cfg.rrlIPv4Prefix)
		assert.Equal(t, 56, cfg.rrlIPv6Prefix)

		assert.True(t, cfg.httpCORS)
		assert.Equal(t, "*", cfg.httpCORSOrigin)

		daemonCfg := cfg.toDaemonConfig()
		assert.Equal(t, ":5353", daemonCfg.Network.Address)
		assert.Equal(t, ":8443", daemonCfg.Network.DoHAddr)
		assert.Equal(t, uint64(10000), daemonCfg.Storage.CompactionThreshold)
		assert.Equal(t, 30*time.Minute, daemonCfg.Storage.CompactionInterval)
		assert.True(t, daemonCfg.HTTP.CORS)
		assert.Equal(t, "*", daemonCfg.HTTP.CORSOrigin)
		assert.True(t, daemonCfg.HasDoH())
		assert.True(t, daemonCfg.HasRRL())
	})

	t.Run("CustomFlags", func(t *testing.T) {
		var buf bytes.Buffer
		cfg, err := parseCLI([]string{
			"-address", ":1053",
			"-dot-addr", ":8853",
			"-doh-addr", ":9443",
			"-http-addr", ":9090",
			"-api-token", "secret-api-token-1234",
			"-zone-file", "my.zone",
			"-storage-dir", "/tmp/kdns",
			"-tls-cert", "cert.pem",
			"-tls-key", "key.pem",
			"-compaction-threshold", "5000",
			"-compaction-interval", "15m",
			"-debug=true",
			"-rrl=false",
			"-rrl-rate", "100",
			"-rrl-error-rate", "20",
			"-rrl-slip", "4",
			"-rrl-table-size", "32768",
			"-rrl-ipv4-prefix", "28",
			"-rrl-ipv6-prefix", "64",
		}, &buf)
		require.NoError(t, err)

		assert.Equal(t, ":1053", cfg.address)
		assert.Equal(t, ":8853", cfg.dotAddr)
		assert.Equal(t, ":9443", cfg.dohAddr)
		assert.Equal(t, ":9090", cfg.httpAddr)
		assert.Equal(t, "secret-api-token-1234", cfg.apiToken)
		assert.Equal(t, "my.zone", cfg.zoneFile)
		assert.Equal(t, "/tmp/kdns", cfg.storageDir)
		assert.Equal(t, "cert.pem", cfg.tlsCert)
		assert.Equal(t, "key.pem", cfg.tlsKey)
		assert.Equal(t, uint64(5000), cfg.compactionThreshold)
		assert.Equal(t, 15*time.Minute, cfg.compactionInterval)
		assert.True(t, cfg.debug)
		assert.False(t, cfg.rrlEnabled)

		daemonCfg := cfg.toDaemonConfig()
		assert.Equal(t, ":1053", daemonCfg.Network.Address)
		assert.Equal(t, ":8853", daemonCfg.Network.DoTAddr)
		assert.Equal(t, ":9443", daemonCfg.Network.DoHAddr)
		assert.Equal(t, uint64(5000), daemonCfg.Storage.CompactionThreshold)
		assert.Equal(t, 15*time.Minute, daemonCfg.Storage.CompactionInterval)
		assert.True(t, daemonCfg.HasTLS())
		assert.True(t, daemonCfg.HasDoH())
		assert.False(t, daemonCfg.HasRRL())
	})

	t.Run("EnvOverrides", func(t *testing.T) {
		t.Setenv("KDNS_ADDRESS", ":9053")
		t.Setenv("KDNS_DOT_ADDR", ":9853")
		t.Setenv("KDNS_DOH_ADDR", ":9443")
		t.Setenv("KDNS_HTTP_ADDR", ":7070")
		t.Setenv("KDNS_API_TOKEN", "secret-api-token-1234")
		t.Setenv("KDNS_ZONE_FILE", "env.zone")
		t.Setenv("KDNS_STORAGE_DIR", "/var/kdns")
		t.Setenv("KDNS_TLS_CERT", "env-cert.pem")
		t.Setenv("KDNS_TLS_KEY", "env-key.pem")
		t.Setenv("KDNS_COMPACTION_THRESHOLD", "20000")
		t.Setenv("KDNS_COMPACTION_INTERVAL", "45m")
		t.Setenv("KDNS_DEBUG", "true")
		t.Setenv("KDNS_RRL", "false")
		t.Setenv("KDNS_RRL_RATE", "25")
		t.Setenv("KDNS_RRL_ERROR_RATE", "5")
		t.Setenv("KDNS_RRL_SLIP", "1")
		t.Setenv("KDNS_RRL_TABLE_SIZE", "16384")
		t.Setenv("KDNS_RRL_IPV4_PREFIX", "16")
		t.Setenv("KDNS_RRL_IPV6_PREFIX", "48")

		var buf bytes.Buffer
		cfg, err := parseCLI([]string{}, &buf)
		require.NoError(t, err)

		assert.Equal(t, ":9053", cfg.address)
		assert.Equal(t, ":9853", cfg.dotAddr)
		assert.Equal(t, ":9443", cfg.dohAddr)
		assert.Equal(t, ":7070", cfg.httpAddr)
		assert.Equal(t, "secret-api-token-1234", cfg.apiToken)
		assert.Equal(t, "env.zone", cfg.zoneFile)
		assert.Equal(t, "/var/kdns", cfg.storageDir)
		assert.Equal(t, "env-cert.pem", cfg.tlsCert)
		assert.Equal(t, "env-key.pem", cfg.tlsKey)
		assert.Equal(t, uint64(20000), cfg.compactionThreshold)
		assert.Equal(t, 45*time.Minute, cfg.compactionInterval)
		assert.True(t, cfg.debug)
		assert.False(t, cfg.rrlEnabled)
	})

	t.Run("CLIPrecedenceOverEnv", func(t *testing.T) {
		t.Setenv("KDNS_ADDRESS", ":9053")
		t.Setenv("KDNS_DEBUG", "false")
		t.Setenv("KDNS_RRL", "false")

		var buf bytes.Buffer
		cfg, err := parseCLI([]string{
			"-address", ":1053",
			"-debug=true",
			"-rrl=true",
		}, &buf)
		require.NoError(t, err)

		assert.Equal(t, ":1053", cfg.address)
		assert.True(t, cfg.debug)
		assert.True(t, cfg.rrlEnabled)
	})

	t.Run("UnknownFlag", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := parseCLI([]string{"-unknown-flag"}, &buf)
		require.Error(t, err)
	})
}

func TestEnv_GetEnv(t *testing.T) {
	t.Run("FallbackWhenUnset", func(t *testing.T) {
		val := getEnv("KDNS_NON_EXISTENT_VAR_12345", "default_val")
		assert.Equal(t, "default_val", val)
	})

	t.Run("ValueWhenSet", func(t *testing.T) {
		t.Setenv("KDNS_TEST_VAR_12345", "custom_val")
		val := getEnv("KDNS_TEST_VAR_12345", "default_val")
		assert.Equal(t, "custom_val", val)
	})
}

func TestEnv_GetEnvBool(t *testing.T) {
	t.Run("TruthyValues", func(t *testing.T) {
		for _, v := range []string{"true", "1", "yes"} {
			t.Setenv("KDNS_TEST_BOOL_VAR", v)
			assert.True(t, getEnvBool("KDNS_TEST_BOOL_VAR", false))
		}
	})

	t.Run("FalsyValues", func(t *testing.T) {
		for _, v := range []string{"false", "0", "no", "other"} {
			t.Setenv("KDNS_TEST_BOOL_VAR", v)
			assert.False(t, getEnvBool("KDNS_TEST_BOOL_VAR", true))
		}
	})
}

func TestCLIConfig_ServerIDAndTSIG(t *testing.T) {
	t.Run("ServerIDAndTSIGKeys", func(t *testing.T) {
		var buf bytes.Buffer
		cfg, err := parseCLI([]string{
			"-server-id", "node-eu-west-1",
			"-tsig-keys", "key1:hmac-sha256:c2VjcmV0MQ==,key2:c2VjcmV0Mg==",
		}, &buf)
		require.NoError(t, err)

		assert.Equal(t, "node-eu-west-1", cfg.serverID)
		daemonCfg := cfg.toDaemonConfig()
		assert.Equal(t, "node-eu-west-1", daemonCfg.Network.ServerID)
		require.Len(t, daemonCfg.TSIG.Keys, 2)
		assert.Equal(t, "key1", daemonCfg.TSIG.Keys[0].Name)
		assert.Equal(t, "hmac-sha256", daemonCfg.TSIG.Keys[0].Algorithm)
		assert.Equal(t, "c2VjcmV0MQ==", daemonCfg.TSIG.Keys[0].Secret)
		assert.Equal(t, "key2", daemonCfg.TSIG.Keys[1].Name)
		assert.Equal(t, "hmac-sha256", daemonCfg.TSIG.Keys[1].Algorithm)

		kr := daemonCfg.KeyRing()
		require.NotNil(t, kr)
		k1, ok := kr.Get("key1")
		require.True(t, ok)
		assert.Equal(t, "secret1", string(k1.Secret))
	})

	t.Run("ServerIDNone", func(t *testing.T) {
		var buf bytes.Buffer
		cfg, err := parseCLI([]string{
			"-server-id", "none",
		}, &buf)
		require.NoError(t, err)
		assert.Equal(t, "none", cfg.serverID)
		daemonCfg := cfg.toDaemonConfig()
		assert.Equal(t, "none", daemonCfg.Network.ServerID)
	})

	t.Run("DNSSECFlags", func(t *testing.T) {
		var buf bytes.Buffer
		cfg, err := parseCLI([]string{
			"-dnssec=true",
			"-dnssec-keys", "example.com:13,example.org:15",
		}, &buf)
		require.NoError(t, err)

		assert.True(t, cfg.dnssecEnabled)
		daemonCfg := cfg.toDaemonConfig()
		assert.True(t, daemonCfg.DNSSEC.Enabled)
		require.Len(t, daemonCfg.DNSSEC.Keys, 2)
		assert.Equal(t, "example.com", daemonCfg.DNSSEC.Keys[0].Zone)
		assert.Equal(t, "13", daemonCfg.DNSSEC.Keys[0].Algorithm)
		assert.Equal(t, "example.org", daemonCfg.DNSSEC.Keys[1].Zone)
		assert.Equal(t, "15", daemonCfg.DNSSEC.Keys[1].Algorithm)

		mgr, err := daemonCfg.DNSSECManager()
		require.NoError(t, err)
		require.NotNil(t, mgr)
		assert.True(t, mgr.HasKeys("example.com"))
		assert.True(t, mgr.HasKeys("example.org"))
	})

	t.Run("ClusterFlags", func(t *testing.T) {
		var buf bytes.Buffer
		cfg, err := parseCLI([]string{
			"-mode", "replica",
			"-primary-url", "http://primary.kdns:8081",
			"-cluster-token", "cluster-secret-key",
			"-cluster-addr", ":8082",
		}, &buf)
		require.NoError(t, err)

		assert.Equal(t, "replica", cfg.mode)
		assert.Equal(t, "http://primary.kdns:8081", cfg.primaryURL)
		assert.Equal(t, "cluster-secret-key", cfg.clusterToken)
		assert.Equal(t, ":8082", cfg.clusterAddr)

		daemonCfg := cfg.toDaemonConfig()
		assert.Equal(t, daemon.ModeReplica, daemonCfg.Cluster.Mode)
		assert.Equal(t, "http://primary.kdns:8081", daemonCfg.Cluster.PrimaryURL)
		assert.Equal(t, "cluster-secret-key", daemonCfg.Cluster.Token)
		assert.Equal(t, ":8082", daemonCfg.Cluster.Addr)
	})

	t.Run("ClusterTLSFlags", func(t *testing.T) {
		var buf bytes.Buffer
		cfg, err := parseCLI([]string{
			"-mode", "primary",
			"-cluster-token", "cluster-secret-key",
			"-cluster-tls-cert", "cluster.crt",
			"-cluster-tls-key", "cluster.key",
			"-cluster-ca-cert", "ca.crt",
		}, &buf)
		require.NoError(t, err)

		assert.Equal(t, "cluster.crt", cfg.clusterTLSCert)
		assert.Equal(t, "cluster.key", cfg.clusterTLSKey)
		assert.Equal(t, "ca.crt", cfg.clusterCACert)

		daemonCfg := cfg.toDaemonConfig()
		assert.Equal(t, "cluster.crt", daemonCfg.Cluster.TLSCert)
		assert.Equal(t, "cluster.key", daemonCfg.Cluster.TLSKey)
		assert.Equal(t, "ca.crt", daemonCfg.Cluster.CACert)
	})
}
