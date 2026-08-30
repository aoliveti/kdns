// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/daemon"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/tsig"
)

func TestIntegration_Standalone(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)
	httpPort := freePort(t)
	apiToken := "secret-api-token"

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     httpPort,
			APIToken: apiToken,
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	t.Run("UDP_Query_A", func(t *testing.T) {
		t.Parallel()
		respUDP, err := queryDNSUDP(t, dnsPort, "www.example.com", dns.TypeA)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, respUDP.Header.RCode())
		require.Len(t, respUDP.Answers, 1)
		textA, err := dns.UnpackRData(dns.TypeA, respUDP.Answers[0].RData)
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.50", textA)
	})

	t.Run("UDP_Query_TXT", func(t *testing.T) {
		t.Parallel()
		respTXT, err := queryDNSUDP(t, dnsPort, "example.com", dns.TypeTXT)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, respTXT.Header.RCode())
		require.Len(t, respTXT.Answers, 1)
	})

	t.Run("TCP_Query_AAAA", func(t *testing.T) {
		t.Parallel()
		respTCP, err := queryDNSTCP(t, dnsPort, "www.example.com", dns.TypeAAAA)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, respTCP.Header.RCode())
		require.Len(t, respTCP.Answers, 1)
		textAAAA, err := dns.UnpackRData(dns.TypeAAAA, respTCP.Answers[0].RData)
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::50", textAAAA)
	})

	t.Run("CNAME_Transparency", func(t *testing.T) {
		t.Parallel()
		respCNAME, err := queryDNSUDP(t, dnsPort, "app.example.com", dns.TypeA)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, respCNAME.Header.RCode())
		require.Len(t, respCNAME.Answers, 1)
		assert.Equal(t, dns.TypeCNAME, respCNAME.Answers[0].Type)
	})

	t.Run("Wildcard_Resolution", func(t *testing.T) {
		t.Parallel()
		respWild, err := queryDNSUDP(t, dnsPort, "sub.wild.example.com", dns.TypeA)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, respWild.Header.RCode())
		require.Len(t, respWild.Answers, 1)
		textWild, err := dns.UnpackRData(dns.TypeA, respWild.Answers[0].RData)
		require.NoError(t, err)
		assert.Equal(t, "198.51.100.1", textWild)
	})

	t.Run("REST_AddRecord_And_Query", func(t *testing.T) {
		status, err := putRecordHTTP(t, httpPort, apiToken, "dynamic.example.com", apiRecord{
			Type:  "A",
			TTL:   300,
			RData: []string{"10.20.30.40"},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)

		respDyn, err := queryDNSUDP(t, dnsPort, "dynamic.example.com", dns.TypeA)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, respDyn.Header.RCode())
		require.Len(t, respDyn.Answers, 1)
		textDyn, err := dns.UnpackRData(dns.TypeA, respDyn.Answers[0].RData)
		require.NoError(t, err)
		assert.Equal(t, "10.20.30.40", textDyn)
	})
}

func TestIntegration_DoH(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)
	dohPort := freePort(t)

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
			DoHAddr: dohPort,
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	// 1. Test DoH POST (application/dns-message)
	respPOST, statusPOST, cacheControlPOST, err := queryDoHPOST(t, dohPort, "www.example.com", dns.TypeA)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusPOST)
	assert.Equal(t, "max-age=300", cacheControlPOST)
	assert.Equal(t, dns.RCodeSuccess, respPOST.Header.RCode())
	require.Len(t, respPOST.Answers, 1)
	textPOST, err := dns.UnpackRData(dns.TypeA, respPOST.Answers[0].RData)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.50", textPOST)

	// 2. Test DoH GET (?dns=base64url)
	respGET, statusGET, cacheControlGET, err := queryDoHGET(t, dohPort, "mail.example.com", dns.TypeA)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusGET)
	assert.Equal(t, "max-age=300", cacheControlGET)
	assert.Equal(t, dns.RCodeSuccess, respGET.Header.RCode())
	require.Len(t, respGET.Answers, 1)
	textGET, err := dns.UnpackRData(dns.TypeA, respGET.Answers[0].RData)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.10", textGET)
}

func TestIntegration_DoT(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)
	certPath, keyPath := generateTLSCertFiles(t, dataDir)

	dnsPort := freePort(t)
	dotPort := freePort(t)

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
			DoTAddr: dotPort,
		},
		TLS: daemon.TLSConfig{
			CertPath: certPath,
			KeyPath:  keyPath,
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	dataRoot, rootErr := os.OpenRoot(dataDir)
	require.NoError(t, rootErr)
	defer func() { _ = dataRoot.Close() }()

	certPEM, err := dataRoot.ReadFile("tls.crt")
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	tlsClientConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	}

	resp, err := queryDoTTLS(t, dotPort, "www.example.com", dns.TypeA, tlsClientConfig)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeSuccess, resp.Header.RCode())
	require.Len(t, resp.Answers, 1)
	text, err := dns.UnpackRData(dns.TypeA, resp.Answers[0].RData)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.50", text)
}

func TestIntegration_RFC2136_TSIG(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)
	httpPort := freePort(t)

	tsigKeyName := "admin-key.example.com."
	tsigSecret := "secret-key-1234567890"

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     httpPort,
			APIToken: "integration-api-token-1234",
		},
		TSIG: daemon.TSIGConfig{
			Keys: []daemon.TSIGKey{
				{
					Name:      tsigKeyName,
					Algorithm: "hmac-sha256",
					Secret:    tsigSecret,
				},
			},
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	key := &tsig.Key{
		Name:      tsigKeyName,
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte(tsigSecret),
	}

	rData, err := dns.PackRData(dns.TypeA, "10.99.88.11")
	require.NoError(t, err)

	// 1. Send signed RFC 2136 update
	resp, err := sendRFC2136Update(t, dnsPort, "example.com", "rfc2136.example.com", dns.TypeA, rData, key)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeSuccess, resp.Header.RCode())

	// 2. Query newly added record via DNS UDP
	respDNS, err := queryDNSUDP(t, dnsPort, "rfc2136.example.com", dns.TypeA)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeSuccess, respDNS.Header.RCode())
	require.Len(t, respDNS.Answers, 1)
	text, err := dns.UnpackRData(dns.TypeA, respDNS.Answers[0].RData)
	require.NoError(t, err)
	assert.Equal(t, "10.99.88.11", text)

	// 3. Send update with wrong key -> rejected with NOTAUTH
	wrongKey := &tsig.Key{
		Name:      tsigKeyName,
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("wrong-password-secret"),
	}
	respRejected, err := sendRFC2136Update(t, dnsPort, "example.com", "bad.example.com", dns.TypeA, rData, wrongKey)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeNotAuth, respRejected.Header.RCode())
}

func TestIntegration_Cluster_HubAndReplica(t *testing.T) {
	t.Parallel()

	clusterToken := "integration-cluster-secret"
	primaryToken := "primary-api-secret" //nolint:gosec // Test mock token

	primaryDataDir := t.TempDir()
	zonePath := copyFixture(t, primaryDataDir)

	primaryDNSPort := freePort(t)
	primaryHTTPPort := freePort(t)
	primaryClusterPort := freePort(t)

	primaryCfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: primaryDNSPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     primaryHTTPPort,
			APIToken: primaryToken,
		},
		Cluster: daemon.ClusterConfig{
			Mode:  "primary",
			Addr:  primaryClusterPort,
			Token: clusterToken,
		},
		Storage: daemon.StorageConfig{
			Dir:      primaryDataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, primaryCfg)

	// Start Replica
	replicaDataDir := t.TempDir()
	replicaDNSPort := freePort(t)
	replicaHTTPPort := freePort(t)

	replicaCfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: replicaDNSPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     replicaHTTPPort,
			APIToken: "integration-api-token-1234",
		},
		Cluster: daemon.ClusterConfig{
			Mode:       "replica",
			PrimaryURL: "http://" + primaryClusterPort,
			Token:      clusterToken,
		},
		Storage: daemon.StorageConfig{
			Dir: replicaDataDir,
		},
	}

	startNode(t, replicaCfg)

	// Wait for initial snapshot synchronization
	require.Eventually(t, func() bool {
		resp, err := queryDNSUDP(t, replicaDNSPort, "www.example.com", dns.TypeA)
		return err == nil && resp.Header.RCode() == dns.RCodeSuccess && len(resp.Answers) > 0
	}, 3*time.Second, 50*time.Millisecond, "replica failed to sync initial snapshot")

	// Verify that replica REST API rejects writes (Read-Only Replica Mode)
	status, err := putRecordHTTP(t, replicaHTTPPort, "integration-api-token-1234", "forbidden.example.com", apiRecord{
		Type:  "A",
		TTL:   300,
		RData: []string{"1.1.1.1"},
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, status)

	// Insert 5 records on Primary and assert they stream to Replica
	for i := range 5 {
		domain := fmt.Sprintf("stream-%d.example.com", i)
		ip := fmt.Sprintf("10.0.0.%d", i+1)

		putStatus, putErr := putRecordHTTP(t, primaryHTTPPort, primaryToken, domain, apiRecord{
			Type:  "A",
			TTL:   300,
			RData: []string{ip},
		})
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, putStatus)
	}

	// Verify that all 5 records resolve from Replica
	for i := range 5 {
		domain := fmt.Sprintf("stream-%d.example.com", i)
		expectedIP := fmt.Sprintf("10.0.0.%d", i+1)

		require.Eventually(t, func() bool {
			resp, qErr := queryDNSUDP(t, replicaDNSPort, domain, dns.TypeA)
			if qErr != nil || len(resp.Answers) == 0 {
				return false
			}
			text, err := dns.UnpackRData(dns.TypeA, resp.Answers[0].RData)
			return err == nil && text == expectedIP
		}, 3*time.Second, 50*time.Millisecond, "replica failed to stream record %s", domain)
	}
}

func TestIntegration_Cluster_TLS(t *testing.T) {
	t.Parallel()

	clusterToken := "integration-tls-secret"
	primaryDataDir := t.TempDir()
	certPath, keyPath := generateTLSCertFiles(t, primaryDataDir)
	zonePath := copyFixture(t, primaryDataDir)

	primaryDNSPort := freePort(t)
	primaryHTTPPort := freePort(t)
	primaryClusterPort := freePort(t)

	primaryCfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: primaryDNSPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     primaryHTTPPort,
			APIToken: "integration-api-token-1234",
		},
		Cluster: daemon.ClusterConfig{
			Mode:    "primary",
			Addr:    primaryClusterPort,
			Token:   clusterToken,
			TLSCert: certPath,
			TLSKey:  keyPath,
		},
		Storage: daemon.StorageConfig{
			Dir:      primaryDataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, primaryCfg)

	// Start Replica connecting via HTTPS
	replicaDataDir := t.TempDir()
	replicaDNSPort := freePort(t)

	replicaCfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: replicaDNSPort,
		},
		Cluster: daemon.ClusterConfig{
			Mode:       "replica",
			PrimaryURL: "https://" + primaryClusterPort,
			Token:      clusterToken,
			CACert:     certPath,
		},
		Storage: daemon.StorageConfig{
			Dir: replicaDataDir,
		},
	}

	startNode(t, replicaCfg)

	// Wait for replica to sync over TLS
	require.Eventually(t, func() bool {
		resp, err := queryDNSUDP(t, replicaDNSPort, "www.example.com", dns.TypeA)
		return err == nil && resp.Header.RCode() == dns.RCodeSuccess && len(resp.Answers) > 0
	}, 5*time.Second, 50*time.Millisecond, "replica failed to sync over TLS")
}

func TestIntegration_Cluster_CompactionAndResync(t *testing.T) {
	t.Parallel()

	clusterToken := "integration-compaction-secret"
	primaryToken := "primary-compaction-api-secret"

	primaryDataDir := t.TempDir()
	zonePath := copyFixture(t, primaryDataDir)

	primaryDNSPort := freePort(t)
	primaryHTTPPort := freePort(t)
	primaryClusterPort := freePort(t)

	primaryCfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: primaryDNSPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     primaryHTTPPort,
			APIToken: primaryToken,
		},
		Cluster: daemon.ClusterConfig{
			Mode:  "primary",
			Addr:  primaryClusterPort,
			Token: clusterToken,
		},
		Storage: daemon.StorageConfig{
			Dir:                 primaryDataDir,
			ZoneFile:            filepath.Base(zonePath),
			CompactionThreshold: 100,
			CompactionInterval:  1 * time.Minute,
		},
	}

	startNode(t, primaryCfg)

	// Start Replica
	replicaDataDir := t.TempDir()
	replicaDNSPort := freePort(t)
	replicaHTTPPort := freePort(t)

	replicaCfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: replicaDNSPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     replicaHTTPPort,
			APIToken: "integration-api-token-1234",
		},
		Cluster: daemon.ClusterConfig{
			Mode:       "replica",
			PrimaryURL: "http://" + primaryClusterPort,
			Token:      clusterToken,
		},
		Storage: daemon.StorageConfig{
			Dir: replicaDataDir,
		},
	}

	startNode(t, replicaCfg)

	// Wait for initial sync
	require.Eventually(t, func() bool {
		resp, err := queryDNSUDP(t, replicaDNSPort, "www.example.com", dns.TypeA)
		return err == nil && resp.Header.RCode() == dns.RCodeSuccess && len(resp.Answers) > 0
	}, 3*time.Second, 50*time.Millisecond, "replica failed initial sync")

	// Insert 105 records to trigger background compaction on primary
	for i := range 105 {
		domain := fmt.Sprintf("compact-%d.example.com", i)
		ip := fmt.Sprintf("172.16.0.%d", (i%250)+1)

		putStatus, putErr := putRecordHTTP(t, primaryHTTPPort, primaryToken, domain, apiRecord{
			Type:  "A",
			TTL:   300,
			RData: []string{ip},
		})
		require.NoError(t, putErr)
		require.Equal(t, http.StatusOK, putStatus)
	}

	// Verify that record 104 is replicated and resolvable on Replica
	require.Eventually(t, func() bool {
		resp, qErr := queryDNSUDP(t, replicaDNSPort, "compact-104.example.com", dns.TypeA)
		if qErr != nil {
			t.Logf("query error: %v", qErr)
			return false
		}
		if len(resp.Answers) == 0 {
			t.Logf("no answers returned, rcode=%d", resp.Header.RCode())
			return false
		}
		text, err := dns.UnpackRData(dns.TypeA, resp.Answers[0].RData)
		if err != nil {
			t.Logf("unpack error: %v", err)
			return false
		}
		return text == "172.16.0.105"
	}, 20*time.Second, 200*time.Millisecond, "replica failed to resync after primary compaction")
}

func TestIntegration_Observability_And_Probes(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)
	httpPort := freePort(t)

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     httpPort,
			APIToken: "integration-api-token-1234",
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	// 1. Livez, Startupz, and Readyz probe checks
	statusLive, bodyLive, err := getLivezHTTP(t, httpPort)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusLive)
	assert.Contains(t, bodyLive, "ok")

	statusStartup, bodyStartup, err := getStartupzHTTP(t, httpPort)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusStartup)
	assert.Contains(t, bodyStartup, "ok")

	statusReady, bodyReady, err := getReadyzHTTP(t, httpPort)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusReady)
	assert.Contains(t, bodyReady, "ok")

	// 2. Perform a DNS query
	_, err = queryDNSUDP(t, dnsPort, "www.example.com", dns.TypeA)
	require.NoError(t, err)

	// 3. Check Prometheus metrics
	statusMetrics, bodyMetrics, err := getMetricsHTTP(t, httpPort, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusMetrics)
	assert.Contains(t, bodyMetrics, "kdns_server_info")
	assert.Contains(t, bodyMetrics, "kdns_queries_total")
	assert.Contains(t, bodyMetrics, "kdns_queries_by_type_total")
	assert.Contains(t, bodyMetrics, "kdns_network_receive_bytes_total")
	assert.Contains(t, bodyMetrics, "kdns_domains_total")
}

func TestIntegration_DNSSEC(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
		},
		DNSSEC: daemon.DNSSECConfig{
			Enabled: true,
			Keys: []daemon.DNSSECKey{
				{
					Zone:      "example.com",
					Algorithm: "ed25519",
				},
			},
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	// 1. Positive query with DO=1 -> Expect answer + RRSIG
	respPositive, err := queryDNSUDPWithDO(t, dnsPort, "www.example.com", dns.TypeA)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeSuccess, respPositive.Header.RCode())
	require.NotEmpty(t, respPositive.Answers)

	var hasA, hasRRSIG bool
	for _, ans := range respPositive.Answers {
		if ans.Type == dns.TypeA {
			hasA = true
		}
		if ans.Type == dns.TypeRRSIG {
			hasRRSIG = true
		}
	}
	assert.True(t, hasA, "expected TypeA in answers")
	assert.True(t, hasRRSIG, "expected TypeRRSIG in answers when DO=1")

	// 2. Non-existent domain with DO=1 -> NXDOMAIN with NSEC + RRSIG in Authority
	respNX, err := queryDNSUDPWithDO(t, dnsPort, "nonexistent.example.com", dns.TypeA)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeNameError, respNX.Header.RCode())
	var hasNSEC, hasAuthRRSIG bool
	for _, auth := range respNX.Authorities {
		if auth.Type == dns.TypeNSEC {
			hasNSEC = true
		}
		if auth.Type == dns.TypeRRSIG {
			hasAuthRRSIG = true
		}
	}
	assert.True(t, hasNSEC, "expected NSEC denial in authority for NXDOMAIN")
	assert.True(t, hasAuthRRSIG, "expected RRSIG for NSEC denial in authority")

	// 3. DNSKEY query at apex -> Synthesized apex DNSKEY
	respDNSKEY, err := queryDNSUDPWithDO(t, dnsPort, "example.com", dns.TypeDNSKEY)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeSuccess, respDNSKEY.Header.RCode())
	var hasDNSKEY bool
	for _, ans := range respDNSKEY.Answers {
		if ans.Type == dns.TypeDNSKEY {
			hasDNSKEY = true
		}
	}
	assert.True(t, hasDNSKEY, "expected synthesized DNSKEY in answers")
}

func TestIntegration_RRL_Slip(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
		},
		RRL: daemon.RRLConfig{
			Enabled:            true,
			ResponsesPerSecond: 2,
			ErrorsPerSecond:    2,
			SlipRate:           2,
			IPv4Prefix:         24,
			IPv6Prefix:         56,
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	// Send burst of identical queries with 50ms timeout for dropped packets
	var received int
	for range 15 {
		resp, err := queryDNSUDPWithTimeout(t, dnsPort, "www.example.com", dns.TypeA, 50*time.Millisecond)
		if err == nil && resp != nil {
			received++
		}
	}

	assert.Greater(t, received, 0, "server must respond to queries")
}

func TestIntegration_REST_CRUD_Search_Delete(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)
	httpPort := freePort(t)
	apiToken := "admin-crud-secret" //nolint:gosec // Test mock token

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     httpPort,
			APIToken: apiToken,
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	t.Run("CreateRecord", func(t *testing.T) {
		status, err := putRecordHTTP(t, httpPort, apiToken, "temp-crud.example.com", apiRecord{
			Type:  "A",
			TTL:   300,
			RData: []string{"198.51.100.42"},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	})

	t.Run("QueryCreatedRecord", func(t *testing.T) {
		resp, err := queryDNSUDP(t, dnsPort, "temp-crud.example.com", dns.TypeA)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, resp.Header.RCode())
		require.Len(t, resp.Answers, 1)
	})

	t.Run("SearchRecords", func(t *testing.T) {
		searchStatus, searchBody, err := searchRecordsHTTP(t, httpPort, apiToken, "temp-crud")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, searchStatus)
		assert.Contains(t, searchBody, "temp-crud.example.com")
	})

	t.Run("CursorPagination", func(t *testing.T) {
		listStatus, listBody, err := listRecordsHTTP(t, httpPort, apiToken, 5, "")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, listStatus)
		assert.Contains(t, listBody, "domains")
	})

	t.Run("DeleteRecord", func(t *testing.T) {
		delStatus, err := deleteRecordHTTP(t, httpPort, apiToken, "temp-crud.example.com")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, delStatus)
	})

	t.Run("QueryDeletedRecordReturnsNXDOMAIN", func(t *testing.T) {
		resp, err := queryDNSUDP(t, dnsPort, "temp-crud.example.com", dns.TypeA)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNameError, resp.Header.RCode())
	})

	t.Run("ExportZoneFile", func(t *testing.T) {
		exportStatus, exportBody, contentType, err := exportZoneFileHTTP(t, httpPort, apiToken, "example.com")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, exportStatus)
		assert.Equal(t, "text/dns; charset=utf-8", contentType)
		assert.Contains(t, exportBody, "$ORIGIN example.com.")
		assert.Contains(t, exportBody, "www.example.com.")
		assert.Contains(t, exportBody, "192.0.2.50")
	})
}

func TestIntegration_CHAOS_Diagnostics(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address:  dnsPort,
			ServerID: "kdns-cluster-node-01",
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	// 1. Query version.bind in Class CH
	respVer, err := queryDNSCHAOS(t, dnsPort, "version.bind")
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeSuccess, respVer.Header.RCode())
	require.NotEmpty(t, respVer.Answers)
	assert.Equal(t, dns.ClassCH, respVer.Answers[0].Class)

	// 2. Query id.server in Class CH
	respID, err := queryDNSCHAOS(t, dnsPort, "id.server")
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeSuccess, respID.Header.RCode())
	require.NotEmpty(t, respID.Answers)
	textID, err := dns.UnpackRData(dns.TypeTXT, respID.Answers[0].RData)
	require.NoError(t, err)
	assert.Equal(t, "kdns-cluster-node-01", textID)
}

func TestIntegration_Restart_Durability(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort1 := freePort(t)
	httpPort1 := freePort(t)
	apiToken := "durability-token"

	cfg1 := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort1,
		},
		HTTP: daemon.HTTPConfig{
			Addr:     httpPort1,
			APIToken: apiToken,
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	stopNode1 := startNodeWithStopper(t, cfg1)

	// Write 3 records via HTTP API
	records := map[string]string{
		"durability-1.example.com": "192.0.2.101",
		"durability-2.example.com": "192.0.2.102",
		"durability-3.example.com": "192.0.2.103",
	}

	for domain, ip := range records {
		status, err := putRecordHTTP(t, httpPort1, apiToken, domain, apiRecord{
			Type:  "A",
			TTL:   300,
			RData: []string{ip},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
	}

	// Verify that records resolve on Node 1
	for domain, ip := range records {
		resp, err := queryDNSUDP(t, dnsPort1, domain, dns.TypeA)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Answers)
		text, err := dns.UnpackRData(dns.TypeA, resp.Answers[0].RData)
		require.NoError(t, err)
		assert.Equal(t, ip, text)
	}

	// Stop Node 1
	stopNode1()

	// Start Node 2 pointing to the SAME data directory (no initial zonefile, state restored from WAL/snapshot)
	dnsPort2 := freePort(t)
	cfg2 := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort2,
		},
		Storage: daemon.StorageConfig{
			Dir: dataDir,
		},
	}

	startNode(t, cfg2)

	// Verify that all 3 records survive reboot and resolve correctly on Node 2
	for domain, ip := range records {
		resp, err := queryDNSUDP(t, dnsPort2, domain, dns.TypeA)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, resp.Header.RCode())
		require.NotEmpty(t, resp.Answers)
		text, err := dns.UnpackRData(dns.TypeA, resp.Answers[0].RData)
		require.NoError(t, err)
		assert.Equal(t, ip, text)
	}
}

func TestIntegration_RFC7766_TCP_Pipelining(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	zonePath := copyFixture(t, dataDir)

	dnsPort := freePort(t)

	cfg := daemon.Config{
		Network: daemon.NetworkConfig{
			Address: dnsPort,
		},
		Storage: daemon.StorageConfig{
			Dir:      dataDir,
			ZoneFile: filepath.Base(zonePath),
		},
	}

	startNode(t, cfg)

	// Open a single TCP connection
	var d net.Dialer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", dnsPort)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send 10 pipelined queries back-to-back
	queryCount := 10
	for i := range queryCount {
		txID := uint16(2000 + i)
		raw := buildQuery(txID, "www.example.com", dns.TypeA)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(min(len(raw), 65535)))
		_, writeErr := conn.Write(append(lenBuf[:], raw...))
		require.NoError(t, writeErr)
	}

	// Read all 10 responses sequentially from the same TCP stream
	for i := range queryCount {
		var respLenBuf [2]byte
		_, readLenErr := io.ReadFull(conn, respLenBuf[:])
		require.NoError(t, readLenErr)
		respLen := binary.BigEndian.Uint16(respLenBuf[:])

		respBuf := make([]byte, respLen)
		_, readBodyErr := io.ReadFull(conn, respBuf)
		require.NoError(t, readBodyErr)

		resp, parseErr := parseDNSResponse(respBuf)
		require.NoError(t, parseErr)
		assert.Equal(t, uint16(2000+i), resp.Header.ID)
		assert.Equal(t, dns.RCodeSuccess, resp.Header.RCode())
		require.NotEmpty(t, resp.Answers)
	}
}
