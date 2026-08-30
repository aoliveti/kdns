// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cluster_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/cluster/hub"
	"github.com/aoliveti/kdns/internal/cluster/replica"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/metrics"
	"github.com/aoliveti/kdns/internal/state"
	"github.com/aoliveti/kdns/internal/store"
)

type forwardingHub struct {
	hub store.ClusterHub
}

func (f *forwardingHub) NotifyFlush() {
	if f.hub != nil {
		f.hub.NotifyFlush()
	}
}

func (f *forwardingHub) NotifyCompaction() {
	if f.hub != nil {
		f.hub.NotifyCompaction()
	}
}

func TestCluster_EndToEndReplication(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	fhub := &forwardingHub{}

	primaryStore, err := store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	token := "secret123"
	m := metrics.New()
	srv := hub.New("127.0.0.1:0", token, primaryStore, hub.WithLogger(logger), hub.WithMetrics(m))
	fhub.hub = srv

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	replicaDir := t.TempDir()
	stReplica := state.New(100)
	client := replica.New("http://"+addr, token, replicaDir, stReplica, replica.WithLogger(logger), replica.WithMetrics(m))

	go func() {
		_ = client.Start(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	domain := "example.com."
	rrs := dns.RRSets{
		{
			Type:  dns.TypeA,
			TTL:   300,
			RData: [][]byte{[]byte("1.2.3.4")},
		},
	}

	require.NoError(t, primaryStore.Upsert(domain, rrs))

	// Assert that replica receives the mutation asynchronously
	require.Eventually(t, func() bool {
		records, ok := stReplica.Get(domain)
		return ok && len(records) > 0
	}, 3*time.Second, 50*time.Millisecond)

	// Test deletion propagation
	require.NoError(t, primaryStore.DeleteDomain(domain))

	require.Eventually(t, func() bool {
		_, ok := stReplica.Get(domain)
		return !ok
	}, 3*time.Second, 50*time.Millisecond)
}

func TestCluster_FunctionalOptionsAndNilSafety(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	fhub := &forwardingHub{}

	primaryStore, err := store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	clusterTok := "nil-metrics-mock"

	// Instantiate Hub and Replica Client with nil metrics (both by omission and explicit nil)
	srv := hub.New("127.0.0.1:0", clusterTok, primaryStore, hub.WithLogger(logger), hub.WithMetrics(nil))
	fhub.hub = srv

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	replicaDir := t.TempDir()
	stReplica := state.New(100)
	client := replica.New("http://"+addr, clusterTok, replicaDir, stReplica, replica.WithLogger(logger))

	go func() {
		_ = client.Start(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	domain := "nil-metrics.example.com."
	rrs := dns.RRSets{
		{
			Type:  dns.TypeA,
			TTL:   300,
			RData: [][]byte{[]byte("1.2.3.4")},
		},
	}
	require.NoError(t, primaryStore.Upsert(domain, rrs))

	require.Eventually(t, func() bool {
		_, ok := stReplica.Get(domain)
		return ok
	}, 3*time.Second, 50*time.Millisecond)
}

func TestCluster_TLSEndToEnd(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	ctx := t.Context()

	serverTLS, clientTLS := generateTestTLSConfig(t)

	primaryDir := t.TempDir()
	stPrimary := state.New(100)
	fhub := &forwardingHub{}

	primaryStore, err := store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	require.NoError(t, err)
	defer func() { _ = primaryStore.Close() }()

	clusterTok := "tok-tls-test"
	m := metrics.New()

	srv := hub.New(
		"127.0.0.1:0",
		clusterTok,
		primaryStore,
		hub.WithLogger(logger),
		hub.WithMetrics(m),
		hub.WithTLSConfig(serverTLS),
	)
	fhub.hub = srv

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	replicaDir := t.TempDir()
	stReplica := state.New(100)

	client := replica.New(
		"https://"+addr,
		clusterTok,
		replicaDir,
		stReplica,
		replica.WithLogger(logger),
		replica.WithMetrics(m),
		replica.WithTLSConfig(clientTLS),
	)

	go func() {
		_ = client.Start(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	domain := "tls-replicated.com."
	rrs := dns.RRSets{
		{
			Type:  dns.TypeA,
			TTL:   300,
			RData: [][]byte{[]byte("192.168.1.100")},
		},
	}

	require.NoError(t, primaryStore.Upsert(domain, rrs))

	require.Eventually(t, func() bool {
		records, ok := stReplica.Get(domain)
		return ok && len(records) > 0
	}, 3*time.Second, 50*time.Millisecond)
}

func generateTestTLSConfig(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"KDNS Cluster Test"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(parsedCert)

	clientCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	return serverCfg, clientCfg
}
