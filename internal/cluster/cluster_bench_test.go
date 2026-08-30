// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cluster_test

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/aoliveti/kdns/internal/cluster/hub"
	"github.com/aoliveti/kdns/internal/cluster/replica"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/metrics"
	"github.com/aoliveti/kdns/internal/state"
	"github.com/aoliveti/kdns/internal/store"
)

func BenchmarkCluster_Replication(b *testing.B) {
	logger := slog.New(slog.DiscardHandler)
	ctx := b.Context()

	primaryDir := b.TempDir()
	stPrimary := state.New(100)
	fhub := &forwardingHub{}

	primaryStore, err := store.Open(primaryDir, stPrimary, store.WithClusterHub(fhub))
	if err != nil {
		b.Fatalf("primary store open: %v", err)
	}
	defer func() { _ = primaryStore.Close() }()

	token := "benchtoken"
	m := metrics.New()
	srv := hub.New("127.0.0.1:0", token, primaryStore, hub.WithLogger(logger), hub.WithMetrics(m))
	fhub.hub = srv

	go func() {
		_ = srv.Start(ctx)
	}()
	<-srv.Ready()
	addr := srv.Addr()

	replicaDir := b.TempDir()
	stReplica := state.New(100)
	client := replica.New("http://"+addr, token, replicaDir, stReplica, replica.WithLogger(logger), replica.WithMetrics(m))

	go func() {
		_ = client.Start(ctx)
	}()
	time.Sleep(200 * time.Millisecond)

	// Pre-allocate domains to adhere to zero-allocation hot path principles for benchmark
	domains := make([]string, b.N)
	for i := range b.N {
		domains[i] = fmt.Sprintf("bench%d.com.", i)
	}

	rrs := dns.RRSets{
		{
			Type: dns.TypeA,
			TTL:  300,
			RData: [][]byte{
				[]byte("1.2.3.4"),
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		if err := primaryStore.Upsert(domains[i], rrs); err != nil {
			b.Fatalf("upsert: %v", err)
		}
	}

	// Wait for the final mutation to propagate
	if b.N > 0 {
		lastDomain := domains[b.N-1]
		success := false
		for range 500 {
			time.Sleep(10 * time.Millisecond)
			if _, ok := stReplica.Get(lastDomain); ok {
				success = true
				break
			}
		}
		if !success {
			b.Fatal("replica did not catch up in time")
		}
	}
}
