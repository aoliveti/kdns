// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestMetrics_ProtocolAndResponseCounters(t *testing.T) {
	t.Parallel()

	m := New(WithBuildInfo("1.0.0", "abc1234", "2026-08-13"))
	require.NotNil(t, m)

	t.Run("QueryAndProtocolCounters", func(t *testing.T) {
		t.Parallel()
		m := New(WithBuildInfo("1.0.0", "abc1234", "2026-08-13"))
		m.IncQueriesUDP()
		m.IncQueriesUDP()
		m.IncQueriesTCP()
		m.IncQueriesDoT()
		m.IncQueriesDoH()

		assert.Equal(t, uint64(2), m.QueriesUDP())
		assert.Equal(t, uint64(1), m.QueriesTCP())
		assert.Equal(t, uint64(1), m.QueriesDoT())
		assert.Equal(t, uint64(1), m.QueriesDoH())
	})

	t.Run("ResponseCodeCounters", func(t *testing.T) {
		t.Parallel()
		m := New(WithBuildInfo("1.0.0", "abc1234", "2026-08-13"))
		m.IncResponses(dns.RCodeSuccess)
		m.IncResponses(dns.RCodeNameError)
		m.IncResponses(dns.RCodeServerFailure)
		m.IncResponses(dns.RCodeRefused)
		m.IncResponses(dns.RCodeNotImplemented)
		m.IncResponses(dns.RCode(99)) // OTHER

		var buf bytes.Buffer
		n, err := m.WriteTo(&buf)
		require.NoError(t, err)
		assert.Positive(t, n)
		out := buf.String()

		assert.Contains(t, out, `kdns_responses_total{rcode="NOERROR"} 1`)
		assert.Contains(t, out, `kdns_responses_total{rcode="NXDOMAIN"} 1`)
		assert.Contains(t, out, `kdns_responses_total{rcode="SERVFAIL"} 1`)
		assert.Contains(t, out, `kdns_responses_total{rcode="REFUSED"} 1`)
		assert.Contains(t, out, `kdns_responses_total{rcode="NOTIMP"} 1`)
		assert.Contains(t, out, `kdns_responses_total{rcode="OTHER"} 1`)
	})
}

func TestMetrics_StorageAndCacheCounters(t *testing.T) {
	t.Parallel()

	t.Run("CacheCounters", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.IncCacheHit()
		m.IncCacheHit()
		m.IncCacheMiss()

		assert.Equal(t, uint64(2), m.CacheHits())
		assert.Equal(t, uint64(1), m.CacheMisses())
	})

	t.Run("DomainGaugeAndStorageCounters", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.SetDomains(42)
		m.IncMutations()
		m.IncMutations()
		m.IncCompactions()

		assert.Equal(t, int64(42), m.Domains())
		assert.Equal(t, uint64(2), m.Mutations())
		assert.Equal(t, uint64(1), m.Compactions())
	})

	t.Run("StorageAndCompactionMetrics", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.SetSnapshotBytes(10240)
		m.SetWALBytes(4096)
		m.SetCompactionDuration(125 * 1000 * 1000) // 125ms
		m.SetMutationsPending(55)

		assert.Equal(t, int64(10240), m.SnapshotBytes())
		assert.Equal(t, int64(4096), m.WALBytes())
		assert.Equal(t, int64(125*1000*1000), int64(m.CompactionDuration()))
		assert.Equal(t, uint64(55), m.MutationsPending())
	})

	t.Run("CacheEntriesMetric", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.SetCacheEntries(128)
		assert.Equal(t, int64(128), m.CacheEntries())
	})
}

func TestMetrics_DNSSECAndTSIGCounters(t *testing.T) {
	t.Parallel()

	t.Run("DNSSECMetrics", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.IncDNSSECSignatures()
		m.IncDNSSECSignatures()
		m.IncDNSSECQueries()

		assert.Equal(t, uint64(2), m.DNSSECSignatures())
		assert.Equal(t, uint64(1), m.DNSSECQueries())
	})

	t.Run("TSIGAndRFC2136Metrics", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.IncTSIG("ok")
		m.IncTSIG("badsig")
		m.IncTSIG("badkey")
		m.IncTSIG("badtime")
		m.IncTSIG("badalgo")
		m.IncTSIG("unknown")

		assert.Equal(t, uint64(1), m.TSIGRequests("ok"))
		assert.Equal(t, uint64(1), m.TSIGRequests("badsig"))
		assert.Equal(t, uint64(1), m.TSIGRequests("badkey"))
		assert.Equal(t, uint64(1), m.TSIGRequests("badtime"))
		assert.Equal(t, uint64(1), m.TSIGRequests("badalgo"))
		assert.Equal(t, uint64(1), m.TSIGRequests("other"))

		m.IncRFC2136("success")
		m.IncRFC2136("rejected")

		assert.Equal(t, uint64(1), m.RFC2136Updates("success"))
		assert.Equal(t, uint64(1), m.RFC2136Updates("rejected"))
	})
}

func TestMetrics_RRLAndClusterCounters(t *testing.T) {
	t.Parallel()

	t.Run("RRLCounters", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.IncRRLDrop()
		m.IncRRLDrop()
		m.IncRRLSlip()

		assert.Equal(t, uint64(2), m.RRLDrops())
		assert.Equal(t, uint64(1), m.RRLSlips())
	})

	t.Run("ClusterAndReplicaMetrics", func(t *testing.T) {
		t.Parallel()
		m := New()
		m.IncClusterStream()
		m.IncClusterStream()
		m.DecClusterStream()
		assert.Equal(t, int64(1), m.ClusterStreamsActive())

		m.IncClusterSnapshotSent()
		m.IncClusterSnapshotSent()
		assert.Equal(t, uint64(2), m.ClusterSnapshotsSent())

		m.SetReplicaSyncStatus(1)
		assert.Equal(t, int64(1), m.ReplicaSyncStatus())

		m.IncReplicaSnapshotRecv()
		assert.Equal(t, uint64(1), m.ReplicaSnapshotsRecv())

		m.SetReplicaLastSync(1787306652)
		assert.Equal(t, int64(1787306652), m.ReplicaLastSync())

		var buf bytes.Buffer
		n, err := m.WriteTo(&buf)
		require.NoError(t, err)
		assert.Positive(t, n)
		out := buf.String()

		assert.Contains(t, out, "kdns_cluster_streams_active 1")
		assert.Contains(t, out, "kdns_cluster_snapshots_sent_total 2")
		assert.Contains(t, out, "kdns_replica_sync_status 1")
		assert.Contains(t, out, "kdns_replica_snapshots_received_total 1")
		assert.Contains(t, out, "kdns_replica_last_sync_timestamp_seconds 1787306652")
	})
}

func TestMetrics_WriteTo(t *testing.T) {
	t.Parallel()

	m := New(WithBuildInfo("v1.2.3", "deadbeef", "2026-08-13T12:00:00Z"))
	m.IncQueriesUDP()
	m.IncResponses(dns.RCodeSuccess)
	m.SetDomains(100)

	var buf bytes.Buffer
	n, err := m.WriteTo(&buf)
	require.NoError(t, err)
	assert.Positive(t, n)

	out := buf.String()
	assert.Contains(t, out, `kdns_build_info{version="v1.2.3",commit="deadbeef",build_time="2026-08-13T12:00:00Z"} 1`)
	assert.Contains(t, out, "kdns_uptime_seconds ")
	assert.Contains(t, out, `kdns_queries_total{proto="udp"} 1`)
	assert.Contains(t, out, `kdns_queries_total{proto="tcp"} 0`)
	assert.Contains(t, out, `kdns_queries_total{proto="dot"} 0`)
	assert.Contains(t, out, `kdns_queries_total{proto="doh"} 0`)
	assert.Contains(t, out, "kdns_domains_total 100")

	// Verify Prometheus comment headers
	assert.True(t, strings.Contains(out, "# HELP kdns_queries_total"))
	assert.True(t, strings.Contains(out, "# TYPE kdns_queries_total counter"))
}

func TestMetrics_ServerInfoAndBandwidth(t *testing.T) {
	t.Parallel()

	m := New(
		WithBuildInfo("1.0.0", "abc1234", "2026-08-13"),
		WithServerInfo("primary", true, true, true, true, true, "ns1.example.com"),
	)
	m.AddBytesInUDP(100)
	m.AddBytesInTCP(200)
	m.AddBytesInDoT(300)
	m.AddBytesInDoH(400)
	m.AddBytesOutUDP(500)
	m.AddBytesOutTCP(600)
	m.AddBytesOutDoT(700)
	m.AddBytesOutDoH(800)
	m.IncTCPConnection()
	m.IncTCPConnection()
	m.DecTCPConnection()
	m.IncReloadEvent(true)
	m.IncReloadEvent(false)

	m.IncQueryType(dns.TypeA)
	m.IncQueryType(dns.TypeAAAA)
	m.IncQueryType(dns.TypeCNAME)
	m.IncQueryType(dns.TypeTXT)
	m.IncQueryType(dns.TypeMX)
	m.IncQueryType(dns.TypeNS)
	m.IncQueryType(dns.TypeSOA)
	m.IncQueryType(dns.TypeSRV)
	m.IncQueryType(dns.TypeCAA)
	m.IncQueryType(dns.TypePTR)
	m.IncQueryType(dns.TypeDS)
	m.IncQueryType(dns.TypeDNSKEY)
	m.IncQueryType(dns.Type(999)) // OTHER

	assert.Equal(t, uint64(1), m.QueriesByType("A"))
	assert.Equal(t, uint64(1), m.QueriesByType("AAAA"))
	assert.Equal(t, uint64(1), m.QueriesByType("CNAME"))
	assert.Equal(t, uint64(1), m.QueriesByType("TXT"))
	assert.Equal(t, uint64(1), m.QueriesByType("MX"))
	assert.Equal(t, uint64(1), m.QueriesByType("NS"))
	assert.Equal(t, uint64(1), m.QueriesByType("SOA"))
	assert.Equal(t, uint64(1), m.QueriesByType("SRV"))
	assert.Equal(t, uint64(1), m.QueriesByType("CAA"))
	assert.Equal(t, uint64(1), m.QueriesByType("PTR"))
	assert.Equal(t, uint64(1), m.QueriesByType("DS"))
	assert.Equal(t, uint64(1), m.QueriesByType("DNSKEY"))
	assert.Equal(t, uint64(1), m.QueriesByType("OTHER"))

	assert.Equal(t, int64(1), m.TCPConnectionsActive())
	assert.Equal(t, uint64(1), m.ReloadEvents("success"))
	assert.Equal(t, uint64(1), m.ReloadEvents("failed"))

	var buf bytes.Buffer
	n, err := m.WriteTo(&buf)
	require.NoError(t, err)
	assert.Positive(t, n)
	out := buf.String()

	assert.Contains(t, out, `kdns_server_info{mode="primary",ha_enabled="true",dnssec_enabled="true",rrl_enabled="true",tls_enabled="true",doh_enabled="true",server_id="ns1.example.com"} 1`)
	assert.Contains(t, out, "kdns_start_time_seconds ")
	assert.Contains(t, out, `kdns_queries_by_type_total{type="A"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="AAAA"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="CNAME"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="TXT"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="MX"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="NS"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="SOA"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="SRV"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="CAA"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="PTR"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="DS"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="DNSKEY"} 1`)
	assert.Contains(t, out, `kdns_queries_by_type_total{type="OTHER"} 1`)
	assert.Contains(t, out, `kdns_network_receive_bytes_total{proto="udp"} 100`)
	assert.Contains(t, out, `kdns_network_receive_bytes_total{proto="tcp"} 200`)
	assert.Contains(t, out, `kdns_network_receive_bytes_total{proto="dot"} 300`)
	assert.Contains(t, out, `kdns_network_receive_bytes_total{proto="doh"} 400`)
	assert.Contains(t, out, `kdns_network_transmit_bytes_total{proto="udp"} 500`)
	assert.Contains(t, out, `kdns_network_transmit_bytes_total{proto="tcp"} 600`)
	assert.Contains(t, out, `kdns_network_transmit_bytes_total{proto="dot"} 700`)
	assert.Contains(t, out, `kdns_network_transmit_bytes_total{proto="doh"} 800`)
	assert.Contains(t, out, "kdns_tcp_connections_active 1")
	assert.Contains(t, out, `kdns_reload_events_total{status="success"} 1`)
	assert.Contains(t, out, `kdns_reload_events_total{status="failed"} 1`)
}

func TestMetrics_NilSafety(t *testing.T) {
	t.Parallel()

	var m *Metrics

	assert.NotPanics(t, func() {
		m.IncQueriesUDP()
		m.IncQueriesTCP()
		m.IncQueriesDoT()
		m.IncQueriesDoH()
		m.IncQueryType(dns.TypeA)
		m.AddBytesInUDP(10)
		m.AddBytesInTCP(10)
		m.AddBytesInDoT(10)
		m.AddBytesInDoH(10)
		m.AddBytesOutUDP(10)
		m.AddBytesOutTCP(10)
		m.AddBytesOutDoT(10)
		m.AddBytesOutDoH(10)
		m.IncTCPConnection()
		m.DecTCPConnection()
		m.IncReloadEvent(true)
		m.IncResponses(dns.RCodeSuccess)
		m.IncCacheHit()
		m.IncCacheMiss()
		m.SetDomains(10)
		m.IncMutations()
		m.IncCompactions()
		m.IncClusterStream()
		m.DecClusterStream()
		m.IncClusterSnapshotSent()
		m.SetReplicaSyncStatus(1)
		m.IncReplicaSnapshotRecv()
		m.SetReplicaLastSync(12345)

		assert.Equal(t, uint64(0), m.QueriesUDP())
		assert.Equal(t, uint64(0), m.QueriesTCP())
		assert.Equal(t, uint64(0), m.QueriesDoT())
		assert.Equal(t, uint64(0), m.QueriesDoH())
		assert.Equal(t, uint64(0), m.QueriesByType("A"))
		assert.Equal(t, int64(0), m.TCPConnectionsActive())
		assert.Equal(t, uint64(0), m.ReloadEvents("success"))
		assert.Equal(t, uint64(0), m.ReloadEvents("failed"))
		assert.Equal(t, uint64(0), m.CacheHits())
		assert.Equal(t, uint64(0), m.CacheMisses())
		assert.Equal(t, int64(0), m.Domains())
		assert.Equal(t, uint64(0), m.Mutations())
		assert.Equal(t, uint64(0), m.Compactions())
		assert.Equal(t, int64(0), m.ClusterStreamsActive())
		assert.Equal(t, uint64(0), m.ClusterSnapshotsSent())
		assert.Equal(t, int64(0), m.ReplicaSyncStatus())
		assert.Equal(t, uint64(0), m.ReplicaSnapshotsRecv())
		assert.Equal(t, int64(0), m.ReplicaLastSync())

		var buf bytes.Buffer
		n, err := m.WriteTo(&buf)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), n)
	})
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	m := New()
	const workers = 10
	const iterations = 1000

	var wg sync.WaitGroup

	for i := range workers {
		wg.Go(func() {
			for j := range iterations {
				switch (i + j) % 2 {
				case 0:
					m.IncQueriesUDP()
					m.IncCacheHit()
				default:
					m.IncQueriesTCP()
					m.IncCacheMiss()
				}
				m.IncResponses(dns.RCodeSuccess)
				m.SetDomains(j)
			}
		})
	}

	wg.Wait()

	assert.Equal(t, uint64(workers*iterations), m.QueriesUDP()+m.QueriesTCP())
	assert.Equal(t, uint64(workers*iterations), m.CacheHits()+m.CacheMisses())
	assert.Equal(t, uint64(workers*iterations), m.responsesNOERROR.Load())
}
