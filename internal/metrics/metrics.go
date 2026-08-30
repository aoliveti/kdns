// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package metrics implements zero-allocation, lock-free telemetry collection
// and native Prometheus text format exposition for kdns.
package metrics

import (
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

var metricsBufPool = sync.Pool{
	New: func() any {
		// 4096 bytes comfortably hold the entire Prometheus text payload
		b := make([]byte, 0, 4096)
		return &b
	},
}

// Metrics manages lock-free atomic telemetry counters and gauges for the DNS server.
type Metrics struct {
	startTime time.Time

	version   string
	commit    string
	buildTime string
	mode      string
	serverID  string

	queriesUDP  atomic.Uint64
	queriesTCP  atomic.Uint64
	queriesDoT  atomic.Uint64
	queriesDoH  atomic.Uint64
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64

	qTypeA      atomic.Uint64
	qTypeAAAA   atomic.Uint64
	qTypeCNAME  atomic.Uint64
	qTypeTXT    atomic.Uint64
	qTypeMX     atomic.Uint64
	qTypeNS     atomic.Uint64
	qTypeSOA    atomic.Uint64
	qTypeSRV    atomic.Uint64
	qTypeCAA    atomic.Uint64
	qTypePTR    atomic.Uint64
	qTypeDS     atomic.Uint64
	qTypeDNSKEY atomic.Uint64
	qTypeOTHER  atomic.Uint64

	bytesInUDP atomic.Uint64
	bytesInTCP atomic.Uint64
	bytesInDoT atomic.Uint64
	bytesInDoH atomic.Uint64

	bytesOutUDP atomic.Uint64
	bytesOutTCP atomic.Uint64
	bytesOutDoT atomic.Uint64
	bytesOutDoH atomic.Uint64

	tcpConnsActive atomic.Int64
	reloadsSuccess atomic.Uint64
	reloadsFailed  atomic.Uint64

	responsesNOERROR  atomic.Uint64
	responsesNXDOMAIN atomic.Uint64
	responsesSERVFAIL atomic.Uint64
	responsesREFUSED  atomic.Uint64
	responsesNOTIMP   atomic.Uint64
	responsesOTHER    atomic.Uint64

	domainsCount      atomic.Int64
	mutationsTotal    atomic.Uint64
	mutationsPending  atomic.Uint64
	compactionsDone   atomic.Uint64
	compactionLatency atomic.Int64 // nanoseconds
	snapshotBytes     atomic.Int64
	walBytes          atomic.Int64
	cacheEntries      atomic.Int64

	rrlDrops atomic.Uint64
	rrlSlips atomic.Uint64

	dnssecSignatures atomic.Uint64
	dnssecQueries    atomic.Uint64

	tsigSuccess atomic.Uint64
	tsigBadSig  atomic.Uint64
	tsigBadKey  atomic.Uint64
	tsigBadTime atomic.Uint64
	tsigBadAlgo atomic.Uint64
	tsigOther   atomic.Uint64

	rfc2136Success  atomic.Uint64
	rfc2136Rejected atomic.Uint64

	clusterStreamsActive atomic.Int64
	clusterSnapshotsSent atomic.Uint64
	replicaSyncStatus    atomic.Int64
	replicaSnapshotsRecv atomic.Uint64
	replicaLastSyncUnix  atomic.Int64

	haEnabled     bool
	dnssecEnabled bool
	rrlEnabled    bool
	tlsEnabled    bool
	dohEnabled    bool
}

// Option configures Metrics parameters via functional options.
type Option func(*Metrics)

// WithBuildInfo sets the application build metadata exported in the build_info metric.
func WithBuildInfo(version, commit, buildTime string) Option {
	return func(m *Metrics) {
		m.version = version
		m.commit = commit
		m.buildTime = buildTime
	}
}

// WithServerInfo sets the server runtime topology and capability metadata.
func WithServerInfo(mode string, ha, dnssec, rrl, tls, doh bool, serverID string) Option {
	return func(m *Metrics) {
		m.mode = mode
		m.haEnabled = ha
		m.dnssecEnabled = dnssec
		m.rrlEnabled = rrl
		m.tlsEnabled = tls
		m.dohEnabled = doh
		m.serverID = serverID
	}
}

// New initializes and returns a Metrics instance.
func New(opts ...Option) *Metrics {
	m := &Metrics{
		startTime: time.Now(),
		version:   "dev",
		commit:    "unknown",
		buildTime: "unknown",
		mode:      "standalone",
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// IncQueriesUDP increments the total queries counter for the UDP protocol.
func (m *Metrics) IncQueriesUDP() {
	if m == nil {
		return
	}
	m.queriesUDP.Add(1)
}

// IncQueriesTCP increments the total queries counter for the TCP protocol.
func (m *Metrics) IncQueriesTCP() {
	if m == nil {
		return
	}
	m.queriesTCP.Add(1)
}

// IncQueriesDoT increments the total queries counter for the DOT protocol.
func (m *Metrics) IncQueriesDoT() {
	if m == nil {
		return
	}
	m.queriesDoT.Add(1)
}

// IncQueriesDoH increments the total queries counter for the DOH protocol.
func (m *Metrics) IncQueriesDoH() {
	if m == nil {
		return
	}
	m.queriesDoH.Add(1)
}

// IncResponses increments the response counter corresponding to the DNS RCode.
func (m *Metrics) IncResponses(rCode dns.RCode) {
	if m == nil {
		return
	}
	switch rCode {
	case dns.RCodeSuccess:
		m.responsesNOERROR.Add(1)
	case dns.RCodeNameError:
		m.responsesNXDOMAIN.Add(1)
	case dns.RCodeServerFailure:
		m.responsesSERVFAIL.Add(1)
	case dns.RCodeRefused:
		m.responsesREFUSED.Add(1)
	case dns.RCodeNotImplemented:
		m.responsesNOTIMP.Add(1)
	default:
		m.responsesOTHER.Add(1)
	}
}

// IncCacheHit increments the cache hit counter.
func (m *Metrics) IncCacheHit() {
	if m == nil {
		return
	}
	m.cacheHits.Add(1)
}

// IncCacheMiss increments the cache miss counter.
func (m *Metrics) IncCacheMiss() {
	if m == nil {
		return
	}
	m.cacheMisses.Add(1)
}

// SetDomains sets the gauge for the total number of domains in the store.
func (m *Metrics) SetDomains(count int) {
	if m == nil {
		return
	}
	m.domainsCount.Store(int64(count))
}

// IncMutations increments the total WAL mutations counter.
func (m *Metrics) IncMutations() {
	if m == nil {
		return
	}
	m.mutationsTotal.Add(1)
}

// IncCompactions increments the total snapshot compactions counter.
func (m *Metrics) IncCompactions() {
	if m == nil {
		return
	}
	m.compactionsDone.Add(1)
}

// IncRRLDrop increments the counter for responses silently dropped by RRL.
func (m *Metrics) IncRRLDrop() {
	if m == nil {
		return
	}
	m.rrlDrops.Add(1)
}

// IncRRLSlip increments the counter for responses sent with TC=1 by RRL.
func (m *Metrics) IncRRLSlip() {
	if m == nil {
		return
	}
	m.rrlSlips.Add(1)
}

// QueriesUDP returns the total UDP queries processed.
func (m *Metrics) QueriesUDP() uint64 {
	if m == nil {
		return 0
	}
	return m.queriesUDP.Load()
}

// QueriesTCP returns the total TCP queries processed.
func (m *Metrics) QueriesTCP() uint64 {
	if m == nil {
		return 0
	}
	return m.queriesTCP.Load()
}

// QueriesDoT returns the total DoT queries processed.
func (m *Metrics) QueriesDoT() uint64 {
	if m == nil {
		return 0
	}
	return m.queriesDoT.Load()
}

// QueriesDoH returns the total DoH queries processed.
func (m *Metrics) QueriesDoH() uint64 {
	if m == nil {
		return 0
	}
	return m.queriesDoH.Load()
}

// CacheHits returns the total cache hits.
func (m *Metrics) CacheHits() uint64 {
	if m == nil {
		return 0
	}
	return m.cacheHits.Load()
}

// CacheMisses returns the total cache misses.
func (m *Metrics) CacheMisses() uint64 {
	if m == nil {
		return 0
	}
	return m.cacheMisses.Load()
}

// Domains returns the current domain gauge value.
func (m *Metrics) Domains() int64 {
	if m == nil {
		return 0
	}
	return m.domainsCount.Load()
}

// Mutations returns the total mutations processed.
func (m *Metrics) Mutations() uint64 {
	if m == nil {
		return 0
	}
	return m.mutationsTotal.Load()
}

// Compactions returns the total snapshot compactions performed.
func (m *Metrics) Compactions() uint64 {
	if m == nil {
		return 0
	}
	return m.compactionsDone.Load()
}

// RRLDrops returns the total responses dropped by RRL.
func (m *Metrics) RRLDrops() uint64 {
	if m == nil {
		return 0
	}
	return m.rrlDrops.Load()
}

// RRLSlips returns the total responses truncated by RRL.
func (m *Metrics) RRLSlips() uint64 {
	if m == nil {
		return 0
	}
	return m.rrlSlips.Load()
}

// SetSnapshotBytes sets the gauge for the snapshot file size in bytes.
func (m *Metrics) SetSnapshotBytes(size int64) {
	if m == nil {
		return
	}
	m.snapshotBytes.Store(size)
}

// SnapshotBytes returns the current snapshot file size in bytes.
func (m *Metrics) SnapshotBytes() int64 {
	if m == nil {
		return 0
	}
	return m.snapshotBytes.Load()
}

// SetWALBytes sets the gauge for the active WAL file size in bytes.
func (m *Metrics) SetWALBytes(size int64) {
	if m == nil {
		return
	}
	m.walBytes.Store(size)
}

// WALBytes returns the current WAL file size in bytes.
func (m *Metrics) WALBytes() int64 {
	if m == nil {
		return 0
	}
	return m.walBytes.Load()
}

// SetCompactionDuration records the latency duration of the most recent compaction.
func (m *Metrics) SetCompactionDuration(d time.Duration) {
	if m == nil {
		return
	}
	m.compactionLatency.Store(d.Nanoseconds())
}

// CompactionDuration returns the duration of the latest compaction.
func (m *Metrics) CompactionDuration() time.Duration {
	if m == nil {
		return 0
	}
	return time.Duration(m.compactionLatency.Load())
}

// SetMutationsPending sets the gauge for uncompacted mutations in the active WAL.
func (m *Metrics) SetMutationsPending(count uint64) {
	if m == nil {
		return
	}
	m.mutationsPending.Store(count)
}

// MutationsPending returns the count of uncompacted mutations in the active WAL.
func (m *Metrics) MutationsPending() uint64 {
	if m == nil {
		return 0
	}
	return m.mutationsPending.Load()
}

// SetCacheEntries sets the gauge for total active entries in the LRU cache.
func (m *Metrics) SetCacheEntries(count int) {
	if m == nil {
		return
	}
	m.cacheEntries.Store(int64(count))
}

// CacheEntries returns the total active entries in the LRU cache.
func (m *Metrics) CacheEntries() int64 {
	if m == nil {
		return 0
	}
	return m.cacheEntries.Load()
}

// IncDNSSECSignatures increments the counter for on-the-fly RRSIG cryptographic signatures generated.
func (m *Metrics) IncDNSSECSignatures() {
	if m == nil {
		return
	}
	m.dnssecSignatures.Add(1)
}

// DNSSECSignatures returns the total DNSSEC signatures generated.
func (m *Metrics) DNSSECSignatures() uint64 {
	if m == nil {
		return 0
	}
	return m.dnssecSignatures.Load()
}

// IncDNSSECQueries increments the counter for queries with EDNS0 DO=1 bit set.
func (m *Metrics) IncDNSSECQueries() {
	if m == nil {
		return
	}
	m.dnssecQueries.Add(1)
}

// DNSSECQueries returns the total DNSSEC-requested queries.
func (m *Metrics) DNSSECQueries() uint64 {
	if m == nil {
		return 0
	}
	return m.dnssecQueries.Load()
}

// IncTSIG increments the counter corresponding to TSIG authentication outcome.
func (m *Metrics) IncTSIG(status string) {
	if m == nil {
		return
	}
	switch status {
	case "ok", "success":
		m.tsigSuccess.Add(1)
	case "badsig":
		m.tsigBadSig.Add(1)
	case "badkey":
		m.tsigBadKey.Add(1)
	case "badtime":
		m.tsigBadTime.Add(1)
	case "badalgo":
		m.tsigBadAlgo.Add(1)
	default:
		m.tsigOther.Add(1)
	}
}

// TSIGRequests returns the total TSIG requests for a given status.
func (m *Metrics) TSIGRequests(status string) uint64 {
	if m == nil {
		return 0
	}
	switch status {
	case "ok", "success":
		return m.tsigSuccess.Load()
	case "badsig":
		return m.tsigBadSig.Load()
	case "badkey":
		return m.tsigBadKey.Load()
	case "badtime":
		return m.tsigBadTime.Load()
	case "badalgo":
		return m.tsigBadAlgo.Load()
	default:
		return m.tsigOther.Load()
	}
}

// IncRFC2136 increments the counter for RFC 2136 dynamic updates by status.
func (m *Metrics) IncRFC2136(status string) {
	if m == nil {
		return
	}
	switch status {
	case "success", "ok":
		m.rfc2136Success.Add(1)
	default:
		m.rfc2136Rejected.Add(1)
	}
}

// RFC2136Updates returns the total RFC 2136 dynamic updates for a given status.
func (m *Metrics) RFC2136Updates(status string) uint64 {
	if m == nil {
		return 0
	}
	switch status {
	case "success", "ok":
		return m.rfc2136Success.Load()
	default:
		return m.rfc2136Rejected.Load()
	}
}

// IncClusterStream increments the active cluster streams gauge.
func (m *Metrics) IncClusterStream() {
	if m == nil {
		return
	}
	m.clusterStreamsActive.Add(1)
}

// DecClusterStream decrements the active cluster streams gauge.
func (m *Metrics) DecClusterStream() {
	if m == nil {
		return
	}
	m.clusterStreamsActive.Add(-1)
}

// ClusterStreamsActive returns the number of active cluster streaming replicas.
func (m *Metrics) ClusterStreamsActive() int64 {
	if m == nil {
		return 0
	}
	return m.clusterStreamsActive.Load()
}

// IncClusterSnapshotSent increments the total snapshots sent counter.
func (m *Metrics) IncClusterSnapshotSent() {
	if m == nil {
		return
	}
	m.clusterSnapshotsSent.Add(1)
}

// ClusterSnapshotsSent returns the total snapshots sent to replicas.
func (m *Metrics) ClusterSnapshotsSent() uint64 {
	if m == nil {
		return 0
	}
	return m.clusterSnapshotsSent.Load()
}

// SetReplicaSyncStatus sets the replica sync status gauge (1 = streaming, 0 = disconnected).
func (m *Metrics) SetReplicaSyncStatus(status int64) {
	if m == nil {
		return
	}
	m.replicaSyncStatus.Store(status)
}

// ReplicaSyncStatus returns the replica sync status gauge.
func (m *Metrics) ReplicaSyncStatus() int64 {
	if m == nil {
		return 0
	}
	return m.replicaSyncStatus.Load()
}

// IncReplicaSnapshotRecv increments the total snapshots received counter.
func (m *Metrics) IncReplicaSnapshotRecv() {
	if m == nil {
		return
	}
	m.replicaSnapshotsRecv.Add(1)
}

// ReplicaSnapshotsRecv returns the total snapshots received by replica.
func (m *Metrics) ReplicaSnapshotsRecv() uint64 {
	if m == nil {
		return 0
	}
	return m.replicaSnapshotsRecv.Load()
}

// SetReplicaLastSync sets the unix timestamp of the last successful sync.
func (m *Metrics) SetReplicaLastSync(unix int64) {
	if m == nil {
		return
	}
	m.replicaLastSyncUnix.Store(unix)
}

// ReplicaLastSync returns the timestamp of the last successful sync.
func (m *Metrics) ReplicaLastSync() int64 {
	if m == nil {
		return 0
	}
	return m.replicaLastSyncUnix.Load()
}

// AddBytesInUDP adds received bytes to the UDP transport counter.
func (m *Metrics) AddBytesInUDP(n uint64) {
	if m != nil {
		m.bytesInUDP.Add(n)
	}
}

// AddBytesInTCP adds received bytes to the TCP transport counter.
func (m *Metrics) AddBytesInTCP(n uint64) {
	if m != nil {
		m.bytesInTCP.Add(n)
	}
}

// AddBytesInDoT adds received bytes to the DoT transport counter.
func (m *Metrics) AddBytesInDoT(n uint64) {
	if m != nil {
		m.bytesInDoT.Add(n)
	}
}

// AddBytesInDoH adds received bytes to the DoH transport counter.
func (m *Metrics) AddBytesInDoH(n uint64) {
	if m != nil {
		m.bytesInDoH.Add(n)
	}
}

// AddBytesOutUDP adds transmitted bytes to the UDP transport counter.
func (m *Metrics) AddBytesOutUDP(n uint64) {
	if m != nil {
		m.bytesOutUDP.Add(n)
	}
}

// AddBytesOutTCP adds transmitted bytes to the TCP transport counter.
func (m *Metrics) AddBytesOutTCP(n uint64) {
	if m != nil {
		m.bytesOutTCP.Add(n)
	}
}

// AddBytesOutDoT adds transmitted bytes to the DoT transport counter.
func (m *Metrics) AddBytesOutDoT(n uint64) {
	if m != nil {
		m.bytesOutDoT.Add(n)
	}
}

// AddBytesOutDoH adds transmitted bytes to the DoH transport counter.
func (m *Metrics) AddBytesOutDoH(n uint64) {
	if m != nil {
		m.bytesOutDoH.Add(n)
	}
}

// IncTCPConnection increments the gauge of active TCP/DoT client connections.
func (m *Metrics) IncTCPConnection() {
	if m != nil {
		m.tcpConnsActive.Add(1)
	}
}

// DecTCPConnection decrements the gauge of active TCP/DoT client connections.
func (m *Metrics) DecTCPConnection() {
	if m != nil {
		m.tcpConnsActive.Add(-1)
	}
}

// TCPConnectionsActive returns the count of currently active TCP and DoT client connections.
func (m *Metrics) TCPConnectionsActive() int64 {
	if m == nil {
		return 0
	}
	return m.tcpConnsActive.Load()
}

// IncReloadEvent increments the reload events counter for SIGHUP invocations.
func (m *Metrics) IncReloadEvent(success bool) {
	if m == nil {
		return
	}
	if success {
		m.reloadsSuccess.Add(1)
		return
	}
	m.reloadsFailed.Add(1)
}

// ReloadEvents returns the total count of SIGHUP reload attempts by status.
func (m *Metrics) ReloadEvents(status string) uint64 {
	if m == nil {
		return 0
	}
	if status == "success" || status == "ok" {
		return m.reloadsSuccess.Load()
	}
	return m.reloadsFailed.Load()
}

// IncQueryType increments the query counter corresponding to the requested DNS record type.
func (m *Metrics) IncQueryType(qType dns.Type) {
	if m == nil {
		return
	}
	switch qType {
	case dns.TypeA:
		m.qTypeA.Add(1)
	case dns.TypeAAAA:
		m.qTypeAAAA.Add(1)
	case dns.TypeCNAME:
		m.qTypeCNAME.Add(1)
	case dns.TypeTXT:
		m.qTypeTXT.Add(1)
	case dns.TypeMX:
		m.qTypeMX.Add(1)
	case dns.TypeNS:
		m.qTypeNS.Add(1)
	case dns.TypeSOA:
		m.qTypeSOA.Add(1)
	case dns.TypeSRV:
		m.qTypeSRV.Add(1)
	case dns.TypeCAA:
		m.qTypeCAA.Add(1)
	case dns.TypePTR:
		m.qTypePTR.Add(1)
	case dns.TypeDS:
		m.qTypeDS.Add(1)
	case dns.TypeDNSKEY:
		m.qTypeDNSKEY.Add(1)
	default:
		m.qTypeOTHER.Add(1)
	}
}

// QueriesByType returns the total queries processed for a given record type string.
func (m *Metrics) QueriesByType(typeName string) uint64 {
	if m == nil {
		return 0
	}
	switch strings.ToUpper(typeName) {
	case "A":
		return m.qTypeA.Load()
	case "AAAA":
		return m.qTypeAAAA.Load()
	case "CNAME":
		return m.qTypeCNAME.Load()
	case "TXT":
		return m.qTypeTXT.Load()
	case "MX":
		return m.qTypeMX.Load()
	case "NS":
		return m.qTypeNS.Load()
	case "SOA":
		return m.qTypeSOA.Load()
	case "SRV":
		return m.qTypeSRV.Load()
	case "CAA":
		return m.qTypeCAA.Load()
	case "PTR":
		return m.qTypePTR.Load()
	case "DS":
		return m.qTypeDS.Load()
	case "DNSKEY":
		return m.qTypeDNSKEY.Load()
	default:
		return m.qTypeOTHER.Load()
	}
}

// WriteTo formats and writes all metrics in Prometheus text format to w.
// It implements the standard io.WriterTo.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, nil
	}

	ptr := metricsBufPool.Get().(*[]byte)
	buf := (*ptr)[:0]
	defer func() {
		*ptr = buf[:0]
		metricsBufPool.Put(ptr)
	}()

	uptime := time.Since(m.startTime).Seconds()
	startTimeUnix := m.startTime.Unix()

	buf = append(buf, "# HELP kdns_build_info Build and version metadata\n# TYPE kdns_build_info gauge\nkdns_build_info{version=\""...)
	buf = append(buf, m.version...)
	buf = append(buf, "\",commit=\""...)
	buf = append(buf, m.commit...)
	buf = append(buf, "\",build_time=\""...)
	buf = append(buf, m.buildTime...)
	buf = append(buf, "\"} 1\n\n"...)

	buf = append(buf, "# HELP kdns_server_info Server configuration and runtime operational mode\n# TYPE kdns_server_info gauge\nkdns_server_info{mode=\""...)
	buf = append(buf, m.mode...)
	buf = append(buf, "\",ha_enabled=\""...)
	buf = append(buf, strconv.FormatBool(m.haEnabled)...)
	buf = append(buf, "\",dnssec_enabled=\""...)
	buf = append(buf, strconv.FormatBool(m.dnssecEnabled)...)
	buf = append(buf, "\",rrl_enabled=\""...)
	buf = append(buf, strconv.FormatBool(m.rrlEnabled)...)
	buf = append(buf, "\",tls_enabled=\""...)
	buf = append(buf, strconv.FormatBool(m.tlsEnabled)...)
	buf = append(buf, "\",doh_enabled=\""...)
	buf = append(buf, strconv.FormatBool(m.dohEnabled)...)
	buf = append(buf, "\",server_id=\""...)
	buf = append(buf, m.serverID...)
	buf = append(buf, "\"} 1\n\n"...)

	buf = append(buf, "# HELP kdns_start_time_seconds Unix timestamp in seconds when the process started\n# TYPE kdns_start_time_seconds gauge\nkdns_start_time_seconds "...)
	buf = strconv.AppendInt(buf, startTimeUnix, 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_uptime_seconds Total server uptime in seconds\n# TYPE kdns_uptime_seconds gauge\nkdns_uptime_seconds "...)
	buf = strconv.AppendFloat(buf, uptime, 'f', 3, 64)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_queries_total Total DNS queries processed by transport protocol\n# TYPE kdns_queries_total counter\nkdns_queries_total{proto=\"udp\"} "...)
	buf = strconv.AppendUint(buf, m.queriesUDP.Load(), 10)
	buf = append(buf, "\nkdns_queries_total{proto=\"tcp\"} "...)
	buf = strconv.AppendUint(buf, m.queriesTCP.Load(), 10)
	buf = append(buf, "\nkdns_queries_total{proto=\"dot\"} "...)
	buf = strconv.AppendUint(buf, m.queriesDoT.Load(), 10)
	buf = append(buf, "\nkdns_queries_total{proto=\"doh\"} "...)
	buf = strconv.AppendUint(buf, m.queriesDoH.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_queries_by_type_total Total DNS queries processed by record type\n# TYPE kdns_queries_by_type_total counter\nkdns_queries_by_type_total{type=\"A\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeA.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"AAAA\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeAAAA.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"CNAME\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeCNAME.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"TXT\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeTXT.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"MX\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeMX.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"NS\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeNS.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"SOA\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeSOA.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"SRV\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeSRV.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"CAA\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeCAA.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"PTR\"} "...)
	buf = strconv.AppendUint(buf, m.qTypePTR.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"DS\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeDS.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"DNSKEY\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeDNSKEY.Load(), 10)
	buf = append(buf, "\nkdns_queries_by_type_total{type=\"OTHER\"} "...)
	buf = strconv.AppendUint(buf, m.qTypeOTHER.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_network_receive_bytes_total Total bytes received by transport protocol\n# TYPE kdns_network_receive_bytes_total counter\nkdns_network_receive_bytes_total{proto=\"udp\"} "...)
	buf = strconv.AppendUint(buf, m.bytesInUDP.Load(), 10)
	buf = append(buf, "\nkdns_network_receive_bytes_total{proto=\"tcp\"} "...)
	buf = strconv.AppendUint(buf, m.bytesInTCP.Load(), 10)
	buf = append(buf, "\nkdns_network_receive_bytes_total{proto=\"dot\"} "...)
	buf = strconv.AppendUint(buf, m.bytesInDoT.Load(), 10)
	buf = append(buf, "\nkdns_network_receive_bytes_total{proto=\"doh\"} "...)
	buf = strconv.AppendUint(buf, m.bytesInDoH.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_network_transmit_bytes_total Total bytes sent by transport protocol\n# TYPE kdns_network_transmit_bytes_total counter\nkdns_network_transmit_bytes_total{proto=\"udp\"} "...)
	buf = strconv.AppendUint(buf, m.bytesOutUDP.Load(), 10)
	buf = append(buf, "\nkdns_network_transmit_bytes_total{proto=\"tcp\"} "...)
	buf = strconv.AppendUint(buf, m.bytesOutTCP.Load(), 10)
	buf = append(buf, "\nkdns_network_transmit_bytes_total{proto=\"dot\"} "...)
	buf = strconv.AppendUint(buf, m.bytesOutDoT.Load(), 10)
	buf = append(buf, "\nkdns_network_transmit_bytes_total{proto=\"doh\"} "...)
	buf = strconv.AppendUint(buf, m.bytesOutDoH.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_tcp_connections_active Number of active TCP and DoT client connections\n# TYPE kdns_tcp_connections_active gauge\nkdns_tcp_connections_active "...)
	buf = strconv.AppendInt(buf, m.tcpConnsActive.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_reload_events_total Total SIGHUP state and certificate reload events\n# TYPE kdns_reload_events_total counter\nkdns_reload_events_total{status=\"success\"} "...)
	buf = strconv.AppendUint(buf, m.reloadsSuccess.Load(), 10)
	buf = append(buf, "\nkdns_reload_events_total{status=\"failed\"} "...)
	buf = strconv.AppendUint(buf, m.reloadsFailed.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_responses_total Total DNS responses by RCode\n# TYPE kdns_responses_total counter\nkdns_responses_total{rcode=\"NOERROR\"} "...)
	buf = strconv.AppendUint(buf, m.responsesNOERROR.Load(), 10)
	buf = append(buf, "\nkdns_responses_total{rcode=\"NXDOMAIN\"} "...)
	buf = strconv.AppendUint(buf, m.responsesNXDOMAIN.Load(), 10)
	buf = append(buf, "\nkdns_responses_total{rcode=\"SERVFAIL\"} "...)
	buf = strconv.AppendUint(buf, m.responsesSERVFAIL.Load(), 10)
	buf = append(buf, "\nkdns_responses_total{rcode=\"REFUSED\"} "...)
	buf = strconv.AppendUint(buf, m.responsesREFUSED.Load(), 10)
	buf = append(buf, "\nkdns_responses_total{rcode=\"NOTIMP\"} "...)
	buf = strconv.AppendUint(buf, m.responsesNOTIMP.Load(), 10)
	buf = append(buf, "\nkdns_responses_total{rcode=\"OTHER\"} "...)
	buf = strconv.AppendUint(buf, m.responsesOTHER.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_cache_hits_total Total LRU cache hits\n# TYPE kdns_cache_hits_total counter\nkdns_cache_hits_total "...)
	buf = strconv.AppendUint(buf, m.cacheHits.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_cache_misses_total Total LRU cache misses\n# TYPE kdns_cache_misses_total counter\nkdns_cache_misses_total "...)
	buf = strconv.AppendUint(buf, m.cacheMisses.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_cache_entries_total Total entries currently held in the LRU cache\n# TYPE kdns_cache_entries_total gauge\nkdns_cache_entries_total "...)
	buf = strconv.AppendInt(buf, m.cacheEntries.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_domains_total Total active domains stored in memory\n# TYPE kdns_domains_total gauge\nkdns_domains_total "...)
	buf = strconv.AppendInt(buf, m.domainsCount.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_mutations_total Total WAL mutations persisted\n# TYPE kdns_mutations_total counter\nkdns_mutations_total "...)
	buf = strconv.AppendUint(buf, m.mutationsTotal.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_storage_mutations_pending Current uncompacted mutations in active WAL\n# TYPE kdns_storage_mutations_pending gauge\nkdns_storage_mutations_pending "...)
	buf = strconv.AppendUint(buf, m.mutationsPending.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_compactions_total Total state snapshot compactions completed\n# TYPE kdns_compactions_total counter\nkdns_compactions_total "...)
	buf = strconv.AppendUint(buf, m.compactionsDone.Load(), 10)
	buf = append(buf, "\n\n"...)

	compactionLatencySec := float64(m.compactionLatency.Load()) / float64(time.Second)
	buf = append(buf, "# HELP kdns_storage_compaction_duration_seconds Latency duration of latest state compaction\n# TYPE kdns_storage_compaction_duration_seconds gauge\nkdns_storage_compaction_duration_seconds "...)
	buf = strconv.AppendFloat(buf, compactionLatencySec, 'f', 6, 64)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_storage_snapshot_bytes Disk footprint size of compressed state snapshot\n# TYPE kdns_storage_snapshot_bytes gauge\nkdns_storage_snapshot_bytes "...)
	buf = strconv.AppendInt(buf, m.snapshotBytes.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_storage_wal_bytes Disk footprint size of active mutations WAL file\n# TYPE kdns_storage_wal_bytes gauge\nkdns_storage_wal_bytes "...)
	buf = strconv.AppendInt(buf, m.walBytes.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_rrl_dropped_total Total DNS responses dropped by response rate limiting\n# TYPE kdns_rrl_dropped_total counter\nkdns_rrl_dropped_total "...)
	buf = strconv.AppendUint(buf, m.rrlDrops.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_rrl_slipped_total Total DNS responses truncated (TC=1) by response rate limiting\n# TYPE kdns_rrl_slipped_total counter\nkdns_rrl_slipped_total "...)
	buf = strconv.AppendUint(buf, m.rrlSlips.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_dnssec_signatures_total Total on-the-fly RRSIG cryptographic signatures generated\n# TYPE kdns_dnssec_signatures_total counter\nkdns_dnssec_signatures_total "...)
	buf = strconv.AppendUint(buf, m.dnssecSignatures.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_dnssec_queries_total Total DNS queries requesting DNSSEC OK (DO=1)\n# TYPE kdns_dnssec_queries_total counter\nkdns_dnssec_queries_total "...)
	buf = strconv.AppendUint(buf, m.dnssecQueries.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_tsig_requests_total Total TSIG authenticated requests by outcome\n# TYPE kdns_tsig_requests_total counter\nkdns_tsig_requests_total{status=\"ok\"} "...)
	buf = strconv.AppendUint(buf, m.tsigSuccess.Load(), 10)
	buf = append(buf, "\nkdns_tsig_requests_total{status=\"badsig\"} "...)
	buf = strconv.AppendUint(buf, m.tsigBadSig.Load(), 10)
	buf = append(buf, "\nkdns_tsig_requests_total{status=\"badkey\"} "...)
	buf = strconv.AppendUint(buf, m.tsigBadKey.Load(), 10)
	buf = append(buf, "\nkdns_tsig_requests_total{status=\"badtime\"} "...)
	buf = strconv.AppendUint(buf, m.tsigBadTime.Load(), 10)
	buf = append(buf, "\nkdns_tsig_requests_total{status=\"badalgo\"} "...)
	buf = strconv.AppendUint(buf, m.tsigBadAlgo.Load(), 10)
	buf = append(buf, "\nkdns_tsig_requests_total{status=\"other\"} "...)
	buf = strconv.AppendUint(buf, m.tsigOther.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_rfc2136_updates_total Total RFC 2136 dynamic updates processed by outcome\n# TYPE kdns_rfc2136_updates_total counter\nkdns_rfc2136_updates_total{status=\"success\"} "...)
	buf = strconv.AppendUint(buf, m.rfc2136Success.Load(), 10)
	buf = append(buf, "\nkdns_rfc2136_updates_total{status=\"rejected\"} "...)
	buf = strconv.AppendUint(buf, m.rfc2136Rejected.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_cluster_streams_active Number of currently connected replicas streaming WAL\n# TYPE kdns_cluster_streams_active gauge\nkdns_cluster_streams_active "...)
	buf = strconv.AppendInt(buf, m.clusterStreamsActive.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_cluster_snapshots_sent_total Number of full snapshots sent to replicas\n# TYPE kdns_cluster_snapshots_sent_total counter\nkdns_cluster_snapshots_sent_total "...)
	buf = strconv.AppendUint(buf, m.clusterSnapshotsSent.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_replica_sync_status Replica sync status (1 = streaming, 0 = disconnected)\n# TYPE kdns_replica_sync_status gauge\nkdns_replica_sync_status "...)
	buf = strconv.AppendInt(buf, m.replicaSyncStatus.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_replica_snapshots_received_total Number of full snapshots received by replica\n# TYPE kdns_replica_snapshots_received_total counter\nkdns_replica_snapshots_received_total "...)
	buf = strconv.AppendUint(buf, m.replicaSnapshotsRecv.Load(), 10)
	buf = append(buf, "\n\n"...)

	buf = append(buf, "# HELP kdns_replica_last_sync_timestamp_seconds Timestamp of the last received WAL frame or snapshot\n# TYPE kdns_replica_last_sync_timestamp_seconds gauge\nkdns_replica_last_sync_timestamp_seconds "...)
	buf = strconv.AppendInt(buf, m.replicaLastSyncUnix.Load(), 10)
	buf = append(buf, "\n"...)

	n, err := w.Write(buf)
	return int64(n), err
}
