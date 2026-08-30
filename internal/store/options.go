// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"log/slog"
	"time"
)

const (
	// DefaultCompactionInterval is the default duration between periodic background compactions (30 minutes).
	DefaultCompactionInterval = 30 * time.Minute

	// MinCompactionInterval is the minimum allowable background compaction interval (1 minute).
	MinCompactionInterval = 1 * time.Minute

	// DefaultCompactionThreshold is the default number of mutations before triggering compaction (10,000).
	DefaultCompactionThreshold uint64 = 10000

	// MinCompactionThreshold is the minimum allowable mutations threshold before triggering compaction (100).
	MinCompactionThreshold uint64 = 100
)

// ClusterHub defines the callback interface that the Store uses to notify
// the cluster replication hub of WAL updates.
type ClusterHub interface {
	NotifyFlush()
	NotifyCompaction()
}

type options struct {
	logger              *slog.Logger
	metrics             metricsCollector
	hub                 ClusterHub
	zoneFileName        string
	compactionInterval  time.Duration
	compactionThreshold uint64
	isReplica           bool
}

// Option applies a specific configuration parameter to the Store.
type Option func(*options)

// WithReplicaMode configures the store to run as a cluster replica, skipping initial empty snapshot creation.
func WithReplicaMode(isReplica bool) Option {
	return func(o *options) {
		o.isReplica = isReplica
	}
}

// WithClusterHub attaches a cluster hub to receive WAL notifications.
func WithClusterHub(hub ClusterHub) Option {
	return func(o *options) {
		o.hub = hub
	}
}

// WithMetrics attaches a telemetry metrics collector to the store.
func WithMetrics(m metricsCollector) Option {
	return func(o *options) {
		o.metrics = m
	}
}

// WithZoneFile sets an initial RFC 1035 zone file to parse if no persistent state exists.
func WithZoneFile(name string) Option {
	return func(o *options) {
		o.zoneFileName = name
	}
}

// WithLogger injects a custom structured logger into the store.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}

// WithCompactionInterval defines the period between automatic background compactions.
func WithCompactionInterval(d time.Duration) Option {
	return func(o *options) {
		o.compactionInterval = d
	}
}

// WithCompactionThreshold defines the number of mutations triggering a compaction.
func WithCompactionThreshold(t uint64) Option {
	return func(o *options) {
		o.compactionThreshold = t
	}
}
