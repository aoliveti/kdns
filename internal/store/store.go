// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package store implements high-throughput persistence, WAL group-commit batching, and snapshots.
//
// Concurrency Model:
//   - Writes: Mutex-guarded batch commits with single fsync per batch (up to 512 ops).
//   - State Sync: Updates the in-memory state.State and invalidates the LRU cache.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
	"github.com/aoliveti/kdns/internal/snapshot"
	"github.com/aoliveti/kdns/internal/state"
	"github.com/aoliveti/kdns/internal/wal"
)

const (
	snapFileName = "state.snap"
	walFileName  = "mutations.wal"
	storeDirPerm = 0o750

	defaultMutationQueueCap = 10000
	maxBatchSize            = 512
	batchFlushInterval      = 2 * time.Millisecond

	// mutationEnqueueTimeout is the maximum time to wait for space in the mutation queue
	// before returning ErrMutationQueueFull to the caller.
	mutationEnqueueTimeout = 5 * time.Second
)

var (
	// ErrNilState indicates that the provided in-memory state instance is nil.
	ErrNilState = errors.New("store: state cannot be nil")

	// ErrUncleanState indicates that a WAL file exists without a corresponding state snapshot.
	ErrUncleanState = errors.New("store: unclean state, WAL file exists but snapshot is missing")

	// ErrMutationQueueFull indicates that the store mutation queue has reached capacity.
	ErrMutationQueueFull = errors.New("store: mutation queue is full")

	// ErrClosed indicates that the store has been closed.
	ErrClosed = errors.New("store: closed")

	// ErrCompactionThresholdTooLow indicates that the compaction threshold is below the minimum allowed value.
	ErrCompactionThresholdTooLow = errors.New("store: compaction threshold must be at least 100")

	// ErrCompactionIntervalTooLow indicates that the compaction interval is below the minimum allowed duration.
	ErrCompactionIntervalTooLow = errors.New("store: compaction interval must be at least 1m")
)

type metricsCollector interface {
	SetDomains(count int)
	IncMutations()
	IncCompactions()
	SetSnapshotBytes(size int64)
	SetWALBytes(size int64)
	SetCompactionDuration(d time.Duration)
	SetMutationsPending(count uint64)
}

type nopCollector struct{}

func (nopCollector) SetDomains(int)                      {}
func (nopCollector) IncMutations()                       {}
func (nopCollector) IncCompactions()                     {}
func (nopCollector) SetSnapshotBytes(int64)              {}
func (nopCollector) SetWALBytes(int64)                   {}
func (nopCollector) SetCompactionDuration(time.Duration) {}
func (nopCollector) SetMutationsPending(uint64)          {}

type nopHub struct{}

func (nopHub) NotifyFlush()      {}
func (nopHub) NotifyCompaction() {}

// Store coordinates disk persistence, WAL group-commit journaling, and snapshot compactions.
type Store struct {
	st             *state.State
	walWriter      *wal.Writer
	walFile        *os.File
	root           *os.Root
	logger         *slog.Logger
	metrics        metricsCollector
	hub            ClusterHub
	ctx            context.Context
	cancel         context.CancelFunc
	compactCh      chan struct{}
	mutationCh     chan mutationOp
	zoneFileName   string
	wg             sync.WaitGroup
	mutationsCount uint64
	threshold      uint64
	isReplica      bool
	mu             sync.RWMutex
}

// Open bootstraps persistent storage in dir and synchronizes with the in-memory state.
func Open(dir string, st *state.State, opts ...Option) (*Store, error) {
	if st == nil {
		return nil, ErrNilState
	}

	config := &options{
		logger:              slog.Default(),
		compactionInterval:  DefaultCompactionInterval,
		compactionThreshold: DefaultCompactionThreshold,
	}

	for _, opt := range opts {
		opt(config)
	}

	if config.compactionThreshold < MinCompactionThreshold {
		return nil, ErrCompactionThresholdTooLow
	}
	if config.compactionInterval < MinCompactionInterval {
		return nil, ErrCompactionIntervalTooLow
	}

	if err := ensureStoreDir(dir); err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open root directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := config.metrics
	if m == nil {
		m = nopCollector{}
	}
	h := config.hub
	if h == nil {
		h = nopHub{}
	}

	s := &Store{
		st:           st,
		root:         root,
		logger:       config.logger,
		metrics:      m,
		hub:          h,
		ctx:          ctx,
		cancel:       cancel,
		compactCh:    make(chan struct{}, 1),
		mutationCh:   make(chan mutationOp, defaultMutationQueueCap),
		zoneFileName: config.zoneFileName,
		threshold:    config.compactionThreshold,
		isReplica:    config.isReplica,
	}

	snapshot.CleanStaleTemp(dir)

	hasSnap, err := s.hasSnapshot()
	if err != nil {
		return nil, err
	}

	hasWAL, err := s.hasWAL()
	if err != nil {
		return nil, err
	}

	if !hasSnap && hasWAL {
		return nil, ErrUncleanState
	}

	initialTree := radix.New()
	if hasSnap {
		if loadErr := s.loadSnapshotIntoTree(snapFileName, initialTree); loadErr != nil {
			return nil, loadErr
		}
	}

	if bsError := s.bootstrap(hasSnap, config.zoneFileName, initialTree); bsError != nil {
		return nil, bsError
	}

	if err = s.replayWALIntoTree(walFileName, initialTree); err != nil {
		return nil, fmt.Errorf("failed to replay WAL: %w", err)
	}

	st.Swap(initialTree)

	if err := s.openWAL(); err != nil {
		return nil, err
	}

	s.wg.Go(func() {
		s.compactionLoop(ctx, config.compactionInterval)
	})
	s.wg.Go(func() {
		s.batchWorker(ctx)
	})

	s.metrics.SetDomains(st.Len())
	s.logger.Info("storage initialized successfully", slog.String("dir", dir))
	return s, nil
}

// Upsert enqueues an upsert mutation into the group-commit batch worker.
func (s *Store) Upsert(domain string, records dns.RRSets) error {
	done := make(chan error, 1)
	op := mutationOp{
		opType:  opUpsert,
		domain:  domain,
		records: records,
		done:    done,
	}

	enqueueTimer := time.NewTimer(mutationEnqueueTimeout)
	defer enqueueTimer.Stop()

	select {
	case <-s.ctx.Done():
		return ErrClosed
	case s.mutationCh <- op:
	case <-enqueueTimer.C:
		return ErrMutationQueueFull
	}

	select {
	case <-s.ctx.Done():
		return ErrClosed
	case err := <-done:
		return err
	}
}

// DeleteDomain enqueues a domain deletion mutation into the group-commit batch worker.
func (s *Store) DeleteDomain(domain string) error {
	done := make(chan error, 1)
	op := mutationOp{
		opType: opDelete,
		domain: domain,
		done:   done,
	}

	enqueueTimer := time.NewTimer(mutationEnqueueTimeout)
	defer enqueueTimer.Stop()

	select {
	case <-s.ctx.Done():
		return ErrClosed
	case s.mutationCh <- op:
	case <-enqueueTimer.C:
		return ErrMutationQueueFull
	}

	select {
	case <-s.ctx.Done():
		return ErrClosed
	case err := <-done:
		return err
	}
}

// Close gracefully flushes all pending mutations to disk and stops background workers.
func (s *Store) Close() error {
	s.logger.Debug("shutting down storage, waiting for background tasks")
	if s.cancel != nil {
		s.cancel()
		s.wg.Wait()
	}

	s.logger.Debug("flushing wal to disk and closing files")
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	if s.walWriter != nil {
		if err := s.walWriter.Flush(); err != nil {
			errs = append(errs, fmt.Errorf("failed to flush WAL writer: %w", err))
		}
	}
	if s.walFile != nil {
		if err := s.walFile.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close WAL file: %w", err))
		}
	}
	if s.root != nil {
		if err := s.root.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close root directory: %w", err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	s.logger.Info("storage closed successfully")
	return nil
}

func (s *Store) openWAL() error {
	f, err := s.root.OpenFile(walFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open WAL file: %w", err)
	}
	s.walFile = f
	s.walWriter = wal.NewWriter(f)
	return nil
}

// SetClusterHub registers a cluster hub callback on the store for WAL notifications.
func (s *Store) SetClusterHub(hub ClusterHub) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hub == nil {
		hub = nopHub{}
	}
	s.hub = hub
}

// OpenWALReader opens a read-only handle to the current WAL file for cluster streaming.
func (s *Store) OpenWALReader() (*os.File, error) {
	return s.root.OpenFile(walFileName, os.O_RDONLY, 0)
}

// OpenSnapshotReader opens a read-only handle to the current snapshot file for cluster replication.
func (s *Store) OpenSnapshotReader() (*os.File, error) {
	return s.root.OpenFile(snapFileName, os.O_RDONLY, 0)
}

// SnapshotChecksum returns the CRC32-IEEE checksum embedded in the current snapshot file.
func (s *Store) SnapshotChecksum() (uint32, error) {
	f, err := s.root.OpenFile(snapFileName, os.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return snapshot.ReadChecksum(f, info.Size())
}

func (s *Store) hasSnapshot() (bool, error) {
	if _, err := s.root.Stat(snapFileName); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("failed to stat snapshot file: %w", err)
	}
	return true, nil
}

func (s *Store) hasWAL() (bool, error) {
	if _, err := s.root.Stat(walFileName); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("failed to stat WAL file: %w", err)
	}
	return true, nil
}

func (s *Store) bootstrap(hasSnap bool, zoneFileName string, target *radix.Tree) error {
	if hasSnap {
		if zoneFileName != "" {
			s.logger.Info("persistent state found, ignoring provided zone file",
				slog.String("zone_file", zoneFileName),
			)
		}
		return nil
	}

	if zoneFileName != "" {
		if err := s.loadZoneFileIntoTree(zoneFileName, target); err != nil {
			return fmt.Errorf("failed to bootstrap from zone file: %w", err)
		}
		if err := s.saveSnapshotFromTree(target); err != nil {
			return fmt.Errorf("failed to save initial snapshot: %w", err)
		}
		return nil
	}

	if s.isReplica {
		s.logger.Info("replica mode: waiting for initial snapshot from primary")
		return nil
	}

	s.logger.Info("no state found, creating empty initial snapshot")
	if err := s.saveSnapshotFromTree(target); err != nil {
		return fmt.Errorf("failed to save initial snapshot: %w", err)
	}
	return nil
}

// ReloadState synchronizes with any in-flight compactions, reloads state from disk,
// and atomically swaps the in-memory State tree.
func (s *Store) ReloadState() error {
	start := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	newTree := radix.New()

	loader := s.reloadFromDisk
	if s.zoneFileName != "" {
		loader = s.reloadFromZoneFile
	}
	if err := loader(newTree); err != nil {
		return err
	}

	s.st.Swap(newTree)
	s.metrics.SetDomains(newTree.Len())

	s.logger.Info("store state reloaded successfully",
		slog.Int("domains_loaded", newTree.Len()),
		slog.Duration("duration", time.Since(start)),
	)
	return nil
}

func (s *Store) reloadFromZoneFile(newTree *radix.Tree) error {
	if err := s.loadZoneFileIntoTree(s.zoneFileName, newTree); err != nil {
		return fmt.Errorf("reload zone file: %w", err)
	}
	if err := s.saveSnapshotFromTree(newTree); err != nil {
		return fmt.Errorf("save snapshot on reload: %w", err)
	}
	if s.walWriter != nil {
		if err := s.walWriter.Flush(); err != nil {
			return fmt.Errorf("flush wal before zone reload: %w", err)
		}
	}
	if s.walFile != nil {
		if err := s.walFile.Close(); err != nil {
			return fmt.Errorf("close wal before zone reload: %w", err)
		}
	}
	newWalFile, err := s.root.OpenFile(walFileName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("reset wal on reload: %w", err)
	}
	s.walFile = newWalFile
	s.walWriter = wal.NewWriter(newWalFile)
	s.mutationsCount = 0

	s.hub.NotifyCompaction()
	return nil
}

func (s *Store) reloadFromDisk(newTree *radix.Tree) error {
	if s.walWriter != nil {
		if err := s.walWriter.Flush(); err != nil {
			return fmt.Errorf("flush wal on reload: %w", err)
		}
	}
	hasSnap, err := s.hasSnapshot()
	if err != nil {
		return fmt.Errorf("check snapshot on reload: %w", err)
	}
	if hasSnap {
		if err := s.loadSnapshotIntoTree(snapFileName, newTree); err != nil {
			return fmt.Errorf("load snapshot on reload: %w", err)
		}
	}
	if err := s.replayWALIntoTree(walFileName, newTree); err != nil {
		return fmt.Errorf("replay wal on reload: %w", err)
	}
	return nil
}

func ensureStoreDir(dir string) error {
	if err := os.MkdirAll(dir, storeDirPerm); err != nil {
		return fmt.Errorf("failed to create store directory: %w", err)
	}
	if err := os.Chmod(dir, storeDirPerm); err != nil && !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("failed to enforce store directory permissions: %w", err)
	}
	return nil
}

var (
	_ dns.Upserter      = (*Store)(nil)
	_ dns.Deleter       = (*Store)(nil)
	_ dns.UpsertDeleter = (*Store)(nil)
)
