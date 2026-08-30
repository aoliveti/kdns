// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
	"github.com/aoliveti/kdns/internal/snapshot"
	"github.com/aoliveti/kdns/internal/wal"
	"github.com/aoliveti/kdns/internal/zone"
)

const (
	compactionReasonInterval  = "time_interval"
	compactionReasonThreshold = "mutations_threshold"
)

// Compact forces an immediate state checkpoint and resets the active WAL.
func (s *Store) Compact(reason string) error {
	start := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	tree := s.st.SnapshotTree()
	if err := s.saveSnapshotFromTree(tree); err != nil {
		return fmt.Errorf("compact save snapshot: %w", err)
	}

	if s.walWriter != nil {
		if err := s.walWriter.Flush(); err != nil {
			return fmt.Errorf("flush wal before rotation: %w", err)
		}
	}
	if s.walFile != nil {
		if err := s.walFile.Close(); err != nil {
			return fmt.Errorf("close old wal file: %w", err)
		}
	}

	newWalFile, err := s.root.OpenFile(walFileName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create fresh wal file: %w", err)
	}
	s.walFile = newWalFile
	s.walWriter = wal.NewWriter(newWalFile)

	s.hub.NotifyCompaction()

	dur := time.Since(start)
	var snapSize int64
	if info, err := s.root.Stat(snapFileName); err == nil {
		snapSize = info.Size()
		s.metrics.SetSnapshotBytes(snapSize)
	}

	s.logger.Info("compaction completed",
		slog.String("reason", reason),
		slog.Uint64("mutations_compacted", s.mutationsCount),
		slog.Int64("snapshot_bytes", snapSize),
		slog.Duration("duration", dur),
	)

	s.mutationsCount = 0
	s.metrics.IncCompactions()
	s.metrics.SetCompactionDuration(dur)
	s.metrics.SetMutationsPending(0)
	s.metrics.SetWALBytes(0)
	return nil
}

func (s *Store) compactionLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Debug("background compaction loop started",
		slog.Duration("interval", interval),
		slog.Uint64("threshold", s.threshold),
	)

	for {
		var triggerReason string
		select {
		case <-ctx.Done():
			s.logger.Debug("background compaction loop stopped")
			return

		case <-ticker.C:
			s.mu.RLock()
			count := s.mutationsCount
			s.mu.RUnlock()
			if count == 0 {
				continue
			}
			triggerReason = compactionReasonInterval

		case <-s.compactCh:
			triggerReason = compactionReasonThreshold
		}

		if err := s.Compact(triggerReason); err != nil {
			s.logger.Error("background compaction failed",
				slog.String("reason", triggerReason),
				slog.Any("error", err),
			)
		}
		ticker.Reset(interval)
	}
}

func (s *Store) triggerCompactionIfNeeded() {
	if s.threshold == 0 {
		return
	}
	s.mutationsCount++
	if s.mutationsCount >= s.threshold {
		select {
		case s.compactCh <- struct{}{}:
		default:
		}
	}
}

func (s *Store) saveSnapshotFromTree(target *radix.Tree) error {
	f, tmpName, err := snapshot.CreateTemp(s.root, "state-snap-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary snapshot file: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = s.root.Remove(tmpName)
	}()

	if err := snapshot.Save(f, target); err != nil {
		return fmt.Errorf("failed to save snapshot: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync snapshot file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close snapshot file: %w", err)
	}

	if err := s.root.Rename(tmpName, snapFileName); err != nil {
		return fmt.Errorf("failed to commit atomic snapshot: %w", err)
	}

	if info, err := s.root.Stat(snapFileName); err == nil {
		s.metrics.SetSnapshotBytes(info.Size())
	}

	return nil
}

func (s *Store) loadSnapshotIntoTree(name string, target *radix.Tree) error {
	start := time.Now()
	info, err := s.root.Stat(name)
	if err != nil {
		return fmt.Errorf("failed to stat snapshot file: %w", err)
	}

	f, err := s.root.Open(name)
	if err != nil {
		return fmt.Errorf("failed to open snapshot file %q: %w", name, err)
	}
	defer func() { _ = f.Close() }()

	var domainCount int
	err = snapshot.Load(f, func(domain string, records dns.RRSets) {
		target.Upsert(domain, records)
		domainCount++
	})
	if err != nil {
		return fmt.Errorf("failed to decode snapshot: %w", err)
	}

	s.metrics.SetSnapshotBytes(info.Size())
	s.logger.Info("snapshot loaded successfully",
		slog.Int64("size_bytes", info.Size()),
		slog.Int("domains_loaded", domainCount),
		slog.Duration("duration", time.Since(start)),
	)
	return nil
}

func (s *Store) replayWALIntoTree(name string, target *radix.Tree) error {
	start := time.Now()
	info, err := s.root.Stat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to stat WAL file: %w", err)
	}

	f, err := s.root.Open(name)
	if err != nil {
		return fmt.Errorf("failed to open WAL file %q: %w", name, err)
	}
	defer func() { _ = f.Close() }()

	var replayedCount int
	err = wal.Replay(f, func(domain string, records dns.RRSets) {
		target.Upsert(domain, records)
		replayedCount++
	}, func(domain string) {
		target.DeleteDomain(domain)
		replayedCount++
	})

	if err != nil && !errors.Is(err, wal.ErrTruncated) {
		return fmt.Errorf("failed to decode WAL replay: %w", err)
	}

	if errors.Is(err, wal.ErrTruncated) {
		s.logger.Warn("wal truncated tail detected, recovering valid records",
			slog.String("wal_file", name),
			slog.String("cause", "unclean_shutdown"),
		)
	}

	s.metrics.SetWALBytes(info.Size())
	if replayedCount > 0 {
		s.metrics.SetMutationsPending(uint64(replayedCount))
	}

	if replayedCount > 0 {
		s.logger.Info("wal replayed successfully",
			slog.Int64("size_bytes", info.Size()),
			slog.Int("mutations_replayed", replayedCount),
			slog.Duration("duration", time.Since(start)),
		)
	}
	return nil
}

// openZoneFile opens a zone file from the virtual directory root or local filesystem.
func (s *Store) openZoneFile(name string) (io.ReadCloser, int64, error) {
	if s.root != nil {
		if info, err := s.root.Stat(name); err == nil && !info.IsDir() {
			if rf, err := s.root.Open(name); err == nil {
				return rf, info.Size(), nil
			}
		}
	}

	// If the zone file path is outside the storage directory root (e.g. /etc/kdns/zone.db),
	// fallback to standard OS file resolution with path cleaning.
	cleanPath := filepath.Clean(name)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to stat: %w", err)
	}
	if info.IsDir() {
		return nil, 0, fmt.Errorf("%q is a directory, expected a file", cleanPath)
	}

	// #nosec G304
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open zone file %q: %w", cleanPath, err)
	}
	return f, info.Size(), nil
}

func (s *Store) loadZoneFileIntoTree(name string, target *radix.Tree) error {
	f, fileSize, err := s.openZoneFile(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	start := time.Now()
	var domainCount int
	err = zone.Parse(f, func(domain string, records dns.RRSets) {
		target.Upsert(domain, records)
		domainCount++
	})
	if err != nil {
		return fmt.Errorf("failed to parse zone file: %w", err)
	}

	s.logger.Info("loaded zone file into state",
		slog.String("zone_file", name),
		slog.Int64("size_bytes", fileSize),
		slog.Int("domains_loaded", domainCount),
		slog.Duration("duration", time.Since(start)),
	)
	return nil
}
