// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package replica

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
	"github.com/aoliveti/kdns/internal/snapshot"
	"github.com/aoliveti/kdns/internal/wal"
)

const (
	snapFileName             = "state.snap"
	walFileName              = "mutations.wal"
	maxSnapshotDownloadBytes = 512 * 1024 * 1024 // 512 MB payload protection
)

func (c *Client) sync(ctx context.Context) error {
	c.metrics.SetReplicaSyncStatus(1)
	defer c.metrics.SetReplicaSyncStatus(0)

	// If no snapshot exists locally, download initial snapshot from primary.
	if !c.hasSnapshot() {
		c.logger.Info("no local snapshot found on replica, downloading initial snapshot from primary")
		if err := c.downloadSnapshot(ctx); err != nil {
			return fmt.Errorf("download snapshot: %w", err)
		}
	}

	var offset int64
	if c.root != nil {
		if info, err := c.root.Stat(walFileName); err == nil {
			offset = info.Size()
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/cluster/stream?offset=%d", c.primaryURL, offset), http.NoBody)
	if err != nil {
		return fmt.Errorf("create stream request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("stream request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable || resp.StatusCode == http.StatusNotFound {
		c.logger.Warn("primary WAL truncated or offset out of range, downloading fresh snapshot",
			slog.Int("status_code", resp.StatusCode),
			slog.Int64("offset", offset),
		)
		if dlErr := c.downloadSnapshot(ctx); dlErr != nil {
			return fmt.Errorf("resync snapshot: %w", dlErr)
		}
		return nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return ErrRateLimited
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stream returned status %d", resp.StatusCode)
	}

	// Verify snapshot checksum consistency
	if primaryChecksumHex := resp.Header.Get("X-Snapshot-Checksum"); primaryChecksumHex != "" {
		localChecksum, chkErr := c.localSnapshotChecksum(snapFileName)
		if chkErr == nil && fmt.Sprintf("%08x", localChecksum) != primaryChecksumHex {
			c.logger.Warn("local snapshot checksum mismatch with primary, downloading fresh snapshot",
				slog.String("local_checksum", fmt.Sprintf("%08x", localChecksum)),
				slog.String("primary_checksum", primaryChecksumHex),
			)
			if dlErr := c.downloadSnapshot(ctx); dlErr != nil {
				return fmt.Errorf("resync snapshot on checksum mismatch: %w", dlErr)
			}
			return nil
		}
	}

	wf, err := c.root.OpenFile(walFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open local wal: %w", err)
	}
	bufWf := bufio.NewWriterSize(wf, 32*1024)
	defer func() {
		_ = bufWf.Flush()
		_ = wf.Close()
	}()

	tee := io.TeeReader(resp.Body, bufWf)

	onUpsert := func(domain string, records dns.RRSets) {
		_ = bufWf.Flush()
		c.st.Update(func(target *radix.Tree) {
			target.Upsert(domain, records)
		})
	}
	onDelete := func(domain string) {
		_ = bufWf.Flush()
		c.st.Update(func(target *radix.Tree) {
			target.DeleteDomain(domain)
		})
	}

	c.logger.Info("connected to primary stream", slog.Int64("offset", offset))

	// Periodically update last sync timestamp while streaming
	ctxReplay, cancelReplay := context.WithCancel(ctx)
	defer cancelReplay()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctxReplay.Done():
				return
			case <-ticker.C:
				c.metrics.SetReplicaLastSync(time.Now().Unix())
			}
		}
	}()

	err = wal.Replay(tee, onUpsert, onDelete)
	if err != nil && !errors.Is(err, wal.ErrTruncated) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("wal replay: %w", err)
	}
	return nil
}

func (c *Client) hasSnapshot() bool {
	if c.root == nil {
		return false
	}
	_, err := c.root.Stat(snapFileName)
	return err == nil
}

func (c *Client) downloadSnapshot(ctx context.Context) error {
	c.logger.Info("downloading full snapshot from primary")
	snapCtx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(snapCtx, http.MethodGet, c.primaryURL+"/v1/cluster/snapshot", http.NoBody)
	if err != nil {
		return fmt.Errorf("create snapshot request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("execute snapshot request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return ErrRateLimited
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrSnapshotNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	primaryChecksumHex := resp.Header.Get("X-Snapshot-Checksum")

	f, tmpName, createErr := snapshot.CreateTemp(c.root, "state-snap-*.tmp")
	if createErr != nil {
		return fmt.Errorf("create temp snapshot file: %w", createErr)
	}
	defer func() {
		_ = f.Close()
		_ = c.root.Remove(tmpName)
	}()

	limitedBody := io.LimitReader(resp.Body, maxSnapshotDownloadBytes)
	if _, copyErr := io.Copy(f, limitedBody); copyErr != nil {
		return fmt.Errorf("copy snapshot body: %w", copyErr)
	}

	if syncErr := f.Sync(); syncErr != nil {
		return fmt.Errorf("sync temp snapshot file: %w", syncErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		return fmt.Errorf("close temp snapshot file: %w", closeErr)
	}

	if primaryChecksumHex != "" {
		if localChecksum, chkErr := c.localSnapshotChecksum(tmpName); chkErr == nil {
			localHex := fmt.Sprintf("%08x", localChecksum)
			if localHex != primaryChecksumHex {
				return fmt.Errorf("%w: local %s != primary %s", ErrChecksumMismatch, localHex, primaryChecksumHex)
			}
		}
	}

	// Verify binary integrity before committing changes to disk or memory
	tmpFile, openErr := c.root.Open(tmpName)
	if openErr != nil {
		return fmt.Errorf("open temp snapshot file: %w", openErr)
	}
	defer func() { _ = tmpFile.Close() }()

	tree := radix.New()
	if loadErr := snapshot.Load(tmpFile, func(domain string, records dns.RRSets) {
		tree.Upsert(domain, records)
	}); loadErr != nil {
		return fmt.Errorf("load downloaded snapshot: %w", loadErr)
	}

	// Atomic filesystem replacement — file is closed by defer above.
	if renameErr := c.root.Rename(tmpName, snapFileName); renameErr != nil {
		return fmt.Errorf("rename downloaded snapshot: %w", renameErr)
	}

	// Reset local WAL since new snapshot is the baseline
	_ = c.root.Remove(walFileName)

	// Atomic in-memory state swap
	c.st.Swap(tree)

	c.metrics.IncReplicaSnapshotRecv()
	c.metrics.SetReplicaLastSync(time.Now().Unix())
	return nil
}

func (c *Client) localSnapshotChecksum(name string) (uint32, error) {
	f, err := c.root.Open(name)
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
