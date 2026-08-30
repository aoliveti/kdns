// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
)

type mutationOpType uint8

const (
	opUpsert mutationOpType = iota
	opDelete

	// compressionPointerMask identifies the 2-byte DNS message compression pointer tag
	// (0xC0 / 192, high two bits 11) per RFC 1035 §4.1.4.
	compressionPointerMask = 0xC0
)

type mutationOp struct {
	done    chan error
	domain  string
	records dns.RRSets
	opType  mutationOpType
}

func (s *Store) batchWorker(ctx context.Context) {
	batch := make([]mutationOp, 0, maxBatchSize)
	ticker := time.NewTicker(batchFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.drainMutations()
			return

		case op := <-s.mutationCh:
			batch = append(batch, op)

		drainLoop:
			for len(batch) < maxBatchSize {
				select {
				case nextOp := <-s.mutationCh:
					batch = append(batch, nextOp)
				default:
					break drainLoop
				}
			}

			s.commitBatch(batch)
			batch = batch[:0]

		case <-ticker.C:
			if len(batch) > 0 {
				s.commitBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *Store) drainMutations() {
	batch := make([]mutationOp, 0, maxBatchSize)
	for {
		select {
		case op := <-s.mutationCh:
			batch = append(batch, op)
			if len(batch) >= maxBatchSize {
				s.commitBatch(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				s.commitBatch(batch)
			}
			return
		}
	}
}

func (s *Store) commitBatch(batch []mutationOp) {
	if len(batch) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var walErr error
	failedIndex := -1

	s.st.Update(func(target *radix.Tree) {
		for i := range batch {
			if walErr != nil {
				continue
			}

			op := &batch[i]
			walErr = s.applyOperation(target, op)
			if walErr != nil {
				failedIndex = i
				continue
			}

			s.metrics.IncMutations()
			s.triggerCompactionIfNeeded()
		}
	})

	s.metrics.SetDomains(s.st.Len())
	s.metrics.SetMutationsPending(s.mutationsCount)
	if s.walFile != nil {
		if info, err := s.walFile.Stat(); err == nil {
			s.metrics.SetWALBytes(info.Size())
		}
	}

	var flushErr error
	if s.walWriter != nil {
		if err := s.walWriter.Flush(); err != nil {
			flushErr = fmt.Errorf("wal flush batch: %w", err)
		}
	}

	s.hub.NotifyFlush()

	for i := range batch {
		switch {
		case flushErr != nil:
			batch[i].done <- flushErr
		case failedIndex != -1 && i >= failedIndex:
			batch[i].done <- walErr
		default:
			batch[i].done <- nil
		}
	}
}

func (s *Store) applyOperation(target *radix.Tree, op *mutationOp) error {
	switch op.opType {
	case opUpsert:
		return s.applyUpsert(target, op)
	case opDelete:
		return s.applyDelete(target, op)
	default:
		return errors.New("unknown operation type")
	}
}

func (s *Store) applyUpsert(target *radix.Tree, op *mutationOp) error {
	if err := s.autoIncrementSOA(target, op.domain, op.records); err != nil {
		return err
	}
	if err := s.walWriter.AppendUpsert(op.domain, op.records); err != nil {
		return fmt.Errorf("wal append upsert: %w", err)
	}
	target.Upsert(op.domain, op.records)
	return nil
}

func (s *Store) applyDelete(target *radix.Tree, op *mutationOp) error {
	if err := s.autoIncrementSOA(target, op.domain, nil); err != nil {
		return err
	}
	if err := s.walWriter.AppendDelete(op.domain); err != nil {
		return fmt.Errorf("wal append delete: %w", err)
	}
	target.DeleteDomain(op.domain)
	return nil
}

func (s *Store) autoIncrementSOA(tree *radix.Tree, domain string, records dns.RRSets) error {
	for i, set := range records {
		if set.Type == dns.TypeSOA && len(set.RData) > 0 {
			records[i].RData[0] = incrementSOASerial(set.RData[0])
			return nil
		}
	}

	res := tree.Resolve(domain, dns.TypeSOA)
	apexDomain := findApexDomain(res, domain)
	if apexDomain == "" || apexDomain == domain {
		return nil
	}

	apexRecords, ok := tree.Get(apexDomain)
	if !ok {
		return nil
	}

	updatedRecords := apexRecords.Clone()
	for i, set := range updatedRecords {
		if set.Type == dns.TypeSOA && len(set.RData) > 0 {
			updatedRecords[i].RData[0] = incrementSOASerial(set.RData[0])
			if err := s.walWriter.AppendUpsert(apexDomain, updatedRecords); err != nil {
				return fmt.Errorf("wal append soa increment: %w", err)
			}
			tree.Upsert(apexDomain, updatedRecords)
			break
		}
	}
	return nil
}

func incrementSOASerial(rdata []byte) []byte {
	offset := skipDomainName(rdata, 0)
	if offset < 0 {
		return rdata
	}
	offset = skipDomainName(rdata, offset)
	if offset < 0 || offset+20 > len(rdata) {
		return rdata
	}

	serial := binary.BigEndian.Uint32(rdata[offset : offset+4])
	out := bytes.Clone(rdata)
	binary.BigEndian.PutUint32(out[offset:offset+4], serial+1)
	return out
}

func skipDomainName(data []byte, start int) int {
	curr := start
	for curr < len(data) {
		l := int(data[curr])
		if l == 0 {
			return curr + 1
		}
		// RFC 1035 §4.1.4: high two bits set (>= 0xC0) indicates a 2-byte compressed pointer.
		if l >= compressionPointerMask {
			return curr + 2
		}
		curr += 1 + l
	}
	return -1
}

func findApexDomain(res dns.Result, domain string) string {
	if res.HasAnswer() && res.Answer.Type == dns.TypeSOA {
		return domain
	}
	if res.HasAuthority() {
		return res.AuthorityName
	}
	return ""
}
