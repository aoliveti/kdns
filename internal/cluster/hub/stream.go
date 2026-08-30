// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hub

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
)

const streamBufSize = 32 * 1024

var streamBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, streamBufSize)
		return &buf
	},
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if s.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	f, err := s.store.OpenSnapshotReader()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()

	if checksum, chkErr := s.store.SnapshotChecksum(); chkErr == nil {
		w.Header().Set("X-Snapshot-Checksum", fmt.Sprintf("%08x", checksum))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		return
	}
	s.metrics.IncClusterSnapshotSent()
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if s.maxStreams > 0 && s.activeStreams.Load() >= int64(s.maxStreams) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	s.activeStreams.Add(1)
	defer s.activeStreams.Add(-1)

	s.metrics.IncClusterStream()
	defer s.metrics.DecClusterStream()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	offsetStr := r.URL.Query().Get("offset")
	offset, err := strconv.ParseInt(offsetStr, 10, 64)
	if err != nil || offset < 0 {
		http.Error(w, "Invalid offset", http.StatusBadRequest)
		return
	}

	if s.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	s.mu.Lock()
	startGen := s.gen
	s.mu.Unlock()

	f, fErr := s.store.OpenWALReader()
	if fErr != nil && !errors.Is(fErr, os.ErrNotExist) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	if f == nil && offset > 0 {
		http.Error(w, "Requested Range Not Satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	if f != nil {
		stat, statErr := f.Stat()
		if statErr != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if offset > stat.Size() {
			http.Error(w, "Requested Range Not Satisfiable", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if _, seekErr := f.Seek(offset, io.SeekStart); seekErr != nil {
			http.Error(w, "Requested Range Not Satisfiable", http.StatusRequestedRangeNotSatisfiable)
			return
		}
	}

	if checksum, chkErr := s.store.SnapshotChecksum(); chkErr == nil {
		w.Header().Set("X-Snapshot-Checksum", fmt.Sprintf("%08x", checksum))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	s.streamWALToClient(w, r, flusher, f, offset, startGen)
}

func (s *Server) streamWALToClient(w http.ResponseWriter, r *http.Request, flusher http.Flusher, f *os.File, offset int64, startGen uint64) {
	bufPtr := streamBufPool.Get().(*[]byte)
	defer streamBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-r.Context().Done():
			return
		default:
		}

		s.mu.Lock()
		if s.stopped || s.gen != startGen {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		if f == nil {
			s.mu.Lock()
			s.cond.Wait()
			stopped := s.stopped
			s.mu.Unlock()

			if stopped || r.Context().Err() != nil {
				return
			}

			var err error
			f, err = s.store.OpenWALReader()
			if err != nil {
				continue
			}
			if _, seekErr := f.Seek(offset, io.SeekStart); seekErr != nil {
				return
			}
		}

		n, err := f.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			flusher.Flush()
			offset += int64(n)
		}

		if err == nil {
			continue
		}
		
		if !errors.Is(err, io.EOF) {
			return
		}

		s.mu.Lock()
		if s.stopped || s.gen != startGen {
			s.mu.Unlock()
			return
		}

		if stat, statErr := f.Stat(); statErr == nil && stat.Size() > offset {
			s.mu.Unlock()
			continue
		}

		s.cond.Wait()
		stopped := s.stopped
		s.mu.Unlock()
		if stopped {
			return
		}
	}
}
