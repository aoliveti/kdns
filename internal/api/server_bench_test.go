// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

var benchLogger = slog.New(slog.DiscardHandler)

type benchViewer struct {
	records map[string]dns.RRSets
	keys    []string
}

func newBenchmarkViewer(b *testing.B, count int) *benchViewer {
	b.Helper()
	v := &benchViewer{
		records: make(map[string]dns.RRSets, count),
		keys:    make([]string, 0, count),
	}
	for i := range count {
		domain := fmt.Sprintf("host%d.example.com", i)
		wire, _ := dns.PackRData(dns.TypeA, fmt.Sprintf("192.0.2.%d", i%254+1))
		v.records[domain] = dns.RRSets{
			{
				Type:  dns.TypeA,
				Class: dns.ClassIN,
				TTL:   300,
				RData: [][]byte{wire},
			},
		}
		v.keys = append(v.keys, domain)
	}
	return v
}

func (s *benchViewer) Get(domain string) (dns.RRSets, bool) {
	r, ok := s.records[domain]
	return r, ok
}

func (s *benchViewer) Search(query string) iter.Seq2[string, dns.RRSets] {
	return func(yield func(string, dns.RRSets) bool) {
		for _, d := range s.keys {
			if strings.Contains(d, query) {
				if !yield(d, s.records[d]) {
					return
				}
			}
		}
	}
}

func (s *benchViewer) Seek(afterDomain string) iter.Seq2[string, dns.RRSets] {
	return func(yield func(string, dns.RRSets) bool) {
		for _, d := range s.keys {
			if d > afterDomain {
				if !yield(d, s.records[d]) {
					return
				}
			}
		}
	}
}

func (s *benchViewer) Walk() iter.Seq2[string, dns.RRSets] {
	return func(yield func(string, dns.RRSets) bool) {
		for _, d := range s.keys {
			if !yield(d, s.records[d]) {
				return
			}
		}
	}
}

type benchUpsertDeleter struct {
	records map[string]dns.RRSets
}

func newBenchmarkUpsertDeleter() *benchUpsertDeleter {
	return &benchUpsertDeleter{records: make(map[string]dns.RRSets)}
}

func (s *benchUpsertDeleter) Upsert(domain string, records dns.RRSets) error {
	s.records[domain] = records
	return nil
}

func (s *benchUpsertDeleter) DeleteDomain(domain string) error {
	delete(s.records, domain)
	return nil
}

const benchAPIToken = "bench-secret-token-12345"

func BenchmarkAPI_GetDomain(b *testing.B) {
	viewer := newBenchmarkViewer(b, 1000)
	srv := New(viewer, WithAPIToken(benchAPIToken), WithLogger(benchLogger))
	h := srv.Handler()

	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/v1/records/host500.example.com", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+benchAPIToken)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		rec.Body.Reset()
		h.ServeHTTP(rec, req)
	}
}

func BenchmarkAPI_ListRecords(b *testing.B) {
	viewer := newBenchmarkViewer(b, 1000)
	srv := New(viewer, WithAPIToken(benchAPIToken), WithLogger(benchLogger))
	h := srv.Handler()

	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/v1/records?limit=50", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+benchAPIToken)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		rec.Body.Reset()
		h.ServeHTTP(rec, req)
	}
}

func BenchmarkAPI_SearchRecords(b *testing.B) {
	viewer := newBenchmarkViewer(b, 1000)
	srv := New(viewer, WithAPIToken(benchAPIToken), WithLogger(benchLogger))
	h := srv.Handler()

	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/v1/records/search?q=host50", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+benchAPIToken)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		rec.Body.Reset()
		h.ServeHTTP(rec, req)
	}
}

func BenchmarkAPI_UpsertDomain(b *testing.B) {
	viewer := newBenchmarkViewer(b, 100)
	ud := newBenchmarkUpsertDeleter()
	srv := New(viewer, WithAPIToken(benchAPIToken), WithUpsertDeleter(ud), WithLogger(benchLogger))
	h := srv.Handler()

	payload := `{"records":[{"type":"A","ttl":300,"rdata":["1.2.3.4"]}]}`

	b.ReportAllocs()
	b.ResetTimer()

	i := 0
	for b.Loop() {
		target := fmt.Sprintf("/v1/records/bench%d.example.com", i)
		req := httptest.NewRequestWithContext(b.Context(), http.MethodPut, target, strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+benchAPIToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		i++
	}
}

func BenchmarkAPI_ExportZoneFile(b *testing.B) {
	viewer := newBenchmarkViewer(b, 1000)
	srv := New(viewer, WithAPIToken(benchAPIToken), WithLogger(benchLogger))
	h := srv.Handler()

	req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/v1/export/zonefile?zone=example.com", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+benchAPIToken)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		rec.Body.Reset()
		h.ServeHTTP(rec, req)
	}
}
