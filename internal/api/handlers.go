// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/aoliveti/kdns/internal/dns"
)

// listRecords handles paginated listing of domain records via cursor pagination.
func (s *Server) listRecords(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r.URL.Query().Get("limit"))
	after := r.URL.Query().Get("cursor")
	if after == "" {
		after = r.URL.Query().Get("after")
	}

	seq := s.viewer.Walk()
	if after != "" {
		seq = s.viewer.Seek(after)
	}

	domains := make([]DomainRecords, 0, limit)
	var nextCursor string
	var hasMore bool

	count := 0
	for domain, sets := range seq {
		if count == limit {
			hasMore = true
			break
		}
		domains = append(domains, formatDomain(domain, sets))
		nextCursor = domain
		count++
	}

	resp := ListResponse{
		Domains: domains,
		HasMore: hasMore,
	}
	if hasMore {
		resp.NextCursor = nextCursor
	}

	writeJSON(w, http.StatusOK, resp)
}

// searchRecords handles substring search over all domain names.
func (s *Server) searchRecords(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'q' is required")
		return
	}

	limit := parseLimit(r.URL.Query().Get("limit"))
	domains := make([]DomainRecords, 0, limit)

	for domain, sets := range s.viewer.Search(query) {
		if len(domains) >= limit {
			break
		}
		domains = append(domains, formatDomain(domain, sets))
	}

	writeJSON(w, http.StatusOK, SearchResponse{
		Query:   query,
		Domains: domains,
		Total:   len(domains),
	})
}

// getDomain retrieves raw resource records for a specific domain name.
func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) {
	domain, ok := parseDomain(w, r)
	if !ok {
		return
	}

	sets, found := s.viewer.Get(domain)
	if !found {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	writeJSON(w, http.StatusOK, formatDomain(domain, sets))
}

// upsertDomain creates or replaces the resource record sets for a domain.
func (s *Server) upsertDomain(w http.ResponseWriter, r *http.Request) {
	if !s.canUpdate() {
		writeError(w, http.StatusForbidden, "control plane is in read-only replica mode")
		return
	}

	domain, ok := parseDomain(w, r)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyBytes)
	var req UpsertRequest
	if decodeErr := json.UnmarshalRead(r.Body, &req, json.RejectUnknownMembers(true)); decodeErr != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](decodeErr); ok {
			writeError(w, http.StatusRequestEntityTooLarge, "request payload exceeds maximum allowed size")
			return
		}
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid json payload: %v", decodeErr))
		return
	}

	records, compileErr := req.RRSets()
	if compileErr != nil {
		writeError(w, http.StatusBadRequest, compileErr.Error())
		return
	}

	if saveErr := s.upsertDeleter.Upsert(domain, records); saveErr != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save records: %v", saveErr))
		return
	}

	writeJSON(w, http.StatusOK, formatDomain(domain, records))
}

// deleteDomain removes a domain and all its associated resource records.
func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	if !s.canUpdate() {
		writeError(w, http.StatusForbidden, "control plane is in read-only replica mode")
		return
	}

	domain, ok := parseDomain(w, r)
	if !ok {
		return
	}

	if _, found := s.viewer.Get(domain); !found {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	if delErr := s.upsertDeleter.DeleteDomain(domain); delErr != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete domain: %v", delErr))
		return
	}

	writeJSON(w, http.StatusOK, StatusResponse{
		Status:  "ok",
		Domain:  domain,
		Deleted: true,
	})
}

func parseDomain(w http.ResponseWriter, r *http.Request) (string, bool) {
	d := r.PathValue("domain")
	if d == "" {
		writeError(w, http.StatusBadRequest, "domain path parameter is required")
		return "", false
	}
	if d == "@" {
		return ".", true
	}
	canon, err := dns.ValidateDomain(d)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid domain %q: %v", d, err))
		return "", false
	}
	return canon, true
}

func parseLimit(val string) int {
	if val == "" {
		return defaultPageLimit
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return defaultPageLimit
	}
	if n > maxPageLimit {
		return maxPageLimit
	}
	return n
}

func extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}
