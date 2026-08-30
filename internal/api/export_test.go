// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"iter"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestAPI_ExportZoneFile(t *testing.T) {
	t.Parallel()

	records := map[string]dns.RRSets{
		"example.com": {
			dns.NewRRSet(dns.TypeSOA, 3600, "ns1.example.com. hostmaster.example.com. 2026082701 7200 3600 1209600 300"),
			dns.NewRRSet(dns.TypeNS, 3600, "ns1.example.com."),
			dns.NewRRSet(dns.TypeA, 3600, "192.0.2.1"),
		},
		"www.example.com": {
			dns.NewRRSet(dns.TypeA, 300, "192.0.2.10"),
		},
		"othercorp.com": {
			dns.NewRRSet(dns.TypeA, 3600, "198.51.100.1"),
		},
	}

	viewer := compositeViewer{
		Getter: atomicGetter(func(d string) (dns.RRSets, bool) {
			r, ok := records[d]
			return r, ok
		}),
		Walker: atomicScanner{
			walkFn: func() iter.Seq2[string, dns.RRSets] {
				return maps.All(records)
			},
		},
	}

	const validToken = "secret-test-token"
	srv := New(viewer, WithAPIToken(validToken))
	handler := srv.Handler()

	tests := []struct {
		name                 string
		path                 string
		authHeader           string
		expectedContentType  string
		expectedDisposition  string
		expectedBodyContains []string
		excludedBodyContains []string
		expectedStatus       int
	}{
		{
			name:           "unauthenticated request rejected",
			path:           "/v1/export/zonefile",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:                 "export entire database",
			path:                 "/v1/export/zonefile",
			authHeader:           "Bearer " + validToken,
			expectedStatus:       http.StatusOK,
			expectedContentType:  "text/dns; charset=utf-8",
			expectedDisposition:  `inline; filename="kdns.zone"`,
			expectedBodyContains: []string{"example.com.", "192.0.2.1", "othercorp.com.", "198.51.100.1"},
		},
		{
			name:                 "export filtered zone example.com",
			path:                 "/v1/export/zonefile?zone=example.com",
			authHeader:           "Bearer " + validToken,
			expectedStatus:       http.StatusOK,
			expectedContentType:  "text/dns; charset=utf-8",
			expectedDisposition:  `inline; filename="example.com.zone"`,
			expectedBodyContains: []string{"$ORIGIN example.com.", "192.0.2.1", "www.example.com."},
			excludedBodyContains: []string{"othercorp.com.", "198.51.100.1"},
		},
		{
			name:                 "export filtered zone othercorp.com",
			path:                 "/v1/export/zonefile?zone=othercorp.com.",
			authHeader:           "Bearer " + validToken,
			expectedStatus:       http.StatusOK,
			expectedContentType:  "text/dns; charset=utf-8",
			expectedDisposition:  `inline; filename="othercorp.com.zone"`,
			expectedBodyContains: []string{"$ORIGIN othercorp.com.", "198.51.100.1"},
			excludedBodyContains: []string{"example.com.", "192.0.2.1"},
		},
		{
			name:                 "export non-existent zone returns 404",
			path:                 "/v1/export/zonefile?zone=nonexistent.invalid",
			authHeader:           "Bearer " + validToken,
			expectedStatus:       http.StatusNotFound,
			expectedContentType:  "application/json; charset=utf-8",
			expectedBodyContains: []string{"zone not found"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, http.NoBody)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.expectedStatus, rec.Code)
			if tc.expectedContentType != "" {
				assert.Equal(t, tc.expectedContentType, rec.Header().Get("Content-Type"))
			}
			if tc.expectedDisposition != "" {
				assert.Equal(t, tc.expectedDisposition, rec.Header().Get("Content-Disposition"))
			}
			body := rec.Body.String()
			for _, exp := range tc.expectedBodyContains {
				assert.Truef(t, strings.Contains(body, exp), "body should contain %q, got:\n%s", exp, body)
			}
			for _, excl := range tc.excludedBodyContains {
				assert.Falsef(t, strings.Contains(body, excl), "body should NOT contain %q", excl)
			}
		})
	}
}

func TestAPI_ExportZoneFileReadOnlyReplica(t *testing.T) {
	t.Parallel()

	records := map[string]dns.RRSets{
		"example.com": {
			dns.NewRRSet(dns.TypeA, 3600, "192.0.2.1"),
		},
	}

	viewer := compositeViewer{
		Getter: atomicGetter(func(d string) (dns.RRSets, bool) {
			r, ok := records[d]
			return r, ok
		}),
		Walker: atomicScanner{
			walkFn: func() iter.Seq2[string, dns.RRSets] {
				return maps.All(records)
			},
		},
	}

	const replicaToken = "replica-secret"
	// Read-only replica server (no WithUpsertDeleter)
	srv := New(viewer, WithAPIToken(replicaToken))
	handler := srv.Handler()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/export/zonefile", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+replicaToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/dns; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "192.0.2.1")
}
