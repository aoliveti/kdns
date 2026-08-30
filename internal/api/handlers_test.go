// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"errors"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

const defaultTestToken = "test-secret-token-12345"

func newTestServer(viewer Viewer, opts ...Option) *Server {
	return New(viewer, append([]Option{WithAPIToken(defaultTestToken)}, opts...)...)
}

func executeAuthorizedRequest(tb testing.TB, srv *Server, method, path string, body io.Reader) *httptest.ResponseRecorder {
	tb.Helper()
	var headers map[string]string
	if srv.apiToken != "" {
		headers = map[string]string{"Authorization": "Bearer " + srv.apiToken}
	}
	return executeRequest(tb, srv, method, path, body, headers)
}

func TestServer_ListRecords(t *testing.T) {
	t.Parallel()

	t.Run("DefaultPagination", func(t *testing.T) {
		scanner := atomicScanner{
			walkFn: func() iter.Seq2[string, dns.RRSets] {
				return func(yield func(string, dns.RRSets) bool) {
					yield("a.example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "192.0.2.1")})
					yield("b.example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "192.0.2.2")})
					yield("c.example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "192.0.2.3")})
				}
			},
		}
		srv := newTestServer(compositeViewer{Walker: scanner})
		rec := executeGet(t, srv, "/v1/records")
		assert.Equal(t, http.StatusOK, rec.Code)

		resp := decodeJSON[ListResponse](t, rec)
		assert.Len(t, resp.Domains, 3)
		assert.False(t, resp.HasMore)
		assert.Empty(t, resp.NextCursor)
	})

	t.Run("EmptyStore", func(t *testing.T) {
		srv := newTestServer(compositeViewer{})
		rec := executeGet(t, srv, "/v1/records")
		assert.Equal(t, http.StatusOK, rec.Code)

		resp := decodeJSON[ListResponse](t, rec)
		assert.Empty(t, resp.Domains)
		assert.False(t, resp.HasMore)
	})

	t.Run("WithLimitAndCursor", func(t *testing.T) {
		scanner := atomicScanner{
			walkFn: func() iter.Seq2[string, dns.RRSets] {
				return func(yield func(string, dns.RRSets) bool) {
					yield("a.example.com", nil)
					yield("b.example.com", nil)
					yield("c.example.com", nil)
				}
			},
			seekFn: func(after string) iter.Seq2[string, dns.RRSets] {
				return func(yield func(string, dns.RRSets) bool) {
					if after == "b.example.com" {
						yield("c.example.com", nil)
					}
				}
			},
		}
		srv := newTestServer(compositeViewer{Walker: scanner, Seeker: scanner})

		rec1 := executeGet(t, srv, "/v1/records?limit=2")
		assert.Equal(t, http.StatusOK, rec1.Code)
		resp1 := decodeJSON[ListResponse](t, rec1)
		assert.Len(t, resp1.Domains, 2)
		assert.True(t, resp1.HasMore)
		assert.Equal(t, "b.example.com", resp1.NextCursor)

		rec2 := executeGet(t, srv, "/v1/records?limit=2&after="+resp1.NextCursor)
		assert.Equal(t, http.StatusOK, rec2.Code)
		resp2 := decodeJSON[ListResponse](t, rec2)
		assert.Len(t, resp2.Domains, 1)
		assert.Equal(t, "c.example.com", resp2.Domains[0].Domain)

		recCursor := executeGet(t, srv, "/v1/records?limit=2&cursor="+resp1.NextCursor)
		assert.Equal(t, http.StatusOK, recCursor.Code)
		respCursor := decodeJSON[ListResponse](t, recCursor)
		assert.Equal(t, resp2.Domains, respCursor.Domains)
	})
}

func TestServer_SearchRecords(t *testing.T) {
	t.Parallel()

	t.Run("FoundMatch", func(t *testing.T) {
		searcher := atomicSearcher(func(q string) iter.Seq2[string, dns.RRSets] {
			return func(yield func(string, dns.RRSets) bool) {
				if q == "b.example" {
					yield("b.example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "192.0.2.2")})
				}
			}
		})
		srv := newTestServer(compositeViewer{Searcher: searcher})
		rec := executeGet(t, srv, "/v1/records/search?q=b.example")
		assert.Equal(t, http.StatusOK, rec.Code)

		resp := decodeJSON[SearchResponse](t, rec)
		assert.Equal(t, "b.example", resp.Query)
		require.Len(t, resp.Domains, 1)
		assert.Equal(t, "b.example.com", resp.Domains[0].Domain)
		assert.Equal(t, 1, resp.Total)
	})

	t.Run("NoMatch", func(t *testing.T) {
		srv := newTestServer(compositeViewer{})
		rec := executeGet(t, srv, "/v1/records/search?q=nonexistent")
		assert.Equal(t, http.StatusOK, rec.Code)

		resp := decodeJSON[SearchResponse](t, rec)
		assert.Equal(t, "nonexistent", resp.Query)
		assert.Empty(t, resp.Domains)
		assert.Zero(t, resp.Total)
	})

	t.Run("MissingQueryParamReturns400", func(t *testing.T) {
		srv := newTestServer(compositeViewer{})
		rec := executeGet(t, srv, "/v1/records/search")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		errResp := decodeJSON[ErrorResponse](t, rec)
		assert.Contains(t, errResp.Error, "query parameter 'q' is required")
	})
}

func TestServer_GetDomain(t *testing.T) {
	t.Parallel()

	t.Run("Found", func(t *testing.T) {
		getter := atomicGetter(func(d string) (dns.RRSets, bool) {
			if d == "a.example.com" {
				return dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "192.0.2.1")}, true
			}
			return nil, false
		})
		srv := newTestServer(compositeViewer{Getter: getter})
		rec := executeGet(t, srv, "/v1/records/a.example.com")
		assert.Equal(t, http.StatusOK, rec.Code)

		resp := decodeJSON[DomainRecords](t, rec)
		assert.Equal(t, "a.example.com", resp.Domain)
		require.Len(t, resp.Records, 1)
		assert.Equal(t, "A", resp.Records[0].Type)
		assert.Equal(t, []string{"192.0.2.1"}, resp.Records[0].RData)
	})

	t.Run("RootApexViaAtSign", func(t *testing.T) {
		getter := atomicGetter(func(d string) (dns.RRSets, bool) {
			if d == "." {
				return dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "198.51.100.1")}, true
			}
			return nil, false
		})
		srv := newTestServer(compositeViewer{Getter: getter})
		rec := executeGet(t, srv, "/v1/records/@")
		assert.Equal(t, http.StatusOK, rec.Code)

		resp := decodeJSON[DomainRecords](t, rec)
		assert.Equal(t, ".", resp.Domain)
		require.Len(t, resp.Records, 1)
	})

	t.Run("NotFound", func(t *testing.T) {
		getter := atomicGetter(func(string) (dns.RRSets, bool) { return nil, false })
		srv := newTestServer(compositeViewer{Getter: getter})
		rec := executeGet(t, srv, "/v1/records/nonexistent.com")
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("InvalidDomainReturns400", func(t *testing.T) {
		srv := newTestServer(compositeViewer{})
		rec := executeGet(t, srv, "/v1/records/bad..example.com")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestServer_UpsertDomain(t *testing.T) {
	t.Parallel()

	t.Run("ValidPUT", func(t *testing.T) {
		var savedDomain string
		var savedSets dns.RRSets
		ud := atomicUpsertDeleter{
			upsertFn: func(domain string, records dns.RRSets) error {
				savedDomain = domain
				savedSets = records
				return nil
			},
		}
		srv := newTestServer(compositeViewer{}, WithUpsertDeleter(ud))
		payload := `{"records":[{"type":"A","ttl":300,"rdata":["10.0.0.1"]},{"type":"TXT","ttl":3600,"rdata":["v=spf1 -all"]}]}`
		rec := executeAuthorizedRequest(t, srv, http.MethodPut, "/v1/records/new.example.com", strings.NewReader(payload))
		assert.Equal(t, http.StatusOK, rec.Code)

		resp := decodeJSON[DomainRecords](t, rec)
		assert.Equal(t, "new.example.com", resp.Domain)
		assert.Len(t, resp.Records, 2)
		assert.Equal(t, "new.example.com", savedDomain)
		assert.Len(t, savedSets, 2)
	})

	t.Run("ValidPOST", func(t *testing.T) {
		var savedDomain string
		ud := atomicUpsertDeleter{
			upsertFn: func(domain string, _ dns.RRSets) error {
				savedDomain = domain
				return nil
			},
		}
		srv := newTestServer(compositeViewer{}, WithUpsertDeleter(ud))
		payload := `{"records":[{"type":"A","ttl":300,"rdata":["10.0.0.1"]}]}`
		rec := executeAuthorizedRequest(t, srv, http.MethodPost, "/v1/records/post.example.com", strings.NewReader(payload))
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "post.example.com", savedDomain)
	})

	t.Run("ReadOnlyReplicaModeReturns403", func(t *testing.T) {
		srv := newTestServer(compositeViewer{}) // upsertDeleter omitted -> read-only replica
		payload := `{"records":[{"type":"A","ttl":300,"rdata":["10.0.0.1"]}]}`
		rec := executeAuthorizedRequest(t, srv, http.MethodPut, "/v1/records/new.example.com", strings.NewReader(payload))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		errResp := decodeJSON[ErrorResponse](t, rec)
		assert.Contains(t, errResp.Error, "read-only replica mode")
	})

	t.Run("ValidationErrorsTable", func(t *testing.T) {
		ud := atomicUpsertDeleter{upsertFn: func(string, dns.RRSets) error { return nil }}
		srv := newTestServer(compositeViewer{}, WithUpsertDeleter(ud))
		tests := []struct {
			name       string
			domain     string
			payload    string
			wantErrMsg string
		}{
			{
				name:       "EmptyRecords",
				domain:     "empty.com",
				payload:    `{"records":[]}`,
				wantErrMsg: "records cannot be empty",
			},
			{
				name:       "InvalidDomainInPath",
				domain:     "bad..domain.com",
				payload:    `{"records":[{"type":"A","ttl":300,"rdata":["10.0.0.1"]}]}`,
				wantErrMsg: "invalid domain",
			},
			{
				name:       "CNAMEAndOtherRecordsCoexistence",
				domain:     "cname-clash.com",
				payload:    `{"records":[{"type":"CNAME","ttl":300,"rdata":["target.com"]},{"type":"A","ttl":300,"rdata":["1.2.3.4"]}]}`,
				wantErrMsg: "cname record cannot coexist",
			},
			{
				name:       "MultipleCNAMETargets",
				domain:     "multi-cname.com",
				payload:    `{"records":[{"type":"CNAME","ttl":300,"rdata":["a.com","b.com"]}]}`,
				wantErrMsg: "cname record cannot have multiple target records",
			},
			{
				name:       "MultipleSOARecords",
				domain:     "multi-soa.com",
				payload:    `{"records":[{"type":"SOA","ttl":300,"rdata":["ns1 admin 1 7200 3600 1209600 300","ns2 admin 1 7200 3600 1209600 300"]}]}`,
				wantErrMsg: "cannot have multiple soa records",
			},
			{
				name:       "EmptyRDataInRecord",
				domain:     "empty-rdata.com",
				payload:    `{"records":[{"type":"A","ttl":300,"rdata":[]}]}`,
				wantErrMsg: "must contain at least one rdata element",
			},
			{
				name:       "PseudoTypeANY",
				domain:     "pseudo-any.com",
				payload:    `{"records":[{"type":"ANY","ttl":300,"rdata":["1.2.3.4"]}]}`,
				wantErrMsg: "pseudo-type ANY cannot be inserted",
			},
			{
				name:       "PseudoTypeOPT",
				domain:     "pseudo-opt.com",
				payload:    `{"records":[{"type":"OPT","ttl":300,"rdata":["1.2.3.4"]}]}`,
				wantErrMsg: "pseudo-type OPT cannot be inserted",
			},
			{
				name:       "TTLLimitExceeded",
				domain:     "bigttl.com",
				payload:    `{"records":[{"type":"A","ttl":3000000000,"rdata":["1.2.3.4"]}]}`,
				wantErrMsg: "ttl 3000000000 exceeds RFC 2181 maximum",
			},
			{
				name:       "MalformedJSON",
				domain:     "badjson.com",
				payload:    `{not valid json`,
				wantErrMsg: "invalid json payload",
			},
			{
				name:       "UnknownRecordType",
				domain:     "unknown.com",
				payload:    `{"records":[{"type":"NONEXISTENT","ttl":300,"rdata":["1.2.3.4"]}]}`,
				wantErrMsg: "invalid record type",
			},
			{
				name:       "InvalidRDataFormat",
				domain:     "badip.com",
				payload:    `{"records":[{"type":"A","ttl":300,"rdata":["999.999.999.999"]}]}`,
				wantErrMsg: "invalid rdata",
			},
			{
				name:       "DuplicateRecordType",
				domain:     "duptype.com",
				payload:    `{"records":[{"type":"A","ttl":300,"rdata":["1.1.1.1"]},{"type":"A","ttl":300,"rdata":["1.1.1.2"]}]}`,
				wantErrMsg: "duplicate record type A",
			},
			{
				name:       "UnknownJSONField",
				domain:     "unknownfield.com",
				payload:    `{"records":[{"type":"A","ttl":300,"rdata":["1.1.1.1"]}],"typo_field":123}`,
				wantErrMsg: "invalid json payload",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rec := executeAuthorizedRequest(t, srv, http.MethodPut, "/v1/records/"+tt.domain, strings.NewReader(tt.payload))
				assert.Equal(t, http.StatusBadRequest, rec.Code)
				errResp := decodeJSON[ErrorResponse](t, rec)
				assert.Contains(t, errResp.Error, tt.wantErrMsg)
			})
		}
	})
}

func TestServer_DeleteDomain(t *testing.T) {
	t.Parallel()

	t.Run("Found", func(t *testing.T) {
		var deletedDomain string
		getter := atomicGetter(func(d string) (dns.RRSets, bool) {
			if d == "a.example.com" {
				return dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "192.0.2.1")}, true
			}
			return nil, false
		})
		ud := atomicUpsertDeleter{
			deleteFn: func(d string) error {
				deletedDomain = d
				return nil
			},
		}
		srv := newTestServer(compositeViewer{Getter: getter}, WithUpsertDeleter(ud))
		rec := executeAuthorizedRequest(t, srv, http.MethodDelete, "/v1/records/a.example.com", nil)
		assert.Equal(t, http.StatusOK, rec.Code)

		resp := decodeJSON[StatusResponse](t, rec)
		assert.Equal(t, "ok", resp.Status)
		assert.Equal(t, "a.example.com", resp.Domain)
		assert.True(t, resp.Deleted)
		assert.Equal(t, "a.example.com", deletedDomain)
	})

	t.Run("NotFound", func(t *testing.T) {
		getter := atomicGetter(func(string) (dns.RRSets, bool) { return nil, false })
		ud := atomicUpsertDeleter{deleteFn: func(string) error { return nil }}
		srv := newTestServer(compositeViewer{Getter: getter}, WithUpsertDeleter(ud))
		rec := executeAuthorizedRequest(t, srv, http.MethodDelete, "/v1/records/alreadydeleted.com", nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("ReadOnlyReplicaModeReturns403", func(t *testing.T) {
		srv := newTestServer(compositeViewer{}) // upsertDeleter omitted -> read-only replica
		rec := executeAuthorizedRequest(t, srv, http.MethodDelete, "/v1/records/a.example.com", nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		errResp := decodeJSON[ErrorResponse](t, rec)
		assert.Contains(t, errResp.Error, "read-only replica mode")
	})

	t.Run("InvalidDomainReturns400", func(t *testing.T) {
		srv := newTestServer(compositeViewer{}, WithUpsertDeleter(atomicUpsertDeleter{}))
		rec := executeAuthorizedRequest(t, srv, http.MethodDelete, "/v1/records/bad..domain.com", nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestServer_StorageErrors(t *testing.T) {
	t.Parallel()

	t.Run("UpsertStorageFailureReturns500", func(t *testing.T) {
		ud := atomicUpsertDeleter{
			upsertFn: func(_ string, _ dns.RRSets) error { return errors.New("wal write error") },
		}
		srv := newTestServer(compositeViewer{}, WithUpsertDeleter(ud))
		rec := executeAuthorizedRequest(t, srv, http.MethodPut, "/v1/records/err.com", strings.NewReader(`{"records":[{"type":"A","ttl":300,"rdata":["1.1.1.1"]}]}`))
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		errResp := decodeJSON[ErrorResponse](t, rec)
		assert.Contains(t, errResp.Error, "wal write error")
	})

	t.Run("DeleteStorageFailureReturns500", func(t *testing.T) {
		getter := atomicGetter(func(string) (dns.RRSets, bool) {
			return dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "1.1.1.1")}, true
		})
		ud := atomicUpsertDeleter{
			deleteFn: func(_ string) error { return errors.New("wal delete error") },
		}
		srv := newTestServer(compositeViewer{Getter: getter}, WithUpsertDeleter(ud))
		rec := executeAuthorizedRequest(t, srv, http.MethodDelete, "/v1/records/err.com", nil)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		errResp := decodeJSON[ErrorResponse](t, rec)
		assert.Contains(t, errResp.Error, "wal delete error")
	})
}

func TestServer_Helpers(t *testing.T) {
	t.Parallel()

	t.Run("ParseLimit", func(t *testing.T) {
		assert.Equal(t, defaultPageLimit, parseLimit(""))
		assert.Equal(t, defaultPageLimit, parseLimit("0"))
		assert.Equal(t, defaultPageLimit, parseLimit("-10"))
		assert.Equal(t, defaultPageLimit, parseLimit("not-a-number"))
		assert.Equal(t, 25, parseLimit("25"))
		assert.Equal(t, maxPageLimit, parseLimit("50000"))
	})

	t.Run("ExtractToken", func(t *testing.T) {
		reqBearer := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		reqBearer.Header.Set("Authorization", "Bearer secret-api-token-1234")
		assert.Equal(t, "secret-api-token-1234", extractToken(reqBearer))

		reqKey := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		reqKey.Header.Set("X-API-Key", "apikey456")
		assert.Equal(t, "apikey456", extractToken(reqKey))

		reqNone := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		assert.Empty(t, extractToken(reqNone))
	})
}

type mockSyncStatusProvider struct {
	status int64
}

func (m mockSyncStatusProvider) WriteTo(_ io.Writer) (int64, error) { return 0, nil }
func (m mockSyncStatusProvider) ReplicaSyncStatus() int64           { return m.status }

func TestServer_KubernetesProbes(t *testing.T) {
	t.Parallel()

	t.Run("LivezReturnsOK", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(compositeViewer{})
		rec := executeGet(t, srv, "/livez")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "ok")
	})

	t.Run("StartupzReturnsOK", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(compositeViewer{})
		rec := executeGet(t, srv, "/startupz")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "ok")
	})

	t.Run("ReadyzStandaloneReturnsOK", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(compositeViewer{}, WithUpsertDeleter(atomicUpsertDeleter{}))
		rec := executeGet(t, srv, "/readyz")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "ok")
	})

	t.Run("ReadyzReplicaSyncingReturns503", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(compositeViewer{}, WithMetrics(mockSyncStatusProvider{status: 0}))
		rec := executeGet(t, srv, "/readyz")
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "syncing")
	})

	t.Run("ReadyzReplicaSyncedReturns200", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(compositeViewer{}, WithMetrics(mockSyncStatusProvider{status: 1}))
		rec := executeGet(t, srv, "/readyz")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "ok")
	})
}
