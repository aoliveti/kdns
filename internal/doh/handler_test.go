// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package doh

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/metrics"
)

type atomicResolver func(domain string, qType dns.Type) dns.Result

func (r atomicResolver) Resolve(domain string, qType dns.Type) dns.Result {
	return r(domain, qType)
}

func buildWireQuery(tb testing.TB, name string, qType dns.Type) []byte {
	tb.Helper()
	buf := make([]byte, 0, 12+len(name)+8)

	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	buf = append(buf, hdr[:]...)

	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				label := name[start:i]
				// #nosec G115
				buf = append(buf, byte(len(label)))
				buf = append(buf, label...)
			}
			start = i + 1
		}
	}
	buf = append(buf, 0)

	var qTypeClass [4]byte
	binary.BigEndian.PutUint16(qTypeClass[0:2], uint16(qType))
	binary.BigEndian.PutUint16(qTypeClass[2:4], uint16(dns.ClassIN))
	buf = append(buf, qTypeClass[:]...)

	return buf
}

func executeGet(tb testing.TB, srv *Server, target string) *httptest.ResponseRecorder {
	tb.Helper()
	req := httptest.NewRequestWithContext(tb.Context(), http.MethodGet, target, http.NoBody)
	req.Header.Set("Accept", contentTypeDoH)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestDoH_GET(t *testing.T) {
	t.Parallel()

	wireA, err := dns.PackRData(dns.TypeA, "1.2.3.4")
	require.NoError(t, err)

	resolver := atomicResolver(func(domain string, qType dns.Type) dns.Result {
		if domain == "example.com" && qType == dns.TypeA {
			return dns.Result{
				RCode: dns.RCodeSuccess,
				Answer: dns.RRSet{
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   300,
					RData: [][]byte{wireA},
				},
			}
		}
		return dns.Result{RCode: dns.RCodeNameError}
	})

	t.Run("ValidQuery_ReturnsAnswerAndCacheControl", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		queryWire := buildWireQuery(t, "example.com", dns.TypeA)
		dnsParam := base64.RawURLEncoding.EncodeToString(queryWire)

		rec := executeGet(t, srv, "/dns-query?dns="+dnsParam)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, contentTypeDoH, rec.Header().Get("Content-Type"))
		assert.Equal(t, "max-age=300", rec.Header().Get("Cache-Control"))

		var respMsg dns.Message
		require.NoError(t, respMsg.Unpack(rec.Body.Bytes()))
		assert.Equal(t, uint16(1), respMsg.Header.ANCount)
	})

	t.Run("NODATA_AAAAQueryReturnsNoError", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		queryWire := buildWireQuery(t, "example.com", dns.TypeAAAA)
		dnsParam := base64.RawURLEncoding.EncodeToString(queryWire)

		rec := executeGet(t, srv, "/dns-query?dns="+dnsParam)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, contentTypeDoH, rec.Header().Get("Content-Type"))

		var respMsg dns.Message
		require.NoError(t, respMsg.Unpack(rec.Body.Bytes()))
		assert.Equal(t, uint16(0), respMsg.Header.ANCount)
	})

	t.Run("NXDOMAIN_ReturnsNameError", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		queryWire := buildWireQuery(t, "nonexistent.example", dns.TypeTXT)
		dnsParam := base64.RawURLEncoding.EncodeToString(queryWire)

		rec := executeGet(t, srv, "/dns-query?dns="+dnsParam)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, contentTypeDoH, rec.Header().Get("Content-Type"))

		var respMsg dns.Message
		require.NoError(t, respMsg.Unpack(rec.Body.Bytes()))
		assert.Equal(t, dns.RCodeNameError, respMsg.Header.RCode())
	})

	t.Run("MissingDNSParam_ReturnsBadRequest", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		rec := executeGet(t, srv, "/dns-query")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("InvalidBase64_ReturnsBadRequest", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		rec := executeGet(t, srv, "/dns-query?dns=%%%invalid%%%")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("LivezProbe", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		rec := executeGet(t, srv, "/livez")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "ok\n", rec.Body.String())
	})
}

func TestDoH_POST(t *testing.T) {
	t.Parallel()

	wireA, err := dns.PackRData(dns.TypeA, "9.9.9.9")
	require.NoError(t, err)

	resolver := atomicResolver(func(domain string, qType dns.Type) dns.Result {
		if domain == "dns.quad9.net" && qType == dns.TypeA {
			return dns.Result{
				RCode: dns.RCodeSuccess,
				Answer: dns.RRSet{
					Type:  dns.TypeA,
					Class: dns.ClassIN,
					TTL:   60,
					RData: [][]byte{wireA},
				},
			}
		}
		return dns.Result{RCode: dns.RCodeNameError}
	})

	t.Run("ValidQuery_ReturnsAnswer", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		queryWire := buildWireQuery(t, "dns.quad9.net", dns.TypeA)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/dns-query", bytes.NewReader(queryWire))
		req.Header.Set("Content-Type", contentTypeDoH)

		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, contentTypeDoH, rec.Header().Get("Content-Type"))
		assert.Equal(t, "max-age=60", rec.Header().Get("Cache-Control"))

		var respMsg dns.Message
		require.NoError(t, respMsg.Unpack(rec.Body.Bytes()))
		assert.Equal(t, uint16(1), respMsg.Header.ANCount)
	})

	t.Run("UnsupportedContentType_Returns415", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		queryWire := buildWireQuery(t, "dns.quad9.net", dns.TypeA)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/dns-query", bytes.NewReader(queryWire))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
	})

	t.Run("EmptyBody_ReturnsBadRequest", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/dns-query", http.NoBody)
		req.Header.Set("Content-Type", contentTypeDoH)

		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("MalformedPayload_ReturnsBadRequest", func(t *testing.T) {
		t.Parallel()
		srv := New(resolver, WithAddress("127.0.0.1:0"))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/dns-query", bytes.NewReader([]byte{0x01, 0x02}))
		req.Header.Set("Content-Type", contentTypeDoH)

		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestDoH_EdgeCases(t *testing.T) {
	t.Parallel()

	srv := New(nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB", http.NoBody)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	resolver := atomicResolver(func(_ string, _ dns.Type) dns.Result {
		return dns.Result{RCode: dns.RCodeSuccess}
	})
	validSrv := New(resolver)

	// Unsupported Method (e.g. PUT)
	reqPut := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/dns-query", http.NoBody)
	recPut := httptest.NewRecorder()
	validSrv.Handler().ServeHTTP(recPut, reqPut)
	assert.Equal(t, http.StatusMethodNotAllowed, recPut.Code)

	// Base64 padding support
	queryWire := buildWireQuery(t, "example.com", dns.TypeA)
	paddedB64 := base64.URLEncoding.EncodeToString(queryWire)
	reqPadded := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/dns-query?dns="+paddedB64, http.NoBody)
	recPadded := httptest.NewRecorder()
	validSrv.Handler().ServeHTTP(recPadded, reqPadded)
	assert.Equal(t, http.StatusOK, recPadded.Code)
}

func TestDoH_MultipleOPT_FORMERR(t *testing.T) {
	t.Parallel()

	// Construct raw query payload containing 2 OPT records (RFC 6891 violation)
	payload := []byte{
		0x55, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	telemetry := metrics.New()
	dummyResolver := atomicResolver(func(_ string, _ dns.Type) dns.Result {
		return dns.Result{RCode: dns.RCodeSuccess}
	})
	srv := New(dummyResolver, WithMetrics(telemetry))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/dns-query", bytes.NewReader(payload))
	req.Header.Set("Content-Type", contentTypeDoH)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	// RFC 8484: must return HTTP 200 with DNS RCODE=FORMERR in payload
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, contentTypeDoH, rec.Header().Get("Content-Type"))

	var respMsg dns.Message
	require.NoError(t, respMsg.Unpack(rec.Body.Bytes()))
	assert.Equal(t, dns.RCodeFormatError, respMsg.Header.RCode())
}

func TestDoH_NegativeCachingAuthorityTTL(t *testing.T) {
	t.Parallel()

	wireSOA, err := dns.PackRData(dns.TypeSOA, "ns1.example.com. hostmaster.example.com. 2026010101 7200 3600 1209600 300")
	require.NoError(t, err)

	resolver := atomicResolver(func(_ string, _ dns.Type) dns.Result {
		return dns.Result{
			RCode: dns.RCodeNameError,
			Authority: dns.RRSet{
				Type:  dns.TypeSOA,
				Class: dns.ClassIN,
				TTL:   300,
				RData: [][]byte{wireSOA},
			},
		}
	})

	srv := New(resolver)
	queryWire := buildWireQuery(t, "nonexistent.example.com", dns.TypeA)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/dns-query", bytes.NewReader(queryWire))
	req.Header.Set("Content-Type", contentTypeDoH)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "max-age=300", rec.Header().Get("Cache-Control"))
}

func TestDoH_PayloadTooLarge(t *testing.T) {
	t.Parallel()

	dummyResolver := atomicResolver(func(_ string, _ dns.Type) dns.Result {
		return dns.Result{RCode: dns.RCodeSuccess}
	})
	srv := New(dummyResolver)
	largePayload := make([]byte, 65536+1) // > maxDoHBodySize (64 KB)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/dns-query", bytes.NewReader(largePayload))
	req.Header.Set("Content-Type", contentTypeDoH)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
