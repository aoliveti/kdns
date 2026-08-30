// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/metrics"
)

// atomicGetter adapts a function to the Getter interface.
type atomicGetter func(string) (dns.RRSets, bool)

func (fn atomicGetter) Get(domain string) (dns.RRSets, bool) {
	if fn != nil {
		return fn(domain)
	}
	return nil, false
}

// atomicUpsertDeleter implements the UpsertDeleter interface using function fields.
type atomicUpsertDeleter struct {
	upsertFn func(string, dns.RRSets) error
	deleteFn func(string) error
}

func (w atomicUpsertDeleter) Upsert(domain string, records dns.RRSets) error {
	if w.upsertFn != nil {
		return w.upsertFn(domain, records)
	}
	return nil
}

func (w atomicUpsertDeleter) DeleteDomain(domain string) error {
	if w.deleteFn != nil {
		return w.deleteFn(domain)
	}
	return nil
}

// atomicScanner implements Seeker and Walker interfaces using function fields.
type atomicScanner struct {
	seekFn func(string) iter.Seq2[string, dns.RRSets]
	walkFn func() iter.Seq2[string, dns.RRSets]
}

func (s atomicScanner) Seek(afterDomain string) iter.Seq2[string, dns.RRSets] {
	if s.seekFn != nil {
		return s.seekFn(afterDomain)
	}
	return func(func(string, dns.RRSets) bool) {}
}

func (s atomicScanner) Walk() iter.Seq2[string, dns.RRSets] {
	if s.walkFn != nil {
		return s.walkFn()
	}
	return func(func(string, dns.RRSets) bool) {}
}

// atomicSearcher adapts a function to the Searcher interface.
type atomicSearcher func(string) iter.Seq2[string, dns.RRSets]

func (fn atomicSearcher) Search(query string) iter.Seq2[string, dns.RRSets] {
	if fn != nil {
		return fn(query)
	}
	return func(func(string, dns.RRSets) bool) {}
}

// compositeViewer composes individual atomic read interfaces into a full Viewer.
type compositeViewer struct {
	Getter
	Seeker
	Walker
	Searcher
}

func (c compositeViewer) Get(domain string) (dns.RRSets, bool) {
	if c.Getter != nil {
		return c.Getter.Get(domain)
	}
	return nil, false
}

func (c compositeViewer) Seek(afterDomain string) iter.Seq2[string, dns.RRSets] {
	if c.Seeker != nil {
		return c.Seeker.Seek(afterDomain)
	}
	return func(func(string, dns.RRSets) bool) {}
}

func (c compositeViewer) Walk() iter.Seq2[string, dns.RRSets] {
	if c.Walker != nil {
		return c.Walker.Walk()
	}
	return func(func(string, dns.RRSets) bool) {}
}

func (c compositeViewer) Search(query string) iter.Seq2[string, dns.RRSets] {
	if c.Searcher != nil {
		return c.Searcher.Search(query)
	}
	return func(func(string, dns.RRSets) bool) {}
}

var (
	_ Getter        = atomicGetter(nil)
	_ UpsertDeleter = atomicUpsertDeleter{}
	_ Seeker        = atomicScanner{}
	_ Walker        = atomicScanner{}
	_ Viewer        = compositeViewer{}
)

type mockWriterTo struct {
	err error
}

func (m *mockWriterTo) WriteTo(w io.Writer) (int64, error) {
	if m.err != nil {
		return 0, m.err
	}
	n, err := w.Write([]byte("kdns_queries_total 42\n"))
	return int64(n), err
}

func executeGet(tb testing.TB, srv *Server, path string) *httptest.ResponseRecorder {
	var headers map[string]string
	if srv.apiToken != "" {
		headers = map[string]string{"Authorization": "Bearer " + srv.apiToken}
	}
	return executeRequest(tb, srv, http.MethodGet, path, nil, headers)
}

func executeRequest(tb testing.TB, srv *Server, method, path string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	tb.Helper()
	if body == nil {
		body = http.NoBody
	}
	req := httptest.NewRequestWithContext(tb.Context(), method, path, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeJSON[T any](tb testing.TB, rec *httptest.ResponseRecorder) T {
	tb.Helper()
	assert.Equal(tb, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	var out T
	require.NoError(tb, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

func TestServer_Observability(t *testing.T) {
	t.Parallel()

	t.Run("Livez", func(t *testing.T) {
		srv := New(compositeViewer{})
		rec := executeGet(t, srv, "/livez")

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
		assert.Equal(t, "ok\n", rec.Body.String())
	})

	t.Run("Startupz", func(t *testing.T) {
		srv := New(compositeViewer{})
		rec := executeGet(t, srv, "/startupz")

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
		assert.Equal(t, "ok\n", rec.Body.String())
	})

	t.Run("Readyz", func(t *testing.T) {
		srv := New(compositeViewer{})
		rec := executeGet(t, srv, "/readyz")

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
		assert.Equal(t, "ok\n", rec.Body.String())
	})

	t.Run("Start_NilViewerReturnsError", func(t *testing.T) {
		srv := New(nil)
		err := srv.Start(t.Context())
		require.ErrorIs(t, err, ErrNilViewer)
	})

	t.Run("Metrics_LiveExport", func(t *testing.T) {
		m := metrics.New(metrics.WithBuildInfo("1.0.0", "test", "today"))
		m.IncQueriesUDP()
		m.SetDomains(50)

		srv := New(compositeViewer{}, WithMetrics(m))
		rec := executeGet(t, srv, "/metrics")

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", rec.Header().Get("Content-Type"))

		out := rec.Body.String()
		assert.Contains(t, out, `kdns_queries_total{proto="udp"} 1`)
		assert.Contains(t, out, "kdns_domains_total 50")
	})

	t.Run("Metrics_WriterErrorLogged", func(t *testing.T) {
		srv := New(compositeViewer{}, WithMetrics(&mockWriterTo{err: errors.New("exporter error")}))
		rec := executeGet(t, srv, "/metrics")

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Metrics_NilExporter", func(t *testing.T) {
		srv := New(compositeViewer{})
		rec := executeGet(t, srv, "/metrics")

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Body.String())
	})
}

func TestServer_Middleware(t *testing.T) {
	t.Parallel()

	srv := New(compositeViewer{}, WithAPIToken("secret-api-token-1234"))

	t.Run("Auth_MissingTokenReturns401", func(t *testing.T) {
		rec := executeRequest(t, srv, http.MethodGet, "/v1/records", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		errResp := decodeJSON[ErrorResponse](t, rec)
		assert.Equal(t, "unauthorized", errResp.Error)
	})

	t.Run("Auth_InvalidTokenReturns401", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer wrong-token"}
		rec := executeRequest(t, srv, http.MethodGet, "/v1/records", nil, headers)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Auth_ValidTokenSucceeds", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer secret-api-token-1234"}
		rec := executeRequest(t, srv, http.MethodGet, "/v1/records", nil, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Auth_LivezUnprotected", func(t *testing.T) {
		rec := executeGet(t, srv, "/livez")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Auth_ReadyzUnprotected", func(t *testing.T) {
		rec := executeGet(t, srv, "/readyz")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Auth_StartupzUnprotected", func(t *testing.T) {
		rec := executeGet(t, srv, "/startupz")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("CORS_OptionsPreflight", func(t *testing.T) {
		rec := executeRequest(t, srv, http.MethodOptions, "/v1/records/a.example.com", nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "PUT")
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	})

	t.Run("CORS_CustomOrigin", func(t *testing.T) {
		customSrv := New(compositeViewer{}, WithCORSOrigin("https://dashboard.example.com"))
		rec := executeRequest(t, customSrv, http.MethodOptions, "/v1/records/a.example.com", nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://dashboard.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("CORS_Disabled", func(t *testing.T) {
		disabledSrv := New(compositeViewer{}, WithoutCORS())
		rec := executeRequest(t, disabledSrv, http.MethodGet, "/livez", nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("SecurityHeaders_PresentOnResponses", func(t *testing.T) {
		rec := executeGet(t, srv, "/livez")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	})
}

func TestServer_LifecycleAndLimits(t *testing.T) {
	t.Parallel()

	t.Run("StartAndGracefulShutdown", func(t *testing.T) {
		srv := New(compositeViewer{}, WithAddress("127.0.0.1:0"))
		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Start(ctx)
		}()

		time.Sleep(50 * time.Millisecond)

		cancel()

		select {
		case err := <-errCh:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for HTTP server shutdown")
		}
	})

	t.Run("SecurityTimeoutsConfigured", func(t *testing.T) {
		srv := New(compositeViewer{})
		assert.Greater(t, srv.httpServer.ReadHeaderTimeout, time.Duration(0), "ReadHeaderTimeout must be positive to mitigate Slowloris")
		assert.Greater(t, srv.httpServer.ReadTimeout, time.Duration(0), "ReadTimeout must be positive")
		assert.Equal(t, time.Duration(0), srv.httpServer.WriteTimeout, "WriteTimeout must be 0 for streaming zone exports")
		assert.Greater(t, srv.httpServer.IdleTimeout, time.Duration(0), "IdleTimeout must be positive")
		assert.Equal(t, defaultMaxHeaderBytes, srv.httpServer.MaxHeaderBytes, "MaxHeaderBytes must be configured")
	})

	t.Run("MaxBodySizeEnforced", func(t *testing.T) {
		ud := atomicUpsertDeleter{upsertFn: func(string, dns.RRSets) error { return nil }}
		srv := New(compositeViewer{}, WithAPIToken("secret-api-token-1234"), WithUpsertDeleter(ud), WithMaxBodyBytes(1024))

		// Construct an oversized payload exceeding 1024 bytes
		oversized := `{"records":[{"type":"TXT","ttl":300,"rdata":["` + strings.Repeat("a", 2048) + `"]}]}`
		headers := map[string]string{"Authorization": "Bearer secret-api-token-1234"}
		rec := executeRequest(t, srv, http.MethodPost, "/v1/records/overflow.com", strings.NewReader(oversized), headers)

		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		body := decodeJSON[ErrorResponse](t, rec)
		assert.Contains(t, body.Error, "exceeds maximum allowed size")
	})

	t.Run("Capabilities", func(t *testing.T) {
		srv1 := New(compositeViewer{})
		assert.False(t, srv1.canUpdate())

		srv2 := New(compositeViewer{}, WithUpsertDeleter(atomicUpsertDeleter{}), WithAPIToken("tok"))
		assert.True(t, srv2.canUpdate())
	})
}
