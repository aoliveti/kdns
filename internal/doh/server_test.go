// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package doh

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

var discardLogger = slog.New(slog.DiscardHandler)

func TestDoH_Lifecycle(t *testing.T) {
	t.Parallel()
	resolver := atomicResolver(func(_ string, _ dns.Type) dns.Result {
		return dns.Result{RCode: dns.RCodeSuccess}
	})

	srv := New(resolver, WithAddress("127.0.0.1:0"))

	ctx, cancel := context.WithCancel(t.Context())
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
		t.Fatal("DoH server did not shut down within timeout")
	}
}

func TestDoH_Options(t *testing.T) {
	t.Parallel()

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	srv := New(nil, WithLogger(discardLogger), WithTLSConfig(tlsCfg))
	require.NotNil(t, srv)
	require.True(t, srv.hasTLS())

	srvNoTLS := New(nil)
	require.False(t, srvNoTLS.hasTLS())
}

func TestDoH_Probes(t *testing.T) {
	t.Parallel()

	srv := New(nil)
	handler := srv.Handler()

	for _, path := range []string{"/livez", "/readyz", "/startupz"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Body.String(), "ok")
		})
	}
}
