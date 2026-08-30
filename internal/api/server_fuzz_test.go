// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzAPI_UpsertPayload(f *testing.F) {
	f.Add([]byte(`{"records":[{"type":"A","ttl":300,"rdata":["192.0.2.1"]}]}`))
	f.Add([]byte(`{"records":[{"type":"TXT","ttl":3600,"rdata":["v=spf1 -all"]}]}`))
	f.Add([]byte(`{"records":[{"type":"MX","ttl":300,"rdata":["10 mail.example.com"]}]}`))
	f.Add([]byte(`{"records":[]}`))
	f.Add([]byte(`{malformed json`))
	f.Add([]byte(`{"records":[{"type":"INVALID","ttl":0,"rdata":[]}]}`))
	f.Add([]byte(``))

	viewer := compositeViewer{}
	ud := atomicUpsertDeleter{}
	srv := New(viewer, WithAPIToken(benchAPIToken), WithUpsertDeleter(ud), WithLogger(benchLogger))
	h := srv.Handler()

	f.Fuzz(func(t *testing.T, data []byte) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/v1/records/fuzz.example.com", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+benchAPIToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	})
}
