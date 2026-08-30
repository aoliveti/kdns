// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !pprof

package api

import (
	"log/slog"
	"net/http"
)

// mountPprof is a no-op in production builds.
// Compile with -tags pprof to enable /debug/pprof/ endpoints on the HTTP
// management server.
func mountPprof(_ *http.ServeMux, _ *slog.Logger) {} //nolint:unused // called by Server.routes
