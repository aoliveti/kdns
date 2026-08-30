// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build pprof

package api

// This file is only compiled when building with -tags pprof.
// It registers the standard net/http/pprof handlers on the management HTTP
// server at /debug/pprof/.
//
// Usage:
//
//	go build -tags pprof -o bin/kdns-debug .
//	go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30
//	go tool pprof http://localhost:8080/debug/pprof/heap

import (
	"log/slog"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof/ handlers on http.DefaultServeMux
)

// mountPprof attaches the standard pprof endpoints to mux at /debug/pprof/.
// Called by Server.routes only in pprof builds.
func mountPprof(mux *http.ServeMux, logger *slog.Logger) {
	const prefix = "/debug/pprof/"
	// net/http/pprof registers handlers on http.DefaultServeMux; we forward
	// them onto our dedicated mux to avoid polluting the default mux.
	for _, path := range []string{
		prefix,
		prefix + "cmdline",
		prefix + "profile",
		prefix + "symbol",
		prefix + "trace",
	} {
		mux.Handle(path, http.DefaultServeMux)
	}
	logger.Warn("pprof debug endpoints enabled",
		slog.String("path", prefix),
		slog.String("note", "do not expose this port publicly"),
	)
}
