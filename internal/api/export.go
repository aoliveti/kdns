// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/aoliveti/kdns/internal/zone"
)

func (s *Server) exportZoneFile(w http.ResponseWriter, r *http.Request) {
	requestedZone := strings.TrimSpace(r.URL.Query().Get("zone"))

	var targetZone string
	if requestedZone != "" {
		targetZone = strings.TrimSuffix(strings.ToLower(requestedZone), ".")
		if !s.hasMatchingZone(targetZone) {
			writeError(w, http.StatusNotFound, "zone not found")
			return
		}
	}

	filename := exportFilename(targetZone)

	w.Header().Set("Content-Type", "text/dns; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", filename))
	w.WriteHeader(http.StatusOK)

	_ = zone.FormatZone(w, targetZone, s.viewer.Walk())
}

func exportFilename(targetZone string) string {
	if targetZone == "" {
		return "kdns.zone"
	}
	return targetZone + ".zone"
}

func (s *Server) hasMatchingZone(targetZone string) bool {
	if _, ok := s.viewer.Get(targetZone); ok {
		return true
	}
	for domain := range s.viewer.Walk() {
		cleanDomain := strings.TrimSuffix(strings.ToLower(domain), ".")
		if cleanDomain == targetZone || strings.HasSuffix(cleanDomain, "."+targetZone) {
			return true
		}
	}
	return false
}
