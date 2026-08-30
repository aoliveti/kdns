// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"strings"

	"github.com/aoliveti/kdns/internal/dns"
)

func (s *Server) resolveCHAOS(name string, qType dns.Type) dns.Result {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	switch lower {
	case "version.bind", "version.server":
		if qType == dns.TypeTXT || qType == dns.TypeANY {
			return dns.Result{
				RCode: dns.RCodeSuccess,
				Answer: dns.RRSet{
					Type:  dns.TypeTXT,
					Class: dns.ClassCH,
					TTL:   0,
					RData: s.versionWire,
				},
			}
		}
		return dns.Result{RCode: dns.RCodeSuccess}

	case "hostname.bind", "id.server":
		if qType == dns.TypeTXT || qType == dns.TypeANY {
			return dns.Result{
				RCode: dns.RCodeSuccess,
				Answer: dns.RRSet{
					Type:  dns.TypeTXT,
					Class: dns.ClassCH,
					TTL:   0,
					RData: s.identityWire,
				},
			}
		}
		return dns.Result{RCode: dns.RCodeSuccess}

	case "authors.bind":
		if qType == dns.TypeTXT || qType == dns.TypeANY {
			return dns.Result{
				RCode: dns.RCodeSuccess,
				Answer: dns.RRSet{
					Type:  dns.TypeTXT,
					Class: dns.ClassCH,
					TTL:   0,
					RData: s.authorsWire,
				},
			}
		}
		return dns.Result{RCode: dns.RCodeSuccess}

	default:
		return dns.Result{RCode: dns.RCodeNameError}
	}
}
