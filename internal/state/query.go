// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package state

import (
	"iter"

	"github.com/aoliveti/kdns/internal/dns"
)

// Get retrieves all resource records associated with a domain without type filtering.
func (s *State) Get(domain string) (dns.RRSets, bool) {
	return s.tree.Load().Get(domain)
}

// Search yields domains and their RRSets whose domain name contains the query substring.
func (s *State) Search(query string) iter.Seq2[string, dns.RRSets] {
	return s.tree.Load().Search(query)
}

// Seek yields domains and their RRSets in lexicographical order starting strictly after afterDomain.
func (s *State) Seek(afterDomain string) iter.Seq2[string, dns.RRSets] {
	return s.tree.Load().Seek(afterDomain)
}

// Walk yields all domains and their RRSets in lexicographical order.
func (s *State) Walk() iter.Seq2[string, dns.RRSets] {
	return s.tree.Load().Walk()
}
