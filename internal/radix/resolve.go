// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"github.com/aoliveti/kdns/internal/dns"
)

// Resolve traverses the radix tree to answer a DNS query for the data plane.
// It executes completely lock-free using atomic state dereferencing.
// Domain strings MUST be ASCII/UTF-8 normalized to lowercase prior to invocation.
func (t *Tree) Resolve(domain string, qt dns.Type) dns.Result {
	s := t.state.Load()
	if s == nil || s.root == nil {
		return dns.Result{RCode: dns.RCodeNameError}
	}

	currentNode := s.root
	var fallback *Node
	var soaRR dns.RRSet
	soaName := "."
	var labelBuf [64]byte

	if res, ok := evaluateNode(currentNode, qt, domain, len(domain), &soaRR, &soaName); ok {
		return res
	}

	it := NewDomainIterator(domain)
	for {
		label, hasNext := it.NextLower(labelBuf[:])
		if !hasNext {
			break
		}

		if currentNode.Wildcard != nil {
			fallback = currentNode.Wildcard
		}

		if label == "*" {
			if currentNode.Wildcard == nil {
				return wildcardResolve(fallback, qt, soaRR, soaName)
			}
			currentNode = currentNode.Wildcard
			if res, ok := evaluateNode(currentNode, qt, domain, it.cursor, &soaRR, &soaName); ok {
				return res
			}
			continue
		}

		idx, edgeFound := findEdge(currentNode.Children, label)
		if !edgeFound {
			return wildcardResolve(fallback, qt, soaRR, soaName)
		}

		currentNode = currentNode.Children[idx].Node
		if res, ok := evaluateNode(currentNode, qt, domain, it.cursor, &soaRR, &soaName); ok {
			return res
		}
	}

	nameExists := len(currentNode.RRSets) > 0 || len(currentNode.Children) > 0 || currentNode.Wildcard != nil
	if !nameExists {
		if fallback != nil {
			return wildcardResolve(fallback, qt, soaRR, soaName)
		}
		return dns.Result{
			RCode:         dns.RCodeNameError,
			Authority:     soaRR,
			AuthorityName: soaName,
		}
	}

	return resolveAtNode(currentNode, qt, soaRR, soaName)
}

// evaluateNode checks for SOA records to track negative caching context (RFC 2308)
// or intercepts delegations (Zone Cuts, RFC 1034 §4.3.2) returning a referral result.
func evaluateNode(node *Node, qt dns.Type, domain string, cursor int, soaRR *dns.RRSet, soaName *string) (dns.Result, bool) {
	// Guard clause: if the node has no records, it cannot be a zone cut or SOA apex.
	// This completely eliminates traversal overhead on pure structural transit nodes.
	if len(node.RRSets) == 0 {
		return dns.Result{}, false
	}

	if soa, ok := searchRRSet(node, dns.TypeSOA); ok {
		*soaRR = soa
		*soaName = formatDomainName(domain, cursor)
		return dns.Result{}, false
	}

	if ns, ok := searchRRSet(node, dns.TypeNS); ok {
		// RFC 4035: Return referral UNLESS it's an exact-match query for a DS record at the delegation point.
		isExactMatch := cursor == 0
		if qt != dns.TypeDS || !isExactMatch {
			return dns.Result{
				RCode:         dns.RCodeSuccess,
				Authority:     ns,
				AuthorityName: formatDomainName(domain, cursor),
			}, true
		}
	}

	return dns.Result{}, false
}

// formatDomainName maps the iterator cursor position to its corresponding FQDN string representation.
func formatDomainName(domain string, cursor int) string {
	switch {
	case cursor == len(domain):
		return "."
	case cursor > 0:
		return domain[cursor+1:]
	default:
		return domain
	}
}

// resolveAtNode synthesizes the final DNS response for an exact name match.
// It handles minimal responses for ANY queries (RFC 8482) and CNAME transparency (RFC 1034 §3.6.2).
func resolveAtNode(node *Node, qt dns.Type, soaRR dns.RRSet, soaName string) dns.Result {
	if qt == dns.TypeANY && len(node.RRSets) > 0 {
		return dns.Result{
			RCode:  dns.RCodeSuccess,
			Answer: node.RRSets[0],
		}
	}

	if rr, found := searchRRSet(node, qt); found {
		return dns.Result{
			RCode:  dns.RCodeSuccess,
			Answer: rr,
		}
	}

	if qt != dns.TypeCNAME {
		if cname, found := searchRRSet(node, dns.TypeCNAME); found {
			return dns.Result{
				RCode:  dns.RCodeSuccess,
				Answer: cname,
			}
		}
	}

	return dns.Result{
		RCode:         dns.RCodeSuccess,
		Authority:     soaRR,
		AuthorityName: soaName,
	}
}

// wildcardResolve applies fallback logic when an exact match fails.
// If a valid wildcard exists, it attempts to resolve the query type against it.
// Otherwise, it returns NXDOMAIN with the nearest enclosing SOA.
func wildcardResolve(fallback *Node, qt dns.Type, soaRR dns.RRSet, soaName string) dns.Result {
	if fallback == nil || len(fallback.RRSets) == 0 {
		return dns.Result{
			RCode:         dns.RCodeNameError,
			Authority:     soaRR,
			AuthorityName: soaName,
		}
	}
	return resolveAtNode(fallback, qt, soaRR, soaName)
}
