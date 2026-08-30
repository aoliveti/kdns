// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/aoliveti/kdns/internal/dns"
)

var (
	// ErrEmptyRecords indicates that the upsert payload contains no records.
	ErrEmptyRecords = errors.New("records cannot be empty")

	// ErrPseudoTypeNotAllowed indicates that ANY or OPT pseudo-types were attempted to be inserted.
	ErrPseudoTypeNotAllowed = errors.New("pseudo-type cannot be inserted into zone")

	// ErrDuplicateRecordType indicates that multiple records with the same type exist in the payload.
	ErrDuplicateRecordType = errors.New("duplicate record type")

	// ErrTTLExceeded indicates that a TTL exceeds RFC 2181 maximum value.
	ErrTTLExceeded = errors.New("ttl exceeds RFC 2181 maximum allowed value")

	// ErrEmptyRData indicates that a record type has no rdata elements.
	ErrEmptyRData = errors.New("must contain at least one rdata element")

	// ErrCNAMEMultipleTargets indicates that multiple targets were provided for a CNAME record.
	ErrCNAMEMultipleTargets = errors.New("cname record cannot have multiple target records")

	// ErrMultipleSOA indicates that multiple SOA records were specified.
	ErrMultipleSOA = errors.New("cannot have multiple soa records")

	// ErrCNAMECoexistence indicates that CNAME coexists with other record types on the same domain.
	ErrCNAMECoexistence = errors.New("cname record cannot coexist with other record types on the same domain (RFC 1034)")
)

// Record represents the JSON presentation format for an RRSet of a specific DNS record type.
type Record struct {
	Type  string   `json:"type"`
	RData []string `json:"rdata"`
	TTL   uint32   `json:"ttl"`
}

// DomainRecords represents all resource records associated with a specific domain.
type DomainRecords struct {
	Domain  string   `json:"domain"`
	Records []Record `json:"records"`
}

// UpsertRequest represents the incoming JSON payload for creating or updating a domain's records.
type UpsertRequest struct {
	Records []Record `json:"records"`
}

// ListResponse represents the paginated response for listing domain records.
type ListResponse struct {
	NextCursor string          `json:"next_cursor,omitzero"`
	Domains    []DomainRecords `json:"domains"`
	HasMore    bool            `json:"has_more"`
}

// SearchResponse represents the result of a substring search over stored domain records.
type SearchResponse struct {
	Query   string          `json:"query"`
	Domains []DomainRecords `json:"domains"`
	Total   int             `json:"total"`
}

// ErrorResponse represents standard REST error messages.
type ErrorResponse struct {
	Error string `json:"error"`
}

// StatusResponse represents simple operational status confirmations.
type StatusResponse struct {
	Status  string `json:"status"`
	Domain  string `json:"domain,omitzero"`
	Deleted bool   `json:"deleted,omitzero"`
}

// RRSets validates the incoming request payload and compiles it into internal dns.RRSets.
// It enforces RFC 1034/1035 type safety, TTL bounds, RData formats, and semantic CNAME exclusivity.
func (req *UpsertRequest) RRSets() (dns.RRSets, error) {
	if len(req.Records) == 0 {
		return nil, ErrEmptyRecords
	}

	records := make(dns.RRSets, 0, len(req.Records))
	seenTypes := make(map[dns.Type]struct{}, len(req.Records))
	hasCNAME := false

	for _, rec := range req.Records {
		record, err := parseRecordEntry(rec, seenTypes)
		if err != nil {
			return nil, err
		}
		if record.Type == dns.TypeCNAME {
			hasCNAME = true
		}
		records = append(records, record)
	}

	if hasCNAME && len(records) > 1 {
		return nil, ErrCNAMECoexistence
	}

	return records, nil
}

func parseRecordEntry(rec Record, seenTypes map[dns.Type]struct{}) (dns.RRSet, error) {
	qType, err := dns.ParseType(rec.Type)
	if err != nil {
		return dns.RRSet{}, fmt.Errorf("invalid record type %q: %w", rec.Type, err)
	}
	if qType == dns.TypeANY || qType == dns.TypeOPT {
		return dns.RRSet{}, fmt.Errorf("%w: pseudo-type %s cannot be inserted into zone", ErrPseudoTypeNotAllowed, qType.String())
	}
	if _, exists := seenTypes[qType]; exists {
		return dns.RRSet{}, fmt.Errorf("%w %s in request: combine all rdata entries into a single record object", ErrDuplicateRecordType, qType.String())
	}
	seenTypes[qType] = struct{}{}
	if rec.TTL > math.MaxInt32 {
		return dns.RRSet{}, fmt.Errorf("ttl %d exceeds RFC 2181 maximum allowed value of %d: %w", rec.TTL, math.MaxInt32, ErrTTLExceeded)
	}
	if len(rec.RData) == 0 {
		return dns.RRSet{}, fmt.Errorf("record type %s %w", qType.String(), ErrEmptyRData)
	}

	wireRData := make([][]byte, 0, len(rec.RData))
	for _, rdataStr := range rec.RData {
		wire, packErr := dns.PackRData(qType, strings.TrimSpace(rdataStr))
		if packErr != nil {
			return dns.RRSet{}, fmt.Errorf("invalid rdata %q for type %s: %w", rdataStr, qType.String(), packErr)
		}
		wireRData = append(wireRData, wire)
	}

	if qType == dns.TypeCNAME && len(wireRData) > 1 {
		return dns.RRSet{}, ErrCNAMEMultipleTargets
	}
	if qType == dns.TypeSOA && len(wireRData) > 1 {
		return dns.RRSet{}, ErrMultipleSOA
	}

	return dns.RRSet{
		Type:  qType,
		Class: dns.ClassIN,
		TTL:   rec.TTL,
		RData: wireRData,
	}, nil
}

// formatDomain formats internal dns.RRSets into a presentation DomainRecords payload.
func formatDomain(domain string, sets dns.RRSets) DomainRecords {
	records := make([]Record, 0, len(sets))
	for _, set := range sets {
		rdataList := make([]string, 0, len(set.RData))
		for _, wire := range set.RData {
			formatted, err := dns.UnpackRData(set.Type, wire)
			if err != nil {
				formatted = string(wire)
			}
			rdataList = append(rdataList, formatted)
		}
		records = append(records, Record{
			Type:  set.Type.String(),
			TTL:   set.TTL,
			RData: rdataList,
		})
	}
	return DomainRecords{
		Domain:  domain,
		Records: records,
	}
}
