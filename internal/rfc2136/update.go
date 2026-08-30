// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rfc2136 implements Dynamic DNS Updates parsing, prerequisite evaluation,
// and atomic batch application in accordance with RFC 2136.
package rfc2136

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	headerSize   = 12
	rrHeaderSize = 10
)

var (
	// ErrPacketTooSmall indicates that the payload buffer is shorter than the 12-byte header.
	ErrPacketTooSmall = errors.New("rfc2136: packet smaller than header")
	// ErrInvalidZoneSection indicates QDCount != 1 or ztype != SOA or zclass != IN.
	ErrInvalidZoneSection = errors.New("rfc2136: invalid zone section")
	// ErrMalformedRecord indicates malformed wire structure in prerequisite or update sections.
	ErrMalformedRecord = errors.New("rfc2136: malformed record")
)

type rawRR struct {
	name  string
	rData []byte
	ttl   uint32
	qType dns.Type
	class dns.Class
}

// Process parses an RFC 2136 dynamic UPDATE packet, validates the Zone section,
// verifies that all records belong to the authoritative zone, evaluates all prerequisites,
// computes the updated domain states, and atomically applies the mutations to persistence.
func Process(payload []byte, getter dns.Getter, ud dns.UpsertDeleter) (dns.RCode, error) {
	if len(payload) < headerSize {
		return dns.RCodeFormatError, ErrPacketTooSmall
	}

	qdCount := binary.BigEndian.Uint16(payload[4:6])
	anCount := binary.BigEndian.Uint16(payload[6:8])
	nsCount := binary.BigEndian.Uint16(payload[8:10])

	zoneName, offset, err := parseZoneSection(payload, qdCount)
	if err != nil {
		return dns.RCodeFormatError, err
	}

	// Verify that the server is authoritative for the specified zone
	if _, ok := getter.Get(zoneName); !ok && zoneName != "." {
		return dns.RCodeNotAuth, nil
	}

	prereqs, nextOffset, err := parseRecords(payload, offset, anCount)
	if err != nil {
		return dns.RCodeFormatError, err
	}
	offset = nextOffset

	updates, _, err := parseRecords(payload, offset, nsCount)
	if err != nil {
		return dns.RCodeFormatError, err
	}

	// RFC 2136 §3.1.2: All records in prerequisite and update sections must belong to the zone
	for _, pr := range prereqs {
		if !isInZone(pr.name, zoneName) {
			return dns.RCodeNotZone, nil
		}
	}
	for _, up := range updates {
		if !isInZone(up.name, zoneName) {
			return dns.RCodeNotZone, nil
		}
	}

	// RFC 2136 §3.2: Evaluate prerequisites prior to applying any mutations
	if rCode := checkPrerequisites(prereqs, getter); rCode != dns.RCodeSuccess {
		return rCode, nil
	}

	// RFC 2136 §3.4: Compute updated states and apply mutations atomically
	if err := applyUpdates(updates, getter, ud); err != nil {
		return dns.RCodeServerFailure, err
	}

	return dns.RCodeSuccess, nil
}

// parseZoneSection decodes and validates the Zone section of an RFC 2136 UPDATE message.
// RFC 2136 §2.3 mandates exactly one Zone record with Type SOA and Class IN.
func parseZoneSection(payload []byte, qdCount uint16) (string, int, error) {
	if qdCount != 1 {
		return "", 0, ErrInvalidZoneSection
	}

	offset := headerSize
	zname, znameEnd, err := dns.UnpackDomainName(payload, offset)
	if err != nil {
		return "", 0, err
	}
	offset = znameEnd

	if offset+4 > len(payload) {
		return "", 0, ErrInvalidZoneSection
	}

	ztype := dns.Type(binary.BigEndian.Uint16(payload[offset : offset+2]))
	zclass := dns.Class(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
	offset += 4

	if ztype != dns.TypeSOA || zclass != dns.ClassIN {
		return "", 0, ErrInvalidZoneSection
	}

	return canonicalName(zname), offset, nil
}

// parseRecords decodes a sequence of resource records from the wire payload.
func parseRecords(payload []byte, offset int, count uint16) ([]rawRR, int, error) {
	allocCap := min(count, 50)
	records := make([]rawRR, 0, allocCap)
	for range count {
		rr, nextOffset, parseErr := parseRR(payload, offset)
		if parseErr != nil {
			return nil, 0, parseErr
		}
		offset = nextOffset
		records = append(records, rr)
	}
	return records, offset, nil
}

// checkPrerequisites evaluates all RFC 2136 §3.2 prerequisite rules.
func checkPrerequisites(prereqs []rawRR, getter dns.Getter) dns.RCode {
	for _, pr := range prereqs {
		if rCode := evaluatePrerequisite(pr, getter); rCode != dns.RCodeSuccess {
			return rCode
		}
	}
	return dns.RCodeSuccess
}

// applyUpdates computes domain modifications and commits them atomically to persistence.
func applyUpdates(updates []rawRR, getter dns.Getter, ud dns.UpsertDeleter) error {
	domainStates := make(map[string]dns.RRSets)
	modifiedDomains := make(map[string]bool)

	for _, up := range updates {
		domain := up.name
		modifiedDomains[domain] = true

		current, loaded := domainStates[domain]
		if !loaded {
			current = dns.RRSets{}
			if existing, found := getter.Get(domain); found {
				current = existing.Clone()
			}
		}

		domainStates[domain] = applyUpdateOp(current, up)
	}

	for domain := range modifiedDomains {
		final := domainStates[domain]
		if len(final) == 0 {
			if err := ud.DeleteDomain(domain); err != nil {
				return fmt.Errorf("delete domain %s: %w", domain, err)
			}
			continue
		}
		if err := ud.Upsert(domain, final); err != nil {
			return fmt.Errorf("upsert domain %s: %w", domain, err)
		}
	}

	return nil
}

// evaluatePrerequisite checks a single prerequisite rule according to RFC 2136 §2.4 and §3.2.
// The RFC maps prerequisite semantics to specific combinations of Class, Type, and RDATA presence:
// - Class ANY, Type != ANY, RData == nil: Assert RRset exists (value-independent), returning NXRRSet if absent.
// - Class IN, Type != ANY, RData != nil: Assert RRset exists (value-dependent), returning NXRRSet if absent or RData differs.
// - Class NONE, Type != ANY, RData == nil: Assert RRset does not exist, returning YXRRSet if present.
// - Class ANY, Type == ANY, RData == nil: Assert Name is in use (at least one RRSet exists), returning NXDOMAIN if missing.
// - Class NONE, Type == ANY, RData == nil: Assert Name is not in use, returning YXDomain if present.
func evaluatePrerequisite(pr rawRR, getter dns.Getter) dns.RCode {
	existing, found := getter.Get(pr.name)

	switch {
	case pr.class == dns.ClassANY && pr.qType != dns.TypeANY && len(pr.rData) == 0:
		if !found {
			return dns.RCodeNXRRSet
		}
		if _, ok := existing.Get(pr.qType); !ok {
			return dns.RCodeNXRRSet
		}
		return dns.RCodeSuccess

	case pr.class == dns.ClassIN && pr.qType != dns.TypeANY && len(pr.rData) > 0:
		if !found {
			return dns.RCodeNXRRSet
		}
		record, ok := existing.Get(pr.qType)
		if !ok {
			return dns.RCodeNXRRSet
		}
		if !containsRData(record.RData, pr.rData) {
			return dns.RCodeNXRRSet
		}
		return dns.RCodeSuccess

	case pr.class == dns.ClassNONE && pr.qType != dns.TypeANY && len(pr.rData) == 0:
		if found {
			if _, ok := existing.Get(pr.qType); ok {
				return dns.RCodeYXRRSet
			}
		}
		return dns.RCodeSuccess

	case pr.class == dns.ClassANY && pr.qType == dns.TypeANY && len(pr.rData) == 0:
		if !found || len(existing) == 0 {
			return dns.RCodeNameError
		}
		return dns.RCodeSuccess

	case pr.class == dns.ClassNONE && pr.qType == dns.TypeANY && len(pr.rData) == 0:
		if found && len(existing) > 0 {
			return dns.RCodeYXDomain
		}
		return dns.RCodeSuccess

	default:
		return dns.RCodeFormatError
	}
}

// applyUpdateOp applies a single RFC 2136 §2.5 update operation to a domain's current RRSets:
// - Class IN, Type != ANY, RData != nil: Add record to RRSet (§2.5.1).
// - Class ANY, Type != ANY, TTL == 0, RData == nil: Delete entire RRSet (§2.5.2).
// - Class ANY, Type == ANY, TTL == 0, RData == nil: Delete all RRSets at domain name (§2.5.3).
// - Class NONE, Type != ANY, TTL == 0, RData != nil: Delete individual record matching RDATA from RRSet (§2.5.4).
func applyUpdateOp(records dns.RRSets, up rawRR) dns.RRSets {
	switch {
	case up.class == dns.ClassIN && up.qType != dns.TypeANY && len(up.rData) > 0:
		for i := range records {
			if records[i].Type == up.qType {
				records[i].TTL = up.ttl
				if !containsRData(records[i].RData, up.rData) {
					records[i].RData = append(records[i].RData, up.rData)
				}
				return records
			}
		}
		return append(records, dns.RRSet{
			Type:  up.qType,
			Class: dns.ClassIN,
			TTL:   up.ttl,
			RData: [][]byte{up.rData},
		})

	case up.class == dns.ClassANY && up.qType != dns.TypeANY && up.ttl == 0 && len(up.rData) == 0:
		updated := make(dns.RRSets, 0, len(records))
		for _, record := range records {
			if record.Type != up.qType {
				updated = append(updated, record)
			}
		}
		return updated

	case up.class == dns.ClassANY && up.qType == dns.TypeANY && up.ttl == 0 && len(up.rData) == 0:
		return dns.RRSets{}

	case up.class == dns.ClassNONE && up.qType != dns.TypeANY && up.ttl == 0 && len(up.rData) > 0:
		updated := make(dns.RRSets, 0, len(records))
		for _, record := range records {
			if record.Type != up.qType {
				updated = append(updated, record)
				continue
			}
			var remainingRData [][]byte
			for _, r := range record.RData {
				if !bytes.Equal(r, up.rData) {
					remainingRData = append(remainingRData, r)
				}
			}
			if len(remainingRData) > 0 {
				record.RData = remainingRData
				updated = append(updated, record)
			}
		}
		return updated

	default:
		return records
	}
}

func parseRR(payload []byte, offset int) (rawRR, int, error) {
	name, nextOffset, err := dns.UnpackDomainName(payload, offset)
	if err != nil {
		return rawRR{}, 0, err
	}
	offset = nextOffset

	qType, class, ttl, rdLen, err := parseRRHeader(payload, offset)
	if err != nil {
		return rawRR{}, 0, err
	}
	offset += rrHeaderSize

	if offset+rdLen > len(payload) {
		return rawRR{}, 0, ErrMalformedRecord
	}

	var rData []byte
	if rdLen > 0 {
		rData = make([]byte, rdLen)
		copy(rData, payload[offset:offset+rdLen])
		offset += rdLen
	}

	return rawRR{
		name:  canonicalName(name),
		qType: qType,
		class: class,
		ttl:   ttl,
		rData: rData,
	}, offset, nil
}

func parseRRHeader(payload []byte, offset int) (dns.Type, dns.Class, uint32, int, error) {
	if offset+rrHeaderSize > len(payload) {
		return 0, 0, 0, 0, ErrMalformedRecord
	}
	qType := dns.Type(binary.BigEndian.Uint16(payload[offset : offset+2]))
	class := dns.Class(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
	ttl := binary.BigEndian.Uint32(payload[offset+4 : offset+8])
	rdLen := int(binary.BigEndian.Uint16(payload[offset+8 : offset+10]))
	return qType, class, ttl, rdLen, nil
}

func containsRData(rDataList [][]byte, target []byte) bool {
	for _, r := range rDataList {
		if bytes.Equal(r, target) {
			return true
		}
	}
	return false
}

func isInZone(domain, zone string) bool {
	d := canonicalName(domain)
	z := canonicalName(zone)
	if z == "." {
		return true
	}
	return d == z || strings.HasSuffix(d, "."+z)
}

func canonicalName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || lower == "." {
		return "."
	}
	if !strings.HasSuffix(lower, ".") {
		lower += "."
	}
	return lower
}
