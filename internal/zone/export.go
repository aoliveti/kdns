// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zone

import (
	"bufio"
	"cmp"
	"io"
	"iter"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	defaultTTLSeconds = 3600
	streamBufferSize  = 64 * 1024
	spacesPadding     = "                              " // 30 spaces for left-alignment padding
)

var writerPool = sync.Pool{
	New: func() any {
		return bufio.NewWriterSize(io.Discard, streamBufferSize)
	},
}

type domainEntry struct {
	domain  string
	fqdn    string
	records dns.RRSets
}

// Format writes all provided domain records to w in standard RFC 1035 master zone file format.
func Format(w io.Writer, records iter.Seq2[string, dns.RRSets]) error {
	return FormatZone(w, "", records)
}

// FormatZone writes domain records belonging to the specified zone (or all zones if zone is empty)
// to w in standard RFC 1035 master zone file format.
func FormatZone(w io.Writer, zone string, records iter.Seq2[string, dns.RRSets]) error {
	bw, ok := writerPool.Get().(*bufio.Writer)
	if !ok {
		bw = bufio.NewWriterSize(w, streamBufferSize)
	}
	bw.Reset(w)
	defer func() {
		_ = bw.Flush()
		bw.Reset(io.Discard)
		writerPool.Put(bw)
	}()

	normalizedZone := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(zone)), ".")

	entries := make([]domainEntry, 0, 64)
	for domain, domainRecords := range records {
		canonicalDomain := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
		if normalizedZone != "" && canonicalDomain != normalizedZone && !strings.HasSuffix(canonicalDomain, "."+normalizedZone) {
			continue
		}

		entries = append(entries, domainEntry{
			domain:  canonicalDomain,
			fqdn:    canonicalizeFQDN(canonicalDomain),
			records: domainRecords,
		})
	}

	if len(entries) == 0 {
		return nil
	}

	// Sort entries: apex first (if zone filter is set), then alphabetically
	slices.SortFunc(entries, func(a, b domainEntry) int {
		return compareDomainEntries(a, b, normalizedZone)
	})

	defaultTTL := uint32(defaultTTLSeconds)
	// If apex has SOA, use SOA TTL as default
	for _, entry := range entries {
		if soa, ok := entry.records.Get(dns.TypeSOA); ok && soa.TTL > 0 {
			defaultTTL = soa.TTL
			break
		}
	}

	if normalizedZone != "" {
		if _, err := bw.WriteString("$ORIGIN "); err != nil {
			return err
		}
		if _, err := bw.WriteString(normalizedZone); err != nil {
			return err
		}
		if _, err := bw.WriteString(".\n"); err != nil {
			return err
		}
	}

	if _, err := bw.WriteString("$TTL "); err != nil {
		return err
	}
	var numBuf [16]byte
	ttlBytes := strconv.AppendUint(numBuf[:0], uint64(defaultTTL), 10)
	if _, err := bw.Write(ttlBytes); err != nil {
		return err
	}
	if _, err := bw.WriteString("\n\n"); err != nil {
		return err
	}

	// Write apex SOA and NS first
	for i := range entries {
		if err := writeApexRecords(bw, &entries[i]); err != nil {
			return err
		}
	}

	// Write remaining record types
	for _, entry := range entries {
		if err := writeStandardRecords(bw, entry); err != nil {
			return err
		}
	}

	return bw.Flush()
}

func canonicalizeFQDN(domain string) string {
	if domain == "" {
		return "."
	}
	if strings.HasSuffix(domain, ".") {
		return domain
	}
	return domain + "."
}

func compareDomainEntries(a, b domainEntry, normalizedZone string) int {
	if normalizedZone == "" {
		return cmp.Compare(a.domain, b.domain)
	}
	if a.domain == normalizedZone && b.domain != normalizedZone {
		return -1
	}
	if b.domain == normalizedZone && a.domain != normalizedZone {
		return 1
	}
	return cmp.Compare(a.domain, b.domain)
}

func formatTXT(text string) string {
	if strings.HasPrefix(text, `"`) && strings.HasSuffix(text, `"`) {
		return text
	}
	return strconv.Quote(text)
}

func writeApexRecords(bw *bufio.Writer, entry *domainEntry) error {
	if soa, ok := entry.records.Get(dns.TypeSOA); ok {
		for _, wire := range soa.RData {
			text, err := dns.UnpackRData(dns.TypeSOA, wire)
			if err != nil {
				continue
			}
			if err := writeRecordLine(bw, entry.fqdn, soa.TTL, "SOA", text); err != nil {
				return err
			}
		}
	}

	if ns, ok := entry.records.Get(dns.TypeNS); ok {
		for _, wire := range ns.RData {
			text, err := dns.UnpackRData(dns.TypeNS, wire)
			if err != nil {
				continue
			}
			if err := writeRecordLine(bw, entry.fqdn, ns.TTL, "NS", text); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeStandardRecords(bw *bufio.Writer, entry domainEntry) error {
	for _, record := range entry.records {
		if record.Type == dns.TypeSOA || record.Type == dns.TypeNS {
			continue
		}
		for _, wire := range record.RData {
			text, err := dns.UnpackRData(record.Type, wire)
			if err != nil {
				continue
			}

			if record.Type == dns.TypeTXT {
				text = formatTXT(text)
			}

			if err := writeRecordLine(bw, entry.fqdn, record.TTL, record.Type.String(), text); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeRecordLine(bw *bufio.Writer, fqdn string, ttl uint32, typeName, text string) error {
	// 1. Write domain name (left-aligned with 30-char padding)
	if _, err := bw.WriteString(fqdn); err != nil {
		return err
	}
	if len(fqdn) < 30 {
		if _, err := bw.WriteString(spacesPadding[:30-len(fqdn)]); err != nil {
			return err
		}
	}

	// 2. Write Tab + TTL
	if err := bw.WriteByte('\t'); err != nil {
		return err
	}
	var numBuf [16]byte
	ttlBytes := strconv.AppendUint(numBuf[:0], uint64(ttl), 10)
	if _, err := bw.Write(ttlBytes); err != nil {
		return err
	}

	// 3. Write Tab + IN + Tab + Record Type (left-aligned with 7-char padding)
	if _, err := bw.WriteString("\tIN\t"); err != nil {
		return err
	}
	if _, err := bw.WriteString(typeName); err != nil {
		return err
	}
	if len(typeName) < 7 {
		if _, err := bw.WriteString(spacesPadding[:7-len(typeName)]); err != nil {
			return err
		}
	}

	// 4. Write Tab + Text RData + Newline
	if err := bw.WriteByte('\t'); err != nil {
		return err
	}
	if _, err := bw.WriteString(text); err != nil {
		return err
	}
	return bw.WriteByte('\n')
}
