// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package zone provides a high-performance, RFC 1035 compliant parser for DNS master zone files.
package zone

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aoliveti/kdns/internal/dns"
)

const maxLineBufferSize = 1024 * 1024

var (
	// ErrInvalidZoneFile indicates a syntax or formatting violation in an RFC 1035 zone file.
	ErrInvalidZoneFile = errors.New("zone: invalid zone file format")

	// ErrMalformedTTL indicates a malformed or syntactically invalid $TTL directive.
	ErrMalformedTTL = errors.New("zone: malformed $TTL directive")

	// ErrMalformedOrigin indicates a malformed or missing $ORIGIN directive value.
	ErrMalformedOrigin = errors.New("zone: malformed $ORIGIN directive")

	// ErrUnknownQueryType indicates an unrecognized or unsupported DNS query type.
	ErrUnknownQueryType = errors.New("zone: unknown query type")

	// ErrMalformedLine indicates a malformed resource record line syntax.
	ErrMalformedLine = errors.New("zone: malformed line")

	// ErrUnclosedParenthesis indicates an unclosed opening parenthesis '(' in a multiline record.
	ErrUnclosedParenthesis = errors.New("zone: unclosed parenthesis")

	// ErrUnmatchedParenthesis indicates an unexpected closing parenthesis ')' without a preceding opening one.
	ErrUnmatchedParenthesis = errors.New("zone: unmatched closing parenthesis")

	// ErrUnclosedQuote indicates a string literal missing its closing double quote '"'.
	ErrUnclosedQuote = errors.New("zone: unclosed quote")
)

// Parse reads an RFC 1035 zone master file from the reader and invokes yield
// for each parsed domain and its corresponding resource record sets.
func Parse(r io.Reader, yield func(domain string, records dns.RRSets)) error {
	p := newZoneParser(r)
	if err := p.parseAll(); err != nil {
		return err
	}

	for domain, records := range p.records {
		yield(domain, records)
	}

	return nil
}

type zoneParser struct {
	scanner       *bufio.Scanner
	records       map[string]dns.RRSets
	complexTokens []string
	origin        string
	lastDomain    string
	quoteBuf      strings.Builder
	parenCount    int
	defaultTTL    uint32
	defaultClass  dns.Class
	inQuote       bool
}

func newZoneParser(r io.Reader) *zoneParser {
	s := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, maxLineBufferSize)

	return &zoneParser{
		scanner:      s,
		defaultTTL:   3600,
		defaultClass: dns.ClassIN,
		records:      make(map[string]dns.RRSets),
	}
}

func (p *zoneParser) parseAll() error {
	for p.scanner.Scan() {
		rawLine := p.scanner.Text()

		// Fast-Path
		if p.parenCount == 0 && !p.inQuote &&
			strings.IndexByte(rawLine, '"') == -1 &&
			strings.IndexByte(rawLine, '(') == -1 &&
			strings.IndexByte(rawLine, ')') == -1 {
			if idx := strings.IndexByte(rawLine, ';'); idx != -1 {
				rawLine = rawLine[:idx]
			}
			trimmed := strings.TrimSpace(rawLine)
			if trimmed == "" {
				continue
			}

			fields := strings.Fields(trimmed)
			if len(fields) == 0 {
				continue
			}

			if err := p.processRecordTokens(fields); err != nil {
				return err
			}
			continue
		}

		// Slow-Path
		lineTokens, err := p.tokenizeComplexLine(rawLine)
		if err != nil {
			return err
		}

		p.complexTokens = append(p.complexTokens, lineTokens...)

		// Execute and flush when multiline context closes
		if p.parenCount == 0 && !p.inQuote && len(p.complexTokens) > 0 {
			if err := p.processRecordTokens(p.complexTokens); err != nil {
				return err
			}
			p.complexTokens = p.complexTokens[:0]
		}
	}

	if p.inQuote {
		return fmt.Errorf("%w: %w", ErrInvalidZoneFile, ErrUnclosedQuote)
	}

	if p.parenCount > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidZoneFile, ErrUnclosedParenthesis)
	}

	if err := p.scanner.Err(); err != nil {
		return fmt.Errorf("zone: scan error: %w", err)
	}

	return nil
}

func (p *zoneParser) tokenizeComplexLine(line string) ([]string, error) {
	var tokens []string
	var token strings.Builder

	i := 0
	n := len(line)
	for i < n {
		ch := line[i]

		if p.inQuote {
			if ch == '\\' && i+1 < n {
				p.quoteBuf.WriteByte(ch)
				p.quoteBuf.WriteByte(line[i+1])
				i += 2
				continue
			}
			p.quoteBuf.WriteByte(ch)
			if ch == '"' {
				p.inQuote = false
				tokens = append(tokens, p.quoteBuf.String())
				p.quoteBuf.Reset()
			}
			i++
			continue
		}

		if ch == ';' {
			break
		}

		if ch == '(' {
			p.parenCount++
			i++
			continue
		}

		if ch == ')' {
			p.parenCount--
			if p.parenCount < 0 {
				return nil, fmt.Errorf("%w: %w", ErrInvalidZoneFile, ErrUnmatchedParenthesis)
			}
			i++
			continue
		}

		if ch == '"' {
			p.inQuote = true
			p.quoteBuf.WriteByte('"')
			i++
			continue
		}

		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			if token.Len() > 0 {
				tokens = append(tokens, token.String())
				token.Reset()
			}
			i++
			continue
		}

		if ch == '\\' && i+1 < n {
			token.WriteByte(ch)
			token.WriteByte(line[i+1])
			i += 2
			continue
		}

		token.WriteByte(ch)
		i++
	}

	if token.Len() > 0 {
		tokens = append(tokens, token.String())
	}

	return tokens, nil
}

type parsedHeader struct {
	rawName  string
	ttl      uint32
	class    dns.Class
	hasOwner bool
}

func (p *zoneParser) processRecordTokens(tokens []string) error {
	if len(tokens) == 0 {
		return nil
	}

	handled, err := p.processDirective(tokens)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	typeIdx, qType, err := findRecordTypeIndex(tokens)
	if err != nil {
		return fmt.Errorf("%w: %w: %w", ErrInvalidZoneFile, ErrMalformedLine, err)
	}

	header, err := p.parseRecordHeader(tokens[:typeIdx])
	if err != nil {
		return err
	}

	name, resolveErr := p.resolveOwnerName(header.rawName, header.hasOwner)
	if resolveErr != nil {
		return resolveErr
	}

	rdata := strings.Join(tokens[typeIdx+1:], " ")
	if rdata == "" {
		return fmt.Errorf("%w: %w: missing rdata for type %v on %q", ErrInvalidZoneFile, ErrMalformedLine, qType, name)
	}

	wireBytes, err := dns.PackRData(qType, rdata)
	if err != nil {
		return fmt.Errorf("%w: failed to build wire RData for type %v %q on %q: %w", ErrInvalidZoneFile, qType, rdata, name, err)
	}

	sets := p.records[name]
	p.records[name] = appendOrUpdateRRSet(sets, qType, header.class, header.ttl, wireBytes)
	return nil
}

func (p *zoneParser) processDirective(tokens []string) (bool, error) {
	if strings.EqualFold(tokens[0], "$TTL") {
		if len(tokens) < 2 {
			return true, fmt.Errorf("%w: %w: missing value", ErrInvalidZoneFile, ErrMalformedTTL)
		}
		ttl, ok := parseTTL(tokens[1])
		if !ok {
			return true, fmt.Errorf("%w: %w: invalid syntax", ErrInvalidZoneFile, ErrMalformedTTL)
		}
		p.defaultTTL = ttl
		return true, nil
	}

	if strings.EqualFold(tokens[0], "$ORIGIN") {
		if len(tokens) < 2 || tokens[1] == "" {
			return true, fmt.Errorf("%w: %w: missing value", ErrInvalidZoneFile, ErrMalformedOrigin)
		}
		normalized, err := normalizeName(tokens[1], "")
		if err != nil {
			return true, fmt.Errorf("%w: %w: %w", ErrInvalidZoneFile, ErrMalformedOrigin, err)
		}
		p.origin = normalized
		p.lastDomain = normalized
		return true, nil
	}

	return false, nil
}

func (p *zoneParser) parseRecordHeader(headerTokens []string) (parsedHeader, error) {
	res := parsedHeader{
		ttl:   p.defaultTTL,
		class: p.defaultClass,
	}
	hasExplicitTTL := false

	for _, tok := range headerTokens {
		if parsedTTL, ok := parseTTL(tok); ok && !hasExplicitTTL {
			res.ttl = parsedTTL
			hasExplicitTTL = true
			continue
		}
		if parsedClass, ok := parseClass(tok); ok {
			res.class = parsedClass
			p.defaultClass = res.class
			continue
		}
		if !res.hasOwner {
			res.rawName = tok
			res.hasOwner = true
			continue
		}
		return parsedHeader{}, fmt.Errorf("%w: %w: unexpected token %q in record header", ErrInvalidZoneFile, ErrMalformedLine, tok)
	}
	return res, nil
}

func (p *zoneParser) resolveOwnerName(rawName string, hasOwner bool) (string, error) {
	if hasOwner {
		resolved, err := resolveDomainName(rawName, p.origin)
		if err != nil {
			return "", fmt.Errorf("%w: %w: %w", ErrInvalidZoneFile, ErrMalformedLine, err)
		}
		p.lastDomain = resolved
		return resolved, nil
	}

	if p.lastDomain != "" {
		return p.lastDomain, nil
	}
	if p.origin != "" {
		return p.origin, nil
	}
	return "", fmt.Errorf("%w: %w: omitted owner name with no preceding domain or origin", ErrInvalidZoneFile, ErrMalformedLine)
}

func findRecordTypeIndex(tokens []string) (int, dns.Type, error) {
	if len(tokens) < 2 {
		return -1, 0, errors.New("insufficient tokens for resource record")
	}

	maxIdx := min(len(tokens)-1, 3)
	for i := maxIdx; i >= 0; i-- {
		qt, ok := isTypeToken(tokens[i])
		if !ok {
			continue
		}
		if i+1 >= len(tokens) {
			return -1, 0, fmt.Errorf("%w: missing RDATA for type %v", ErrMalformedLine, qt)
		}
		if isValidPrefix(tokens[:i]) {
			return i, qt, nil
		}
	}

	return -1, 0, ErrUnknownQueryType
}

func isTypeToken(s string) (dns.Type, bool) {
	if s == "" {
		return 0, false
	}
	if _, ok := parseTTL(s); ok {
		return 0, false
	}
	if _, ok := parseClass(s); ok {
		return 0, false
	}
	qt, err := parseType(s)
	if err != nil {
		return 0, false
	}
	return qt, true
}

func isValidPrefix(prefix []string) bool {
	if len(prefix) > 3 {
		return false
	}
	var hasOwner, hasTTL, hasClass bool
	for _, tok := range prefix {
		if _, ok := parseTTL(tok); ok && !hasTTL {
			hasTTL = true
			continue
		}
		if _, ok := parseClass(tok); ok && !hasClass {
			hasClass = true
			continue
		}
		if !hasOwner {
			hasOwner = true
			continue
		}
		return false
	}
	return true
}

func parseTTL(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	var mult uint64 = 1
	last := s[len(s)-1]
	switch last {
	case 's', 'S':
		s = s[:len(s)-1]
	case 'm', 'M':
		mult = 60
		s = s[:len(s)-1]
	case 'h', 'H':
		mult = 3600
		s = s[:len(s)-1]
	case 'd', 'D':
		mult = 86400
		s = s[:len(s)-1]
	case 'w', 'W':
		mult = 604800
		s = s[:len(s)-1]
	}
	if s == "" {
		return 0, false
	}
	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	total := val * mult
	if total > 0xFFFFFFFF {
		return 0, false
	}
	return uint32(total), true
}

func parseClass(s string) (dns.Class, bool) {
	if strings.EqualFold(s, "IN") {
		return dns.ClassIN, true
	}
	return 0, false
}

func resolveDomainName(rawName, origin string) (string, error) {
	if rawName == "@" {
		if origin == "" {
			return "", nil
		}
		return origin, nil
	}

	if rawName == "." {
		return "", nil
	}

	if !strings.HasSuffix(rawName, ".") && origin != "" {
		rawName = rawName + "." + origin
	}

	return normalizeName(rawName, "")
}

func normalizeName(name, origin string) (string, error) {
	if !strings.HasSuffix(name, ".") && origin != "" {
		name = name + "." + origin
	}

	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)

	if len(name) > dns.MaxNameLen {
		return "", dns.ErrNameTooLong
	}

	if name != "" {
		for label := range strings.SplitSeq(name, ".") {
			if len(label) > dns.MaxLabelLen {
				return "", dns.ErrLabelTooLong
			}
		}
	}

	return name, nil
}

func parseType(s string) (dns.Type, error) {
	q, err := dns.ParseType(s)
	if err != nil {
		return 0, fmt.Errorf("zone: %w", err)
	}
	return q, nil
}

func appendOrUpdateRRSet(sets dns.RRSets, qType dns.Type, class dns.Class, ttl uint32, wireBytes []byte) dns.RRSets {
	for i, set := range sets {
		if set.Type == qType {
			sets[i].RData = append(sets[i].RData, wireBytes)
			return sets
		}
	}
	return append(sets, dns.RRSet{
		Type:  qType,
		Class: class,
		TTL:   ttl,
		RData: [][]byte{wireBytes},
	})
}
