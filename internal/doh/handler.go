// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package doh

import (
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	contentTypeDoH = "application/dns-message"
)

func (s *Server) handleProbe(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	if s.resolver == nil {
		http.Error(w, "DNS resolver unconfigured", http.StatusServiceUnavailable)
		return
	}

	reqData, ok := s.extractDoHPayload(w, r)
	if !ok {
		return
	}

	if s.metrics != nil {
		s.metrics.IncQueriesDoH()
		s.metrics.AddBytesInDoH(uint64(len(reqData)))
	}

	var msg dns.Message
	respBufPtr := dohBufPool.Get().(*[]byte)
	respBuf := *respBufPtr
	defer dohBufPool.Put(respBufPtr)

	if err := msg.Unpack(reqData); err != nil {
		s.handleUnpackError(w, &msg, respBuf, err)
		return
	}

	if msg.Header.IsResponse() || len(msg.Questions) == 0 {
		http.Error(w, "invalid dns query", http.StatusBadRequest)
		return
	}

	res := s.resolveDoHQuery(&msg)
	maxPayloadSize := dns.MaxPayloadSize(dns.MaxTCPSize, msg.EDNS0Size)
	written, err := msg.PackResponse(respBuf, res, maxPayloadSize)
	if err != nil || written == 0 {
		s.logger.Error("failed to pack DoH response", slog.Any("error", err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	minTTL := calculateResponseTTL(res)
	w.Header().Set("Content-Type", contentTypeDoH)
	w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(minTTL), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBuf[:written])
	if s.metrics != nil && written > 0 {
		// #nosec G115
		s.metrics.AddBytesOutDoH(uint64(written))
	}
}

func (s *Server) extractDoHPayload(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Method == http.MethodGet {
		return decodeGetPayload(w, r)
	}
	if r.Method == http.MethodPost {
		return readPostPayload(w, r)
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return nil, false
}

func decodeGetPayload(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	dnsParam := r.URL.Query().Get("dns")
	if dnsParam == "" {
		http.Error(w, "missing 'dns' query parameter", http.StatusBadRequest)
		return nil, false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(dnsParam)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "invalid base64url encoding", http.StatusBadRequest)
			return nil, false
		}
	}
	if len(decoded) == 0 || len(decoded) > dns.MaxTCPSize {
		http.Error(w, "invalid dns message length", http.StatusBadRequest)
		return nil, false
	}
	return decoded, true
}

func readPostPayload(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(ct), contentTypeDoH) {
		http.Error(w, "unsupported content type, expected "+contentTypeDoH, http.StatusUnsupportedMediaType)
		return nil, false
	}

	bodyReader := http.MaxBytesReader(w, r.Body, dns.MaxTCPSize)
	body, err := io.ReadAll(bodyReader)
	_ = bodyReader.Close()
	if err != nil {
		http.Error(w, "failed to read request body: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	if len(body) == 0 {
		http.Error(w, "empty request body", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func (s *Server) resolveDoHQuery(msg *dns.Message) dns.Result {
	q := msg.Questions[0]
	switch msg.Header.Opcode() {
	case dns.OpcodeQuery:
		if s.metrics != nil {
			s.metrics.IncQueryType(q.Type)
		}
		return s.resolver.Resolve(q.Name, q.Type)
	case dns.OpcodeUpdate:
		return dns.Result{RCode: dns.RCodeRefused}
	default:
		return dns.Result{RCode: dns.RCodeNotImplemented}
	}
}

func calculateResponseTTL(res dns.Result) uint32 {
	if res.HasAnswer() && res.Answer.TTL > 0 {
		return res.Answer.TTL
	}
	if res.HasAuthority() && res.Authority.TTL > 0 {
		return res.Authority.TTL
	}
	return 0
}

// handleUnpackError generates a compliant FORMERR or HTTP error response for malformed DoH payloads.
func (s *Server) handleUnpackError(w http.ResponseWriter, msg *dns.Message, respBuf []byte, err error) {
	if errors.Is(err, dns.ErrMultipleOPT) {
		res := dns.Result{RCode: dns.RCodeFormatError}
		written, packErr := msg.PackResponse(respBuf, res, dns.MaxTCPSize)
		if packErr == nil && written > 0 {
			w.Header().Set("Content-Type", contentTypeDoH)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBuf[:written])
			if s.metrics != nil {
				// #nosec G115
				s.metrics.AddBytesOutDoH(uint64(written))
			}
			return
		}
	}
	http.Error(w, "malformed dns message", http.StatusBadRequest)
}
