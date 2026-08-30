// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/rfc2136"
	"github.com/aoliveti/kdns/internal/tsig"
)

type tsigAuthResult struct {
	rec      *tsig.Record
	payload  []byte
	key      tsig.Key
	errCode  uint16
	present  bool
	keyFound bool
}

func (s *Server) resolve(queryBytes, respBuf []byte, transportSize int) (int, string, dns.RCode, error) {
	auth, err := s.authenticateTSIG(queryBytes)
	if err != nil {
		return 0, "", dns.RCodeFormatError, fmt.Errorf("%w: %w", ErrMalformedQuery, err)
	}

	var msg dns.Message
	if unpackErr := msg.Unpack(auth.payload); unpackErr != nil {
		if errors.Is(unpackErr, dns.ErrMultipleOPT) {
			written, optErr := s.handleMultipleOPT(&msg, respBuf)
			if optErr != nil {
				return 0, "", dns.RCodeFormatError, optErr
			}
			return written, "", dns.RCodeFormatError, nil
		}
		return 0, "", dns.RCodeFormatError, fmt.Errorf("%w: %w", ErrMalformedQuery, unpackErr)
	}

	if msg.Header.IsResponse() {
		return 0, "", 0, ErrResponsePacket
	}
	if len(msg.Questions) == 0 {
		return 0, "", dns.RCodeFormatError, fmt.Errorf("%w: zero questions found", ErrMalformedQuery)
	}

	q := msg.Questions[0]
	qName := q.Name
	var res dns.Result

	switch {
	case auth.present && auth.errCode != 0:
		res = dns.Result{RCode: dns.RCodeNotAuth}
	case msg.Header.Opcode() == dns.OpcodeQuery:
		s.metrics.IncQueryType(q.Type)
		res = s.handleQuery(q.Name, q.Type, q.Class, msg.DO)
	case msg.Header.Opcode() == dns.OpcodeUpdate:
		var updateErr error
		res, updateErr = s.handleUpdate(q.Name, auth.payload, auth.present, auth.errCode)
		if updateErr != nil {
			s.metrics.IncRFC2136("rejected")
			return 0, qName, dns.RCodeFormatError, fmt.Errorf("%w: %w", ErrMalformedQuery, updateErr)
		}
	default:
		res = dns.Result{RCode: dns.RCodeNotImplemented}
	}

	maxSize := dns.MaxPayloadSize(transportSize, msg.EDNS0Size)
	written, packErr := msg.PackResponse(respBuf, res, maxSize)
	if packErr != nil {
		return 0, qName, res.RCode, fmt.Errorf("%w: %w", ErrSerialization, packErr)
	}
	if written == 0 {
		return 0, qName, res.RCode, fmt.Errorf("%w: zero bytes packed", ErrSerialization)
	}

	if auth.present && auth.keyFound {
		signedLen, signErr := tsig.Sign(respBuf, written, auth.rec.MAC, auth.key, auth.errCode, time.Now())
		if signErr == nil {
			written = signedLen
		}
	}

	s.metrics.IncResponses(res.RCode)
	return written, qName, res.RCode, nil
}

func (s *Server) handleMultipleOPT(msg *dns.Message, respBuf []byte) (int, error) {
	res := dns.Result{RCode: dns.RCodeFormatError}
	written, packErr := msg.PackResponse(respBuf, res, dns.MaxUDPSize)
	if packErr != nil {
		return 0, fmt.Errorf("%w: %w", ErrSerialization, packErr)
	}
	s.metrics.IncResponses(dns.RCodeFormatError)
	return written, nil
}

func (s *Server) authenticateTSIG(queryBytes []byte) (tsigAuthResult, error) {
	rec, payloadWithoutTSIG, err := tsig.Extract(queryBytes)
	if err != nil {
		return tsigAuthResult{}, err
	}
	if rec == nil {
		return tsigAuthResult{payload: payloadWithoutTSIG}, nil
	}

	res := tsigAuthResult{
		rec:     rec,
		payload: payloadWithoutTSIG,
		present: true,
		errCode: dns.TSIGErrBadKey,
	}

	if s.tsigKeys != nil {
		if k, ok := s.tsigKeys.Key(rec.Name); ok {
			res.key = k
			res.keyFound = true
			res.errCode = 0
			if code, verifyErr := tsig.Verify(payloadWithoutTSIG, rec, k, time.Now()); verifyErr != nil {
				res.errCode = code
			}
		}
	}

	s.recordTSIGMetrics(rec, res.errCode)
	return res, nil
}

func (s *Server) recordTSIGMetrics(rec *tsig.Record, errCode uint16) {
	switch errCode {
	case 0:
		s.metrics.IncTSIG("ok")
	case dns.TSIGErrBadSig:
		s.metrics.IncTSIG("badsig")
		s.logger.Warn("tsig authentication failed",
			slog.String("key", rec.Name),
			slog.String("algorithm", rec.Algorithm),
			slog.String("error", "BADSIG"),
		)
	case dns.TSIGErrBadKey:
		s.metrics.IncTSIG("badkey")
		s.logger.Warn("tsig authentication failed",
			slog.String("key", rec.Name),
			slog.String("algorithm", rec.Algorithm),
			slog.String("error", "BADKEY"),
		)
	case dns.TSIGErrBadTime:
		s.metrics.IncTSIG("badtime")
		s.logger.Warn("tsig authentication failed",
			slog.String("key", rec.Name),
			slog.String("algorithm", rec.Algorithm),
			slog.String("error", "BADTIME"),
		)
	case dns.TSIGErrBadTrunc:
		s.metrics.IncTSIG("badalgo")
		s.logger.Warn("tsig authentication failed",
			slog.String("key", rec.Name),
			slog.String("algorithm", rec.Algorithm),
			slog.String("error", "BADTRUNC"),
		)
	default:
		s.metrics.IncTSIG("other")
	}
}

func (s *Server) handleQuery(name string, qType dns.Type, qClass dns.Class, do bool) dns.Result {
	if qClass == dns.ClassCH {
		return s.resolveCHAOS(name, qType)
	}

	res := s.res.Resolve(name, qType)
	if do {
		s.metrics.IncDNSSECQueries()
		if s.canSign() {
			s.signDNSSEC(name, qType, &res)
		}
	}
	return res
}

func (s *Server) signDNSSEC(name string, qType dns.Type, res *dns.Result) {
	s.dnssecMgr.SignResult(name, qType, res, time.Now())
	if res.HasAnswerRRSIG() {
		s.metrics.IncDNSSECSignatures()
	}
	if res.HasAuthorityRRSIG() {
		s.metrics.IncDNSSECSignatures()
	}
}

func (s *Server) handleUpdate(zone string, payload []byte, hasTSIG bool, tsigErr uint16) (dns.Result, error) {
	if !s.canUpdate() {
		s.metrics.IncRFC2136("rejected")
		return dns.Result{RCode: dns.RCodeRefused}, nil
	}
	if !hasTSIG || tsigErr != 0 {
		s.metrics.IncRFC2136("rejected")
		return dns.Result{RCode: dns.RCodeNotAuth}, nil
	}

	rCode, err := rfc2136.Process(payload, s.getter, s.upsertDeleter)
	if err != nil {
		return dns.Result{RCode: dns.RCodeFormatError}, err
	}

	if rCode != dns.RCodeSuccess {
		s.metrics.IncRFC2136("rejected")
		return dns.Result{RCode: rCode}, nil
	}

	s.metrics.IncRFC2136("success")
	s.logger.Info("rfc2136 dynamic update processed successfully", slog.String("zone", zone))
	return dns.Result{RCode: rCode}, nil
}
