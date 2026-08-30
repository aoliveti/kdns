// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/dnssec"
	"github.com/aoliveti/kdns/internal/rrl"
	"github.com/aoliveti/kdns/internal/tsig"
)

func TestServer_ResolveHandler(t *testing.T) {
	t.Parallel()

	t.Run("TableDrivenQueries", func(t *testing.T) {
		var badHeaderZeroQuestions [headerSize]byte
		binary.BigEndian.PutUint16(badHeaderZeroQuestions[4:6], 0)

		var badHeaderTooManyQuestions [headerSize]byte
		binary.BigEndian.PutUint16(badHeaderTooManyQuestions[4:6], 11)

		tests := []struct {
			wantErr        error
			query          func(t *testing.T) []byte
			name           string
			transportLimit int
			respBufLen     int
			seedRecord     bool
		}{
			{
				name:           "malformed packet",
				query:          func(_ *testing.T) []byte { return []byte{0x00, 0x01, 0x02} },
				transportLimit: dns.MaxUDPSize,
				wantErr:        ErrMalformedQuery,
			},
			{
				name:           "zero questions",
				query:          func(_ *testing.T) []byte { return badHeaderZeroQuestions[:] },
				transportLimit: dns.MaxUDPSize,
				wantErr:        ErrMalformedQuery,
			},
			{
				name:           "too many questions",
				query:          func(_ *testing.T) []byte { return badHeaderTooManyQuestions[:] },
				transportLimit: dns.MaxUDPSize,
				wantErr:        ErrMalformedQuery,
			},
			{
				name:           "known name returns success",
				seedRecord:     true,
				query:          func(t *testing.T) []byte { return buildQuery(t, "example.com", dns.TypeA) },
				transportLimit: dns.MaxUDPSize,
				wantErr:        nil,
			},
			{
				name:           "unknown name returns NXDOMAIN success",
				query:          func(t *testing.T) []byte { return buildQuery(t, "nonexistent.example", dns.TypeA) },
				transportLimit: dns.MaxUDPSize,
				wantErr:        nil,
			},
			{
				name: "non-standard opcode returns RCodeNotImplemented",
				query: func(t *testing.T) []byte {
					q := buildQuery(t, "example.com", dns.TypeA)
					binary.BigEndian.PutUint16(q[2:4], 0x2800)
					return q
				},
				transportLimit: dns.MaxUDPSize,
				wantErr:        nil,
			},
			{
				name:           "response buffer too small",
				seedRecord:     true,
				query:          func(t *testing.T) []byte { return buildQuery(t, "example.com", dns.TypeA) },
				transportLimit: dns.MaxUDPSize,
				respBufLen:     1,
				wantErr:        ErrSerialization,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				st := newFakeResolver()

				if tt.seedRecord {
					r1, _ := dns.PackRData(dns.TypeA, "1.2.3.4")
					st.Add("example.com", dns.RRSet{
						Type:  dns.TypeA,
						Class: dns.ClassIN,
						TTL:   300,
						RData: [][]byte{r1},
					})
				}

				s := New(st, WithLogger(newTestLogger()))

				respBufLen := tt.respBufLen
				if respBufLen == 0 {
					respBufLen = udpBufferSize
				}

				respBuf := make([]byte, respBufLen)
				written, _, _, err := s.resolve(tt.query(t), respBuf, tt.transportLimit)

				if tt.wantErr != nil {
					assert.Zero(t, written)
					require.Error(t, err)
					assert.ErrorIs(t, err, tt.wantErr)
					return
				}

				require.NoError(t, err)
				assert.Positive(t, written)
			})
		}
	})

	t.Run("EDNS0OptRecord", func(t *testing.T) {
		t.Parallel()

		st := newFakeResolver()

		r1, _ := dns.PackRData(dns.TypeA, "1.2.3.4")
		st.Add("example.com", dns.RRSet{
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: [][]byte{r1},
		})

		s := New(st, WithLogger(newTestLogger()))

		query := buildQuery(t, "example.com", dns.TypeA)
		binary.BigEndian.PutUint16(query[10:12], 1)
		optRecord := []byte{0x00, 0x00, 41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		query = append(query, optRecord...)

		respBuf := make([]byte, udpBufferSize)
		written, _, _, err := s.resolve(query, respBuf, dns.MaxUDPSize)

		require.NoError(t, err)
		assert.Positive(t, written)

		var msg dns.Message
		err = msg.Unpack(respBuf[:written])
		require.NoError(t, err)
		assert.Equal(t, uint16(1), msg.Header.ARCount)
	})
}

func TestServer_ProtocolSemantics(t *testing.T) {
	t.Parallel()

	st := newFakeResolver()

	rTxt, _ := dns.PackRData(dns.TypeTXT, "v=spf1 -all")
	rCname, _ := dns.PackRData(dns.TypeCNAME, "target.example.com")

	st.Add("example.com", dns.RRSet{
		Type:  dns.TypeTXT,
		Class: dns.ClassIN,
		TTL:   300,
		RData: [][]byte{rTxt},
	})
	st.Add("alias.example.com", dns.RRSet{
		Type:  dns.TypeCNAME,
		Class: dns.ClassIN,
		TTL:   300,
		RData: [][]byte{rCname},
	})

	node := startTestServer(t, st, nil)

	t.Run("NODATA_ExistingDomainAbsentTypeReturnsNOERROR", func(t *testing.T) {
		t.Parallel()
		resp := sendTCPQuery(t, node.addr, "example.com", dns.TypeA)
		rCode := dns.RCode(resp.Header.Flags & 0x0F)
		assert.Equal(t, dns.RCodeSuccess, rCode)
		assert.Equal(t, uint16(0), resp.Header.ANCount)
	})

	t.Run("NXDOMAIN_AbsentNameReturnsRCode3", func(t *testing.T) {
		t.Parallel()
		resp := sendTCPQuery(t, node.addr, "nonexistent.example.com", dns.TypeA)
		rCode := dns.RCode(resp.Header.Flags & 0x0F)
		assert.Equal(t, dns.RCodeNameError, rCode)
	})

	t.Run("CNAMETransparency_QueryingAonCNAMEReturnsCNAME", func(t *testing.T) {
		t.Parallel()
		resp := sendTCPQuery(t, node.addr, "alias.example.com", dns.TypeA)
		rCode := dns.RCode(resp.Header.Flags & 0x0F)
		assert.Equal(t, dns.RCodeSuccess, rCode)
		assert.Equal(t, uint16(1), resp.Header.ANCount)
	})

	t.Run("AntiReflection_DropIncomingResponsePackets", func(t *testing.T) {
		t.Parallel()
		conn := dialContext(t, "udp", node.addr)
		defer func() { _ = conn.Close() }()

		qrPacket := []byte{
			0x12, 0x34, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
		}

		_, err := conn.Write(qrPacket)
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(200*time.Millisecond)))

		buf := make([]byte, 512)
		_, err = conn.Read(buf)
		require.Error(t, err)
	})

	t.Run("RRL_RateLimitingAndSlip", func(t *testing.T) {
		rrlLimiter := rrl.New(rrl.Config{
			ResponsesPerSecond: 2,
			ErrorsPerSecond:    1,
			SlipRate:           2,
			TableSize:          1024,
			IPv4Prefix:         24,
			IPv6Prefix:         56,
		})

		addr := freeUDPAddr(t)
		rrlSrv := New(st, WithLogger(newTestLogger()), WithAddress(addr), WithRRL(rrlLimiter))
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})

		go func() {
			defer close(done)
			_ = rrlSrv.Start(ctx)
		}()

		time.Sleep(50 * time.Millisecond)

		defer func() {
			cancel()
			rrlSrv.Close()
			<-done
		}()

		conn := dialContext(t, "udp", addr)
		defer func() { _ = conn.Close() }()

		reqPacket := buildQuery(t, "example.com", dns.TypeA)
		buf := make([]byte, udpBufferSize)

		_, err := conn.Write(reqPacket)
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		n, err := conn.Read(buf)
		require.NoError(t, err)

		var msg1 dns.Message
		require.NoError(t, msg1.Unpack(buf[:n]))
		assert.Equal(t, dns.RCodeSuccess, dns.RCode(msg1.Header.Flags&0x0F))
		assert.Equal(t, uint16(0), msg1.Header.Flags&0x0200)

		_, err = conn.Write(reqPacket)
		require.NoError(t, err)

		n, err = conn.Read(buf)
		require.NoError(t, err)

		var msg2 dns.Message
		require.NoError(t, msg2.Unpack(buf[:n]))
		assert.Equal(t, dns.RCodeSuccess, dns.RCode(msg2.Header.Flags&0x0F))

		_, err = conn.Write(reqPacket)
		require.NoError(t, err)

		_, err = conn.Write(reqPacket)
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		n, err = conn.Read(buf)
		require.NoError(t, err)

		var slipMsg dns.Message
		require.NoError(t, slipMsg.Unpack(buf[:n]))
		assert.True(t, slipMsg.Header.Flags&0x0200 != 0)
		assert.Equal(t, uint16(0), slipMsg.Header.ANCount)
	})
}

func TestServer_TSIGAuthentication(t *testing.T) {
	t.Parallel()

	st := newPopulatedFakeResolver()
	kr := tsig.NewKeyRing()
	key := tsig.Key{
		Name:      "test-key.kdns.",
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("my-secret-key-12345"),
	}
	kr.Add(key)

	s := New(st, WithLogger(newTestLogger()), WithTSIGKeyRing(kr))

	t.Run("ValidTSIGSignedQuery_ReturnsSignedResponse", func(t *testing.T) {
		t.Parallel()
		queryWire := buildQuery(t, "example.com", dns.TypeA)
		var signedBuf [4096]byte
		copy(signedBuf[:], queryWire)

		signedLen, err := tsig.Sign(signedBuf[:], len(queryWire), nil, key, 0, time.Now())
		require.NoError(t, err)

		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(signedBuf[:signedLen], respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		// Response should contain TSIG record in Additional
		tsigRec, _, err := tsig.Extract(respBuf[:written])
		require.NoError(t, err)
		require.NotNil(t, tsigRec)
		assert.Equal(t, "test-key.kdns.", tsigRec.Name)
	})

	t.Run("InvalidTSIGSignature_ReturnsNotAuth", func(t *testing.T) {
		t.Parallel()
		queryWire := buildQuery(t, "example.com", dns.TypeA)
		var signedBuf [4096]byte
		copy(signedBuf[:], queryWire)

		wrongKey := tsig.Key{
			Name:      "test-key.kdns.",
			Algorithm: tsig.HMACSHA256,
			Secret:    []byte("wrong-secret"),
		}
		signedLen, err := tsig.Sign(signedBuf[:], len(queryWire), nil, wrongKey, 0, time.Now())
		require.NoError(t, err)

		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(signedBuf[:signedLen], respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNotAuth, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, dns.RCodeNotAuth, msg.Header.RCode())
	})
}

func buildDOQuery(tb testing.TB, name string, qType dns.Type) []byte {
	tb.Helper()
	buf := make([]byte, 0, headerSize+len(name)+8+11)

	var hdr [headerSize]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	binary.BigEndian.PutUint16(hdr[10:12], 1)    // ARCOUNT=1 (OPT)
	buf = append(buf, hdr[:]...)

	buf = append(buf, encodeName(name)...)

	var qTypeClass [4]byte
	binary.BigEndian.PutUint16(qTypeClass[0:2], uint16(qType))
	binary.BigEndian.PutUint16(qTypeClass[2:4], uint16(dns.ClassIN))
	buf = append(buf, qTypeClass[:]...)

	// EDNS0 OPT RR with DO=1
	var opt [11]byte
	opt[0] = 0 // Root domain
	binary.BigEndian.PutUint16(opt[1:3], uint16(dns.TypeOPT))
	binary.BigEndian.PutUint16(opt[3:5], 4096)   // UDP size
	opt[5] = 0                                   // Extended RCode
	opt[6] = 0                                   // EDNS0 version
	binary.BigEndian.PutUint16(opt[7:9], 0x8000) // Flags (DO=1)
	binary.BigEndian.PutUint16(opt[9:11], 0)     // RDLENGTH=0
	buf = append(buf, opt[:]...)

	return buf
}

func TestServer_DNSSECResolution(t *testing.T) {
	t.Parallel()

	st := newPopulatedFakeResolver()
	mgr := dnssec.NewManager()
	key, err := dnssec.NewECDSAKey("example.com", dnssec.FlagZSK)
	require.NoError(t, err)
	mgr.Add(key)

	s := New(st, WithLogger(newTestLogger()), WithDNSSEC(mgr))

	t.Run("QueryWithDO_ReturnsAnswerAndRRSIG", func(t *testing.T) {
		t.Parallel()
		queryWire := buildDOQuery(t, "example.com", dns.TypeA)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(queryWire, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		// 1 A record + 1 RRSIG record in Answer section
		assert.Equal(t, uint16(2), msg.Header.ANCount)
		assert.True(t, msg.DO)
	})

	t.Run("QueryWithoutDO_ReturnsOnlyAnswer", func(t *testing.T) {
		t.Parallel()
		queryWire := buildQuery(t, "example.com", dns.TypeA)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(queryWire, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, uint16(1), msg.Header.ANCount)
		assert.False(t, msg.DO)
	})

	t.Run("NXDOMAINWithDO_ReturnsNSECAndRRSIGInAuthority", func(t *testing.T) {
		t.Parallel()
		queryWire := buildDOQuery(t, "nonexistent.example.com", dns.TypeA)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(queryWire, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNameError, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		// 1 NSEC + 1 RRSIG in Authority section
		assert.Equal(t, uint16(2), msg.Header.NSCount)
		assert.True(t, msg.DO)
	})
}

func buildRFC2136UpdatePacket(tb testing.TB, zone, recordName string, qType dns.Type, rData []byte) []byte {
	tb.Helper()
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 0x1234)
	binary.BigEndian.PutUint16(buf[2:4], 0x2800) // OpcodeUpdate
	binary.BigEndian.PutUint16(buf[4:6], 1)      // Zone section (QDCOUNT)

	// Zone section
	buf = append(buf, encodeName(zone)...)
	var zTypeClass [4]byte
	binary.BigEndian.PutUint16(zTypeClass[0:2], uint16(dns.TypeSOA))
	binary.BigEndian.PutUint16(zTypeClass[2:4], uint16(dns.ClassIN))
	buf = append(buf, zTypeClass[:]...)

	// Update section: add 1 record
	buf = append(buf, encodeName(recordName)...)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(qType))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dns.ClassIN))
	binary.BigEndian.PutUint32(hdr[4:8], 300)
	rDataLen := min(len(rData), 65535)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(rDataLen))
	buf = append(buf, hdr[:]...)
	buf = append(buf, rData[:rDataLen]...)

	// Update section count (NSCOUNT)
	binary.BigEndian.PutUint16(buf[8:10], 1)
	return buf
}

func TestServer_RFC2136_SecurityHardening(t *testing.T) {
	t.Parallel()

	rData, err := dns.PackRData(dns.TypeA, "10.0.0.1")
	require.NoError(t, err)

	updateWire := buildRFC2136UpdatePacket(t, "example.com", "dynamic.example.com", dns.TypeA, rData)

	validKey := tsig.Key{
		Name:      "admin-key.kdns.",
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("secret-key-12345"),
	}

	t.Run("UnsignedUpdate_WhenKeyringConfigured_RejectedWithNotAuth", func(t *testing.T) {
		t.Parallel()
		kr := tsig.NewKeyRing()
		kr.Add(validKey)
		res := newPopulatedFakeResolver()
		ud := newFakeUpsertDeleter()
		s := New(res, WithLogger(newTestLogger()), WithTSIGKeyRing(kr), WithUpsertDeleter(ud))

		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(updateWire, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNotAuth, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, dns.RCodeNotAuth, msg.Header.RCode())
	})

	t.Run("UnsignedUpdate_WhenNoKeyringConfigured_RejectedWithRefused", func(t *testing.T) {
		t.Parallel()
		res := newPopulatedFakeResolver()
		ud := newFakeUpsertDeleter()
		s := New(res, WithLogger(newTestLogger()), WithUpsertDeleter(ud))

		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(updateWire, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeRefused, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, dns.RCodeRefused, msg.Header.RCode())
	})

	t.Run("SignedUpdate_WithUnknownTSIGKey_RejectedWithNotAuth", func(t *testing.T) {
		t.Parallel()
		kr := tsig.NewKeyRing()
		kr.Add(validKey)
		res := newPopulatedFakeResolver()
		ud := newFakeUpsertDeleter()
		s := New(res, WithLogger(newTestLogger()), WithTSIGKeyRing(kr), WithUpsertDeleter(ud))

		unknownKey := tsig.Key{
			Name:      "unknown-key.kdns.",
			Algorithm: tsig.HMACSHA256,
			Secret:    []byte("some-secret"),
		}
		var signedBuf [4096]byte
		copy(signedBuf[:], updateWire)
		signedLen, signErr := tsig.Sign(signedBuf[:], len(updateWire), nil, unknownKey, 0, time.Now())
		require.NoError(t, signErr)

		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(signedBuf[:signedLen], respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNotAuth, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, dns.RCodeNotAuth, msg.Header.RCode())
	})

	t.Run("SignedUpdate_WithCorruptedSignature_RejectedWithNotAuth", func(t *testing.T) {
		t.Parallel()
		kr := tsig.NewKeyRing()
		kr.Add(validKey)
		res := newPopulatedFakeResolver()
		ud := newFakeUpsertDeleter()
		s := New(res, WithLogger(newTestLogger()), WithTSIGKeyRing(kr), WithUpsertDeleter(ud))

		tamperedKey := tsig.Key{
			Name:      "admin-key.kdns.",
			Algorithm: tsig.HMACSHA256,
			Secret:    []byte("wrong-signature-secret"),
		}
		var signedBuf [4096]byte
		copy(signedBuf[:], updateWire)
		signedLen, signErr := tsig.Sign(signedBuf[:], len(updateWire), nil, tamperedKey, 0, time.Now())
		require.NoError(t, signErr)

		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(signedBuf[:signedLen], respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNotAuth, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, dns.RCodeNotAuth, msg.Header.RCode())
	})

	t.Run("SignedUpdate_WithValidTSIGSignature_AcceptedAndApplied", func(t *testing.T) {
		t.Parallel()
		kr := tsig.NewKeyRing()
		kr.Add(validKey)
		res := newPopulatedFakeResolver()
		ud := newFakeUpsertDeleter()
		s := New(res, WithLogger(newTestLogger()), WithTSIGKeyRing(kr), WithUpsertDeleter(ud))

		var signedBuf [4096]byte
		copy(signedBuf[:], updateWire)
		signedLen, signErr := tsig.Sign(signedBuf[:], len(updateWire), nil, validKey, 0, time.Now())
		require.NoError(t, signErr)

		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(signedBuf[:signedLen], respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, dns.RCodeSuccess, msg.Header.RCode())

		// Verify record was inserted into store
		records, found := ud.Record("dynamic.example.com")
		require.True(t, found)
		require.NotEmpty(t, records)
		assert.Equal(t, dns.TypeA, records[0].Type)
	})

	t.Run("Update_WithoutUpsertDeleter_ReturnsRefused", func(t *testing.T) {
		t.Parallel()
		kr := tsig.NewKeyRing()
		kr.Add(validKey)
		res := newPopulatedFakeResolver()
		// Server without WithUpsertDeleter (read-only replica)
		s := New(res, WithLogger(newTestLogger()), WithTSIGKeyRing(kr))

		var signedBuf [4096]byte
		copy(signedBuf[:], updateWire)
		signedLen, signErr := tsig.Sign(signedBuf[:], len(updateWire), nil, validKey, 0, time.Now())
		require.NoError(t, signErr)

		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(signedBuf[:signedLen], respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeRefused, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, dns.RCodeRefused, msg.Header.RCode())
	})
}

func TestServer_MultipleOPT_ReturnsFORMERR(t *testing.T) {
	t.Parallel()

	res := newPopulatedFakeResolver()
	s := New(res, WithLogger(newTestLogger()))

	// Construct query with 2 OPT RRs in Additional section
	query := buildQuery(t, "example.com", dns.TypeA)
	// Add 2 OPT records
	binary.BigEndian.PutUint16(query[10:12], 2) // ARCount = 2
	optRR := []byte{0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0}
	query = append(query, optRR...)
	query = append(query, optRR...)

	var respBuf [4096]byte
	written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeFormatError, rCode)

	var msg dns.Message
	require.NoError(t, msg.Unpack(respBuf[:written]))
	assert.Equal(t, dns.RCodeFormatError, msg.Header.RCode())
}
