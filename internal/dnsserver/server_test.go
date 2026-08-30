// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

const headerSize = 12

type resolverKey struct {
	domain string
	qType  dns.Type
}

type fakeResolver struct {
	records map[resolverKey]dns.RRSet
	mu      sync.RWMutex
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{records: make(map[resolverKey]dns.RRSet)}
}

func newPopulatedFakeResolver() *fakeResolver {
	st := newFakeResolver()

	rA, _ := dns.PackRData(dns.TypeA, "1.2.3.4")
	rTxt, _ := dns.PackRData(dns.TypeTXT, "v=spf1 -all")
	rSOA, _ := dns.PackRData(dns.TypeSOA, "ns1.example.com. hostmaster.example.com. 2026081301 7200 3600 1209600 300")

	st.Add("example.com", dns.RRSet{
		Type:  dns.TypeSOA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: [][]byte{rSOA},
	})
	st.Add("example.com", dns.RRSet{
		Type:  dns.TypeA,
		Class: dns.ClassIN,
		TTL:   300,
		RData: [][]byte{rA},
	})
	st.Add("example.com", dns.RRSet{
		Type:  dns.TypeTXT,
		Class: dns.ClassIN,
		TTL:   300,
		RData: [][]byte{rTxt},
	})

	return st
}

func (f *fakeResolver) Resolve(domain string, qType dns.Type) dns.Result {
	norm := strings.ToLower(strings.TrimSuffix(domain, "."))
	f.mu.RLock()
	defer f.mu.RUnlock()

	rr, ok := f.records[resolverKey{domain: norm, qType: qType}]
	if ok {
		return dns.Result{
			RCode:  dns.RCodeSuccess,
			Answer: rr,
		}
	}

	if qType != dns.TypeCNAME {
		if cname, ok := f.records[resolverKey{domain: norm, qType: dns.TypeCNAME}]; ok {
			return dns.Result{
				RCode:  dns.RCodeSuccess,
				Answer: cname,
			}
		}
	}

	for k, v := range f.records {
		if k.domain != norm {
			continue
		}
		soaRecord, hasSOA := f.records[resolverKey{domain: norm, qType: dns.TypeSOA}]
		if k.qType == dns.TypeSOA {
			soaRecord = v
			hasSOA = true
		}
		var soa dns.RRSet
		if hasSOA {
			soa = soaRecord
		}
		return dns.Result{
			RCode:         dns.RCodeSuccess,
			Authority:     soa,
			AuthorityName: domain,
		}
	}

	return dns.Result{RCode: dns.RCodeNameError}
}

func (f *fakeResolver) Add(domain string, record dns.RRSet) {
	norm := strings.ToLower(strings.TrimSuffix(domain, "."))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[resolverKey{domain: norm, qType: record.Type}] = record
}

func (f *fakeResolver) Get(domain string) (dns.RRSets, bool) {
	norm := strings.ToLower(strings.TrimSuffix(domain, "."))
	f.mu.RLock()
	defer f.mu.RUnlock()
	var sets dns.RRSets
	for k, v := range f.records {
		if k.domain == norm {
			sets = append(sets, v)
		}
	}
	return sets, len(sets) > 0
}

type fakeUpsertDeleter struct {
	records map[string]dns.RRSets
	mu      sync.RWMutex
}

func newFakeUpsertDeleter() *fakeUpsertDeleter {
	return &fakeUpsertDeleter{records: make(map[string]dns.RRSets)}
}

func (s *fakeUpsertDeleter) Upsert(domain string, records dns.RRSets) error {
	norm := strings.ToLower(strings.TrimSuffix(domain, "."))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[norm] = records
	return nil
}

func (s *fakeUpsertDeleter) DeleteDomain(domain string) error {
	norm := strings.ToLower(strings.TrimSuffix(domain, "."))
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, norm)
	return nil
}

func (s *fakeUpsertDeleter) Record(domain string) (dns.RRSets, bool) {
	norm := strings.ToLower(strings.TrimSuffix(domain, "."))
	s.mu.RLock()
	defer s.mu.RUnlock()
	sets, ok := s.records[norm]
	return sets, ok
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())
	return addr
}

func dialContext(t *testing.T, network, addr string) net.Conn {
	t.Helper()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), network, addr)
	require.NoError(t, err)
	return conn
}

func buildQuery(tb testing.TB, name string, qType dns.Type) []byte {
	tb.Helper()
	buf := make([]byte, 0, headerSize+len(name)+8)

	var hdr [headerSize]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	buf = append(buf, hdr[:]...)

	buf = append(buf, encodeName(name)...)

	var qTypeClass [4]byte
	binary.BigEndian.PutUint16(qTypeClass[0:2], uint16(qType))
	binary.BigEndian.PutUint16(qTypeClass[2:4], uint16(dns.ClassIN))
	buf = append(buf, qTypeClass[:]...)

	return buf
}

func encodeName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i > start {
				label := name[start:i]
				// #nosec G115
				out = append(out, byte(len(label)))
				out = append(out, label...)
			}
			start = i + 1
		}
	}
	out = append(out, 0)
	return out
}

func tcpLenPrefixed(payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	// #nosec G115
	binary.BigEndian.PutUint16(out, uint16(len(payload)))
	copy(out[2:], payload)
	return out
}

func sendTCPQuery(t *testing.T, addr, domain string, qType dns.Type) dns.Message {
	t.Helper()
	queryBytes := buildQuery(t, domain, qType)

	conn := dialContext(t, "tcp", addr)
	defer func() { _ = conn.Close() }()

	_, err := conn.Write(tcpLenPrefixed(queryBytes))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	var lenBuf [2]byte
	_, err = io.ReadFull(conn, lenBuf[:])
	require.NoError(t, err)

	respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	_, err = io.ReadFull(conn, respBuf)
	require.NoError(t, err)

	var resp dns.Message
	require.NoError(t, resp.Unpack(respBuf))
	return resp
}

func sendUDPQuery(t *testing.T, addr, domain string, qType dns.Type) (dns.Message, error) {
	t.Helper()
	conn := dialContext(t, "udp", addr)
	defer func() { _ = conn.Close() }()

	queryBytes := buildQuery(t, domain, qType)
	_, err := conn.Write(queryBytes)
	if err != nil {
		return dns.Message{}, err
	}

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))

	respBuf := make([]byte, udpBufferSize)
	n, err := conn.Read(respBuf)
	if err != nil {
		return dns.Message{}, err
	}

	var msg dns.Message
	err = msg.Unpack(respBuf[:n])
	return msg, err
}

type testNode struct {
	addr    string
	dotAddr string
}

func startTestServer(t *testing.T, res resolver, tlsCfg *tls.Config) testNode {
	t.Helper()

	addr := freeUDPAddr(t)
	dotAddr := freeUDPAddr(t)

	opts := []Option{
		WithLogger(newTestLogger()),
		WithAddress(addr),
	}

	if tlsCfg != nil {
		opts = append(opts, WithTLSConfig(tlsCfg), WithDoTAddress(dotAddr))
	}

	s := New(res, opts...)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})

	go func() {
		defer close(done)
		_ = s.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	t.Cleanup(func() {
		cancel()
		s.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not shut down in time")
		}
	})

	return testNode{
		addr:    addr,
		dotAddr: dotAddr,
	}
}

type fakeTimeoutErr struct{ timeout bool }

func (e *fakeTimeoutErr) Error() string   { return "fake timeout error" }
func (e *fakeTimeoutErr) Timeout() bool   { return e.timeout }
func (e *fakeTimeoutErr) Temporary() bool { return false }

func TestServer_IsTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err  error
		name string
		want bool
	}{
		{name: "direct net.Error timeout", err: &fakeTimeoutErr{timeout: true}, want: true},
		{name: "direct net.Error non-timeout", err: &fakeTimeoutErr{timeout: false}, want: false},
		{name: "wrapped net.Error timeout", err: errors.Join(errors.New("context"), &fakeTimeoutErr{timeout: true}), want: true},
		{name: "non-net error", err: errors.New("plain error"), want: false},
		{name: "nil error", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isTimeout(tt.err))
		})
	}
}

func TestServer_Lifecycle(t *testing.T) {
	t.Parallel()

	t.Run("CloseBeforeStartDoesNotPanic", func(t *testing.T) {
		t.Parallel()
		s := New(newFakeResolver(), WithLogger(newTestLogger()))
		assert.NotPanics(t, func() {
			s.Close()
		})
	})

	t.Run("ConcurrentCloseAndStartHasNoRace", func(t *testing.T) {
		t.Parallel()
		s := New(newFakeResolver(), WithLogger(newTestLogger()), WithAddress(freeUDPAddr(t)))
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()

		var wg sync.WaitGroup
		wg.Go(func() {
			_ = s.Start(ctx)
		})
		wg.Go(func() {
			time.Sleep(10 * time.Millisecond)
			s.Close()
		})
		wg.Wait()
	})

	t.Run("Start_NilResolverReturnsError", func(t *testing.T) {
		t.Parallel()
		s := New(nil, WithLogger(newTestLogger()))
		err := s.Start(t.Context())
		require.ErrorIs(t, err, ErrNilResolver)
	})

	t.Run("ResolveWireTo_NilResolverReturnsError", func(t *testing.T) {
		t.Parallel()
		s := New(nil, WithLogger(newTestLogger()))
		var buf bytes.Buffer
		err := s.ResolveWireTo([]byte{0x01, 0x02}, &buf)
		require.ErrorIs(t, err, ErrNilResolver)
	})

	t.Run("WithUpsertDeleterOption", func(t *testing.T) {
		t.Parallel()
		s := New(newFakeResolver(), WithLogger(newTestLogger()), WithUpsertDeleter(nil))
		require.NotNil(t, s)
	})

	t.Run("Capabilities", func(t *testing.T) {
		t.Parallel()
		s := New(newFakeResolver(), WithLogger(newTestLogger()))
		assert.False(t, s.canUpdate())
		assert.False(t, s.canSign())
		assert.False(t, s.hasDoT())
		assert.False(t, s.hasRRL())

		s2 := New(newFakeResolver(),
			WithLogger(newTestLogger()),
			WithDoTAddress(":853"),
			WithTLSConfig(&tls.Config{}),
		)
		assert.True(t, s2.hasDoT())
	})

	t.Run("ResolveWireTo_ValidQuery", func(t *testing.T) {
		t.Parallel()
		res := newPopulatedFakeResolver()
		s := New(res, WithLogger(newTestLogger()))
		queryWire := buildQuery(t, "example.com", dns.TypeA)

		var buf bytes.Buffer
		err := s.ResolveWireTo(queryWire, &buf)
		require.NoError(t, err)
		assert.Greater(t, buf.Len(), 12)

		var respMsg dns.Message
		require.NoError(t, respMsg.Unpack(buf.Bytes()))
		assert.Equal(t, dns.RCodeSuccess, respMsg.Header.RCode())
		assert.Equal(t, uint16(1), respMsg.Header.ANCount)
	})
}

type customAddr struct{}

func (c customAddr) Network() string { return "custom" }
func (c customAddr) String() string  { return "custom:1234" }

func TestServer_ExtractIP(t *testing.T) {
	t.Parallel()

	udpAddr, err := net.ResolveUDPAddr("udp", "192.0.2.1:53")
	require.NoError(t, err)
	assert.True(t, extractIP(udpAddr).IsValid())

	tcpAddr, err := net.ResolveTCPAddr("tcp", "198.51.100.2:853")
	require.NoError(t, err)
	assert.True(t, extractIP(tcpAddr).IsValid())

	assert.False(t, extractIP(customAddr{}).IsValid())
}
