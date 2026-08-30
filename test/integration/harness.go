// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/daemon"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/tsig"
)

var integrationHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
}

func freePort(t testing.TB) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func startNode(t *testing.T, cfg daemon.Config) {
	t.Helper()
	_ = startNodeWithStopper(t, cfg)
}

func startNodeWithStopper(t *testing.T, cfg daemon.Config) func() {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup

	logger := slog.New(slog.DiscardHandler)
	d, err := daemon.New(cfg, daemon.WithLogger(logger))
	require.NoError(t, err)

	wg.Go(func() {
		_ = d.Run(ctx)
	})

	var once sync.Once
	stopFn := func() {
		once.Do(func() {
			cancel()
			wg.Wait()
		})
	}

	t.Cleanup(func() {
		stopFn()
	})

	// Wait for server listeners to accept connections
	waitForPort(t, cfg.Network.Address)
	if cfg.Network.DoTAddr != "" {
		waitForPort(t, cfg.Network.DoTAddr)
	}
	if cfg.Network.DoHAddr != "" {
		waitForPort(t, cfg.Network.DoHAddr)
	}
	if cfg.HTTP.Addr != "" {
		waitForPort(t, cfg.HTTP.Addr)
	}
	if cfg.Cluster.Addr != "" {
		waitForPort(t, cfg.Cluster.Addr)
	}

	return stopFn
}

func waitForPort(t testing.TB, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var d net.Dialer
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		conn, err := d.DialContext(ctx, "tcp", addr)
		cancel()
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for port %s", addr)
}

func encodeDomain(domain string) []byte {
	var buf []byte
	for l := range strings.SplitSeq(strings.TrimSuffix(domain, "."), ".") {
		if l != "" {
			buf = append(buf, byte(min(len(l), 63)))
			buf = append(buf, l...)
		}
	}
	buf = append(buf, 0x00)
	return buf
}

func buildQuery(id uint16, domain string, qType dns.Type) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1

	buf = append(buf, encodeDomain(domain)...)

	var typeClass [4]byte
	binary.BigEndian.PutUint16(typeClass[0:2], uint16(qType))
	binary.BigEndian.PutUint16(typeClass[2:4], uint16(dns.ClassIN))
	buf = append(buf, typeClass[:]...)
	return buf
}

type dnsAnswer struct {
	RData []byte
	TTL   uint32
	Type  dns.Type
	Class dns.Class
}

type dnsResponse struct {
	Raw         []byte
	Answers     []dnsAnswer
	Authorities []dnsAnswer
	Header      dns.Header
}

func parseDNSResponse(raw []byte) (*dnsResponse, error) {
	if len(raw) < 12 {
		return nil, fmt.Errorf("packet too small: %d bytes", len(raw))
	}

	var msg dns.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, err
	}

	resp := &dnsResponse{
		Header: msg.Header,
		Raw:    raw,
	}

	// Parse answers and authorities sections
	offset := 12
	// Skip questions
	for range int(msg.Header.QDCount) {
		for offset < len(raw) {
			b := raw[offset]
			if b == 0 {
				offset++
				break
			}
			if b >= 0xC0 {
				offset += 2
				break
			}
			offset += int(b) + 1
		}
		offset += 4 // Type + Class
	}

	for range int(msg.Header.ANCount) {
		if offset >= len(raw) {
			break
		}
		for offset < len(raw) {
			b := raw[offset]
			if b == 0 {
				offset++
				break
			}
			if b >= 0xC0 {
				offset += 2
				break
			}
			offset += int(b) + 1
		}
		if offset+10 > len(raw) {
			break
		}
		aType := dns.Type(binary.BigEndian.Uint16(raw[offset : offset+2]))
		aClass := dns.Class(binary.BigEndian.Uint16(raw[offset+2 : offset+4]))
		aTTL := binary.BigEndian.Uint32(raw[offset+4 : offset+8])
		rdLen := int(binary.BigEndian.Uint16(raw[offset+8 : offset+10]))
		offset += 10

		if offset+rdLen > len(raw) {
			break
		}
		rData := raw[offset : offset+rdLen]
		offset += rdLen

		resp.Answers = append(resp.Answers, dnsAnswer{
			RData: rData,
			Type:  aType,
			Class: aClass,
			TTL:   aTTL,
		})
	}

	for range int(msg.Header.NSCount) {
		if offset >= len(raw) {
			break
		}
		for offset < len(raw) {
			b := raw[offset]
			if b == 0 {
				offset++
				break
			}
			if b >= 0xC0 {
				offset += 2
				break
			}
			offset += int(b) + 1
		}
		if offset+10 > len(raw) {
			break
		}
		nsType := dns.Type(binary.BigEndian.Uint16(raw[offset : offset+2]))
		nsClass := dns.Class(binary.BigEndian.Uint16(raw[offset+2 : offset+4]))
		nsTTL := binary.BigEndian.Uint32(raw[offset+4 : offset+8])
		rdLen := int(binary.BigEndian.Uint16(raw[offset+8 : offset+10]))
		offset += 10

		if offset+rdLen > len(raw) {
			break
		}
		rData := raw[offset : offset+rdLen]
		offset += rdLen

		resp.Authorities = append(resp.Authorities, dnsAnswer{
			RData: rData,
			Type:  nsType,
			Class: nsClass,
			TTL:   nsTTL,
		})
	}

	return resp, nil
}

func buildQueryWithEDNS0(id uint16, domain string, qType dns.Type, doBit bool) []byte {
	buf := buildQuery(id, domain, qType)
	var optHdr [10]byte
	binary.BigEndian.PutUint16(optHdr[0:2], uint16(dns.TypeOPT))
	binary.BigEndian.PutUint16(optHdr[2:4], 1232)
	optHdr[4] = 0
	optHdr[5] = 0
	if doBit {
		binary.BigEndian.PutUint16(optHdr[6:8], 0x8000) // DO bit
	}
	binary.BigEndian.PutUint16(optHdr[8:10], 0)

	buf[11] = 1 // ARCOUNT = 1
	buf = append(buf, 0x00)
	buf = append(buf, optHdr[:]...)
	return buf
}

func buildQueryCHAOS(id uint16, domain string, qType dns.Type) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1

	buf = append(buf, encodeDomain(domain)...)

	var typeClass [4]byte
	binary.BigEndian.PutUint16(typeClass[0:2], uint16(qType))
	binary.BigEndian.PutUint16(typeClass[2:4], uint16(dns.ClassCH))
	buf = append(buf, typeClass[:]...)
	return buf
}

func queryDNSUDPWithDO(t *testing.T, serverAddr, domain string, qType dns.Type) (*dnsResponse, error) {
	t.Helper()

	raw := buildQueryWithEDNS0(1234, domain, qType, true)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, writeErr := conn.Write(raw); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		return nil, readErr
	}

	return parseDNSResponse(buf[:n])
}

func queryDNSCHAOS(t *testing.T, serverAddr, domain string) (*dnsResponse, error) {
	t.Helper()

	raw := buildQueryCHAOS(4321, domain, dns.TypeTXT)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, writeErr := conn.Write(raw); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		return nil, readErr
	}

	return parseDNSResponse(buf[:n])
}

func queryDNSUDP(t *testing.T, serverAddr, domain string, qType dns.Type) (*dnsResponse, error) {
	t.Helper()
	return queryDNSUDPWithTimeout(t, serverAddr, domain, qType, 2*time.Second)
}

func queryDNSUDPWithTimeout(t *testing.T, serverAddr, domain string, qType dns.Type, timeout time.Duration) (*dnsResponse, error) {
	t.Helper()

	raw := buildQuery(1234, domain, qType)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, writeErr := conn.Write(raw); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		return nil, readErr
	}

	return parseDNSResponse(buf[:n])
}

func queryDNSTCP(t *testing.T, serverAddr, domain string, qType dns.Type) (*dnsResponse, error) {
	t.Helper()

	raw := buildQuery(5678, domain, qType)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(min(len(raw), 65535)))
	if _, writeErr := conn.Write(append(lenBuf[:], raw...)); writeErr != nil {
		return nil, writeErr
	}

	var respLenBuf [2]byte
	if _, readErr := io.ReadFull(conn, respLenBuf[:]); readErr != nil {
		return nil, readErr
	}
	respLen := binary.BigEndian.Uint16(respLenBuf[:])

	respBuf := make([]byte, respLen)
	if _, readErr := io.ReadFull(conn, respBuf); readErr != nil {
		return nil, readErr
	}

	return parseDNSResponse(respBuf)
}

func queryDoTTLS(t *testing.T, dotAddr, domain string, qType dns.Type, tlsCfg *tls.Config) (*dnsResponse, error) {
	t.Helper()

	raw := buildQuery(9012, domain, qType)

	var d tls.Dialer
	d.Config = tlsCfg
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", dotAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(min(len(raw), 65535)))
	if _, writeErr := conn.Write(append(lenBuf[:], raw...)); writeErr != nil {
		return nil, writeErr
	}

	var respLenBuf [2]byte
	if _, readErr := io.ReadFull(conn, respLenBuf[:]); readErr != nil {
		return nil, readErr
	}
	respLen := binary.BigEndian.Uint16(respLenBuf[:])

	respBuf := make([]byte, respLen)
	if _, readErr := io.ReadFull(conn, respBuf); readErr != nil {
		return nil, readErr
	}

	return parseDNSResponse(respBuf)
}

func queryDoHPOST(t *testing.T, dohAddr, domain string, qType dns.Type) (*dnsResponse, int, string, error) {
	t.Helper()

	raw := buildQuery(3456, domain, qType)
	url := fmt.Sprintf("http://%s/dns-query", dohAddr)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, "", err
	}

	cacheControl := resp.Header.Get("Cache-Control")
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, cacheControl, nil
	}

	dnsResp, err := parseDNSResponse(data)
	return dnsResp, resp.StatusCode, cacheControl, err
}

func queryDoHGET(t *testing.T, dohAddr, domain string, qType dns.Type) (*dnsResponse, int, string, error) {
	t.Helper()

	raw := buildQuery(7890, domain, qType)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	url := fmt.Sprintf("http://%s/dns-query?dns=%s", dohAddr, encoded)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, "", err
	}

	cacheControl := resp.Header.Get("Cache-Control")
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, cacheControl, nil
	}

	dnsResp, err := parseDNSResponse(data)
	return dnsResp, resp.StatusCode, cacheControl, err
}

func sendRFC2136Update(t *testing.T, serverAddr, zone, domain string, qType dns.Type, rData []byte, key *tsig.Key) (*dnsResponse, error) {
	t.Helper()

	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 0x4321)
	binary.BigEndian.PutUint16(buf[2:4], 0x2800) // OpcodeUpdate
	binary.BigEndian.PutUint16(buf[4:6], 1)      // Zone section (QDCOUNT)

	// Zone section
	buf = append(buf, encodeDomain(zone)...)
	var zTypeClass [4]byte
	binary.BigEndian.PutUint16(zTypeClass[0:2], uint16(dns.TypeSOA))
	binary.BigEndian.PutUint16(zTypeClass[2:4], uint16(dns.ClassIN))
	buf = append(buf, zTypeClass[:]...)

	// Update section (add 1 record)
	buf = append(buf, encodeDomain(domain)...)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(qType))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dns.ClassIN))
	binary.BigEndian.PutUint32(hdr[4:8], 300)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(min(len(rData), 65535)))
	buf = append(buf, hdr[:]...)
	buf = append(buf, rData...)

	// Set NSCOUNT = 1
	binary.BigEndian.PutUint16(buf[8:10], 1)

	if key != nil {
		var signedBuf [4096]byte
		copy(signedBuf[:], buf)
		signedLen, err := tsig.Sign(signedBuf[:], len(buf), nil, *key, 0, time.Now())
		if err != nil {
			return nil, err
		}
		buf = signedBuf[:signedLen]
	}

	var d net.Dialer
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, writeErr := conn.Write(buf); writeErr != nil {
		return nil, writeErr
	}

	respBuf := make([]byte, 4096)
	n, readErr := conn.Read(respBuf)
	if readErr != nil {
		return nil, readErr
	}

	return parseDNSResponse(respBuf[:n])
}

type apiRecord struct {
	Type  string   `json:"type"`
	RData []string `json:"rdata"`
	TTL   uint32   `json:"ttl"`
}

type upsertRequest struct {
	Records []apiRecord `json:"records"`
}

func putRecordHTTP(t *testing.T, httpAddr, token, domain string, records ...apiRecord) (int, error) {
	t.Helper()

	body, err := json.Marshal(upsertRequest{Records: records})
	if err != nil {
		return 0, err
	}

	url := fmt.Sprintf("http://%s/v1/records/%s", httpAddr, domain)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode, nil
}

func deleteRecordHTTP(t *testing.T, httpAddr, token, domain string) (int, error) {
	t.Helper()

	url := fmt.Sprintf("http://%s/v1/records/%s", httpAddr, domain)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, url, http.NoBody)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode, nil
}

func searchRecordsHTTP(t *testing.T, httpAddr, token, query string) (int, string, error) {
	t.Helper()

	url := fmt.Sprintf("http://%s/v1/records/search?q=%s", httpAddr, query)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(data), nil
}

func listRecordsHTTP(t *testing.T, httpAddr, token string, limit int, cursor string) (int, string, error) {
	t.Helper()

	url := fmt.Sprintf("http://%s/v1/records?limit=%d&cursor=%s", httpAddr, limit, cursor)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(data), nil
}

func getMetricsHTTP(t *testing.T, httpAddr, token string) (int, string, error) {
	t.Helper()

	url := fmt.Sprintf("http://%s/metrics", httpAddr)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(data), nil
}

func getLivezHTTP(t *testing.T, httpAddr string) (int, string, error) {
	t.Helper()

	url := fmt.Sprintf("http://%s/livez", httpAddr)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", err
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(data), nil
}

func getStartupzHTTP(t *testing.T, httpAddr string) (int, string, error) {
	t.Helper()

	url := fmt.Sprintf("http://%s/startupz", httpAddr)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", err
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(data), nil
}

func getReadyzHTTP(t *testing.T, httpAddr string) (int, string, error) {
	t.Helper()

	url := fmt.Sprintf("http://%s/readyz", httpAddr)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", err
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(data), nil
}

func exportZoneFileHTTP(t *testing.T, httpAddr, token, zone string) (int, string, string, error) {
	t.Helper()

	url := fmt.Sprintf("http://%s/v1/export/zonefile", httpAddr)
	if zone != "" {
		url += "?zone=" + zone
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, "", "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := integrationHTTPClient.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", "", err
	}

	contentType := resp.Header.Get("Content-Type")
	return resp.StatusCode, string(data), contentType, nil
}

func generateTLSCertFiles(t *testing.T, destDir string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"KDNS Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	destRoot, err := os.OpenRoot(destDir)
	require.NoError(t, err)
	defer func() { _ = destRoot.Close() }()

	certFile, err := destRoot.Create("tls.crt")
	require.NoError(t, err)
	defer func() { _ = certFile.Close() }()
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	keyFile, err := destRoot.Create("tls.key")
	require.NoError(t, err)
	defer func() { _ = keyFile.Close() }()
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	return filepath.Join(destDir, "tls.crt"), filepath.Join(destDir, "tls.key")
}

func copyFixture(t *testing.T, destDir string) string {
	t.Helper()

	fixturesRoot, err := os.OpenRoot(filepath.Join("..", "fixtures"))
	require.NoError(t, err)
	defer func() { _ = fixturesRoot.Close() }()

	data, err := fixturesRoot.ReadFile("integration.zone")
	require.NoError(t, err)

	destRoot, err := os.OpenRoot(destDir)
	require.NoError(t, err)
	defer func() { _ = destRoot.Close() }()

	require.NoError(t, destRoot.WriteFile("integration.zone", data, 0o600))
	return filepath.Join(destDir, "integration.zone")
}
