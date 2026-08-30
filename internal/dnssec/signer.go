// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnssec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	rrsigHeaderFixedSize = 18
)

var (
	// ErrInvalidSignature indicates that cryptographic signature verification failed.
	ErrInvalidSignature = errors.New("dnssec: invalid cryptographic signature")
	// ErrMalformedRRSIG indicates that the RRSIG wire payload is truncated or invalid.
	ErrMalformedRRSIG = errors.New("dnssec: malformed RRSIG rdata")
)

// Sign generates an RRSIG signature record over an RRSet in canonical DNSSEC format (RFC 4034 §3 & §6).
func Sign(owner string, record dns.RRSet, k *Key, inception, expiration time.Time) (dns.RRSet, error) {
	if len(record.RData) == 0 {
		return dns.RRSet{}, errors.New("dnssec: cannot sign empty RRSet")
	}

	owner = canonicalZone(owner)
	signerName := canonicalZone(k.Zone)
	labelCount := countLabels(owner)

	signerWire := dns.EncodeDomainName(signerName)
	hdr := make([]byte, rrsigHeaderFixedSize+len(signerWire))

	binary.BigEndian.PutUint16(hdr[0:2], uint16(record.Type))
	hdr[2] = k.Algorithm
	hdr[3] = byte(min(labelCount, 255)) //nolint:gosec // bounded label count
	binary.BigEndian.PutUint32(hdr[4:8], record.TTL)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(max(0, expiration.Unix()))) //nolint:gosec // unix timestamp conversion
	binary.BigEndian.PutUint32(hdr[12:16], uint32(max(0, inception.Unix()))) //nolint:gosec // unix timestamp conversion
	binary.BigEndian.PutUint16(hdr[16:18], k.KeyTag)
	copy(hdr[rrsigHeaderFixedSize:], signerWire)

	signBuf := buildSignBuffer(hdr, owner, record)

	sig, err := k.Sign(signBuf)
	if err != nil {
		return dns.RRSet{}, err
	}

	wire := make([]byte, len(hdr)+len(sig))
	copy(wire, hdr)
	copy(wire[len(hdr):], sig)

	return dns.RRSet{
		Type:  dns.TypeRRSIG,
		Class: dns.ClassIN,
		TTL:   record.TTL,
		RData: [][]byte{wire},
	}, nil
}

// Verify validates an RRSIG signature over an RRSet against the provided public key.
func Verify(owner string, record dns.RRSet, rrsigRData, pubKey []byte, algorithm byte) error {
	if len(rrsigRData) < rrsigHeaderFixedSize {
		return ErrMalformedRRSIG
	}

	signerWireEnd := rrsigHeaderFixedSize
	for {
		if signerWireEnd >= len(rrsigRData) {
			return ErrMalformedRRSIG
		}
		lenByte := rrsigRData[signerWireEnd]
		if lenByte == 0 {
			signerWireEnd++
			break
		}
		signerWireEnd += 1 + int(lenByte)
	}

	hdr := rrsigRData[:signerWireEnd]
	sig := rrsigRData[signerWireEnd:]

	verifyBuf := buildSignBuffer(hdr, owner, record)

	switch algorithm {
	case ECDSAP256:
		if len(pubKey) != 64 || len(sig) != 64 {
			return ErrInvalidSignature
		}
		var uncompressed [65]byte
		uncompressed[0] = 0x04
		copy(uncompressed[1:], pubKey)
		ecdsaPub, parseErr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed[:])
		if parseErr != nil {
			return ErrInvalidSignature
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		digest := sha256.Sum256(verifyBuf)
		if !ecdsa.Verify(ecdsaPub, digest[:], r, s) {
			return ErrInvalidSignature
		}
		return nil

	case ED25519:
		if len(pubKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return ErrInvalidSignature
		}
		if !ed25519.Verify(pubKey, verifyBuf, sig) {
			return ErrInvalidSignature
		}
		return nil

	default:
		return ErrUnsupportedAlgorithm
	}
}

func buildSignBuffer(hdr []byte, owner string, record dns.RRSet) []byte {
	sortedRData := make([][]byte, len(record.RData))
	copy(sortedRData, record.RData)
	slices.SortFunc(sortedRData, bytes.Compare)

	ownerWire := dns.EncodeDomainName(owner)
	var buf bytes.Buffer
	buf.Write(hdr)

	for _, rdata := range sortedRData {
		buf.Write(ownerWire)

		var meta [10]byte
		binary.BigEndian.PutUint16(meta[0:2], uint16(record.Type))
		binary.BigEndian.PutUint16(meta[2:4], uint16(record.Class))
		binary.BigEndian.PutUint32(meta[4:8], record.TTL)
		binary.BigEndian.PutUint16(meta[8:10], uint16(min(len(rdata), 65535)))
		buf.Write(meta[:])
		buf.Write(rdata)
	}

	return buf.Bytes()
}

func countLabels(name string) int {
	canonical := strings.TrimSuffix(canonicalZone(name), ".")
	if canonical == "" {
		return 0
	}
	count := 0
	for range strings.SplitSeq(canonical, ".") {
		count++
	}
	return count
}
