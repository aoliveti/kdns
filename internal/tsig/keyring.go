// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsig implements Transaction Signatures for DNS authentication (RFC 2845 and RFC 8945).
package tsig

import (
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // MD5 is required for legacy TSIG RFC 2845 compatibility
	"crypto/sha1" //nolint:gosec // SHA1 is required for legacy TSIG RFC 2845 compatibility
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	// HMACSHA256 is the standard recommended TSIG HMAC algorithm (RFC 4635 / RFC 8945).
	HMACSHA256 = "hmac-sha256."
	// HMACSHA512 provides high-security 512-bit HMAC TSIG authentication.
	HMACSHA512 = "hmac-sha512."
	// HMACSHA1 is the legacy SHA-1 TSIG algorithm (RFC 2845).
	HMACSHA1 = "hmac-sha1."
	// HMACMD5 is the legacy MD5 TSIG algorithm (RFC 2845).
	HMACMD5 = "hmac-md5.sig-alg.reg.int."

	defaultFudge = 300
	headerSize   = 12
)

var (
	// ErrBadSignature indicates the computed HMAC does not match the received TSIG MAC.
	ErrBadSignature = errors.New("tsig: signature verification failed (BADSIG)")
	// ErrBadKey indicates the key name in the TSIG record was not found in the KeyRing.
	ErrBadKey = errors.New("tsig: unknown key name (BADKEY)")
	// ErrBadTime indicates the timestamp is outside the allowed clock skew window.
	ErrBadTime = errors.New("tsig: signature time out of bounds (BADTIME)")
	// ErrBadAlgorithm indicates an unsupported or mismatched TSIG HMAC algorithm.
	ErrBadAlgorithm = errors.New("tsig: unsupported algorithm (BADALG)")
	// ErrMalformedTSIG indicates the TSIG record format is invalid.
	ErrMalformedTSIG = errors.New("tsig: malformed record")
)

// Key represents a shared secret credential for TSIG HMAC signing and verification.
type Key struct {
	Name      string
	Algorithm string
	Secret    []byte
}

// CanonicalName returns the lowercase, trailing-dot normalized key name.
func CanonicalName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(lower, ".") {
		lower += "."
	}
	return lower
}

// CanonicalAlgorithm returns the lowercase, trailing-dot normalized algorithm name.
func CanonicalAlgorithm(algo string) string {
	lower := strings.ToLower(strings.TrimSpace(algo))
	switch lower {
	case "hmac-sha256", "hmac-sha256.":
		return HMACSHA256
	case "hmac-sha512", "hmac-sha512.":
		return HMACSHA512
	case "hmac-sha1", "hmac-sha1.":
		return HMACSHA1
	case "hmac-md5", "hmac-md5.", "hmac-md5.sig-alg.reg.int", "hmac-md5.sig-alg.reg.int.":
		return HMACMD5
	default:
		if !strings.HasSuffix(lower, ".") {
			lower += "."
		}
		return lower
	}
}

// KeyRing maintains a thread-safe registry of authorized TSIG keys.
type KeyRing struct {
	keys map[string]Key
}

// NewKeyRing initializes an empty KeyRing.
func NewKeyRing() *KeyRing {
	return &KeyRing{
		keys: make(map[string]Key),
	}
}

// Add registers a key into the KeyRing.
func (kr *KeyRing) Add(key Key) {
	canonicalKeyName := CanonicalName(key.Name)
	canonicalAlgo := CanonicalAlgorithm(key.Algorithm)
	kr.keys[canonicalKeyName] = Key{
		Name:      canonicalKeyName,
		Algorithm: canonicalAlgo,
		Secret:    key.Secret,
	}
}

// Key retrieves an authorized key by its name, returning false if absent.
func (kr *KeyRing) Key(name string) (Key, bool) {
	k, ok := kr.keys[CanonicalName(name)]
	return k, ok
}

// Get retrieves a key by its name (alias for Key to satisfy map-like semantics).
func (kr *KeyRing) Get(name string) (Key, bool) {
	return kr.Key(name)
}

func newHasher(algo string, secret []byte) (hash.Hash, error) {
	switch CanonicalAlgorithm(algo) {
	case HMACSHA256:
		return hmac.New(sha256.New, secret), nil
	case HMACSHA512:
		return hmac.New(sha512.New, secret), nil
	case HMACSHA1:
		return hmac.New(sha1.New, secret), nil
	case HMACMD5:
		return hmac.New(md5.New, secret), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrBadAlgorithm, algo)
	}
}

func writeTSIGVariables(h hash.Hash, keyName, algo string, timeSigned uint64, fudge, tsigErr uint16, otherData []byte) {
	h.Write(dns.EncodeDomainName(keyName))

	var classTTL [6]byte
	binary.BigEndian.PutUint16(classTTL[0:2], uint16(dns.ClassANY))
	binary.BigEndian.PutUint32(classTTL[2:6], 0)
	h.Write(classTTL[:])

	h.Write(dns.EncodeDomainName(algo))

	var timeFudge [8]byte
	binary.BigEndian.PutUint16(timeFudge[0:2], uint16((timeSigned>>32)&0xFFFF))
	binary.BigEndian.PutUint32(timeFudge[2:6], uint32(timeSigned&0xFFFFFFFF))
	binary.BigEndian.PutUint16(timeFudge[6:8], fudge)
	h.Write(timeFudge[:])

	var errOtherLen [4]byte
	binary.BigEndian.PutUint16(errOtherLen[0:2], tsigErr)
	binary.BigEndian.PutUint16(errOtherLen[2:4], uint16(min(len(otherData), 65535)))
	h.Write(errOtherLen[:])

	if len(otherData) > 0 {
		h.Write(otherData)
	}
}
