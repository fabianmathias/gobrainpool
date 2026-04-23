package gobrainpool

import (
	"crypto/sha256"
	"io"
)

// rngDRBGSeedLen is the entropy input length for the approved-RNG
// wrapper. SP 800-90A §10.1.2.3 requires entropy of at least
// security_strength bits; with SHA-256 HMAC-DRBG the maximum security
// strength is 256 bits. 48 bytes = 384 bits covers the 3/2×security
// recommendation for reseed-free single-use DRBGs.
const rngDRBGSeedLen = 48

// newRNGDRBG reads a seed from r and instantiates a plain SP 800-90A
// HMAC-DRBG (SHA-256) primed to emit uniform random bytes via
// generate(). qbytes/nBE are set to harmless defaults because the
// ECDSA-range filter in next() is not used on this path.
//
// Every approved RNG consumer in this package goes through this wrapper
// so the byte stream the crypto primitives actually see is produced by
// an approved SP 800-90A DRBG, regardless of how weak a user-supplied
// io.Reader might be. The caller's Reader contributes only seed material.
//
// Mirrors stdlib crypto/internal/fips140/drbg/rand.go in role, though
// stdlib uses AES-CTR_DRBG there; HMAC_DRBG is equally approved under
// SP 800-90A and lets us stay symmetric with the ECDSA nonce path.
func newRNGDRBG(r io.Reader) (*hmacDRBG, error) {
	var seed [rngDRBGSeedLen]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		return nil, err
	}
	return newPlainHMACDRBG(sha256.New, seed[:], nil, nil, 1, nil), nil
}
