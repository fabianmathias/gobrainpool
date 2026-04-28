package gobrainpool

import (
	"errors"
	"io"
)

// rngDRBGSeedLen is the entropy input length for the approved-RNG
// wrapper. SP 800-90A §8.6.7 requires entropy_input + nonce supply at
// least 1.5×security_strength bits when no separate nonce is used. For
// SHA-512 HMAC-DRBG (max security_strength = 256 bits) that is 384 bits
// = 48 bytes, which also covers the 192-bit and 128-bit cases. Same
// 48-byte seed works for all curves; the underlying DRBG hash differs
// per curve (see curveHash).
const rngDRBGSeedLen = 48

// newRNGDRBG reads a seed from r and instantiates an SP 800-90A
// HMAC-DRBG matched to the curve (SHA-256 / SHA-384 / SHA-512 for
// BP256r1 / BP384r1 / BP512r1). The instance is configured for
// generate()-only use: nBE is left nil and allowNext is false, so
// next() panics on this instance — see hmacDRBG.next.
//
// Every approved RNG consumer in this package goes through this wrapper
// so the byte stream the crypto primitives see is shaped by an approved
// SP 800-90A DRBG. The DRBG does NOT add entropy: a chosen-seed
// caller's Reader fully determines the output. The wrapper provides
// uniform distribution at the crypto boundary; the entropy guarantee
// rests on the caller's Reader. The default rand.Reader is the OS
// CSPRNG, which AIS 20/31 / SP 800-90A treat as an approved entropy
// source.
//
// Mirrors stdlib crypto/internal/fips140/drbg/rand.go in role, though
// stdlib uses AES-CTR_DRBG there; HMAC_DRBG is equally approved under
// SP 800-90A and lets us stay symmetric with the ECDSA nonce path.
func newRNGDRBG(r io.Reader, c *Curve) (*hmacDRBG, error) {
	newHash, err := curveHash(c)
	if err != nil {
		return nil, err
	}
	var seed [rngDRBGSeedLen]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		return nil, err
	}
	drbg := newPlainHMACDRBG(newHash, seed[:], nil, nil, 1, nil)
	// The DRBG retains its own internal state derived from `seed`; the
	// raw seed itself is no longer needed and is wiped to limit
	// in-memory residence of the entropy block (FIPS 140-3 IG 9.7.B,
	// AIS 20/31 zeroization guidance for CSPs).
	clear(seed[:])
	return drbg, nil
}

// errRNGDRBG wraps the underlying DRBG error, currently unused but kept
// for future reseed/state-error paths.
var _ = errors.New
