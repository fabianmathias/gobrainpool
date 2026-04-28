package gobrainpool

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
)

// hmacDRBG is an SP 800-90A Rev. 1 HMAC_DRBG used to generate ECDSA
// nonces and approved random bits. It is instantiated ex novo for each
// signature / RNG-wrapper call and produces successive candidates k in
// [1, N-1] via next(); the spec's retry rule (§3.2 step h for RFC 6979;
// equivalent 10.1.2.5 for plain HMAC-DRBG) is applied on out-of-range
// emissions and between calls so that a caller who rejects the previous
// k transparently advances the state.
//
// Three instantiations are supported:
//
//   - RFC 6979 deterministic ECDSA per FIPS 186-5 / RFC 6979 §3.2:
//     entropy = priv.d, nonce = bits2octets(H), no personalization,
//     hash function matching the curve order (SHA-256 / SHA-384 /
//     SHA-512 for BP256r1 / BP384r1 / BP512r1). See newRFC6979Gen.
//
//   - Hedged ECDSA per draft-irtf-cfrg-det-sigs-with-noise-04 §4:
//     entropy = Z (fresh random block, curve byteSize), nonce = empty,
//     personalization = block-aligned [priv.d, bits2octets(H)], hash
//     function matching the curve order — same per-curve mapping as the
//     RFC 6979 path so that the DRBG hash is symmetric across both
//     deterministic and hedged signing. See newHedgedGen.
//
//   - Approved-RNG wrapper (rand.go): entropy = caller-supplied seed,
//     no nonce/persStr, hash function matching the curve. See newRNGDRBG.
//
// SP 800-90A §10.1.2.5 Step 1 reseed-counter check: each instance
// enforces reseed_interval = 2^48 generate calls (Tab. 2). On exhaust
// the DRBG returns an error from next()/generate(); since every callsite
// instantiates a fresh DRBG and emits ≤ 128·byteSize bytes (≤ 128
// generate calls), the limit is unreachable in practice but the check
// is required for normative SP 800-90A conformance.
type hmacDRBG struct {
	newHash        func() hash.Hash
	K, V           []byte
	qbytes         int
	nBE            []byte // N as a big-endian byte slice of length qbytes
	primed         bool   // true once next()/generate() has emitted at least one value
	reseedCounter  uint64
	reseedInterval uint64
	allowNext      bool // false for the RNG-wrapper instance; guards against misuse via next()
}

// reseedIntervalDefault is the SP 800-90A Rev. 1 Tab. 2 ceiling on
// generate-requests-without-reseed for HMAC-DRBG (all hash variants).
// Single-use DRBGs in this package never approach this; the check is
// for normative conformance.
const reseedIntervalDefault uint64 = 1 << 48

// errReseedRequired is returned from next()/generate() when the
// reseed_interval has been exhausted. SP 800-90A §10.1.2.5 Step 1
// mandates this status; we surface it as an error so that callers
// (signing loops) abort instead of silently violating the spec.
var errReseedRequired = errors.New("gobrainpool: HMAC-DRBG reseed_interval exhausted")

// newRFC6979Gen instantiates the pure RFC 6979 §3.2 HMAC-DRBG for the
// given curve. xBytes is the private scalar as a fixed-width big-endian
// byte slice of length c.byteSize. hashMsg is the message digest
// supplied by the caller (treated as a bit string — never re-hashed).
func newRFC6979Gen(c *Curve, xBytes, hashMsg []byte) (*hmacDRBG, error) {
	newHash, err := curveHash(c)
	if err != nil {
		return nil, err
	}
	h1 := hashToScalarBytes(hashMsg, c)
	return newPlainHMACDRBG(newHash, xBytes, h1, nil, c.byteSize, c.nBE), nil
}

// newHedgedGen instantiates the hedged HMAC-DRBG described in
// draft-irtf-cfrg-det-sigs-with-noise-04 §4. Z is a fresh random entropy
// block of length c.byteSize; priv.d and the bits2octets-reduced digest
// are folded in as a block-aligned personalization string. The DRBG
// hash matches the curve (SHA-256 / SHA-384 / SHA-512) per the draft,
// keeping symmetry with the RFC 6979 path.
func newHedgedGen(c *Curve, xBytes, hashMsg, Z []byte) (*hmacDRBG, error) {
	newHash, err := curveHash(c)
	if err != nil {
		return nil, err
	}
	h1 := hashToScalarBytes(hashMsg, c)
	return newBlockAlignedHMACDRBG(newHash, Z, nil, [][]byte{xBytes, h1}, c.byteSize, c.nBE), nil
}

// curveHash returns the hash constructor matched to the curve order, per
// FIPS 186-5 / RFC 6979 / draft-det-sigs-with-noise: BP256→SHA-256,
// BP384→SHA-384, BP512→SHA-512. Used for every DRBG instantiation in
// the package so the hash is consistently curve-matched.
func curveHash(c *Curve) (func() hash.Hash, error) {
	switch c {
	case bp256r1:
		return sha256.New, nil
	case bp384r1:
		return sha512.New384, nil
	case bp512r1:
		return sha512.New, nil
	default:
		return nil, errors.New("gobrainpool: unknown curve")
	}
}

// newPlainHMACDRBG runs SP 800-90A §10.1.2.3 Instantiate with a plain
// personalization string (no block alignment). This covers RFC 6979
// and any "seed = entropy||nonce||persStr" construction.
func newPlainHMACDRBG(newHash func() hash.Hash, entropy, nonce, persStr []byte, qbytes int, nBE []byte) *hmacDRBG {
	hlen := newHash().Size()
	V := make([]byte, hlen)
	for i := range V {
		V[i] = 0x01
	}
	K := make([]byte, hlen)

	h := hmac.New(newHash, K)
	h.Write(V)
	h.Write([]byte{0x00})
	h.Write(entropy)
	h.Write(nonce)
	h.Write(persStr)
	K = h.Sum(K[:0])

	h = hmac.New(newHash, K)
	h.Write(V)
	V = h.Sum(V[:0])

	h = hmac.New(newHash, K)
	h.Write(V)
	h.Write([]byte{0x01})
	h.Write(entropy)
	h.Write(nonce)
	h.Write(persStr)
	K = h.Sum(K[:0])

	h = hmac.New(newHash, K)
	h.Write(V)
	V = h.Sum(V[:0])

	return &hmacDRBG{
		newHash:        newHash,
		K:              K,
		V:              V,
		qbytes:         qbytes,
		nBE:            nBE,
		reseedInterval: reseedIntervalDefault,
		allowNext:      nBE != nil,
	}
}

// newBlockAlignedHMACDRBG runs SP 800-90A §10.1.2.3 Instantiate with
// a block-aligned personalization string, per draft-irtf-cfrg-det-sigs-
// with-noise-04 §4: each entry of persBlocks is written starting at an
// HMAC block boundary, padding with zeros as needed.
func newBlockAlignedHMACDRBG(newHash func() hash.Hash, entropy, nonce []byte, persBlocks [][]byte, qbytes int, nBE []byte) *hmacDRBG {
	hlen := newHash().Size()
	V := make([]byte, hlen)
	for i := range V {
		V[i] = 0x01
	}
	K := make([]byte, hlen)

	writePers := func(h hash.Hash, prefixLen int) {
		l := prefixLen
		for _, b := range persBlocks {
			pad000(h, l)
			h.Write(b)
			l = len(b)
		}
	}

	h := hmac.New(newHash, K)
	h.Write(V)
	h.Write([]byte{0x00})
	h.Write(entropy)
	h.Write(nonce)
	writePers(h, len(V)+1+len(entropy)+len(nonce))
	K = h.Sum(K[:0])

	h = hmac.New(newHash, K)
	h.Write(V)
	V = h.Sum(V[:0])

	h = hmac.New(newHash, K)
	h.Write(V)
	h.Write([]byte{0x01})
	h.Write(entropy)
	h.Write(nonce)
	writePers(h, len(V)+1+len(entropy)+len(nonce))
	K = h.Sum(K[:0])

	h = hmac.New(newHash, K)
	h.Write(V)
	V = h.Sum(V[:0])

	return &hmacDRBG{
		newHash:        newHash,
		K:              K,
		V:              V,
		qbytes:         qbytes,
		nBE:            nBE,
		reseedInterval: reseedIntervalDefault,
		allowNext:      nBE != nil,
	}
}

// pad000 writes zero bytes to h so that the next byte Write starts at
// an HMAC block boundary. writtenSoFar is the total number of bytes
// already written to h since the last boundary.
func pad000(h hash.Hash, writtenSoFar int) {
	blockSize := h.BlockSize()
	if rem := writtenSoFar % blockSize; rem != 0 {
		h.Write(make([]byte, blockSize-rem))
	}
}

// next emits the next candidate nonce k in [1, N-1] per SP 800-90A
// §10.1.2.5 with the extra range-check retry. The first call runs the
// Generate step directly; subsequent calls first apply the HMAC-DRBG
// update rule (K = HMAC_K(V || 0x00); V = HMAC_K(V)) before regenerating
// T, which is also exactly the RFC 6979 §3.2 step-h continuation.
//
// Returns errReseedRequired if reseed_interval is exhausted (SP 800-90A
// §10.1.2.5 Step 1). Panics if the DRBG was instantiated in RNG-wrapper
// mode (allowNext == false), which would otherwise loop forever in the
// nBE==nil range check — see newRNGDRBG for that path's caveat.
func (g *hmacDRBG) next() ([]byte, error) {
	if !g.allowNext {
		panic("gobrainpool: hmacDRBG.next called on RNG-wrapper instance")
	}
	if g.reseedCounter >= g.reseedInterval {
		return nil, errReseedRequired
	}
	if g.primed {
		g.K = g.hmac(g.V, []byte{0x00})
		g.V = g.hmac(g.V)
	}
	g.primed = true

	T := make([]byte, 0, g.qbytes+len(g.V))
	for {
		T = T[:0]
		for len(T) < g.qbytes {
			g.V = g.hmac(g.V)
			T = append(T, g.V...)
		}
		T = T[:g.qbytes]
		// Brainpool N has its top bit set and bit length == curve bit
		// length, so no right-shift after emission; only the range
		// check 1 <= k <= N-1 remains.
		if nonceInRange(T, g.nBE) {
			out := make([]byte, g.qbytes)
			copy(out, T)
			g.reseedCounter++
			return out, nil
		}
		g.K = g.hmac(g.V, []byte{0x00})
		g.V = g.hmac(g.V)
	}
}

func (g *hmacDRBG) hmac(data ...[]byte) []byte {
	m := hmac.New(g.newHash, g.K)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// generate emits n bytes per SP 800-90A §10.1.2.5 Generate, without
// the ECDSA-specific [1, N-1] range filter that next() applies. Used
// as the approved random-bit source for the RNG wrapper (see
// newRNGDRBG); ECDSA nonce generation continues to use next().
//
// Returns errReseedRequired if reseed_interval is exhausted.
func (g *hmacDRBG) generate(n int) ([]byte, error) {
	if g.reseedCounter >= g.reseedInterval {
		return nil, errReseedRequired
	}
	if g.primed {
		g.K = g.hmac(g.V, []byte{0x00})
		g.V = g.hmac(g.V)
	}
	g.primed = true

	out := make([]byte, 0, n+len(g.V))
	for len(out) < n {
		g.V = g.hmac(g.V)
		out = append(out, g.V...)
	}
	g.reseedCounter++
	return out[:n], nil
}

// nonceInRange reports whether k (fixed-width big-endian, same length
// as nBE) is in [1, N-1]. Runs in constant time w.r.t. the bytes of k —
// relevant because k is the ECDSA nonce, and any timing leakage on its
// value would translate into bits of information an HNP/lattice attack
// could compound across signatures. Also reused on public values
// (verify r/s, key-generation rejection sampling) to keep the byte-
// wise pattern uniform and remove math/big from runtime scalar paths.
func nonceInRange(k, nBE []byte) bool {
	if len(k) != len(nBE) {
		return false
	}
	// k != 0: OR every byte of k; the result is zero iff all bytes are zero.
	var or byte
	for _, b := range k {
		or |= b
	}
	nonZero := 1 ^ subtle.ConstantTimeByteEq(or, 0)
	lessThan := bytesLessBE(k, nBE)
	return nonZero&lessThan == 1
}

// bytesLessBE returns 1 if a < b and 0 otherwise, where a and b are
// equal-length big-endian byte slices. Runs in constant time w.r.t.
// the bytes of a and b. Panics on a length mismatch — callers are
// internal and control their widths.
func bytesLessBE(a, b []byte) int {
	if len(a) != len(b) {
		panic("gobrainpool: bytesLessBE: length mismatch")
	}
	var borrow uint64
	for i := len(a) - 1; i >= 0; i-- {
		d := uint64(a[i]) - uint64(b[i]) - borrow
		borrow = (d >> 63) & 1
	}
	return int(borrow)
}
