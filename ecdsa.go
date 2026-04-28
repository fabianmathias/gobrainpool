package gobrainpool

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/fabianmathias/gobrainpool/internal/bpec"
)

// PublicKey is an ECDSA/ECDH public key on a Brainpool curve. It is
// constructed only by the package — reach for [Curve.NewPublicKey] to
// decode one from wire bytes, or derive it from a *PrivateKey via
// [PrivateKey.PublicKey].
type PublicKey struct {
	curve     *Curve
	publicKey []byte // SEC1 uncompressed: 0x04 || X || Y
}

// Curve returns the curve this public key lives on.
func (k *PublicKey) Curve() *Curve { return k.curve }

// Bytes returns the SEC1 uncompressed encoding of the public key
// (0x04 || X || Y). The returned slice is a fresh copy; callers can
// mutate it freely.
func (k *PublicKey) Bytes() []byte { return slices.Clone(k.publicKey) }

// Equal reports whether x is a *PublicKey on the same curve with the
// same encoding.
func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok || xx == nil {
		return false
	}
	return k.curve == xx.curve && bytes.Equal(k.publicKey, xx.publicKey)
}

// PrivateKey is an ECDSA/ECDH private key on a Brainpool curve.
type PrivateKey struct {
	curve     *Curve
	d         []byte // fixed-width big-endian scalar, length = curve.byteSize
	publicKey *PublicKey
}

// Curve returns the curve this private key lives on.
func (k *PrivateKey) Curve() *Curve { return k.curve }

// Bytes returns the private scalar as a fixed-width big-endian byte
// slice (length = curve byte size). The returned slice is a fresh copy.
func (k *PrivateKey) Bytes() []byte { return slices.Clone(k.d) }

// PublicKey returns the associated public key.
func (k *PrivateKey) PublicKey() *PublicKey { return k.publicKey }

// Public returns the associated public key as a crypto.PublicKey, so
// that *PrivateKey satisfies the crypto.Signer interface.
func (k *PrivateKey) Public() crypto.PublicKey { return k.publicKey }

// Equal reports whether x is a *PrivateKey on the same curve with the
// same scalar. The comparison is constant-time on the scalar bytes.
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok || xx == nil {
		return false
	}
	if k.curve != xx.curve {
		return false
	}
	return subtle.ConstantTimeCompare(k.d, xx.d) == 1
}

// GenerateKey produces a fresh ECDSA/ECDH key pair on the curve.
// rand must be a secure random source; if rand is nil, crypto/rand is used.
func (c *Curve) GenerateKey(rand io.Reader) (*PrivateKey, error) {
	ensureSelfTestsPassed()
	d, err := randScalarBytes(rand, c)
	if err != nil {
		return nil, err
	}
	return newPrivateKeyFromScalar(c, d)
}

// NewPrivateKey decodes a big-endian scalar as a Brainpool private key.
// The scalar length must equal the curve's byte size and lie in [1, N-1].
// The range check is constant-time on the scalar bytes — same structure
// as stdlib crypto/internal/fips140/ecdh.NewPrivateKey — so the private
// scalar never transits math/big.
func (c *Curve) NewPrivateKey(key []byte) (*PrivateKey, error) {
	ensureSelfTestsPassed()
	if len(key) != c.byteSize {
		return nil, errors.New("gobrainpool: private key has wrong length")
	}
	if !nonceInRange(key, c.nBE) {
		return nil, errors.New("gobrainpool: private scalar out of range [1, N-1]")
	}
	return newPrivateKeyFromScalar(c, slices.Clone(key))
}

// NewPublicKey decodes a SEC1-encoded point as a Brainpool public key.
// Both uncompressed (0x04 || X || Y) and compressed (0x02/0x03 || X)
// forms are accepted. The decoded point is validated to lie on the
// curve; the point at infinity is rejected.
func (c *Curve) NewPublicKey(key []byte) (*PublicKey, error) {
	ensureSelfTestsPassed()
	enc, err := curveCanonicalizePoint(c, key)
	if err != nil {
		return nil, err
	}
	return &PublicKey{curve: c, publicKey: enc}, nil
}

// Sign implements crypto.Signer. It produces a hedged ASN.1-DER-encoded
// ECDSA signature over digest — equivalent to calling SignASN1(rand, k,
// digest). The caller must have hashed the message with a function
// whose output matches the curve size (SHA-256 for BP256r1, SHA-384 for
// BP384r1, SHA-512 for BP512r1).
//
// Under approved-parameter enforcement (see SetEnforceApproved), if
// opts is non-nil and opts.HashFunc() reports a hash whose output size
// does not equal the curve byte size, Sign returns an error before any
// entropy is read. With enforcement off, opts is informational only and
// the digest length is the sole approval-relevant input.
func (k *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && EnforceApproved() {
		if h := opts.HashFunc(); h != 0 && h.Size() != k.curve.byteSize {
			return nil, errors.New("gobrainpool: non-approved operation blocked by approved-parameter enforcement (opts.HashFunc output size must equal curve byte size)")
		}
	}
	return SignASN1(rand, k, digest)
}

// Compile-time check that *PrivateKey satisfies crypto.Signer.
var _ crypto.Signer = (*PrivateKey)(nil)

// SignASN1 produces a hedged DER-encoded ECDSA signature over digest.
// Matches the shape of crypto/ecdsa.SignASN1: rand is an entropy source,
// and a nil rand defaults to crypto/rand.Reader.
//
// The per-signature scalar k is derived from the private key, the
// digest, and a fresh entropy block read from rand — the "hedged"
// construction of draft-irtf-cfrg-det-sigs-with-noise-04. A healthy
// RNG gives the usual random-ECDSA non-determinism; a compromised RNG
// degrades gracefully to pure RFC 6979 deterministic signing.
//
// For pure RFC 6979 deterministic signatures (no RNG dependency), use
// [SignDeterministicASN1].
//
// The signature arithmetic (k⁻¹, r·d, +e, ·k⁻¹ mod N) runs inside the
// fiat-generated Montgomery scalar field via internal/bpec — constant
// time on the secret inputs priv.d and k.
func SignASN1(rand io.Reader, priv *PrivateKey, digest []byte) ([]byte, error) {
	if rand == nil {
		rand = crand.Reader
	}
	return signASN1(priv, digest, rand)
}

// SignDeterministicASN1 produces a pure RFC 6979 deterministic DER-
// encoded ECDSA signature over digest. The signature is a deterministic
// function of (priv, digest): the same inputs always produce the same
// signature bytes. Useful for test vectors and environments where
// reproducibility is required; callers who want defense against RNG
// compromise should prefer [SignASN1].
func SignDeterministicASN1(priv *PrivateKey, digest []byte) ([]byte, error) {
	return signASN1(priv, digest, nil)
}

// signASN1 is the shared signing core. rand == nil selects pure RFC 6979
// deterministic output; any non-nil rand selects the hedged construction
// and a fresh entropy block is read from it.
func signASN1(priv *PrivateKey, digest []byte, rand io.Reader) ([]byte, error) {
	ensureSelfTestsPassed()
	if priv == nil || len(priv.d) != priv.curve.byteSize {
		return nil, errors.New("gobrainpool: invalid private key")
	}
	// In best-effort mode any digest length is accepted: FIPS 186-5
	// §6.4.1 bits2int handles digests wider or narrower than the curve
	// order. Under approved-parameter enforcement the digest length
	// must equal the curve byte size or the operation aborts with an
	// error before any entropy is read or arithmetic is performed.
	if len(digest) != priv.curve.byteSize && EnforceApproved() {
		return nil, errors.New("gobrainpool: non-approved operation blocked by approved-parameter enforcement (digest length must equal curve byte size)")
	}
	var hedge []byte
	if rand != nil {
		// Run the hedge entropy through the approved DRBG wrapper for
		// the same reason randScalarBytes does: the bytes that reach
		// the crypto core come from an approved SP 800-90A DRBG seeded
		// from the caller's Reader, not directly from the Reader.
		drbg, err := newRNGDRBG(rand, priv.curve)
		if err != nil {
			return nil, err
		}
		hedge, err = drbg.generate(priv.curve.byteSize)
		if err != nil {
			return nil, err
		}
	}
	var rBytes, sBytes []byte
	var err error
	switch priv.curve {
	case bp256r1:
		rBytes, sBytes, err = sign256(priv, digest, hedge)
	case bp384r1:
		rBytes, sBytes, err = sign384(priv, digest, hedge)
	case bp512r1:
		rBytes, sBytes, err = sign512(priv, digest, hedge)
	default:
		return nil, errors.New("gobrainpool: unknown curve")
	}
	if err != nil {
		return nil, err
	}
	return encodeECDSASignature(rBytes, sBytes)
}

// encodeECDSASignature builds a canonical DER SEQUENCE { r INTEGER,
// s INTEGER } from fixed-width big-endian r and s. Matches the
// encoding produced by stdlib crypto/ecdsa.
func encodeECDSASignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes emits an ASN.1 INTEGER encoding of a positive
// big-endian integer represented as raw bytes with any number of
// leading zero bytes. Mirrors crypto/ecdsa.addASN1IntBytes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("gobrainpool: invalid integer"))
		return
	}
	b.AddASN1(cbasn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// VerifyASN1 parses a DER-encoded ECDSA signature and checks it against
// pub/digest. Parsing enforces strict DER (via cryptobyte): non-minimal
// length encodings, non-minimal integer encodings, trailing bytes,
// negative components and components ≥ N are all rejected.
func VerifyASN1(pub *PublicKey, digest, sig []byte) bool {
	ensureSelfTestsPassed()
	if pub == nil {
		return false
	}
	// Same digest-length approval rule as signing. Under approved-
	// parameter enforcement a mismatch returns false without running
	// the cryptographic verify: a non-approved result cannot be
	// surfaced as "valid" even if the math would have matched.
	if len(digest) != pub.curve.byteSize && EnforceApproved() {
		return false
	}
	r, s, ok := parseECDSASignature(sig)
	if !ok {
		return false
	}
	c := pub.curve
	if len(r) == 0 || len(s) == 0 || len(r) > c.byteSize || len(s) > c.byteSize {
		return false
	}
	// Pad the minimal magnitudes returned by cryptobyte's ReadASN1Integer
	// up to the fixed curve width, then range-check 0 < r, s < N in
	// constant-time byte-wise form. Mirrors the stdlib FIPS pattern
	// (bigmod.Nat.SetBytes + IsZero) — no math/big on the hot path.
	rBytes := make([]byte, c.byteSize)
	sBytes := make([]byte, c.byteSize)
	copy(rBytes[c.byteSize-len(r):], r)
	copy(sBytes[c.byteSize-len(s):], s)
	if !nonceInRange(rBytes, c.nBE) || !nonceInRange(sBytes, c.nBE) {
		return false
	}
	switch c {
	case bp256r1:
		return verify256(pub, digest, rBytes, sBytes)
	case bp384r1:
		return verify384(pub, digest, rBytes, sBytes)
	case bp512r1:
		return verify512(pub, digest, rBytes, sBytes)
	}
	return false
}

// parseECDSASignature reads a strict-DER-encoded SEQUENCE { r INTEGER,
// s INTEGER }. cryptobyte.ReadASN1Integer rejects non-minimal
// integer encodings and returns the magnitude as a minimal
// big-endian byte slice. Mirrors crypto/ecdsa.parseSignature.
func parseECDSASignature(sig []byte) (r, s []byte, ok bool) {
	input := cryptobyte.String(sig)
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, false
	}
	return r, s, true
}

// newPrivateKeyFromScalar builds a PrivateKey from an already-validated
// byte-slice scalar by deriving Q = d·G, then runs a Pairwise
// Consistency Test on the resulting pair (sign a fixed digest, verify
// it round-trips). A PCT failure means
// the keypair is internally inconsistent and must not be exposed to
// the caller. Ownership of d passes to the returned key — the caller
// must not retain it.
func newPrivateKeyFromScalar(c *Curve, d []byte) (*PrivateKey, error) {
	pubEnc, err := curveScalarBaseMult(c, d)
	if err != nil {
		return nil, err
	}
	priv := &PrivateKey{
		curve:     c,
		d:         d,
		publicKey: &PublicKey{curve: c, publicKey: pubEnc},
	}
	if err := pairwiseConsistencyCheck(priv); err != nil {
		return nil, fmt.Errorf("gobrainpool: pairwise consistency check failed: %w", err)
	}
	return priv, nil
}

// hashToIntBytes implements FIPS 186-5 §6.4.1/§6.4.2 bits2int on the
// hash input: take the leftmost min(N, outlen) bits as a non-negative
// integer and encode it as a fixed-width big-endian byte slice of
// length c.byteSize. NO mod-N reduction is applied — that is the
// distinction from bits2octets (hashToScalarBytes) per RFC 6979 §2.3.
//
// Used as the ECDSA "e" input to the signing/verification arithmetic.
// Because the subsequent NScalar.SetBytes step reduces mod N the
// arithmetic result is mathematically identical to passing
// bits2octets, but keeping the helpers separate makes the spec mapping
// explicit for review (FIPS 186-5: "e" = bits2int; RFC 6979: DRBG seed
// = bits2octets).
func hashToIntBytes(hash []byte, c *Curve) []byte {
	if len(hash) > c.byteSize {
		hash = hash[:c.byteSize]
	}
	if excess := len(hash)*8 - c.bitSize; excess > 0 {
		hash = rightShift(hash, excess)
	}
	out := make([]byte, c.byteSize)
	copy(out[c.byteSize-len(hash):], hash)
	return out
}

// hashToScalarBytes implements RFC 6979 §2.3.4 bits2octets on the hash
// input: take the leftmost ceil(log2 n) bits (bits2int), reduce mod n,
// then encode as a fixed-width big-endian byte slice of length
// c.byteSize. This is the same value used for ECDSA's "e" (SEC1 §4.1.3)
// and for the HMAC-DRBG seed input in RFC 6979.
//
// The mod-N reduction runs via NScalar.SetBytes — symmetric to the
// stdlib FIPS path (bigmod.Nat.SetOverflowingBytes). Valid because
// after left-truncation hash < 2^bitSize < 2N for all Brainpool curves
// (N has its top bit set), so the single-step conditional subtract
// inside scalarReduce is sufficient.
//
// Historical note: an earlier version omitted the mod-n reduction and
// emitted only bits2int. For Brainpool curves N has its top bit set
// but the remaining bits are well below 2^(bitSize-1), so ~34% of
// 256-bit inputs exceed N. The DRBG seed therefore diverged from strict
// RFC 6979 for that fraction of inputs. See rfc6979_test.go for the
// cross-check against an independent reference implementation.
func hashToScalarBytes(hash []byte, c *Curve) []byte {
	orderBits := c.bitSize
	orderBytes := c.byteSize
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}
	// For Brainpool, bitSize == 8*byteSize, so after truncation
	// excess == 0 and the bits2int shift branch is dead. Kept
	// structurally to mirror FIPS 186-5 and RFC 6979 §2.3.2.
	if excess := len(hash)*8 - orderBits; excess > 0 {
		hash = rightShift(hash, excess)
	}
	switch c {
	case bp256r1:
		var e bpec.NScalar256
		if _, err := e.SetBytes(hash); err != nil {
			panic("gobrainpool: hashToScalarBytes: " + err.Error())
		}
		return e.Bytes()
	case bp384r1:
		var e bpec.NScalar384
		if _, err := e.SetBytes(hash); err != nil {
			panic("gobrainpool: hashToScalarBytes: " + err.Error())
		}
		return e.Bytes()
	case bp512r1:
		var e bpec.NScalar512
		if _, err := e.SetBytes(hash); err != nil {
			panic("gobrainpool: hashToScalarBytes: " + err.Error())
		}
		return e.Bytes()
	}
	panic("gobrainpool: hashToScalarBytes: unknown curve")
}

// rightShift implements the right shift necessary for bits2int, which
// takes the leftmost bits of a hash that is wider than log2(N). Dead
// code for Brainpool (bitSize is always a multiple of 8), kept to
// mirror the FIPS 186-5 structure. Copied from stdlib crypto/internal/
// fips140/ecdsa.rightShift verbatim; see THIRD_PARTY_NOTICES.md for
// the upstream attribution and license (BSD-3-Clause).
func rightShift(b []byte, shift int) []byte {
	if shift <= 0 || shift >= 8 {
		panic("gobrainpool: rightShift: shift out of range")
	}
	b = bytes.Clone(b)
	for i := len(b) - 1; i >= 0; i-- {
		b[i] >>= shift
		if i > 0 {
			b[i] |= b[i-1] << (8 - shift)
		}
	}
	return b
}

// randScalarBytes returns a uniform element of [1, N-1] as a fixed-
// width big-endian byte slice. Uses rejection sampling on raw bytes,
// mirroring the stdlib FIPS randomPoint path (read byteSize bytes,
// retry if not in [1, N-1]). Acceptance rate per iteration is N/2^bitSize;
// for Brainpool ≥ 0.663, so 128 attempts miss with probability < 2^-180.
//
// The caller's io.Reader is only used to seed an approved SP 800-90A
// HMAC-DRBG (newRNGDRBG). The bytes consumed by the rejection loop
// come from that DRBG — so even with a weak user-supplied Reader, the
// scalar generation still flows through an approved random-bit source.
func randScalarBytes(rand io.Reader, c *Curve) ([]byte, error) {
	if rand == nil {
		rand = crand.Reader
	}
	drbg, err := newRNGDRBG(rand, c)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 128; i++ {
		buf, err := drbg.generate(c.byteSize)
		if err != nil {
			return nil, err
		}
		if nonceInRange(buf, c.nBE) {
			out := make([]byte, c.byteSize)
			copy(out, buf)
			return out, nil
		}
	}
	return nil, errors.New("gobrainpool: failed to generate non-zero scalar after 128 attempts")
}

// curveScalarBaseMult computes k·G via bpec and returns the affine
// SEC1-uncompressed encoding. k is big-endian, length = c.byteSize.
func curveScalarBaseMult(c *Curve, k []byte) ([]byte, error) {
	switch c {
	case bp256r1:
		p := new(bpec.BP256Point)
		if _, err := p.ScalarBaseMult(k); err != nil {
			return nil, err
		}
		if p.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: derived public key is the point at infinity")
		}
		return p.Bytes(), nil
	case bp384r1:
		p := new(bpec.BP384Point)
		if _, err := p.ScalarBaseMult(k); err != nil {
			return nil, err
		}
		if p.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: derived public key is the point at infinity")
		}
		return p.Bytes(), nil
	case bp512r1:
		p := new(bpec.BP512Point)
		if _, err := p.ScalarBaseMult(k); err != nil {
			return nil, err
		}
		if p.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: derived public key is the point at infinity")
		}
		return p.Bytes(), nil
	}
	return nil, errors.New("gobrainpool: unknown curve")
}

// curveCanonicalizePoint parses a SEC1-encoded point via bpec and
// returns it in the canonical uncompressed form. Rejects the identity.
func curveCanonicalizePoint(c *Curve, data []byte) ([]byte, error) {
	switch c {
	case bp256r1:
		p := new(bpec.BP256Point)
		if _, err := p.SetBytes(data); err != nil {
			return nil, err
		}
		if p.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: public key is point at infinity")
		}
		return p.Bytes(), nil
	case bp384r1:
		p := new(bpec.BP384Point)
		if _, err := p.SetBytes(data); err != nil {
			return nil, err
		}
		if p.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: public key is point at infinity")
		}
		return p.Bytes(), nil
	case bp512r1:
		p := new(bpec.BP512Point)
		if _, err := p.SetBytes(data); err != nil {
			return nil, err
		}
		if p.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: public key is point at infinity")
		}
		return p.Bytes(), nil
	}
	return nil, errors.New("gobrainpool: unknown curve")
}

// --- Per-curve Sign / Verify ---
//
// These operate on the scalar field N via internal/bpec. Secret
// inputs (priv.d, k) never hit math/big.
//
// Invariant: the per-curve sign256/384/512 and verify256/384/512
// primitives do not themselves check approval. They may only be
// reached via:
//
//   - signASN1 / VerifyASN1, which perform the approved-parameter
//     enforcement check (digest length vs curve byte size) before
//     calling through to the primitive; or
//   - castECDSA / pairwiseConsistencyCheck, which pass
//     approved-length digests by construction.
//
// Adding a new caller that bypasses both gates would silently defeat
// SetEnforceApproved. The call-site set is enumerated in
// TestEnforce_PrimitiveCallSitesAreGated (indicator_test.go).

// newSignDRBG picks the nonce generator: nil hedge selects pure RFC
// 6979 deterministic; a non-nil hedge selects the SHA-512 hedged
// construction of draft-irtf-cfrg-det-sigs-with-noise-04.
func newSignDRBG(c *Curve, xBytes, hashMsg, hedge []byte) (*hmacDRBG, error) {
	if hedge == nil {
		return newRFC6979Gen(c, xBytes, hashMsg)
	}
	return newHedgedGen(c, xBytes, hashMsg, hedge)
}

func sign256(priv *PrivateKey, hash, hedge []byte) (rB, sB []byte, err error) {
	c := bp256r1
	eBytes := hashToIntBytes(hash, c)

	var d, e bpec.NScalar256
	if _, err := d.SetBytes(priv.d); err != nil {
		return nil, nil, err
	}
	if _, err := e.SetBytes(eBytes); err != nil {
		return nil, nil, err
	}

	gen, err := newSignDRBG(c, priv.d, hash, hedge)
	if err != nil {
		return nil, nil, err
	}

	for attempt := 0; attempt < 128; attempt++ {
		kBuf, err := gen.next()
		if err != nil {
			return nil, nil, err
		}

		kG := new(bpec.BP256Point)
		if _, err := kG.ScalarBaseMult(kBuf); err != nil {
			return nil, nil, err
		}
		if kG.IsIdentity() == 1 {
			continue
		}
		xb, err := kG.BytesX()
		if err != nil {
			return nil, nil, err
		}

		var r bpec.NScalar256
		if _, err := r.SetBytes(xb); err != nil {
			return nil, nil, err
		}
		if r.IsZero() == 1 {
			continue
		}

		var k, kInv, t, s bpec.NScalar256
		if _, err := k.SetBytes(kBuf); err != nil {
			return nil, nil, err
		}
		kInv.Invert(&k)
		t.Mul(&r, &d)
		t.Add(&t, &e)
		s.Mul(&kInv, &t)
		if s.IsZero() == 1 {
			continue
		}
		return r.Bytes(), s.Bytes(), nil
	}
	return nil, nil, errors.New("gobrainpool: failed to produce ECDSA signature after 128 attempts")
}

func sign384(priv *PrivateKey, hash, hedge []byte) (rB, sB []byte, err error) {
	c := bp384r1
	eBytes := hashToIntBytes(hash, c)

	var d, e bpec.NScalar384
	if _, err := d.SetBytes(priv.d); err != nil {
		return nil, nil, err
	}
	if _, err := e.SetBytes(eBytes); err != nil {
		return nil, nil, err
	}

	gen, err := newSignDRBG(c, priv.d, hash, hedge)
	if err != nil {
		return nil, nil, err
	}

	for attempt := 0; attempt < 128; attempt++ {
		kBuf, err := gen.next()
		if err != nil {
			return nil, nil, err
		}

		kG := new(bpec.BP384Point)
		if _, err := kG.ScalarBaseMult(kBuf); err != nil {
			return nil, nil, err
		}
		if kG.IsIdentity() == 1 {
			continue
		}
		xb, err := kG.BytesX()
		if err != nil {
			return nil, nil, err
		}

		var r bpec.NScalar384
		if _, err := r.SetBytes(xb); err != nil {
			return nil, nil, err
		}
		if r.IsZero() == 1 {
			continue
		}

		var k, kInv, t, s bpec.NScalar384
		if _, err := k.SetBytes(kBuf); err != nil {
			return nil, nil, err
		}
		kInv.Invert(&k)
		t.Mul(&r, &d)
		t.Add(&t, &e)
		s.Mul(&kInv, &t)
		if s.IsZero() == 1 {
			continue
		}
		return r.Bytes(), s.Bytes(), nil
	}
	return nil, nil, errors.New("gobrainpool: failed to produce ECDSA signature after 128 attempts")
}

func sign512(priv *PrivateKey, hash, hedge []byte) (rB, sB []byte, err error) {
	c := bp512r1
	eBytes := hashToIntBytes(hash, c)

	var d, e bpec.NScalar512
	if _, err := d.SetBytes(priv.d); err != nil {
		return nil, nil, err
	}
	if _, err := e.SetBytes(eBytes); err != nil {
		return nil, nil, err
	}

	gen, err := newSignDRBG(c, priv.d, hash, hedge)
	if err != nil {
		return nil, nil, err
	}

	for attempt := 0; attempt < 128; attempt++ {
		kBuf, err := gen.next()
		if err != nil {
			return nil, nil, err
		}

		kG := new(bpec.BP512Point)
		if _, err := kG.ScalarBaseMult(kBuf); err != nil {
			return nil, nil, err
		}
		if kG.IsIdentity() == 1 {
			continue
		}
		xb, err := kG.BytesX()
		if err != nil {
			return nil, nil, err
		}

		var r bpec.NScalar512
		if _, err := r.SetBytes(xb); err != nil {
			return nil, nil, err
		}
		if r.IsZero() == 1 {
			continue
		}

		var k, kInv, t, s bpec.NScalar512
		if _, err := k.SetBytes(kBuf); err != nil {
			return nil, nil, err
		}
		kInv.Invert(&k)
		t.Mul(&r, &d)
		t.Add(&t, &e)
		s.Mul(&kInv, &t)
		if s.IsZero() == 1 {
			continue
		}
		return r.Bytes(), s.Bytes(), nil
	}
	return nil, nil, errors.New("gobrainpool: failed to produce ECDSA signature after 128 attempts")
}

func verify256(pub *PublicKey, hash, rBytes, sBytes []byte) bool {
	c := bp256r1
	eBytes := hashToIntBytes(hash, c)

	var r, s, e, w, u1, u2 bpec.NScalar256
	if _, err := r.SetBytes(rBytes); err != nil {
		return false
	}
	if _, err := s.SetBytes(sBytes); err != nil {
		return false
	}
	if _, err := e.SetBytes(eBytes); err != nil {
		return false
	}
	w.Invert(&s)
	u1.Mul(&e, &w)
	u2.Mul(&r, &w)

	Q := new(bpec.BP256Point)
	if _, err := Q.SetBytes(pub.publicKey); err != nil {
		return false
	}

	p1 := new(bpec.BP256Point)
	if _, err := p1.ScalarBaseMult(u1.Bytes()); err != nil {
		return false
	}
	p2 := new(bpec.BP256Point)
	if _, err := p2.ScalarMult(Q, u2.Bytes()); err != nil {
		return false
	}
	sum := new(bpec.BP256Point).Add(p1, p2)
	if sum.IsIdentity() == 1 {
		return false
	}
	xb, err := sum.BytesX()
	if err != nil {
		return false
	}
	// Reduce xb mod N via NScalar — the same fixed-width CT scalar path
	// used by Sign. xb ∈ [0, p), and p < 2N for all Brainpool curves
	// (since N has its top bit set), so SetBytes' single-step reduction
	// is sufficient here. Mirrors stdlib's bigmod.SetOverflowingBytes.
	var rS, xS bpec.NScalar256
	if _, err := rS.SetBytes(rBytes); err != nil {
		return false
	}
	if _, err := xS.SetBytes(xb); err != nil {
		return false
	}
	return bytes.Equal(rS.Bytes(), xS.Bytes())
}

func verify384(pub *PublicKey, hash, rBytes, sBytes []byte) bool {
	c := bp384r1
	eBytes := hashToIntBytes(hash, c)

	var r, s, e, w, u1, u2 bpec.NScalar384
	if _, err := r.SetBytes(rBytes); err != nil {
		return false
	}
	if _, err := s.SetBytes(sBytes); err != nil {
		return false
	}
	if _, err := e.SetBytes(eBytes); err != nil {
		return false
	}
	w.Invert(&s)
	u1.Mul(&e, &w)
	u2.Mul(&r, &w)

	Q := new(bpec.BP384Point)
	if _, err := Q.SetBytes(pub.publicKey); err != nil {
		return false
	}

	p1 := new(bpec.BP384Point)
	if _, err := p1.ScalarBaseMult(u1.Bytes()); err != nil {
		return false
	}
	p2 := new(bpec.BP384Point)
	if _, err := p2.ScalarMult(Q, u2.Bytes()); err != nil {
		return false
	}
	sum := new(bpec.BP384Point).Add(p1, p2)
	if sum.IsIdentity() == 1 {
		return false
	}
	xb, err := sum.BytesX()
	if err != nil {
		return false
	}
	var rS, xS bpec.NScalar384
	if _, err := rS.SetBytes(rBytes); err != nil {
		return false
	}
	if _, err := xS.SetBytes(xb); err != nil {
		return false
	}
	return bytes.Equal(rS.Bytes(), xS.Bytes())
}

func verify512(pub *PublicKey, hash, rBytes, sBytes []byte) bool {
	c := bp512r1
	eBytes := hashToIntBytes(hash, c)

	var r, s, e, w, u1, u2 bpec.NScalar512
	if _, err := r.SetBytes(rBytes); err != nil {
		return false
	}
	if _, err := s.SetBytes(sBytes); err != nil {
		return false
	}
	if _, err := e.SetBytes(eBytes); err != nil {
		return false
	}
	w.Invert(&s)
	u1.Mul(&e, &w)
	u2.Mul(&r, &w)

	Q := new(bpec.BP512Point)
	if _, err := Q.SetBytes(pub.publicKey); err != nil {
		return false
	}

	p1 := new(bpec.BP512Point)
	if _, err := p1.ScalarBaseMult(u1.Bytes()); err != nil {
		return false
	}
	p2 := new(bpec.BP512Point)
	if _, err := p2.ScalarMult(Q, u2.Bytes()); err != nil {
		return false
	}
	sum := new(bpec.BP512Point).Add(p1, p2)
	if sum.IsIdentity() == 1 {
		return false
	}
	xb, err := sum.BytesX()
	if err != nil {
		return false
	}
	var rS, xS bpec.NScalar512
	if _, err := rS.SetBytes(rBytes); err != nil {
		return false
	}
	if _, err := xS.SetBytes(xb); err != nil {
		return false
	}
	return bytes.Equal(rS.Bytes(), xS.Bytes())
}
