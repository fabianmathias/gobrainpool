// Package gobrainpool implements the Brainpool elliptic curves BP256r1,
// BP384r1 and BP512r1 defined in RFC 5639, with ECDSA signing /
// verification and ECDH key agreement on top. Go's standard library
// does not support Brainpool; this package fills that gap.
//
// # Design
//
// Field arithmetic mod P (coordinates) and mod N (scalars) is performed
// by fiat-crypto generated, fixed-width Montgomery code in the internal
// bp{256,384,512} / bp{256,384,512}n subpackages. The output is pure Go
// (no cgo), branch-free and machine-independent. On top of that, point
// arithmetic uses the Renes-Costello-Batina 2015 complete projective
// addition formula (Algorithm 1, "general a"), which is safe on every
// curve point including the identity and self-addition.
//
// Scalar multiplication uses a fixed 4-bit unsigned window schedule
// with a constant-time table lookup (table[0..15], no Booth recoding).
// The iteration count and memory-access pattern depend only on the
// curve, not on the secret scalar.
//
// ECDSA signatures are produced with RFC 6979 deterministic nonces. If
// the caller supplies a non-nil rand, fresh CSPRNG bytes are folded into
// the HMAC-DRBG seed as a hedge against RNG-state compromise (cf. "A
// Riddle Wrapped in an Enigma", Bernstein et al.). Signature bytes
// match what stdlib crypto/ecdsa would produce for the same inputs on
// an equivalent curve — no low-S post-processing, to stay faithful to
// FIPS 186-5.
//
// ECDSA signatures are structurally malleable: for any valid (r, s) the
// pair (r, N-s) also verifies. VerifyASN1 accepts both forms, matching
// crypto/ecdsa.VerifyASN1 and the interop expectations of X.509 / TLS /
// JWS, which do not mandate low-S. Applications that need a single
// canonical byte representation per (message, key) — e.g. content-
// addressed or replay-sensitive protocols — must enforce low-S outside
// this package.
//
// ECDH returns the affine x-coordinate of priv·peer as a fixed-width
// big-endian byte slice. The full arithmetic path, including Z⁻¹ and
// byte encoding, stays inside the fiat limb representation — the shared
// secret never transits math/big on its way out.
//
// # API shape
//
// The public surface is byte-only and mirrors crypto/ecdh: Curve is
// opaque (obtain the singleton via [BP256r1], [BP384r1] or [BP512r1]);
// keys are constructed only by the package (via the curve's
// GenerateKey / NewPrivateKey / NewPublicKey methods). Private keys
// serialize as fixed-width big-endian scalar bytes; public keys
// serialize as SEC1-uncompressed (0x04 || X || Y).
//
//	priv, err := gobrainpool.BP256r1().GenerateKey(rand.Reader)
//	sig,  err := gobrainpool.SignASN1(rand.Reader, priv, digest)
//	ok        := gobrainpool.VerifyASN1(priv.PublicKey(), digest, sig)
//	ss,   err := priv.ECDH(peer)
//
// *PrivateKey satisfies crypto.Signer (its Sign method produces a DER-
// encoded ASN.1 signature), so Brainpool keys slot into any API that
// accepts a crypto.Signer.
//
// # Constant-time scope
//
// The following operations are constant-time on secret inputs (private
// scalar d, nonce k, shared ECDH X):
//
//   - Point scalar multiplication (base-point and arbitrary-point)
//   - ECDSA Sign arithmetic: k⁻¹, r·d, +e, ·k⁻¹ mod N
//   - ECDH shared-secret extraction
//
// ECDSA verification is implemented through the same constant-time
// scalar-mult and NScalar arithmetic used by signing (Fermat-based
// modular inverse, ctLookup table reads). Verify operates only on
// public values, so this is not a hard security requirement, but the
// implementation does not branch or memory-access on (r, s) or e.
//
// # Curve parameters
//
// All curve parameters are taken verbatim from RFC 5639, section 3 and
// are exercised against the RFC 7027 known-answer ECDH vectors on all
// three curves.
package gobrainpool
