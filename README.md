# gobrainpool

Pure-Go implementation of the Brainpool elliptic curves (BP256r1, BP384r1,
BP512r1) defined in [RFC 5639](https://datatracker.ietf.org/doc/html/rfc5639),
with ECDSA signing / verification and ECDH key agreement.

## Why

Go's standard library does not support Brainpool curves. `crypto/elliptic`
hard-codes the NIST curves. Existing third-party packages (notably
`github.com/ProtonMail/go-crypto/brainpool`) fill the hole, but are
byproducts of GPG support, rely on the deprecated `elliptic.Curve` /
`*big.Int` interface, and are not constant-time.

This package is a dedicated Brainpool implementation, validated against
the RFC 7027 test vectors and Google's Wycheproof ECDSA test suite for
BP256r1/BP384r1/BP512r1. The API shape mirrors modern stdlib
(`crypto/ecdh`, `crypto/internal/fips140/nistec`): opaque curve handles,
byte-only keys, no `*big.Int` on the public surface.

## Implementation

**Constant-time throughout.** Point arithmetic uses the
Renes–Costello–Batina complete projective formulas ([RCB 2015]):
Algorithm 1 for general addition, Algorithm 3 for dedicated doubling.
Both are branch-free and valid for all inputs including P = Q, P = -Q,
and the point at infinity. Scalar multiplication uses a fixed 4-bit
window over the full curve bit length with a precomputed 16-entry
table. The lookup is a byte-level masked select so the chosen index
is not visible to the control flow. The schedule runs the same number
of doublings and additions for any non-zero scalar.

Field arithmetic is fiat-crypto-generated fixed-width saturated
Montgomery code with four limbs for BP256, six for BP384, eight for
BP512. Every field operation executes the same instruction sequence
on the same number of words regardless of operand value. There is no
leading-zero stripping as with `math/big`. Inversion uses Fermat
(`a^(p-2) mod p`) with the public bit pattern of `p-2`, driving
constant-time squarings and multiplications via the fiat primitives.
Hand-written assembler hot paths are not in place yet. The current
implementation is portable Go.

ECDSA signatures are ASN.1-DER encoded and verified via
`golang.org/x/crypto/cryptobyte`, the same strict-DER path used by
`crypto/ecdsa`. Non-minimal lengths, non-minimal integer encodings and
trailing bytes are rejected on the parse side, so a valid signature
cannot be re-encoded into a second accepted byte string.

ECDSA nonces use RFC 6979 deterministic derivation (HMAC-DRBG seeded
from the private key and message digest, using the hash paired to the
curve size: SHA-256 for BP256, SHA-384 for BP384, SHA-512 for BP512).
Passing a non-nil `rand` to `SignASN1` additionally hedges. RNG
entropy is folded into the HMAC-DRBG input, so a weak RNG cannot
cause nonce reuse.

ECDH returns the X coordinate of `[d]P` (SEC1 §3.3.1). Public keys are
validated on construction (on-curve, non-infinity). Brainpool r-curves
have cofactor 1, so no small-subgroup check is needed.

Pure Go, no cgo. Only dependency is `golang.org/x/crypto` (for
`cryptobyte`).

The public API is safe for concurrent use by multiple goroutines.

[RCB 2015]: https://eprint.iacr.org/2015/1060

## Install

```
go get github.com/fabianmathias/gobrainpool
```

## Usage

See the [package documentation on pkg.go.dev](https://pkg.go.dev/github.com/fabianmathias/gobrainpool)
for the full API. The curve-handle pattern mirrors `crypto/ecdh`:
`gobrainpool.BP256r1()` returns an opaque `*Curve` that you call
`GenerateKey`, `NewPublicKey`, and `NewPrivateKey` on. `*PrivateKey`
implements `crypto.Signer`.

## Scope

This package is the curve layer: ECDSA, ECDH, point and scalar
arithmetic, and the SEC1 / fixed-width byte encodings you need to
exchange raw keys. Higher-level key containers and protocol framing
are out of scope. Build those on top as a separate package.

## Approved Mode

ECDSA Sign and Verify treat a digest as matching the curve when its
byte length equals the curve byte size: 32 for BP256r1, 48 for
BP384r1, 64 for BP512r1. The remaining services (key generation, key
import, ECDH) have no parameter variability at this layer.

`SetEnforceApproved(true)` activates enforcement. While enforcement is
on, the Sign family returns an error and no signature bytes on a
mismatched digest length, and `VerifyASN1` returns false without
running the cryptographic verify. The check runs at the start of each
service, before any arithmetic or entropy is consumed. With
enforcement off (the default) the package accepts any digest length
and computes the signature or verification result through FIPS 186-5
§6.4.1 bits2int, matching stdlib `crypto/ecdsa` behaviour.

**Guarantee.** With enforcement on, no exported service returns a
successful result on a mismatched digest length. The only outcomes on
mismatched input are (error, no signature) from Sign and false from
Verify.

**No per-call approval query.** The package does not expose a
per-call approval query. A correct per-goroutine approval state needs
goroutine-local storage, which external Go packages cannot obtain
without depending on undocumented runtime internals. Approval is
therefore expressed as a call-entry guard rather than a call-exit
query.

## Project status

This is a personal open-source project, maintained by a single
developer in their spare time. It is not a commercial product, not
a commercial service, and no commercial support, service-level
agreements, warranties or consulting are offered or implied.
Integration into any product is at the integrator's sole
responsibility.

## Security

The threat model, supported versions and private disclosure channel
are in [SECURITY.md](SECURITY.md). Please do not open public issues
for suspected vulnerabilities.

## License

Apache License 2.0. See [LICENSE](LICENSE).