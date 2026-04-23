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

## Project status

This is a personal open-source project that I maintain in my spare
time. It is not a commercial product or service, and no commercial
support, warranties, or consulting are provided.

This code has not been independently audited. Integration is at your
own risk.

## Implementation

**Constant-time throughout.** Point arithmetic uses the
Renes–Costello–Batina complete projective formulas (RCB 2015):
Algorithm 1 for general addition and Algorithm 3 for doubling. Both
are branch-free and valid for all inputs, including edge cases such as
P = Q, P = -Q, and the point at infinity.

Scalar multiplication uses a fixed 4-bit window over the full curve
bit length with a precomputed 16-entry table. Table lookup is
implemented as a masked byte-level select, avoiding control-flow
leakage. The execution schedule is identical for all non-zero scalars.

Field arithmetic is generated via fiat-crypto using fixed-width,
saturated Montgomery representations: four limbs (BP256), six (BP384),
and eight (BP512). All operations execute a fixed instruction sequence
independent of operand values. Unlike `math/big`, no leading-zero
stripping occurs.

Inversion uses Fermat’s little theorem (`a^(p-2) mod p`) with a fixed
exponent, ensuring constant-time execution via the fiat primitives.
The implementation is currently pure Go; no handwritten assembly is
used.

ECDSA signatures are ASN.1 DER encoded and verified using
`golang.org/x/crypto/cryptobyte`, matching the strict DER handling of
`crypto/ecdsa`. Non-minimal encodings and trailing data are rejected,
ensuring a unique valid encoding per signature.

Nonces follow RFC 6979 deterministic generation (HMAC-DRBG seeded from
the private key and message digest, using SHA-256/384/512 depending on
curve size). Providing a non-nil `rand` to `SignASN1` adds entropy as a
hedge.

ECDH returns the X coordinate of `[d]P` (SEC1 §3.3.1). Public keys are
validated on construction (on-curve, non-infinity). Brainpool r-curves
have cofactor 1, so no subgroup checks are required.

Pure Go, no cgo. Only dependency is `golang.org/x/crypto`.

The public API is safe for concurrent use.

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

This package provides the curve layer: ECDSA, ECDH, point and scalar
arithmetic, and SEC1 / fixed-width encodings for raw key exchange.

Higher-level key containers and protocol framing are out of scope.

## Approved Mode

ECDSA Sign and Verify treat a digest as matching the curve when its
byte length equals the curve size (32/48/64 bytes for BP256/384/512).

`SetEnforceApproved(true)` enables enforcement. When enabled:
- Sign returns an error for mismatched digest lengths
- Verify returns false without performing verification

Checks run before any cryptographic computation.

With enforcement disabled (default), arbitrary digest lengths are
accepted and processed via FIPS 186-5 §6.4.1 (bits2int), matching
stdlib `crypto/ecdsa`.

**Guarantee:** With enforcement enabled, no exported function returns a
successful result for mismatched digest lengths.

**No per-call approval query.** The package does not expose a
per-call approval query. A correct per-goroutine approval state needs
goroutine-local storage, which external Go packages cannot obtain
without depending on undocumented runtime internals. Approval is
therefore expressed as a call-entry guard rather than a call-exit
query.

## Security

The threat model, supported versions and private disclosure channel
are in [SECURITY.md](SECURITY.md). Please do not open public issues
for suspected vulnerabilities.

## License

Apache License 2.0. See [LICENSE](LICENSE).
