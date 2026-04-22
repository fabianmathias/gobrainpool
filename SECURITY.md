# Security policy

## Reporting a vulnerability

Please report suspected security issues **privately** via GitHub Security
Advisories:

> https://github.com/fabianmathias/gobrainpool/security/advisories/new

Do not open a public issue, pull request or discussion for a potential
vulnerability. I will acknowledge reports within 7 days and aim to
publish a fix and advisory within 90 days of a confirmed report, or
sooner for actively exploited issues.

## Supported versions

Pre-1.0: only the latest tagged release receives security fixes. Once
v1.0 is cut, the latest minor line will receive fixes; any further
support commitment will be stated here.

## Security model

The threat model this package is designed against, and the limits of
that design, are stated below. These are the *claims* — any deviation
between these claims and the actual behaviour of the code is a bug and
in scope for a security report.

### In scope

- **Timing side channels on secret inputs.** Private-scalar paths
  (ECDSA `d` and nonce `k`, ECDH `d`, ECDH shared x-coordinate) are
  intended to execute in time independent of the secret bytes. The
  operations covered are enumerated in the *Constant-time scope*
  section of the package godoc.
- **Invalid-input rejection at the public API boundary.** Off-curve
  points, the identity as peer public key in ECDH, out-of-range
  scalars, and non-DER signature encodings must be refused rather
  than silently accepted.
- **Strict DER on Verify.** Signature parsing goes through
  `golang.org/x/crypto/cryptobyte`, matching the stdlib
  `crypto/ecdsa` strict-DER path. Non-minimal integer encodings,
  non-minimal length fields and trailing bytes are rejected.
- **Approved Mode enforcement.** When `SetEnforceApproved(true)` is
  active, no exported service returns a successful result on a
  mismatched digest length (digest byte length must equal curve byte
  size: 32 for BP256r1, 48 for BP384r1, 64 for BP512r1). On a
  mismatch the Sign family returns an error and no signature bytes;
  `VerifyASN1` returns false without running the cryptographic verify.
  A successful mismatched call under enforcement is a bug.

### Out of scope

- **Physical side channels** — power (SPA/DPA), EM, acoustic, timing
  leakage measurable only at the physical layer, and active fault
  injection.
- **Micro-architectural attacks** — cache-timing, speculative-
  execution, port-contention, Rowhammer and similar host-CPU
  attacks. The pure-Go build has no awareness of these and no
  countermeasures.
- **Runtime / OS / RNG compromise.** We trust the Go runtime, the
  operating system, and the entropy source provided to the library.
  Key material in process memory is not explicitly zeroed;
  `runtime.KeepAlive` and Go's garbage collector make this a
  best-effort discipline rather than a guarantee.
- **Verification-path timing.** `VerifyASN1` operates on public
  values (signature and public key) and is not hardened against
  timing observation.
- **Denial-of-service.** Pathologically large inputs may take
  proportionally longer to process; parse-time quadratic blow-ups
  are out of scope unless they exceed the cost of the underlying
  scalar multiplication by a wide margin.
- **Key lifecycle, storage and protocol framing.** The package
  exposes raw byte-encoded keys and raw signatures; wrapping them
  in a key store, a protocol, or a PKI is the integrator's
  responsibility.

### Known limitations

- **Low-S is not enforced.** For any valid signature `(r, s)` the
  pair `(r, N-s)` also verifies. This matches stdlib
  `crypto/ecdsa.VerifyASN1` and the interop requirements of X.509 /
  TLS / JWS. Applications requiring a single canonical byte
  representation per `(message, key)` — content-addressed or
  replay-sensitive protocols — must enforce low-S themselves.
- **Nonce-bias resistance** relies on RFC 6979 determinism, with a
  CSPRNG hedge folded into the HMAC-DRBG seed per
  draft-irtf-cfrg-det-sigs-with-noise-04. We make no claim beyond
  those two constructions.
- **No hardware acceleration.** The pure-Go build does not use
  assembler or hardware crypto instructions. Operations are
  correct and constant-time but not competitive with hand-tuned
  assembler backends.

## Certification status

This package is **not itself a certified cryptographic module** —
certification in the BSI sense attaches to a product, not to a
standalone library. The package is designed to be suitable as a
building block inside a product pursuing BSI TR-02102 / AIS 20-31-46-49
evaluation (self-tests, Approved Mode with enforcement, approved DRBG
wrapper), but no certification claim is made on the library in
isolation.

The package deliberately does not implement a FIPS 140-3 §7.4.2
service indicator: the audit target is BSI, not FIPS, and the BSI
Approved Mode requirement is met by the enforcement toggle
(`SetEnforceApproved`) alone. See the godoc on `SetEnforceApproved`
for the full rationale.

## Scope of the license disclaimer

This package is distributed as a **personal open-source project**,
maintained by a single developer in their spare time. It is not a
commercial product, not a commercial service, and no commercial
support, service-level agreements, warranties or consulting are
offered or implied.

The Apache 2.0 license under which this code is distributed disclaims
warranty and limits liability to the full extent permitted by law
(see sections 7 and 8 of `LICENSE`). The security model above is a
best-effort statement of intent, not a warranty.

Integration into any commercial, certified or regulated product is
the integrator's sole responsibility.
