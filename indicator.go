package gobrainpool

import "sync/atomic"

// Approved Mode
//
// Two approval rules govern this package:
//
//   - For ECDSA Sign and Verify, the digest byte length must equal the
//     curve byte size: 32 bytes for BP256r1, 48 for BP384r1, 64 for
//     BP512r1. Other lengths still produce a valid signature or
//     verification result (via FIPS 186-5 §6.4.1 bits2int), but are
//     flagged non-approved.
//   - For GenerateKey, NewPrivateKey, NewPublicKey and ECDH there is
//     no parameter variability at this layer. On a supported curve
//     they are always approved.
//
// Enforcement
//
// SetEnforceApproved(true) switches the package into approved-parameter
// enforcement. While enforcement is on, a service called with
// non-approved parameters refuses instead of running:
//
//   - Sign / SignASN1 / SignDeterministicASN1 return a non-nil error
//     and no signature bytes.
//   - VerifyASN1 returns false without performing any cryptographic
//     verification.
//
// Guarantee. With enforcement on, no exported service returns a
// successful result computed on non-approved parameters. The only
// outcomes on non-approved inputs are (error, no signature) from the
// Sign family and false from Verify. The check runs at the very start
// of each service, before any arithmetic or entropy consumption.
//
// With enforcement off (the default) the package matches stdlib
// crypto/ecdsa behaviour: any digest length is accepted and a
// signature / verification result is computed via bits2int.
//
// No per-call approval query
//
// The package does not expose a per-call approval query (such as a
// ServiceIndicator() function). A correct per-goroutine approval state
// needs goroutine-local storage, which external Go packages cannot
// obtain without depending on undocumented runtime internals. Approved
// Mode is therefore expressed as an enforcement guard on call entry
// rather than a per-call query on call exit.

var approvedModeEnforced atomic.Bool

// SetEnforceApproved switches the package between best-effort mode
// (default, matches stdlib crypto/ecdsa behaviour: any digest length
// accepted) and approved-parameter enforcement (non-approved inputs
// produce errors from Sign and false from Verify without performing
// the cryptographic operation).
//
// Safe to call concurrently with crypto operations. Each service
// reads the flag atomically on entry. Calls that are already in flight
// when the flag flips complete under the setting that was in effect
// at their entry. To enforce a consistent setting across a batch of
// operations, flip the flag before invoking any service in that batch.
func SetEnforceApproved(on bool) { approvedModeEnforced.Store(on) }

// EnforceApproved reports whether approved-parameter enforcement is
// currently active.
func EnforceApproved() bool { return approvedModeEnforced.Load() }
