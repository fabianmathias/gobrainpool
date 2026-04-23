package gobrainpool

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/fabianmathias/gobrainpool/internal/bpec"
)

// TestSelfTest_PassesCleanly exercises the full CAST with the live
// vectors. A regression in any primitive (sign256/384/512, verify,
// ecdhShared, ASN.1 encoding, newPrivateKeyFromScalar) that affected
// one of the frozen outputs would be caught here.
func TestSelfTest_PassesCleanly(t *testing.T) {
	if err := selfTest(); err != nil {
		t.Fatalf("selfTest() = %v, want nil", err)
	}
}

// TestSelfTest_DetectsBadSignatureVector pins the signature-mismatch
// path: flipping a single bit of the frozen expected signature must
// cause selfTest to surface a "signature mismatch" error. This is the
// regression test for the CAST itself — without it, a silently-broken
// CAST that always returned nil would give a false sense of coverage.
func TestSelfTest_DetectsBadSignatureVector(t *testing.T) {
	orig := lookupECDSAVector
	t.Cleanup(func() { lookupECDSAVector = orig })

	lookupECDSAVector = func(c *Curve) ecdsaCASTVector {
		v := orig(c)
		bad := make([]byte, len(v.expectedSig))
		copy(bad, v.expectedSig)
		bad[len(bad)-1] ^= 0x01
		v.expectedSig = bad
		return v
	}
	err := selfTest()
	if err == nil {
		t.Fatal("selfTest() = nil, want signature-mismatch error")
	}
	if !strings.Contains(err.Error(), "signature mismatch") {
		t.Errorf("expected 'signature mismatch' in error, got: %v", err)
	}
}

// TestSelfTest_DetectsBadSharedSecret pins the ECDH-mismatch path.
func TestSelfTest_DetectsBadSharedSecret(t *testing.T) {
	orig := lookupECDHVector
	t.Cleanup(func() { lookupECDHVector = orig })

	lookupECDHVector = func(c *Curve) ecdhCASTVector {
		v := orig(c)
		bad := make([]byte, len(v.expectedZ))
		copy(bad, v.expectedZ)
		bad[0] ^= 0x01
		v.expectedZ = bad
		return v
	}
	err := selfTest()
	if err == nil {
		t.Fatal("selfTest() = nil, want shared-secret-mismatch error")
	}
	if !strings.Contains(err.Error(), "shared-secret mismatch") {
		t.Errorf("expected 'shared-secret mismatch' in error, got: %v", err)
	}
}

// TestPCT_PassesForFreshKeys covers the happy path: GenerateKey on each
// curve must succeed, and by the time it returns the PCT has already
// passed.
func TestPCT_PassesForFreshKeys(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.GenerateKey(rand.Reader); err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
		})
	}
}

// TestPCT_DetectsInconsistentKeypair pins that pairwiseConsistencyCheck
// catches a keypair whose public key has been corrupted — verify must
// reject the signature, and pairwiseConsistencyCheck must surface the
// mismatch as an error. Without this test the PCT could silently
// accept broken keys and we'd have no coverage of its failure branch.
func TestPCT_DetectsInconsistentKeypair(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			// Build a legitimate keypair, then swap Q for a different
			// curve point (the public key of a different scalar) so
			// priv.d no longer matches priv.publicKey.
			good, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			other, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey other: %v", err)
			}
			if bytes.Equal(good.publicKey.publicKey, other.publicKey.publicKey) {
				t.Fatal("invariant: two independent GenerateKey calls produced identical pubkeys")
			}

			bad := &PrivateKey{
				curve: c,
				d:     bytes.Clone(good.d),
				publicKey: &PublicKey{
					curve:     c,
					publicKey: bytes.Clone(other.publicKey.publicKey),
				},
			}
			err = pairwiseConsistencyCheck(bad)
			if err == nil {
				t.Fatal("pairwiseConsistencyCheck on inconsistent keypair = nil, want error")
			}
			if !strings.Contains(err.Error(), "verify rejected") {
				t.Errorf("expected 'verify rejected' in error, got: %v", err)
			}
		})
	}
}

// TestPCT_DetectsIdentityDerivedPubkey covers the degenerate case: if
// scalar-mult produced the identity point, newPrivateKeyFromScalar
// must refuse to build a PrivateKey — curveScalarBaseMult already
// guards this, but we pin it so a future regression in that guard is
// caught here as well.
func TestPCT_DetectsIdentityDerivedPubkey(t *testing.T) {
	// Can't easily produce an identity through valid inputs (would need
	// d == N, which NewPrivateKey rejects). Assert the guard directly
	// on the internal helper by passing an identity-producing scalar if
	// the internal primitives ever allowed it.
	c := BP256r1()
	// d = 0 is rejected upstream by NewPrivateKey; here we call the
	// internal scalar-mult with all-zero bytes to confirm it doesn't
	// silently return an identity-encoded pub bytes.
	zero := make([]byte, c.byteSize)
	p := new(bpec.BP256Point)
	if _, err := p.ScalarBaseMult(zero); err != nil {
		// Error here is also acceptable — either rejection mode keeps
		// identity out of newPrivateKeyFromScalar.
		return
	}
	if p.IsIdentity() != 1 {
		t.Fatal("ScalarBaseMult(0) did not return the identity point — check invariant")
	}
	// curveScalarBaseMult must surface this as an error.
	if _, err := curveScalarBaseMult(c, zero); err == nil {
		t.Error("curveScalarBaseMult(0) = nil error, want identity rejection")
	}
}
