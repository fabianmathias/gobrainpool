package gobrainpool

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"math/big"
	"testing"

	"github.com/fabianmathias/gobrainpool/internal/bpec"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// --- shared helpers -------------------------------------------------------
//
// Tests compare against math/big references in several places; these
// two methods project a curve's N and P into *big.Int for use in
// those comparisons. Runtime code is byte-only and never reconstructs
// these from curve parameters, so the helpers are test-only.

func (c *Curve) nBig() *big.Int { return new(big.Int).SetBytes(c.nBE) }
func (c *Curve) pBig() *big.Int { return new(big.Int).SetBytes(c.pBE) }

func hasherFor(c *Curve) func() hash.Hash {
	switch c.bitSize {
	case 256:
		return sha256.New
	case 384:
		return sha512.New384
	case 512:
		return sha512.New
	}
	return sha256.New
}

func digest(c *Curve, msg []byte) []byte {
	h := hasherFor(c)()
	h.Write(msg)
	return h.Sum(nil)
}

// encodeSig builds a strict-DER SEQUENCE { R INTEGER, S INTEGER } for
// use in malleability tests.
func encodeSig(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("encodeSig: %v", err)
	}
	return out
}

// parseSigRS extracts (R, S) from a valid baseline signature for use
// in malleation tests.
func parseSigRS(t *testing.T, sig []byte) (r, s *big.Int) {
	t.Helper()
	input := cryptobyte.String(sig)
	var inner cryptobyte.String
	r, s = new(big.Int), new(big.Int)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		t.Fatalf("parseSigRS: could not parse baseline signature")
	}
	return r, s
}

func mustHexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("bad hex int: %s", s)
	}
	return n
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex bytes %q: %v", s, err)
	}
	return b
}

func bytes0xFF(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xFF
	}
	return b
}

// zeroReader yields all-zero bytes. Used to feed a zero hedge block to
// SignASN1 — the DRBG still diverges across messages because the digest
// is mixed in, so a failure here means the digest is not reaching the
// HMAC-DRBG seed. Mirrors stdlib ecdsa_test.go's zeroReader.
type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

// --- roundtrip / verify ---------------------------------------------------

// TestSignVerifyRoundtrip covers the happy path: sign with a fresh
// key, verify with the public half.
func TestSignVerifyRoundtrip(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			msg := []byte("gobrainpool roundtrip test")
			h := digest(c, msg)
			sig, err := SignASN1(rand.Reader, priv, h)
			if err != nil {
				t.Fatalf("SignASN1: %v", err)
			}
			if !VerifyASN1(priv.PublicKey(), h, sig) {
				t.Errorf("VerifyASN1 returned false for a fresh signature")
			}

			// Tampered hash must fail.
			h[0] ^= 0xff
			if VerifyASN1(priv.PublicKey(), h, sig) {
				t.Errorf("VerifyASN1 accepted tampered hash")
			}
		})
	}
}

// TestVerify_MalleabilityRejected checks that the verifier rejects
// signatures where r or s are out of [1, n-1], and that trailing bytes
// after the SEQUENCE are refused.
func TestVerify_MalleabilityRejected(t *testing.T) {
	c := BP256r1()
	priv, _ := c.GenerateKey(rand.Reader)
	h := digest(c, []byte("x"))
	sig, err := SignASN1(rand.Reader, priv, h)
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	goodR, goodS := parseSigRS(t, sig)

	cases := []struct {
		name string
		sig  []byte
	}{
		{"r=0", encodeSig(t, big.NewInt(0), goodS)},
		{"s=0", encodeSig(t, goodR, big.NewInt(0))},
		{"r=N", encodeSig(t, c.nBig(), goodS)},
		{"s=N", encodeSig(t, goodR, c.nBig())},
		{"trailing byte", append(append([]byte{}, sig...), 0x00)},
	}
	for _, tc := range cases {
		if VerifyASN1(priv.PublicKey(), h, tc.sig) {
			t.Errorf("VerifyASN1 accepted %s", tc.name)
		}
	}
}

// TestVerify_StrictDER pins the verifier against DER re-encoding
// attacks. A third party must not be able to mutate a valid signature
// into a second valid byte string that still verifies.
func TestVerify_StrictDER(t *testing.T) {
	c := BP256r1()
	priv, _ := c.GenerateKey(rand.Reader)
	h := digest(c, []byte("strict der"))
	good, err := SignASN1(rand.Reader, priv, h)
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	if !VerifyASN1(priv.PublicKey(), h, good) {
		t.Fatalf("baseline signature did not verify")
	}

	// Baseline shape: 30 LL 02 RL r 02 SL s (short-form lengths).
	if good[0] != 0x30 || good[1] >= 0x80 {
		t.Fatalf("unexpected baseline shape: % x", good[:3])
	}
	bodyLen := int(good[1])
	body := good[2 : 2+bodyLen]
	if body[0] != 0x02 || body[1] >= 0x80 {
		t.Fatalf("unexpected INTEGER shape: % x", body[:3])
	}
	rLen := int(body[1])
	rBytes := body[2 : 2+rLen]
	sTLV := body[2+rLen:]

	seqLongForm := append([]byte{0x30, 0x81, byte(bodyLen)}, body...)
	indef := append([]byte{0x30, 0x80}, body...)
	indef = append(indef, 0x00, 0x00)
	intLongForm := append([]byte{0x30, byte(3 + rLen + len(sTLV)), 0x02, 0x81, byte(rLen)}, rBytes...)
	intLongForm = append(intLongForm, sTLV...)

	cases := []struct {
		name string
		sig  []byte
	}{
		{"SEQUENCE long-form length (non-minimal)", seqLongForm},
		{"SEQUENCE indefinite length", indef},
		{"INTEGER long-form length (non-minimal)", intLongForm},
	}
	if rBytes[0] != 0x00 && rBytes[0]&0x80 == 0 {
		padded := append([]byte{0x00}, rBytes...)
		newBody := append([]byte{0x02, byte(len(padded))}, padded...)
		newBody = append(newBody, sTLV...)
		newSig := append([]byte{0x30, byte(len(newBody))}, newBody...)
		cases = append(cases, struct {
			name string
			sig  []byte
		}{"INTEGER non-minimal leading zero", newSig})
	}

	for _, tc := range cases {
		if VerifyASN1(priv.PublicKey(), h, tc.sig) {
			t.Errorf("VerifyASN1 accepted %s", tc.name)
		}
	}
}

// TestVerify_NilPublicKey ensures a nil *PublicKey does not panic.
func TestVerify_NilPublicKey(t *testing.T) {
	if VerifyASN1(nil, []byte("x"), []byte{0x30, 0x00}) {
		t.Errorf("VerifyASN1 accepted nil pub")
	}
}

// TestGenerateKey_PublicOnCurve ensures keys produced by GenerateKey
// have a scalar in [1, N-1] and a public half that re-parses.
func TestGenerateKey_PublicOnCurve(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			d := new(big.Int).SetBytes(priv.Bytes())
			if d.Sign() <= 0 || d.Cmp(c.nBig()) >= 0 {
				t.Errorf("scalar out of range [1, N-1]")
			}
			pub2, err := c.NewPublicKey(priv.PublicKey().Bytes())
			if err != nil {
				t.Fatalf("public key does not re-parse: %v", err)
			}
			if !priv.PublicKey().Equal(pub2) {
				t.Errorf("public key bytes round-trip mismatch")
			}
		})
	}
}

// TestNewPublicKey_RejectsOffCurve: an off-curve (x, y) encoded as an
// uncompressed SEC1 point must be refused by NewPublicKey — the
// invalid-curve attack mitigation.
func TestNewPublicKey_RejectsOffCurve(t *testing.T) {
	c := BP256r1()
	bad := make([]byte, 1+2*c.byteSize)
	bad[0] = 0x04
	bad[len(bad)-1] = 0x01 // y = 1, x = 0 — not on the curve
	if _, err := c.NewPublicKey(bad); err == nil {
		t.Errorf("NewPublicKey accepted off-curve point")
	}
}

// TestSignerInterface verifies that *PrivateKey satisfies crypto.Signer
// and that the Sign method round-trips through VerifyASN1.
func TestSignerInterface(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			var signer crypto.Signer = priv
			msg := digest(c, []byte("signer interface"))
			sig, err := signer.Sign(rand.Reader, msg, nil)
			if err != nil {
				t.Fatalf("Signer.Sign: %v", err)
			}
			pub, ok := signer.Public().(*PublicKey)
			if !ok {
				t.Fatalf("Signer.Public() is not *PublicKey")
			}
			if !VerifyASN1(pub, msg, sig) {
				t.Errorf("VerifyASN1 rejected a signature produced by Signer.Sign")
			}
		})
	}
}

// --- parity with stdlib crypto/ecdsa --------------------------------------
//
// Each test mirrors a stdlib test of the same name, adapted to our API
// surface (DER-only signatures, curve-sized raw private-key bytes). The
// point is behavioural equivalence with the FIPS-gated reference, which
// is the closest thing to a certification oracle we have.

// TestNonceSafety mirrors stdlib's TestNonceSafety: with a constant
// (zero) hedge block, two different messages must still yield different
// (r, s). If either r or s collides across messages, the digest is not
// feeding into the nonce and the scheme is broken.
func TestNonceSafety(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			sig0, err := SignASN1(zeroReader{}, priv, digest(c, []byte("testing")))
			if err != nil {
				t.Fatalf("SignASN1 0: %v", err)
			}
			sig1, err := SignASN1(zeroReader{}, priv, digest(c, []byte("testing...")))
			if err != nil {
				t.Fatalf("SignASN1 1: %v", err)
			}
			r0, s0 := parseSigRS(t, sig0)
			r1, s1 := parseSigRS(t, sig1)
			if r0.Cmp(r1) == 0 {
				t.Errorf("nonce r collided across messages")
			}
			if s0.Cmp(s1) == 0 {
				t.Errorf("s collided across messages")
			}
		})
	}
}

// TestINDCCA mirrors stdlib's TestINDCCA: two signatures of the same
// message with a real random hedge must differ (the hedge folds fresh
// entropy into the DRBG seed). This is what blocks an attacker with a
// random-oracle view of (msg, sig) from gaining any per-signature
// information beyond the signature itself.
func TestINDCCA(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			h := digest(c, []byte("testing"))
			sig0, err := SignASN1(rand.Reader, priv, h)
			if err != nil {
				t.Fatalf("SignASN1 0: %v", err)
			}
			sig1, err := SignASN1(rand.Reader, priv, h)
			if err != nil {
				t.Fatalf("SignASN1 1: %v", err)
			}
			r0, s0 := parseSigRS(t, sig0)
			r1, s1 := parseSigRS(t, sig1)
			if r0.Cmp(r1) == 0 {
				t.Errorf("same-message signatures produced the same nonce")
			}
			if s0.Cmp(s1) == 0 {
				t.Errorf("same-message signatures produced the same s")
			}
		})
	}
}

// TestZeroHashSignature mirrors stdlib: signing an all-zero digest must
// succeed and round-trip through Verify. A previous regression in the
// bits2int path could cause the scalar derivation to return 0·G which
// must then be rejected by the "r != 0" check inside sign; if that
// retry is broken the test fails via Sign returning an error.
func TestZeroHashSignature(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			zeroHash := make([]byte, c.byteSize)
			sig, err := SignASN1(rand.Reader, priv, zeroHash)
			if err != nil {
				t.Fatalf("SignASN1(zero hash): %v", err)
			}
			if !VerifyASN1(priv.PublicKey(), zeroHash, sig) {
				t.Errorf("zero-hash signature failed to verify")
			}
		})
	}
}

// TestZeroSignature mirrors stdlib: VerifyASN1 must reject (r=0, s=0).
// Existing TestVerify_MalleabilityRejected also covers this for BP256;
// this test pins the property across all three curves.
func TestZeroSignature(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, _ := c.GenerateKey(rand.Reader)
			h := make([]byte, c.byteSize)
			sig := encodeSig(t, big.NewInt(0), big.NewInt(0))
			if VerifyASN1(priv.PublicKey(), h, sig) {
				t.Errorf("VerifyASN1 accepted (r=0, s=0)")
			}
		})
	}
}

// TestNegativeSignature mirrors stdlib: verifying a signature whose r
// has been negated (via DER INTEGER two's-complement encoding) must be
// rejected. In practice, strict DER plus cryptobyte.ReadASN1Integer into
// *[]byte already refuses the bytes before the range check runs — this
// test locks that in.
func TestNegativeSignature(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, _ := c.GenerateKey(rand.Reader)
			h := digest(c, []byte("neg sig"))
			good, err := SignASN1(rand.Reader, priv, h)
			if err != nil {
				t.Fatalf("SignASN1: %v", err)
			}
			r, s := parseSigRS(t, good)
			negR := new(big.Int).Neg(r)
			if VerifyASN1(priv.PublicKey(), h, encodeSig(t, negR, s)) {
				t.Errorf("VerifyASN1 accepted negative r")
			}
			negS := new(big.Int).Neg(s)
			if VerifyASN1(priv.PublicKey(), h, encodeSig(t, r, negS)) {
				t.Errorf("VerifyASN1 accepted negative s")
			}
		})
	}
}

// TestRPlusNSignature mirrors stdlib: a signature with r' = r + N (same
// congruence class mod N, but out of the canonical [1, N-1] range) must
// be rejected. A verifier that silently reduces modulo N would accept
// this forgery — FIPS 186-4 §6.4 forbids it.
func TestRPlusNSignature(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, _ := c.GenerateKey(rand.Reader)
			h := digest(c, []byte("r plus n"))
			good, err := SignASN1(rand.Reader, priv, h)
			if err != nil {
				t.Fatalf("SignASN1: %v", err)
			}
			r, s := parseSigRS(t, good)
			rPlusN := new(big.Int).Add(r, c.nBig())
			if VerifyASN1(priv.PublicKey(), h, encodeSig(t, rPlusN, s)) {
				t.Errorf("VerifyASN1 accepted r = r+N")
			}
		})
	}
}

// TestRMinusNSignature mirrors stdlib: r' = r - N is negative (since
// 0 < r < N by construction), so this simultaneously tests the
// negative-integer refusal path and the range check.
func TestRMinusNSignature(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, _ := c.GenerateKey(rand.Reader)
			h := digest(c, []byte("r minus n"))
			good, err := SignASN1(rand.Reader, priv, h)
			if err != nil {
				t.Fatalf("SignASN1: %v", err)
			}
			r, s := parseSigRS(t, good)
			rMinusN := new(big.Int).Sub(r, c.nBig())
			if VerifyASN1(priv.PublicKey(), h, encodeSig(t, rMinusN, s)) {
				t.Errorf("VerifyASN1 accepted r = r-N")
			}
		})
	}
}

// TestNegativeInputs mirrors stdlib: a signature carrying huge negative
// r, s (far outside any curve's field and order) must be rejected
// cleanly. This pins the "no integer overflow / wraparound" property
// of the strict-DER parser combined with nonceInRange.
func TestNegativeInputs(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, _ := c.GenerateKey(rand.Reader)
			r := new(big.Int).Lsh(big.NewInt(1), 600) // wider than any curve
			r.Neg(r)
			sig := encodeSig(t, r, r)
			h := make([]byte, c.byteSize)
			if VerifyASN1(priv.PublicKey(), h, sig) {
				t.Errorf("VerifyASN1 accepted large negative r, s")
			}
		})
	}
}

// TestInvalidPrivateKeys mirrors stdlib: NewPrivateKey must refuse the
// scalar 0, any scalar >= N (tested with d = N and d = N+5), and any
// input whose length doesn't match the curve byte size. Together these
// pin the pre-conditions a signer relies on for the scalar to live in
// [1, N-1].
func TestInvalidPrivateKeys(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			t.Run("Zero", func(t *testing.T) {
				d := make([]byte, c.byteSize)
				if _, err := c.NewPrivateKey(d); err == nil {
					t.Errorf("NewPrivateKey accepted d = 0")
				}
			})
			t.Run("EqualsN", func(t *testing.T) {
				if _, err := c.NewPrivateKey(c.nBE); err == nil {
					t.Errorf("NewPrivateKey accepted d = N")
				}
			})
			t.Run("Overflow", func(t *testing.T) {
				// d = N + 5: still width = byteSize because N has top bit set
				// for each brainpool curve, so adding 5 can't raise the bit
				// length.
				d := new(big.Int).Add(c.nBig(), big.NewInt(5))
				buf := make([]byte, c.byteSize)
				d.FillBytes(buf)
				if _, err := c.NewPrivateKey(buf); err == nil {
					t.Errorf("NewPrivateKey accepted d = N+5")
				}
			})
			t.Run("ShortLength", func(t *testing.T) {
				if _, err := c.NewPrivateKey([]byte{1, 2, 3}); err == nil {
					t.Errorf("NewPrivateKey accepted a 3-byte key")
				}
			})
			t.Run("LongLength", func(t *testing.T) {
				buf := make([]byte, c.byteSize+3)
				buf[c.byteSize+1] = 1 // non-zero to make sure we're not short-circuiting
				if _, err := c.NewPrivateKey(buf); err == nil {
					t.Errorf("NewPrivateKey accepted an overlong key")
				}
			})
		})
	}
}

// TestParseAndBytesRoundTrip mirrors stdlib: priv.Bytes() followed by
// NewPrivateKey must reproduce an Equal key, and the public half's
// Bytes() must round-trip through NewPublicKey. This pins the wire
// format — anyone implementing interop works off these encodings.
func TestParseAndBytesRoundTrip(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			pubBytes := priv.PublicKey().Bytes()
			if len(pubBytes) == 0 || pubBytes[0] != 0x04 {
				t.Fatalf("unexpected public-key header")
			}
			pub2, err := c.NewPublicKey(pubBytes)
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}
			if !priv.PublicKey().Equal(pub2) {
				t.Errorf("public-key round-trip mismatch")
			}
			if !bytes.Equal(pubBytes, pub2.Bytes()) {
				t.Errorf("public-key re-encode mismatch")
			}

			privBytes := priv.Bytes()
			if len(privBytes) != c.byteSize {
				t.Errorf("private-key bytes have length %d, want %d", len(privBytes), c.byteSize)
			}
			priv2, err := c.NewPrivateKey(privBytes)
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}
			if !priv.Equal(priv2) {
				t.Errorf("private-key round-trip mismatch")
			}
			if !bytes.Equal(privBytes, priv2.Bytes()) {
				t.Errorf("private-key re-encode mismatch")
			}
		})
	}
}

// --- SEC1 marshal / parse -------------------------------------------------

// TestPublicKey_BytesRoundTrip covers the public-key SEC1 uncompressed
// path: generate → Bytes() → NewPublicKey() must reproduce the key.
func TestPublicKey_BytesRoundTrip(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			enc := priv.PublicKey().Bytes()
			if len(enc) != 1+2*c.byteSize || enc[0] != 0x04 {
				t.Fatalf("uncompressed header or length wrong")
			}
			pub2, err := c.NewPublicKey(enc)
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}
			if !priv.PublicKey().Equal(pub2) {
				t.Errorf("round-trip produced a different key")
			}
			if !bytes.Equal(pub2.Bytes(), enc) {
				t.Errorf("re-encode does not match original")
			}
		})
	}
}

// TestNewPublicKey_Rejects covers malformed and malicious SEC1 inputs
// across all three curves. Mirrors stdlib's TestInvalidPublicKeys.
func TestNewPublicKey_Rejects(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			bs := c.byteSize

			if _, err := c.NewPublicKey(nil); err == nil {
				t.Errorf("accepted empty input")
			}
			if _, err := c.NewPublicKey([]byte{0x07}); err == nil {
				t.Errorf("accepted unknown tag")
			}
			// Wrong uncompressed length (missing 1-byte tag).
			bad := make([]byte, 2*bs)
			bad[0] = 0x04
			if _, err := c.NewPublicKey(bad); err == nil {
				t.Errorf("accepted truncated uncompressed")
			}
			// Uncompressed off-curve (x=0, y=0) — infinity encoding with
			// the verbose uncompressed tag.
			bad = make([]byte, 1+2*bs)
			bad[0] = 0x04
			if _, err := c.NewPublicKey(bad); err == nil {
				t.Errorf("accepted off-curve uncompressed point (x=0, y=0)")
			}
			// Compressed with x == P (out of field).
			bad = make([]byte, 1+bs)
			bad[0] = 0x02
			copy(bad[1:], c.pBE)
			if _, err := c.NewPublicKey(bad); err == nil {
				t.Errorf("accepted compressed point with x == P")
			}
			// Compressed with x = P + 1 (still out of field, tests the
			// ≥ P check rather than exact-equality).
			p := c.pBig()
			pPlus1 := new(big.Int).Add(p, big.NewInt(1))
			bad = make([]byte, 1+bs)
			bad[0] = 0x02
			pPlus1.FillBytes(bad[1:])
			if _, err := c.NewPublicKey(bad); err == nil {
				t.Errorf("accepted compressed point with x = P+1")
			}
			// Uncompressed with x == P — bytes fit because P has top bit
			// set for every brainpool curve.
			bad = make([]byte, 1+2*bs)
			bad[0] = 0x04
			copy(bad[1:1+bs], c.pBE)
			if _, err := c.NewPublicKey(bad); err == nil {
				t.Errorf("accepted uncompressed point with x == P")
			}
			// Single 0x00 is the identity encoding; NewPublicKey must
			// reject it (no valid public key encodes the infinity).
			if _, err := c.NewPublicKey([]byte{0x00}); err == nil {
				t.Errorf("accepted identity as public key")
			}
			// Uncompressed tag with a NotOnCurve (x, y): take a valid
			// point and flip x by +1 — vanishingly unlikely to still
			// lie on the curve.
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			enc := priv.PublicKey().Bytes()
			mutant := append([]byte(nil), enc...)
			// Bump the last byte of X by 1. If x+1 happens to also give
			// an on-curve point the test would pass; for a single random
			// key this is astronomically unlikely.
			mutant[bs] ^= 0x01
			if _, err := c.NewPublicKey(mutant); err == nil {
				t.Errorf("accepted not-on-curve uncompressed point")
			}
		})
	}
}

// --- RFC 6979 -------------------------------------------------------------

// TestSign_Deterministic covers RFC 6979 behaviour: the same (key,
// hash) pair must always produce the same signature via
// SignDeterministicASN1.
func TestSign_Deterministic(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			priv, err := c.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			msg := digest(c, []byte("deterministic"))
			sig1, err := SignDeterministicASN1(priv, msg)
			if err != nil {
				t.Fatalf("SignDeterministicASN1 1: %v", err)
			}
			sig2, err := SignDeterministicASN1(priv, msg)
			if err != nil {
				t.Fatalf("SignDeterministicASN1 2: %v", err)
			}
			if !bytes.Equal(sig1, sig2) {
				t.Errorf("deterministic signature produced different bytes across calls")
			}
			if !VerifyASN1(priv.PublicKey(), msg, sig1) {
				t.Errorf("deterministic signature failed to verify")
			}
		})
	}
}

// TestSign_HedgeDiffers: when rand is non-nil, successive signatures
// over the same (key, hash) must differ (hedge folds fresh entropy
// into the DRBG seed) — but both must verify.
func TestSign_HedgeDiffers(t *testing.T) {
	c := BP256r1()
	priv, _ := c.GenerateKey(rand.Reader)
	msg := digest(c, []byte("hedge"))
	sig1, err := SignASN1(rand.Reader, priv, msg)
	if err != nil {
		t.Fatalf("SignASN1 1: %v", err)
	}
	sig2, err := SignASN1(rand.Reader, priv, msg)
	if err != nil {
		t.Fatalf("SignASN1 2: %v", err)
	}
	if bytes.Equal(sig1, sig2) {
		t.Errorf("hedged SignASN1 produced identical signatures across two calls")
	}
	if !VerifyASN1(priv.PublicKey(), msg, sig1) {
		t.Errorf("hedged signature 1 failed to verify")
	}
	if !VerifyASN1(priv.PublicKey(), msg, sig2) {
		t.Errorf("hedged signature 2 failed to verify")
	}
}

// --- RFC 6979 cross-checks against an independent reference implementation ---
//
// The tests below compare rfc6979Gen (production, fiat-crypto scalar path)
// with rfc6979Reference (math/big, spec-literal) defined below. A
// divergence means one of the two is misreading the spec. The scenarios
// deliberately cover the spots that slipped past the earlier
// determinism-only test:
//
//   - bits2int(H) >= N (catches a missing mod-q reduction in bits2octets)
//   - retry path (catches a DRBG-continuation divergence)
//   - short/long digests, boundary scalars

func genNonces(t *testing.T, c *Curve, x *big.Int, hashMsg []byte, count int) [][]byte {
	t.Helper()
	xBytes := make([]byte, c.byteSize)
	x.FillBytes(xBytes)
	gen, err := newRFC6979Gen(c, xBytes, hashMsg)
	if err != nil {
		t.Fatalf("newRFC6979Gen: %v", err)
	}
	out := make([][]byte, count)
	for i := range out {
		out[i] = gen.next()
	}
	return out
}

type rfc6979Case struct {
	name  string
	curve *Curve
	xHex  string // private scalar, hex big-endian (any length up to byteSize)
	hHex  string // message digest, hex big-endian
	count int
}

func rfc6979Cases() []rfc6979Case {
	// All-ones digest for each curve: bits2int(H) == 2^bitSize - 1, which
	// is >= N for every Brainpool curve. The pre-fix implementation
	// silently differed from the spec for exactly this class of inputs.
	allOnes := func(bytes int) string {
		return hex.EncodeToString(bytes0xFF(bytes))
	}

	cases := []rfc6979Case{
		// --- BP256r1
		{
			name:  "bp256/typical",
			curve: BP256r1(),
			xHex:  "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
			hHex:  "0FFA5E0B9EFD7D7D2B14B3E38F7EBAC9B4B09157B34B7E4E36DDE8CC3B4E8C70",
			count: 4,
		},
		{
			name:  "bp256/h_all_ones_forces_mod_n", // bits2int(H) > N
			curve: BP256r1(),
			xHex:  "01",
			hHex:  allOnes(32),
			count: 4,
		},
		{
			name:  "bp256/h_equals_n_minus_1", // boundary: bits2int(H) == N-1 < N (no mod reduction needed)
			curve: BP256r1(),
			xHex:  "0A",
			hHex:  "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A6",
			count: 3,
		},
		{
			name:  "bp256/h_equals_n", // bits2int(H) == N, must reduce to 0
			curve: BP256r1(),
			xHex:  "0A",
			hHex:  "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
			count: 3,
		},
		{
			name:  "bp256/short_digest", // shorter than qbytes
			curve: BP256r1(),
			xHex:  "DEADBEEF",
			hHex:  "CAFE",
			count: 2,
		},
		{
			name:  "bp256/long_digest", // longer than qbytes, gets truncated
			curve: BP256r1(),
			xHex:  "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3",
			hHex:  "1122334455667788" + "1122334455667788" + "1122334455667788" + "1122334455667788" + "AA",
			count: 3,
		},
		{
			name:  "bp256/zero_digest",
			curve: BP256r1(),
			xHex:  "01",
			hHex:  "0000000000000000000000000000000000000000000000000000000000000000",
			count: 2,
		},

		// --- BP384r1
		{
			name:  "bp384/typical",
			curve: BP384r1(),
			xHex:  "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
			hHex:  "8F9028A3A4F2A2E18C1BFC2FC0997B2C2B1A2BD3F8DC5B6A5F1B8A7D8E4F1B2A" + "0FFA5E0B9EFD7D7D2B14B3E38F7EBAC9",
			count: 3,
		},
		{
			name:  "bp384/h_all_ones_forces_mod_n",
			curve: BP384r1(),
			xHex:  "01",
			hHex:  allOnes(48),
			count: 3,
		},
		{
			name:  "bp384/h_equals_n_minus_1",
			curve: BP384r1(),
			xHex:  "02",
			hHex:  "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046564",
			count: 2,
		},

		// --- BP512r1
		{
			name:  "bp512/typical",
			curve: BP512r1(),
			xHex:  "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422",
			hHex:  "C35E2F092553C55772926BDBE87C9796827D17024DBB9233A545366E2E5987DD344DEB72DF987144B8C6C43BC41B654B49DA3525600E35A4DA53F6F0C83F7FB3",
			count: 3,
		},
		{
			name:  "bp512/h_all_ones_forces_mod_n",
			curve: BP512r1(),
			xHex:  "01",
			hHex:  allOnes(64),
			count: 3,
		},
	}
	return cases
}

// TestRFC6979_CrossCheckProductionVsReference drives both the production
// rfc6979Gen (fiat-crypto path) and the spec-literal reference (math/big,
// at the bottom of this file) with the same inputs and requires them to
// emit bit-identical nonce sequences.
//
// Historical relevance: before the bits2octets mod-N reduction was
// restored (commit fixing the RFC 6979 bug), the all-ones digest cases
// produced different nonces in the two implementations. That would now
// break the test loudly.
func TestRFC6979_CrossCheckProductionVsReference(t *testing.T) {
	for _, tc := range rfc6979Cases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			x := mustHexInt(t, tc.xHex)
			h := mustHexBytes(t, tc.hHex)

			prod := genNonces(t, tc.curve, x, h, tc.count)
			ref := rfc6979Reference(tc.curve, x, h, tc.count)

			if len(prod) != len(ref) {
				t.Fatalf("length mismatch: prod=%d ref=%d", len(prod), len(ref))
			}
			for i := range prod {
				if !bytes.Equal(prod[i], ref[i]) {
					t.Errorf("nonce %d differs:\n prod: %x\n ref:  %x", i, prod[i], ref[i])
				}
				// Sanity: every emitted nonce must be in [1, N-1].
				k := new(big.Int).SetBytes(prod[i])
				if k.Sign() <= 0 || k.Cmp(tc.curve.nBig()) >= 0 {
					t.Errorf("nonce %d out of range [1, N-1]: %x", i, prod[i])
				}
			}
		})
	}
}

// TestRFC6979_Bits2OctetsReducesModN is the surgical regression test
// for the bug the original test suite missed. It constructs an input
// whose bits2int value is strictly greater than N, computes the DRBG
// seed `h1` the implementation would feed into HMAC, and requires that
// it equals (bits2int(H) mod N) — not bits2int(H) truncated.
func TestRFC6979_Bits2OctetsReducesModN(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			// All-ones digest: bits2int(H) == 2^bitSize - 1.
			h := bytes0xFF(c.byteSize)

			// Expected: bits2int(H) mod N. Because top bit of H is 1
			// and bitSize == bitLen(N), the integer value is always
			// >= 2^(bitSize-1) >= N/2 + 1, and frequently > N for
			// Brainpool N's that sit well below 2^bitSize.
			bi := new(big.Int).SetBytes(h)
			want := new(big.Int).Mod(bi, c.nBig())

			got := new(big.Int).SetBytes(hashToScalarBytes(h, c))
			if got.Cmp(want) != 0 {
				t.Errorf("hashToScalarBytes(all-ones) not reduced mod N\n got:  %x\n want: %x", got, want)
			}
			// And for sanity, explicitly confirm that without the
			// reduction the raw truncation would still have been >= N.
			raw := new(big.Int).SetBytes(h)
			if raw.Cmp(c.nBig()) < 0 {
				t.Fatalf("test invariant: all-ones digest should exceed N for Brainpool")
			}
		})
	}
}

// TestRFC6979_RetryPathMatchesSpec verifies that pulling N nonces out of
// the production generator matches the first N nonces of the reference.
// A mistake in the retry continuation rule — for instance re-seeding
// the DRBG with a synthetic `extra` counter instead of running step h's
// K/V update — would diverge from the second nonce onward.
func TestRFC6979_RetryPathMatchesSpec(t *testing.T) {
	// Use a fixed input so a regression is trivially bisectable.
	c := BP256r1()
	x := mustHexInt(t, "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D")
	h := sha256.Sum256([]byte("rfc6979 retry path"))

	prod := genNonces(t, c, x, h[:], 10)
	ref := rfc6979Reference(c, x, h[:], 10)

	for i := range prod {
		if !bytes.Equal(prod[i], ref[i]) {
			t.Fatalf("retry nonce %d differs: prod=%x ref=%x", i, prod[i], ref[i])
		}
	}
	// Retry sequence must not repeat — a trivial sanity check against a
	// stuck DRBG.
	seen := map[string]int{}
	for i, k := range prod {
		key := string(k)
		if j, ok := seen[key]; ok {
			t.Errorf("duplicate nonce at positions %d and %d: %x", j, i, k)
		}
		seen[key] = i
	}
}

// TestSignASN1_MatchesReference drives the full ECDSA pipeline end to
// end and checks that SignASN1 (production: fiat Montgomery scalars +
// rfc6979Gen) agrees bit-for-bit with signReference (math/big scalars +
// rfc6979Reference) on the same inputs. Where TestRFC6979_* covers the
// nonce layer, this test covers everything built on top of it: bits2int
// of the digest, r = (kG).x mod N, s = k⁻¹(e + r·x) mod N, and ASN.1
// wrapping.
//
// The "h_all_ones" rows would have failed loudly under the pre-fix
// bits2octets code path: both because the nonce sequence would differ
// from the reference, and because e = bits2int(H) mod N — the same
// reduction — is what makes s agree.
func TestSignASN1_MatchesReference(t *testing.T) {
	cases := []struct {
		name  string
		curve *Curve
		xHex  string
		hHex  string
	}{
		{
			name:  "bp256/typical",
			curve: BP256r1(),
			xHex:  "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
			hHex:  "0FFA5E0B9EFD7D7D2B14B3E38F7EBAC9B4B09157B34B7E4E36DDE8CC3B4E8C70",
		},
		{
			name:  "bp256/h_all_ones",
			curve: BP256r1(),
			xHex:  "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3",
			hHex:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:  "bp384/typical",
			curve: BP384r1(),
			xHex:  "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
			hHex:  "8F9028A3A4F2A2E18C1BFC2FC0997B2C2B1A2BD3F8DC5B6A5F1B8A7D8E4F1B2A0FFA5E0B9EFD7D7D2B14B3E38F7EBAC9",
		},
		{
			name:  "bp384/h_all_ones",
			curve: BP384r1(),
			xHex:  "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
			hHex:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		},
		{
			name:  "bp512/typical",
			curve: BP512r1(),
			xHex:  "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422",
			hHex:  "C35E2F092553C55772926BDBE87C9796827D17024DBB9233A545366E2E5987DD344DEB72DF987144B8C6C43BC41B654B49DA3525600E35A4DA53F6F0C83F7FB3",
		},
		{
			name:  "bp512/h_all_ones",
			curve: BP512r1(),
			xHex:  "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422",
			hHex:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			xInt := mustHexInt(t, tc.xHex)
			h := mustHexBytes(t, tc.hHex)

			// Build a production private key from xInt.
			xBytes := make([]byte, tc.curve.byteSize)
			xInt.FillBytes(xBytes)
			priv, err := tc.curve.NewPrivateKey(xBytes)
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}

			// Deterministic path: pure RFC 6979 output.
			sig, err := SignDeterministicASN1(priv, h)
			if err != nil {
				t.Fatalf("SignDeterministicASN1: %v", err)
			}
			gotR, gotS := parseSigRS(t, sig)

			wantR, wantS := signReference(tc.curve, xInt, h)
			if gotR.Cmp(wantR) != 0 {
				t.Errorf("r mismatch\n prod: %x\n ref:  %x", gotR, wantR)
			}
			if gotS.Cmp(wantS) != 0 {
				t.Errorf("s mismatch\n prod: %x\n ref:  %x", gotS, wantS)
			}

			// End-to-end sanity: the reference-matched signature must
			// also verify against the production verifier.
			if !VerifyASN1(priv.PublicKey(), h, sig) {
				t.Errorf("VerifyASN1 rejected a valid signature")
			}
		})
	}
}

// TestNonceInRange pins the constant-time range check against boundary
// values for all three curves: 0, 1, N-1, N, N+1.
func TestNonceInRange(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			nBE := c.nBE

			zero := make([]byte, c.byteSize)
			one := make([]byte, c.byteSize)
			one[c.byteSize-1] = 1
			nMinus1 := make([]byte, c.byteSize)
			new(big.Int).Sub(c.nBig(), big.NewInt(1)).FillBytes(nMinus1)
			nPlus1 := make([]byte, c.byteSize)
			new(big.Int).Add(c.nBig(), big.NewInt(1)).FillBytes(nPlus1)

			cases := []struct {
				name string
				k    []byte
				want bool
			}{
				{"0", zero, false},
				{"1", one, true},
				{"N-1", nMinus1, true},
				{"N", nBE, false},
				{"N+1", nPlus1, false},
			}
			for _, tc := range cases {
				if got := nonceInRange(tc.k, nBE); got != tc.want {
					t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				}
			}
		})
	}
}

// --- RFC 6979 reference implementation (test-only) ------------------------
//
// Independent, spec-literal implementation of RFC 6979 §3.2 HMAC-DRBG
// and the ECDSA signing loop on top of it. Uses math/big and stdlib
// HMAC only — no Montgomery scalar arithmetic, no fiat limbs — so the
// two implementations share nothing but the specification. A mismatch
// in the cross-check tests above therefore points to a spec-reading bug
// in exactly one of them.
//
// Test-only: variable-time on secrets, not suitable for production.

// rfc6979Reference returns the first `count` successive nonces that the
// DRBG would emit, including the per-iteration K/V continuation update
// mandated by §3.2 step h for every call after the first.
func rfc6979Reference(c *Curve, x *big.Int, hashMsg []byte, count int) [][]byte {
	var newHash func() hash.Hash
	switch c {
	case bp256r1:
		newHash = sha256.New
	case bp384r1:
		newHash = sha512.New384
	case bp512r1:
		newHash = sha512.New
	default:
		panic("rfc6979Reference: unknown curve")
	}

	hlen := newHash().Size()
	qlen := c.bitSize
	qbytes := c.byteSize

	// bits2int(H): interpret H as big-endian integer, shift right so
	// the result fits in qlen bits.
	h1Int := new(big.Int).SetBytes(hashMsg)
	if hbits := len(hashMsg) * 8; hbits > qlen {
		h1Int.Rsh(h1Int, uint(hbits-qlen))
	}
	// bits2octets(H) = int2octets(bits2int(H) mod q, rolen).
	h1Int.Mod(h1Int, c.nBig())
	h1 := make([]byte, qbytes)
	h1Int.FillBytes(h1)

	xBytes := make([]byte, qbytes)
	x.FillBytes(xBytes)

	V := bytes.Repeat([]byte{0x01}, hlen)
	K := make([]byte, hlen)

	hm := func(key []byte, data ...[]byte) []byte {
		m := hmac.New(newHash, key)
		for _, d := range data {
			m.Write(d)
		}
		return m.Sum(nil)
	}

	// Step d / e
	K = hm(K, V, []byte{0x00}, xBytes, h1)
	V = hm(K, V)
	// Step f / g
	K = hm(K, V, []byte{0x01}, xBytes, h1)
	V = hm(K, V)

	out := make([][]byte, 0, count)
	primed := false

	for len(out) < count {
		if primed {
			// §3.2 step h continuation: called for every emission
			// after the first, irrespective of whether the previous
			// k was accepted by the DSA/ECDSA suitability check.
			K = hm(K, V, []byte{0x00})
			V = hm(K, V)
		}
		primed = true

		for {
			T := make([]byte, 0, qbytes)
			for len(T) < qbytes {
				V = hm(K, V)
				T = append(T, V...)
			}
			T = T[:qbytes]

			// bits2int(T): qbytes*8 == bitSize == qlen for Brainpool
			// curves (N has its top bit set), so no right-shift is
			// needed here. Kept general for clarity.
			k := new(big.Int).SetBytes(T)
			if tbits := qbytes * 8; tbits > qlen {
				k.Rsh(k, uint(tbits-qlen))
			}

			if k.Sign() > 0 && k.Cmp(c.nBig()) < 0 {
				kb := make([]byte, qbytes)
				k.FillBytes(kb)
				out = append(out, kb)
				break
			}
			// Out-of-range k: apply the in-loop update and retry.
			// This is the same continuation rule as between calls.
			K = hm(K, V, []byte{0x00})
			V = hm(K, V)
		}
	}
	return out
}

// signReference is a full ECDSA reference implementation that produces
// the same signature SignASN1 would — but via an independent path:
// the nonce comes from rfc6979Reference (math/big) and the scalar
// arithmetic runs on math/big instead of fiat Montgomery. The only
// shared component is the production elliptic-curve point multiplication
// (which has its own RFC 7027 test coverage in internal/bpec).
//
// This gives end-to-end coverage against the sign256/384/512 callers —
// including regressions in how they drive the DRBG across retries —
// without relying on an external reference tool.
func signReference(c *Curve, x *big.Int, hashMsg []byte) (r, s *big.Int) {
	// e = bits2int(H) mod N, same transform rfc6979Reference uses for h1.
	eBig := new(big.Int).SetBytes(hashMsg)
	if hbits := len(hashMsg) * 8; hbits > c.bitSize {
		eBig.Rsh(eBig, uint(hbits-c.bitSize))
	}
	eBig.Mod(eBig, c.nBig())

	ks := rfc6979Reference(c, x, hashMsg, 16)
	for _, kBytes := range ks {
		kBig := new(big.Int).SetBytes(kBytes)
		if kBig.Sign() == 0 {
			continue
		}
		rBig, ok := basePointX(c, kBytes)
		if !ok {
			continue
		}
		rBig.Mod(rBig, c.nBig())
		if rBig.Sign() == 0 {
			continue
		}
		kInv := new(big.Int).ModInverse(kBig, c.nBig())
		if kInv == nil {
			continue
		}
		sBig := new(big.Int).Mul(rBig, x)
		sBig.Add(sBig, eBig)
		sBig.Mul(sBig, kInv)
		sBig.Mod(sBig, c.nBig())
		if sBig.Sign() == 0 {
			continue
		}
		return rBig, sBig
	}
	panic("signReference: DRBG exhausted without producing a valid (r, s)")
}

// basePointX returns the affine X coordinate of k·G using the production
// point ops, as a big.Int (not yet mod N). Returns false for the point
// at infinity or any malformed scalar.
func basePointX(c *Curve, kBytes []byte) (*big.Int, bool) {
	switch c {
	case bp256r1:
		var p bpec.BP256Point
		if _, err := p.ScalarBaseMult(kBytes); err != nil {
			return nil, false
		}
		if p.IsIdentity() == 1 {
			return nil, false
		}
		xb, err := p.BytesX()
		if err != nil {
			return nil, false
		}
		return new(big.Int).SetBytes(xb), true
	case bp384r1:
		var p bpec.BP384Point
		if _, err := p.ScalarBaseMult(kBytes); err != nil {
			return nil, false
		}
		if p.IsIdentity() == 1 {
			return nil, false
		}
		xb, err := p.BytesX()
		if err != nil {
			return nil, false
		}
		return new(big.Int).SetBytes(xb), true
	case bp512r1:
		var p bpec.BP512Point
		if _, err := p.ScalarBaseMult(kBytes); err != nil {
			return nil, false
		}
		if p.IsIdentity() == 1 {
			return nil, false
		}
		xb, err := p.BytesX()
		if err != nil {
			return nil, false
		}
		return new(big.Int).SetBytes(xb), true
	}
	return nil, false
}

// --- benchmarks -----------------------------------------------------------

func benchSign(b *testing.B, c *Curve) {
	priv, _ := c.GenerateKey(rand.Reader)
	h := digest(c, []byte("benchmark message"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignASN1(rand.Reader, priv, h)
	}
}

func BenchmarkSign_BP256r1(b *testing.B) { benchSign(b, BP256r1()) }
func BenchmarkSign_BP384r1(b *testing.B) { benchSign(b, BP384r1()) }
func BenchmarkSign_BP512r1(b *testing.B) { benchSign(b, BP512r1()) }

func benchVerify(b *testing.B, c *Curve) {
	priv, _ := c.GenerateKey(rand.Reader)
	h := digest(c, []byte("benchmark message"))
	sig, _ := SignASN1(rand.Reader, priv, h)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyASN1(priv.PublicKey(), h, sig)
	}
}

func BenchmarkVerify_BP256r1(b *testing.B) { benchVerify(b, BP256r1()) }
func BenchmarkVerify_BP384r1(b *testing.B) { benchVerify(b, BP384r1()) }
func BenchmarkVerify_BP512r1(b *testing.B) { benchVerify(b, BP512r1()) }
