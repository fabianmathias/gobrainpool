package gobrainpool

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
)

// seedReader returns a deterministic io.Reader seeded with `seed`:
// reads produce seed, seed, seed, ... (byte-for-byte). We use it to
// pin that the RNG path is routed through an HMAC-DRBG rather than
// the raw Reader — two callers using the same seed must observe
// identical outputs at the DRBG boundary, and different outputs at
// the byte-reader boundary if the seed is shorter than the request.
func seedReader(seed byte) io.Reader {
	return &constReader{b: seed}
}

type constReader struct{ b byte }

func (r *constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// TestRNGWrapper_GenerateKeyDeterministicOnSameSeed pins that the
// entropy stream reaching the scalar sampler comes from an HMAC-DRBG
// seeded from the user Reader — not from the Reader directly. A naive
// implementation that pipes raw Reader bytes through would produce
// the byte-pattern seed as the scalar itself; the DRBG wrapper must
// produce a different, hash-dependent byte string. Running GenerateKey
// twice with the same constant-seed Reader therefore must:
//
//   - yield identical keys across calls (DRBG output is deterministic
//     on its seed), and
//   - yield a scalar that is NOT equal to the raw seed bytes
//     (otherwise the DRBG wrapper was bypassed).
func TestRNGWrapper_GenerateKeyDeterministicOnSameSeed(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			k1, err := c.GenerateKey(seedReader(0xAB))
			if err != nil {
				t.Fatalf("GenerateKey 1: %v", err)
			}
			k2, err := c.GenerateKey(seedReader(0xAB))
			if err != nil {
				t.Fatalf("GenerateKey 2: %v", err)
			}
			if !bytes.Equal(k1.Bytes(), k2.Bytes()) {
				t.Errorf("same-seed GenerateKey calls produced different scalars\n k1: %x\n k2: %x",
					k1.Bytes(), k2.Bytes())
			}
			// Raw-seed bypass check: a 0xAB-filled scalar would mean
			// the DRBG wrapper was skipped and the Reader bytes flowed
			// straight into the rejection loop.
			rawSeed := bytes.Repeat([]byte{0xAB}, c.byteSize)
			if bytes.Equal(k1.Bytes(), rawSeed) {
				t.Error("scalar matches the raw seed byte-pattern; DRBG wrapper was bypassed")
			}
		})
	}
}

// TestRNGWrapper_DifferentSeedsDifferentKeys pins that different
// seed Readers lead to different keys. A broken wrapper that fed a
// constant into the DRBG regardless of the Reader would fail here.
func TestRNGWrapper_DifferentSeedsDifferentKeys(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			k1, err := c.GenerateKey(seedReader(0x01))
			if err != nil {
				t.Fatalf("GenerateKey 1: %v", err)
			}
			k2, err := c.GenerateKey(seedReader(0x02))
			if err != nil {
				t.Fatalf("GenerateKey 2: %v", err)
			}
			if bytes.Equal(k1.Bytes(), k2.Bytes()) {
				t.Errorf("different-seed GenerateKey calls produced identical scalars: %x", k1.Bytes())
			}
		})
	}
}

// TestRNGWrapper_HedgedSignDeterministicOnSameSeed pins the same
// property for the hedged signing path: two SignASN1 calls on the
// same (key, digest, seed) must produce identical signatures if and
// only if the hedge bytes flowed through the DRBG deterministically.
// If SignASN1 read the Reader raw (no DRBG), same-seed calls would
// also match — but the signature bytes would align with the seed
// pattern; if the DRBG were bypassed differently per call, same-seed
// calls would differ. Both checks are inline.
func TestRNGWrapper_HedgedSignDeterministicOnSameSeed(t *testing.T) {
	c := BP256r1()
	priv, err := c.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	d := sha256.Sum256([]byte("rng wrapper hedge"))

	sig1, err := SignASN1(seedReader(0xCD), priv, d[:])
	if err != nil {
		t.Fatalf("SignASN1 1: %v", err)
	}
	sig2, err := SignASN1(seedReader(0xCD), priv, d[:])
	if err != nil {
		t.Fatalf("SignASN1 2: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Errorf("same-seed hedged signatures differ:\n sig1: %x\n sig2: %x", sig1, sig2)
	}
	if !VerifyASN1(priv.PublicKey(), d[:], sig1) {
		t.Error("VerifyASN1 rejected a valid hedged signature")
	}
	// And different seed → different signature.
	sig3, err := SignASN1(seedReader(0xCE), priv, d[:])
	if err != nil {
		t.Fatalf("SignASN1 3: %v", err)
	}
	if bytes.Equal(sig1, sig3) {
		t.Error("different-seed hedged signatures matched; hedge is not in fact randomising the DRBG")
	}
}

// TestRNGWrapper_ShortReaderSurfacesError pins that a Reader that
// can't supply the DRBG seed (< rngDRBGSeedLen bytes) surfaces an
// error from GenerateKey rather than silently seeding the DRBG with
// whatever partial data was read.
func TestRNGWrapper_ShortReaderSurfacesError(t *testing.T) {
	c := BP256r1()
	short := bytes.NewReader(make([]byte, rngDRBGSeedLen-1))
	if _, err := c.GenerateKey(short); err == nil {
		t.Error("GenerateKey with too-short reader = nil error, want io.ErrUnexpectedEOF or similar")
	}
}
