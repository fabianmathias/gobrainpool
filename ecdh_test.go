package gobrainpool

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// TestECDH_Symmetric checks that Alice·Bob.Public == Bob·Alice.Public.
func TestECDH_Symmetric(t *testing.T) {
	for _, c := range []*Curve{BP256r1(), BP384r1(), BP512r1()} {
		t.Run(c.name, func(t *testing.T) {
			alice, _ := c.GenerateKey(rand.Reader)
			bob, _ := c.GenerateKey(rand.Reader)

			ab, err := alice.ECDH(bob.PublicKey())
			if err != nil {
				t.Fatalf("alice·Bob: %v", err)
			}
			ba, err := bob.ECDH(alice.PublicKey())
			if err != nil {
				t.Fatalf("bob·Alice: %v", err)
			}
			if !bytes.Equal(ab, ba) {
				t.Errorf("ECDH not symmetric")
			}
			if len(ab) != c.byteSize {
				t.Errorf("ECDH output length %d, want %d", len(ab), c.byteSize)
			}
		})
	}
}

// TestECDH_NilKeys pins that ECDH refuses nil peer keys. (A nil
// receiver is not reachable via the public surface — PrivateKey is
// only ever obtained through GenerateKey / NewPrivateKey.)
func TestECDH_NilKeys(t *testing.T) {
	priv, err := BP256r1().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := priv.ECDH(nil); err == nil {
		t.Error("ECDH(nil peer) = nil error, want error")
	}
}

// TestECDH_CurveMismatch pins that ECDH refuses a peer pubkey on a
// different curve. This guards against the invalid-curve class of
// attacks at the API boundary: the raw scalar-mult code assumes
// priv.curve == peer.curve and would otherwise feed a BP384-encoded
// point into BP256 arithmetic.
func TestECDH_CurveMismatch(t *testing.T) {
	priv256, err := BP256r1().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey BP256: %v", err)
	}
	priv384, err := BP384r1().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey BP384: %v", err)
	}
	_, err = priv256.ECDH(priv384.PublicKey())
	if err == nil {
		t.Fatal("ECDH across curves = nil error, want mismatch error")
	}
	if !strings.Contains(err.Error(), "curve mismatch") {
		t.Errorf("expected 'curve mismatch' in error, got: %v", err)
	}
}

func benchECDH(b *testing.B, c *Curve) {
	alice, _ := c.GenerateKey(rand.Reader)
	bob, _ := c.GenerateKey(rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alice.ECDH(bob.PublicKey())
	}
}

func BenchmarkECDH_BP256r1(b *testing.B) { benchECDH(b, BP256r1()) }
func BenchmarkECDH_BP384r1(b *testing.B) { benchECDH(b, BP384r1()) }
func BenchmarkECDH_BP512r1(b *testing.B) { benchECDH(b, BP512r1()) }
