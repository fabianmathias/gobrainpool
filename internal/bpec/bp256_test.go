package bpec

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// TestBP256_GeneratorRoundTrip verifies that the stored generator G
// encodes and decodes to itself. A catch-all for parameter corruption.
func TestBP256_GeneratorRoundTrip(t *testing.T) {
	G := NewBP256Generator()
	enc := G.Bytes()
	if enc[0] != 0x04 || len(enc) != 65 {
		t.Fatalf("unexpected encoding: %x", enc)
	}
	var P BP256Point
	if _, err := P.SetBytes(enc); err != nil {
		t.Fatalf("SetBytes(G.Bytes()): %v", err)
	}
	if !bytes.Equal(P.Bytes(), enc) {
		t.Errorf("roundtrip mismatch")
	}
}

// TestBP256_BasicGroupLaws checks G+(-G)=O, G+O=G, 2G=G+G, 3G=2G+G.
func TestBP256_BasicGroupLaws(t *testing.T) {
	G := NewBP256Generator()
	O := NewBP256Point()
	negG := new(BP256Point).Negate(G)

	sum := new(BP256Point).Add(G, negG)
	if sum.IsIdentity() != 1 {
		t.Errorf("G + (-G) should be identity")
	}

	sum.Add(G, O)
	if !bytes.Equal(sum.Bytes(), G.Bytes()) {
		t.Errorf("G + O != G")
	}
	sum.Add(O, G)
	if !bytes.Equal(sum.Bytes(), G.Bytes()) {
		t.Errorf("O + G != G")
	}

	g2a := new(BP256Point).Double(G)
	g2b := new(BP256Point).Add(G, G)
	if !bytes.Equal(g2a.Bytes(), g2b.Bytes()) {
		t.Errorf("G.Double() != G + G")
	}

	g3a := new(BP256Point).Add(g2a, G)
	g3b := new(BP256Point).ScalarMultOrFail(t, G, big.NewInt(3))
	if !bytes.Equal(g3a.Bytes(), g3b.Bytes()) {
		t.Errorf("2G + G != 3·G")
	}
}

// ScalarMultOrFail is a test helper: ScalarMult with a big.Int-encoded
// scalar, failing the test on error.
func (p *BP256Point) ScalarMultOrFail(t *testing.T, q *BP256Point, k *big.Int) *BP256Point {
	t.Helper()
	var buf [32]byte
	k.FillBytes(buf[:])
	if _, err := p.ScalarMult(q, buf[:]); err != nil {
		t.Fatalf("ScalarMult: %v", err)
	}
	return p
}

// TestBP256_ScalarMultAgainstIterated: for small k, k·G must equal the
// repeated-add reference.
func TestBP256_ScalarMultAgainstIterated(t *testing.T) {
	G := NewBP256Generator()
	ref := NewBP256Point()
	for k := int64(1); k <= 10; k++ {
		ref.Add(ref, G)
		got := new(BP256Point).ScalarMultOrFail(t, G, big.NewInt(k))
		if !bytes.Equal(got.Bytes(), ref.Bytes()) {
			t.Errorf("%d·G mismatch", k)
		}
	}
}

// TestBP256_OrderTimesGeneratorIsIdentity is the canonical curve-order
// sanity check.
func TestBP256_OrderTimesGeneratorIsIdentity(t *testing.T) {
	G := NewBP256Generator()
	N := new(big.Int).SetBytes(bp256NBE[:])
	var nb [32]byte
	N.FillBytes(nb[:])
	out := new(BP256Point)
	if _, err := out.ScalarMult(G, nb[:]); err != nil {
		t.Fatalf("N·G: %v", err)
	}
	if out.IsIdentity() != 1 {
		t.Errorf("N·G should be identity; got %x", out.Bytes())
	}
}

// RFC 7027 §2.1 test vectors for brainpoolP256r1.
var rfc7027Vec256 = struct {
	dA, xA, yA string
	dB, xB, yB string
	xZ         string
}{
	dA: "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
	xA: "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
	yA: "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
	dB: "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3",
	xB: "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
	yB: "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
	xZ: "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B",
}

// TestBP256_RFC7027_PublicDerivation: dA·G and dB·G must match the RFC.
func TestBP256_RFC7027_PublicDerivation(t *testing.T) {
	v := rfc7027Vec256

	QA := new(BP256Point)
	if _, err := QA.ScalarBaseMult(unhex(t, v.dA)); err != nil {
		t.Fatalf("dA·G: %v", err)
	}
	wantA := append([]byte{0x04}, append(unhex(t, v.xA), unhex(t, v.yA)...)...)
	if !bytes.Equal(QA.Bytes(), wantA) {
		t.Errorf("dA·G mismatch\n got  %x\n want %x", QA.Bytes(), wantA)
	}

	QB := new(BP256Point)
	if _, err := QB.ScalarBaseMult(unhex(t, v.dB)); err != nil {
		t.Fatalf("dB·G: %v", err)
	}
	wantB := append([]byte{0x04}, append(unhex(t, v.xB), unhex(t, v.yB)...)...)
	if !bytes.Equal(QB.Bytes(), wantB) {
		t.Errorf("dB·G mismatch")
	}
}

// TestBP256_RFC7027_ECDH: dA·QB and dB·QA must both produce xZ.
func TestBP256_RFC7027_ECDH(t *testing.T) {
	v := rfc7027Vec256

	QB := new(BP256Point)
	if _, err := QB.SetBytes(append([]byte{0x04}, append(unhex(t, v.xB), unhex(t, v.yB)...)...)); err != nil {
		t.Fatalf("SetBytes QB: %v", err)
	}
	QA := new(BP256Point)
	if _, err := QA.SetBytes(append([]byte{0x04}, append(unhex(t, v.xA), unhex(t, v.yA)...)...)); err != nil {
		t.Fatalf("SetBytes QA: %v", err)
	}

	dAQB := new(BP256Point)
	if _, err := dAQB.ScalarMult(QB, unhex(t, v.dA)); err != nil {
		t.Fatalf("dA·QB: %v", err)
	}
	xZ, err := dAQB.BytesX()
	if err != nil {
		t.Fatalf("BytesX: %v", err)
	}
	want := unhex(t, v.xZ)
	if !bytes.Equal(xZ, want) {
		t.Errorf("dA·QB x mismatch\n got  %x\n want %x", xZ, want)
	}

	dBQA := new(BP256Point)
	if _, err := dBQA.ScalarMult(QA, unhex(t, v.dB)); err != nil {
		t.Fatalf("dB·QA: %v", err)
	}
	xZ2, _ := dBQA.BytesX()
	if !bytes.Equal(xZ, xZ2) {
		t.Errorf("ECDH not symmetric")
	}
}

// TestBP256_CompressedRoundTrip covers SEC1 compressed encoding through
// sqrt decompression on both parities.
func TestBP256_CompressedRoundTrip(t *testing.T) {
	// Generate a handful of points via k·G for k = 1..8, covering both
	// parities of Y.
	for k := int64(1); k <= 8; k++ {
		P := new(BP256Point).ScalarMultOrFail(t, NewBP256Generator(), big.NewInt(k))
		enc := P.BytesCompressed()
		if enc[0] != 0x02 && enc[0] != 0x03 {
			t.Fatalf("compressed tag 0x%x", enc[0])
		}
		Q := new(BP256Point)
		if _, err := Q.SetBytes(enc); err != nil {
			t.Fatalf("SetBytes(compressed): %v", err)
		}
		if !bytes.Equal(P.Bytes(), Q.Bytes()) {
			t.Errorf("compressed roundtrip mismatch at k=%d", k)
		}
	}
}

// TestBP256_SetBytesRejects covers malformed inputs.
func TestBP256_SetBytesRejects(t *testing.T) {
	var P BP256Point
	// Empty.
	if _, err := P.SetBytes(nil); err == nil {
		t.Errorf("accepted nil")
	}
	// Unknown tag.
	if _, err := P.SetBytes([]byte{0x07}); err == nil {
		t.Errorf("accepted unknown tag")
	}
	// Uncompressed off-curve (0,0) — for brainpool (0,0) is not on the curve.
	bad := make([]byte, 65)
	bad[0] = 0x04
	if _, err := P.SetBytes(bad); err == nil {
		t.Errorf("accepted (0,0)")
	}
	// x >= P.
	bad = make([]byte, 33)
	bad[0] = 0x02
	copy(bad[1:], bp256PBE[:])
	if _, err := P.SetBytes(bad); err == nil {
		t.Errorf("accepted compressed with x == P")
	}
}

// TestBP256_NScalar_InverseRoundTrip: s · s^-1 ≡ 1 (mod N).
func TestBP256_NScalar_InverseRoundTrip(t *testing.T) {
	// pick a non-trivial scalar
	sBytes := unhex(t, "112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00")
	var s, inv, prod NScalar256
	if _, err := s.SetBytes(sBytes); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	inv.Invert(&s)
	prod.Mul(&s, &inv)
	// 1 in the scalar field, big-endian
	one := make([]byte, 32)
	one[31] = 1
	if !bytes.Equal(prod.Bytes(), one) {
		t.Errorf("s·s^-1 != 1; got %x", prod.Bytes())
	}
}

// TestBP256_DoubleMatchesAdd pins the contract that the dedicated
// Double() (RCB Algorithm 3) produces the same affine point as the
// general Add() applied to (q, q) (RCB Algorithm 1) across a range of
// inputs, including the identity edge case. A regression in Algorithm 3
// — e.g., a transposed step, a sign flip, or a missing 2·t — would
// show here even if ScalarMult happens to still produce correct
// results by accident for the generator (very unlikely, but possible
// for a subtle bug that only manifests on non-generator inputs).
func TestBP256_DoubleMatchesAdd(t *testing.T) {
	// Build a small matrix of test points: identity + k·G for k ∈ {1..7}
	// + a large-scalar point that exercises the full schedule.
	points := []*BP256Point{NewBP256Point()} // identity first
	for k := int64(1); k <= 7; k++ {
		points = append(points, new(BP256Point).ScalarMultOrFail(t, NewBP256Generator(), big.NewInt(k)))
	}
	bigK, _ := new(big.Int).SetString("DEADBEEFCAFEBABE0123456789ABCDEF", 16)
	points = append(points, new(BP256Point).ScalarMultOrFail(t, NewBP256Generator(), bigK))

	for i, q := range points {
		viaDouble := new(BP256Point).Double(q)
		viaAdd := new(BP256Point).Add(q, q)
		// Compare in affine form; the two projective triples may differ
		// by a non-zero Z factor and still represent the same point.
		if !bytes.Equal(viaDouble.Bytes(), viaAdd.Bytes()) {
			t.Errorf("point %d: Double(q) != Add(q, q)", i)
		}
		// Identity must stay identity.
		if i == 0 && viaDouble.IsIdentity() != 1 {
			t.Errorf("Double(identity) did not yield identity")
		}
	}

	// Aliasing: Double(p, p) must match a non-aliased double of the
	// same input. ScalarMult calls result.Double(result) every iter.
	p := new(BP256Point).ScalarMultOrFail(t, NewBP256Generator(), big.NewInt(5))
	before := p.Bytes()
	viaAlias := new(BP256Point).Set(p)
	viaAlias.Double(viaAlias)
	viaFresh := new(BP256Point).Double(p)
	if !bytes.Equal(p.Bytes(), before) {
		t.Errorf("Double mutated its input when not aliased")
	}
	if !bytes.Equal(viaAlias.Bytes(), viaFresh.Bytes()) {
		t.Errorf("Double aliased vs non-aliased mismatch")
	}
}

// TestBP256_scalarReduceCT smoke-tests the CT reduction on a handful of
// values that straddle the N boundary.
func TestBP256_scalarReduceCT(t *testing.T) {
	N := new(big.Int).SetBytes(bp256NBE[:])
	cases := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Sub(N, big.NewInt(1)), // N-1
		new(big.Int).Set(N),                // N
		new(big.Int).Add(N, big.NewInt(1)), // N+1
	}
	for _, x := range cases {
		var be [32]byte
		x.FillBytes(be[:])
		var out [32]byte
		if err := scalarReduce256(&out, be[:]); err != nil {
			t.Fatalf("reduce: %v", err)
		}
		got := new(big.Int).SetBytes(out[:])
		want := new(big.Int).Mod(x, N)
		if got.Cmp(want) != 0 {
			t.Errorf("reduce(%x): got %x, want %x", be[:], got, want)
		}
	}
}
