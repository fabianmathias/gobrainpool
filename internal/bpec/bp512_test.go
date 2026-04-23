package bpec

import (
	"bytes"
	"math/big"
	"testing"
)

// RFC 7027 §2.3 test vectors for brainpoolP512r1.
var rfc7027Vec512 = struct {
	dA, xA, yA string
	dB, xB, yB string
	xZ         string
}{
	dA: "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422",
	xA: "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD",
	yA: "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7",
	dB: "230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CFABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429",
	xB: "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCBAAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F",
	yB: "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA",
	xZ: "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F",
}

func (p *BP512Point) scalarMultOrFail(t *testing.T, q *BP512Point, k *big.Int) *BP512Point {
	t.Helper()
	var buf [64]byte
	k.FillBytes(buf[:])
	if _, err := p.ScalarMult(q, buf[:]); err != nil {
		t.Fatalf("ScalarMult: %v", err)
	}
	return p
}

func TestBP512_GeneratorRoundTrip(t *testing.T) {
	G := NewBP512Generator()
	enc := G.Bytes()
	var P BP512Point
	if _, err := P.SetBytes(enc); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	if !bytes.Equal(P.Bytes(), enc) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestBP512_GroupLaws(t *testing.T) {
	G := NewBP512Generator()
	negG := new(BP512Point).Negate(G)
	if new(BP512Point).Add(G, negG).IsIdentity() != 1 {
		t.Errorf("G + (-G) should be identity")
	}
	g2a := new(BP512Point).Double(G)
	g2b := new(BP512Point).Add(G, G)
	if !bytes.Equal(g2a.Bytes(), g2b.Bytes()) {
		t.Errorf("2G != G+G")
	}
}

func TestBP512_OrderTimesGeneratorIsIdentity(t *testing.T) {
	G := NewBP512Generator()
	N := new(big.Int).SetBytes(bp512NBE[:])
	var nb [64]byte
	N.FillBytes(nb[:])
	out := new(BP512Point)
	if _, err := out.ScalarMult(G, nb[:]); err != nil {
		t.Fatalf("N·G: %v", err)
	}
	if out.IsIdentity() != 1 {
		t.Errorf("N·G should be identity")
	}
}

func TestBP512_RFC7027_PublicDerivation(t *testing.T) {
	v := rfc7027Vec512
	QA := new(BP512Point)
	if _, err := QA.ScalarBaseMult(unhex(t, v.dA)); err != nil {
		t.Fatalf("dA·G: %v", err)
	}
	want := append([]byte{0x04}, append(unhex(t, v.xA), unhex(t, v.yA)...)...)
	if !bytes.Equal(QA.Bytes(), want) {
		t.Errorf("dA·G mismatch")
	}
	QB := new(BP512Point)
	if _, err := QB.ScalarBaseMult(unhex(t, v.dB)); err != nil {
		t.Fatalf("dB·G: %v", err)
	}
	want = append([]byte{0x04}, append(unhex(t, v.xB), unhex(t, v.yB)...)...)
	if !bytes.Equal(QB.Bytes(), want) {
		t.Errorf("dB·G mismatch")
	}
}

func TestBP512_RFC7027_ECDH(t *testing.T) {
	v := rfc7027Vec512
	QB := new(BP512Point)
	if _, err := QB.SetBytes(append([]byte{0x04}, append(unhex(t, v.xB), unhex(t, v.yB)...)...)); err != nil {
		t.Fatalf("QB: %v", err)
	}
	z := new(BP512Point)
	if _, err := z.ScalarMult(QB, unhex(t, v.dA)); err != nil {
		t.Fatalf("dA·QB: %v", err)
	}
	xZ, _ := z.BytesX()
	if !bytes.Equal(xZ, unhex(t, v.xZ)) {
		t.Errorf("ECDH mismatch")
	}
}

func TestBP512_CompressedRoundTrip(t *testing.T) {
	for k := int64(1); k <= 8; k++ {
		P := new(BP512Point).scalarMultOrFail(t, NewBP512Generator(), big.NewInt(k))
		enc := P.BytesCompressed()
		Q := new(BP512Point)
		if _, err := Q.SetBytes(enc); err != nil {
			t.Fatalf("SetBytes: %v", err)
		}
		if !bytes.Equal(P.Bytes(), Q.Bytes()) {
			t.Errorf("k=%d compressed mismatch", k)
		}
	}
}

// TestBP512_DoubleMatchesAdd pins Double() (RCB Alg 3) against
// Add(q, q) (RCB Alg 1) across a matrix of points including identity,
// small multiples of G, and a large scalar. Also exercises the
// aliasing contract (result.Double(result)) required by ScalarMult.
func TestBP512_DoubleMatchesAdd(t *testing.T) {
	points := []*BP512Point{NewBP512Point()} // identity
	for k := int64(1); k <= 7; k++ {
		points = append(points, new(BP512Point).scalarMultOrFail(t, NewBP512Generator(), big.NewInt(k)))
	}
	bigK, _ := new(big.Int).SetString("DEADBEEFCAFEBABE0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 16)
	points = append(points, new(BP512Point).scalarMultOrFail(t, NewBP512Generator(), bigK))

	for i, q := range points {
		viaDouble := new(BP512Point).Double(q)
		viaAdd := new(BP512Point).Add(q, q)
		if !bytes.Equal(viaDouble.Bytes(), viaAdd.Bytes()) {
			t.Errorf("point %d: Double(q) != Add(q, q)", i)
		}
		if i == 0 && viaDouble.IsIdentity() != 1 {
			t.Errorf("Double(identity) did not yield identity")
		}
	}

	p := new(BP512Point).scalarMultOrFail(t, NewBP512Generator(), big.NewInt(5))
	viaAlias := new(BP512Point).Set(p)
	viaAlias.Double(viaAlias)
	viaFresh := new(BP512Point).Double(p)
	if !bytes.Equal(viaAlias.Bytes(), viaFresh.Bytes()) {
		t.Errorf("Double aliased vs non-aliased mismatch")
	}
}

func TestBP512_NScalar_InverseRoundTrip(t *testing.T) {
	sBytes := unhex(t, "112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00")
	var s, inv, prod NScalar512
	if _, err := s.SetBytes(sBytes); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	inv.Invert(&s)
	prod.Mul(&s, &inv)
	one := make([]byte, 64)
	one[63] = 1
	if !bytes.Equal(prod.Bytes(), one) {
		t.Errorf("s·s^-1 != 1")
	}
}
