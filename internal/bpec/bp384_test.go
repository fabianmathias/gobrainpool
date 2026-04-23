package bpec

import (
	"bytes"
	"math/big"
	"testing"
)

// RFC 7027 §2.2 test vectors for brainpoolP384r1.
var rfc7027Vec384 = struct {
	dA, xA, yA string
	dB, xB, yB string
	xZ         string
}{
	dA: "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
	xA: "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885AB698C852D4A6E77A252D6380FCAF068",
	yA: "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493E0D038FF2FD30C2AB67D15C85F7FAA59",
	dB: "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670",
	xB: "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB4",
	yB: "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48",
	xZ: "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42",
}

func (p *BP384Point) scalarMultOrFail(t *testing.T, q *BP384Point, k *big.Int) *BP384Point {
	t.Helper()
	var buf [48]byte
	k.FillBytes(buf[:])
	if _, err := p.ScalarMult(q, buf[:]); err != nil {
		t.Fatalf("ScalarMult: %v", err)
	}
	return p
}

func TestBP384_GeneratorRoundTrip(t *testing.T) {
	G := NewBP384Generator()
	enc := G.Bytes()
	var P BP384Point
	if _, err := P.SetBytes(enc); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	if !bytes.Equal(P.Bytes(), enc) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestBP384_GroupLaws(t *testing.T) {
	G := NewBP384Generator()
	negG := new(BP384Point).Negate(G)
	if new(BP384Point).Add(G, negG).IsIdentity() != 1 {
		t.Errorf("G + (-G) should be identity")
	}
	g2a := new(BP384Point).Double(G)
	g2b := new(BP384Point).Add(G, G)
	if !bytes.Equal(g2a.Bytes(), g2b.Bytes()) {
		t.Errorf("2G != G+G")
	}
}

func TestBP384_OrderTimesGeneratorIsIdentity(t *testing.T) {
	G := NewBP384Generator()
	N := new(big.Int).SetBytes(bp384NBE[:])
	var nb [48]byte
	N.FillBytes(nb[:])
	out := new(BP384Point)
	if _, err := out.ScalarMult(G, nb[:]); err != nil {
		t.Fatalf("N·G: %v", err)
	}
	if out.IsIdentity() != 1 {
		t.Errorf("N·G should be identity")
	}
}

func TestBP384_RFC7027_PublicDerivation(t *testing.T) {
	v := rfc7027Vec384
	QA := new(BP384Point)
	if _, err := QA.ScalarBaseMult(unhex(t, v.dA)); err != nil {
		t.Fatalf("dA·G: %v", err)
	}
	want := append([]byte{0x04}, append(unhex(t, v.xA), unhex(t, v.yA)...)...)
	if !bytes.Equal(QA.Bytes(), want) {
		t.Errorf("dA·G mismatch")
	}
	QB := new(BP384Point)
	if _, err := QB.ScalarBaseMult(unhex(t, v.dB)); err != nil {
		t.Fatalf("dB·G: %v", err)
	}
	want = append([]byte{0x04}, append(unhex(t, v.xB), unhex(t, v.yB)...)...)
	if !bytes.Equal(QB.Bytes(), want) {
		t.Errorf("dB·G mismatch")
	}
}

func TestBP384_RFC7027_ECDH(t *testing.T) {
	v := rfc7027Vec384
	QB := new(BP384Point)
	if _, err := QB.SetBytes(append([]byte{0x04}, append(unhex(t, v.xB), unhex(t, v.yB)...)...)); err != nil {
		t.Fatalf("QB: %v", err)
	}
	z := new(BP384Point)
	if _, err := z.ScalarMult(QB, unhex(t, v.dA)); err != nil {
		t.Fatalf("dA·QB: %v", err)
	}
	xZ, _ := z.BytesX()
	if !bytes.Equal(xZ, unhex(t, v.xZ)) {
		t.Errorf("ECDH mismatch\n got  %x\n want %s", xZ, v.xZ)
	}
}

func TestBP384_CompressedRoundTrip(t *testing.T) {
	for k := int64(1); k <= 8; k++ {
		P := new(BP384Point).scalarMultOrFail(t, NewBP384Generator(), big.NewInt(k))
		enc := P.BytesCompressed()
		Q := new(BP384Point)
		if _, err := Q.SetBytes(enc); err != nil {
			t.Fatalf("SetBytes: %v", err)
		}
		if !bytes.Equal(P.Bytes(), Q.Bytes()) {
			t.Errorf("k=%d compressed mismatch", k)
		}
	}
}

// TestBP384_DoubleMatchesAdd pins Double() (RCB Alg 3) against
// Add(q, q) (RCB Alg 1) across a matrix of points including identity,
// small multiples of G, and a large scalar. Also exercises the
// aliasing contract (result.Double(result)) required by ScalarMult.
func TestBP384_DoubleMatchesAdd(t *testing.T) {
	points := []*BP384Point{NewBP384Point()} // identity
	for k := int64(1); k <= 7; k++ {
		points = append(points, new(BP384Point).scalarMultOrFail(t, NewBP384Generator(), big.NewInt(k)))
	}
	bigK, _ := new(big.Int).SetString("DEADBEEFCAFEBABE0123456789ABCDEF0123456789ABCDEF", 16)
	points = append(points, new(BP384Point).scalarMultOrFail(t, NewBP384Generator(), bigK))

	for i, q := range points {
		viaDouble := new(BP384Point).Double(q)
		viaAdd := new(BP384Point).Add(q, q)
		if !bytes.Equal(viaDouble.Bytes(), viaAdd.Bytes()) {
			t.Errorf("point %d: Double(q) != Add(q, q)", i)
		}
		if i == 0 && viaDouble.IsIdentity() != 1 {
			t.Errorf("Double(identity) did not yield identity")
		}
	}

	p := new(BP384Point).scalarMultOrFail(t, NewBP384Generator(), big.NewInt(5))
	viaAlias := new(BP384Point).Set(p)
	viaAlias.Double(viaAlias)
	viaFresh := new(BP384Point).Double(p)
	if !bytes.Equal(viaAlias.Bytes(), viaFresh.Bytes()) {
		t.Errorf("Double aliased vs non-aliased mismatch")
	}
}

func TestBP384_NScalar_InverseRoundTrip(t *testing.T) {
	sBytes := unhex(t, "112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00")
	var s, inv, prod NScalar384
	if _, err := s.SetBytes(sBytes); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	inv.Invert(&s)
	prod.Mul(&s, &inv)
	one := make([]byte, 48)
	one[47] = 1
	if !bytes.Equal(prod.Bytes(), one) {
		t.Errorf("s·s^-1 != 1")
	}
}
