package bpec

import (
	"errors"

	"github.com/fabianmathias/gobrainpool/internal/fiat/bp384"
)

// Domain parameters of brainpoolP384r1 (RFC 5639 §3.6). See bp256.go
// for the init pattern: byte literals + fiat FromBytes / ToMontgomery,
// no math/big.

type fe384 = bp384.MontgomeryDomainFieldElement

var (
	bp384One fe384
	bp384AM  fe384
	bp384BM  fe384
	bp384B3M fe384
	bp384GxM fe384
	bp384GyM fe384
)

var bp384PBE = [48]byte{
	0x8c, 0xb9, 0x1e, 0x82, 0xa3, 0x38, 0x6d, 0x28, 0x0f, 0x5d, 0x6f, 0x7e, 0x50, 0xe6, 0x41, 0xdf,
	0x15, 0x2f, 0x71, 0x09, 0xed, 0x54, 0x56, 0xb4, 0x12, 0xb1, 0xda, 0x19, 0x7f, 0xb7, 0x11, 0x23,
	0xac, 0xd3, 0xa7, 0x29, 0x90, 0x1d, 0x1a, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xec, 0x53,
}

var bp384ABE = [48]byte{
	0x7b, 0xc3, 0x82, 0xc6, 0x3d, 0x8c, 0x15, 0x0c, 0x3c, 0x72, 0x08, 0x0a, 0xce, 0x05, 0xaf, 0xa0,
	0xc2, 0xbe, 0xa2, 0x8e, 0x4f, 0xb2, 0x27, 0x87, 0x13, 0x91, 0x65, 0xef, 0xba, 0x91, 0xf9, 0x0f,
	0x8a, 0xa5, 0x81, 0x4a, 0x50, 0x3a, 0xd4, 0xeb, 0x04, 0xa8, 0xc7, 0xdd, 0x22, 0xce, 0x28, 0x26,
}

var bp384BBE = [48]byte{
	0x04, 0xa8, 0xc7, 0xdd, 0x22, 0xce, 0x28, 0x26, 0x8b, 0x39, 0xb5, 0x54, 0x16, 0xf0, 0x44, 0x7c,
	0x2f, 0xb7, 0x7d, 0xe1, 0x07, 0xdc, 0xd2, 0xa6, 0x2e, 0x88, 0x0e, 0xa5, 0x3e, 0xeb, 0x62, 0xd5,
	0x7c, 0xb4, 0x39, 0x02, 0x95, 0xdb, 0xc9, 0x94, 0x3a, 0xb7, 0x86, 0x96, 0xfa, 0x50, 0x4c, 0x11,
}

var bp384B3BE = [48]byte{
	0x0d, 0xfa, 0x57, 0x97, 0x68, 0x6a, 0x78, 0x73, 0xa1, 0xad, 0x1f, 0xfc, 0x44, 0xd0, 0xcd, 0x74,
	0x8f, 0x26, 0x79, 0xa3, 0x17, 0x96, 0x77, 0xf2, 0x8b, 0x98, 0x2b, 0xef, 0xbc, 0xc2, 0x28, 0x80,
	0x76, 0x1c, 0xab, 0x07, 0xc1, 0x93, 0x5c, 0xbc, 0xb0, 0x26, 0x93, 0xc4, 0xee, 0xf0, 0xe4, 0x33,
}

var bp384GxBE = [48]byte{
	0x1d, 0x1c, 0x64, 0xf0, 0x68, 0xcf, 0x45, 0xff, 0xa2, 0xa6, 0x3a, 0x81, 0xb7, 0xc1, 0x3f, 0x6b,
	0x88, 0x47, 0xa3, 0xe7, 0x7e, 0xf1, 0x4f, 0xe3, 0xdb, 0x7f, 0xca, 0xfe, 0x0c, 0xbd, 0x10, 0xe8,
	0xe8, 0x26, 0xe0, 0x34, 0x36, 0xd6, 0x46, 0xaa, 0xef, 0x87, 0xb2, 0xe2, 0x47, 0xd4, 0xaf, 0x1e,
}

var bp384GyBE = [48]byte{
	0x8a, 0xbe, 0x1d, 0x75, 0x20, 0xf9, 0xc2, 0xa4, 0x5c, 0xb1, 0xeb, 0x8e, 0x95, 0xcf, 0xd5, 0x52,
	0x62, 0xb7, 0x0b, 0x29, 0xfe, 0xec, 0x58, 0x64, 0xe1, 0x9c, 0x05, 0x4f, 0xf9, 0x91, 0x29, 0x28,
	0x0e, 0x46, 0x46, 0x21, 0x77, 0x91, 0x81, 0x11, 0x42, 0x82, 0x03, 0x41, 0x26, 0x3c, 0x53, 0x15,
}

var bp384PM2BE = []byte{
	0x8c, 0xb9, 0x1e, 0x82, 0xa3, 0x38, 0x6d, 0x28, 0x0f, 0x5d, 0x6f, 0x7e, 0x50, 0xe6, 0x41, 0xdf,
	0x15, 0x2f, 0x71, 0x09, 0xed, 0x54, 0x56, 0xb4, 0x12, 0xb1, 0xda, 0x19, 0x7f, 0xb7, 0x11, 0x23,
	0xac, 0xd3, 0xa7, 0x29, 0x90, 0x1d, 0x1a, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xec, 0x51,
}

var bp384PP1D4BE = []byte{
	0x23, 0x2e, 0x47, 0xa0, 0xa8, 0xce, 0x1b, 0x4a, 0x03, 0xd7, 0x5b, 0xdf, 0x94, 0x39, 0x90, 0x77,
	0xc5, 0x4b, 0xdc, 0x42, 0x7b, 0x55, 0x15, 0xad, 0x04, 0xac, 0x76, 0x86, 0x5f, 0xed, 0xc4, 0x48,
	0xeb, 0x34, 0xe9, 0xca, 0x64, 0x07, 0x46, 0x9c, 0x61, 0xd1, 0xc0, 0x04, 0xcc, 0x41, 0xfb, 0x15,
}

func init() {
	bp384.SetOne(&bp384One)
	for _, entry := range []struct {
		dst *fe384
		src []byte
		tag string
	}{
		{&bp384AM, bp384ABE[:], "A"},
		{&bp384BM, bp384BBE[:], "B"},
		{&bp384B3M, bp384B3BE[:], "3B"},
		{&bp384GxM, bp384GxBE[:], "Gx"},
		{&bp384GyM, bp384GyBE[:], "Gy"},
	} {
		if !fe384FromBytesBE(entry.dst, entry.src) {
			panic("bpec: bp384 init: " + entry.tag + " not in [0, P)")
		}
	}
}

func fe384FromBytesBE(z *fe384, be []byte) bool {
	if len(be) != 48 {
		return false
	}
	if bytesGE48(be, bp384PBE[:]) {
		return false
	}
	var le [48]byte
	for i := 0; i < 48; i++ {
		le[i] = be[47-i]
	}
	var nm bp384.NonMontgomeryDomainFieldElement
	bp384.FromBytes((*[6]uint64)(&nm), &le)
	bp384.ToMontgomery(z, &nm)
	return true
}

func fe384ToBytesBE(be []byte, z *fe384) {
	var nm bp384.NonMontgomeryDomainFieldElement
	bp384.FromMontgomery(&nm, z)
	var le [48]byte
	bp384.ToBytes(&le, (*[6]uint64)(&nm))
	for i := 0; i < 48; i++ {
		be[i] = le[47-i]
	}
}

func fe384IsZero(z *fe384) int {
	var r uint64
	bp384.Nonzero(&r, (*[6]uint64)(z))
	nz := (r | -r) >> 63
	return int(1 ^ nz)
}

func fe384Equal(a, b *fe384) int {
	var d fe384
	bp384.Sub(&d, a, b)
	return fe384IsZero(&d)
}

func fe384ExpBE(out, a *fe384, expBE []byte) {
	var r fe384 = bp384One
	for _, b := range expBE {
		for bit := 7; bit >= 0; bit-- {
			bp384.Square(&r, &r)
			if (b>>uint(bit))&1 == 1 {
				bp384.Mul(&r, &r, a)
			}
		}
	}
	*out = r
}

func fe384Inv(out, a *fe384) { fe384ExpBE(out, a, bp384PM2BE) }

func fe384Select(out, a, b *fe384, cond uint64) {
	mask := -cond
	for i := 0; i < 6; i++ {
		out[i] = a[i] ^ (mask & (a[i] ^ b[i]))
	}
}

func bytesGE48(a, b []byte) bool {
	var borrow uint64
	for i := 47; i >= 0; i-- {
		d := uint64(a[i]) - uint64(b[i]) - borrow
		borrow = (d >> 63) & 1
	}
	return borrow == 0
}

// BP384Point is a projective point on brainpoolP384r1. See BP256Point for
// the behavioural contract — the two types are structurally identical.
type BP384Point struct {
	x, y, z fe384
}

func NewBP384Point() *BP384Point {
	var p BP384Point
	p.y = bp384One
	return &p
}

func NewBP384Generator() *BP384Point {
	return &BP384Point{x: bp384GxM, y: bp384GyM, z: bp384One}
}

func (p *BP384Point) Set(q *BP384Point) *BP384Point {
	p.x, p.y, p.z = q.x, q.y, q.z
	return p
}

func (p *BP384Point) SetIdentity() *BP384Point {
	var z fe384
	p.x = z
	p.y = bp384One
	p.z = z
	return p
}

func (p *BP384Point) SetGenerator() *BP384Point {
	p.x = bp384GxM
	p.y = bp384GyM
	p.z = bp384One
	return p
}

func (p *BP384Point) IsIdentity() int { return fe384IsZero(&p.z) }

func (p *BP384Point) Bytes() []byte {
	out := make([]byte, 97)
	out[0] = 0x04
	var x, y fe384
	if fe384IsZero(&p.z) == 0 {
		var zInv fe384
		fe384Inv(&zInv, &p.z)
		bp384.Mul(&x, &p.x, &zInv)
		bp384.Mul(&y, &p.y, &zInv)
	}
	fe384ToBytesBE(out[1:49], &x)
	fe384ToBytesBE(out[49:97], &y)
	return out
}

func (p *BP384Point) BytesX() ([]byte, error) {
	if fe384IsZero(&p.z) == 1 {
		return nil, errors.New("bpec: BytesX of identity")
	}
	var zInv, x fe384
	fe384Inv(&zInv, &p.z)
	bp384.Mul(&x, &p.x, &zInv)
	out := make([]byte, 48)
	fe384ToBytesBE(out, &x)
	return out, nil
}

func (p *BP384Point) BytesCompressed() []byte {
	out := make([]byte, 49)
	var x, y fe384
	if fe384IsZero(&p.z) == 0 {
		var zInv fe384
		fe384Inv(&zInv, &p.z)
		bp384.Mul(&x, &p.x, &zInv)
		bp384.Mul(&y, &p.y, &zInv)
	}
	var yBE [48]byte
	fe384ToBytesBE(yBE[:], &y)
	out[0] = 0x02 | (yBE[47] & 1)
	fe384ToBytesBE(out[1:49], &x)
	return out
}

func (p *BP384Point) SetBytes(in []byte) (*BP384Point, error) {
	switch {
	case len(in) == 1 && in[0] == 0x00:
		return p.SetIdentity(), nil
	case len(in) == 97 && in[0] == 0x04:
		var xf, yf fe384
		if !fe384FromBytesBE(&xf, in[1:49]) {
			return nil, errors.New("bpec: x out of range")
		}
		if !fe384FromBytesBE(&yf, in[49:97]) {
			return nil, errors.New("bpec: y out of range")
		}
		if !bp384OnCurve(&xf, &yf) {
			return nil, errors.New("bpec: point not on curve")
		}
		p.x, p.y, p.z = xf, yf, bp384One
		return p, nil
	case len(in) == 49 && (in[0] == 0x02 || in[0] == 0x03):
		var xf fe384
		if !fe384FromBytesBE(&xf, in[1:49]) {
			return nil, errors.New("bpec: x out of range")
		}
		var alpha, t fe384
		bp384.Square(&alpha, &xf)
		bp384.Mul(&alpha, &alpha, &xf)
		bp384.Mul(&t, &bp384AM, &xf)
		bp384.Add(&alpha, &alpha, &t)
		bp384.Add(&alpha, &alpha, &bp384BM)

		var y, y2 fe384
		fe384ExpBE(&y, &alpha, bp384PP1D4BE)
		bp384.Square(&y2, &y)
		if fe384Equal(&y2, &alpha) == 0 {
			return nil, errors.New("bpec: x has no square root")
		}
		var yBE [48]byte
		fe384ToBytesBE(yBE[:], &y)
		wantOdd := in[0] == 0x03
		isOdd := (yBE[47] & 1) == 1
		if wantOdd != isOdd {
			bp384.Opp(&y, &y)
		}
		p.x, p.y, p.z = xf, y, bp384One
		return p, nil
	default:
		return nil, errors.New("bpec: invalid point encoding")
	}
}

func bp384OnCurve(x, y *fe384) bool {
	var lhs, rhs, t fe384
	bp384.Square(&lhs, y)
	bp384.Square(&rhs, x)
	bp384.Mul(&rhs, &rhs, x)
	bp384.Mul(&t, &bp384AM, x)
	bp384.Add(&rhs, &rhs, &t)
	bp384.Add(&rhs, &rhs, &bp384BM)
	return fe384Equal(&lhs, &rhs) == 1
}

func (p *BP384Point) Add(p1, p2 *BP384Point) *BP384Point {
	var t0, t1, t2, t3, t4, t5, X3, Y3, Z3, tmp fe384
	a := &bp384AM
	b3 := &bp384B3M
	M := bp384.Mul
	A := bp384.Add
	S := bp384.Sub

	M(&t0, &p1.x, &p2.x)
	M(&t1, &p1.y, &p2.y)
	M(&t2, &p1.z, &p2.z)
	A(&t3, &p1.x, &p1.y)
	A(&tmp, &p2.x, &p2.y)
	M(&t3, &t3, &tmp)
	A(&t4, &t0, &t1)
	S(&t3, &t3, &t4)
	A(&t4, &p1.x, &p1.z)
	A(&tmp, &p2.x, &p2.z)
	M(&t4, &t4, &tmp)
	A(&t5, &t0, &t2)
	S(&t4, &t4, &t5)
	A(&t5, &p1.y, &p1.z)
	A(&tmp, &p2.y, &p2.z)
	M(&t5, &t5, &tmp)
	A(&tmp, &t1, &t2)
	S(&t5, &t5, &tmp)
	M(&Z3, a, &t4)
	M(&X3, b3, &t2)
	A(&Z3, &X3, &Z3)
	S(&X3, &t1, &Z3)
	A(&Z3, &t1, &Z3)
	M(&Y3, &X3, &Z3)
	A(&t1, &t0, &t0)
	A(&t1, &t1, &t0)
	M(&t2, a, &t2)
	M(&t4, b3, &t4)
	A(&t1, &t1, &t2)
	S(&t2, &t0, &t2)
	M(&t2, a, &t2)
	A(&t4, &t4, &t2)
	M(&t0, &t1, &t4)
	A(&Y3, &Y3, &t0)
	M(&t0, &t5, &t4)
	M(&X3, &t3, &X3)
	S(&X3, &X3, &t0)
	M(&t0, &t3, &t1)
	M(&Z3, &t5, &Z3)
	A(&Z3, &Z3, &t0)

	p.x, p.y, p.z = X3, Y3, Z3
	return p
}

// Double sets p = 2·q and returns p. Uses the Renes-Costello-Batina
// 2015 dedicated doubling formula (Algorithm 3, general a). Branch-free,
// complete for all inputs including the point at infinity. Valid when
// q aliases p.
//
// Cost: 3S + 8M + 3·(mul by a) + 2·(mul by b3) + 15 additions, versus
// Add(q, q)'s 12M + 3·a + 2·b3 + 23 additions.
func (p *BP384Point) Double(q *BP384Point) *BP384Point {
	var t0, t1, t2, t3, X3, Y3, Z3 fe384
	a := &bp384AM
	b3 := &bp384B3M
	M := bp384.Mul
	Sq := bp384.Square
	A := bp384.Add
	S := bp384.Sub

	Sq(&t0, &q.x)      // 1:  t0 = X^2
	Sq(&t1, &q.y)      // 2:  t1 = Y^2
	Sq(&t2, &q.z)      // 3:  t2 = Z^2
	M(&t3, &q.x, &q.y) // 4:  t3 = X·Y
	A(&t3, &t3, &t3)   // 5:  t3 = 2·t3
	M(&Z3, &q.x, &q.z) // 6:  Z3 = X·Z
	A(&Z3, &Z3, &Z3)   // 7:  Z3 = 2·Z3
	M(&Y3, a, &Z3)     // 8:  Y3 = a·Z3
	M(&X3, b3, &t2)    // 9:  X3 = b3·t2
	A(&Y3, &X3, &Y3)   // 10: Y3 = X3 + Y3
	S(&X3, &t1, &Y3)   // 11: X3 = t1 - Y3
	A(&Y3, &t1, &Y3)   // 12: Y3 = t1 + Y3
	M(&Y3, &X3, &Y3)   // 13: Y3 = X3·Y3
	M(&X3, &t3, &X3)   // 14: X3 = t3·X3
	M(&Z3, b3, &Z3)    // 15: Z3 = b3·Z3
	M(&t2, a, &t2)     // 16: t2 = a·t2
	S(&t3, &t0, &t2)   // 17: t3 = t0 - t2
	M(&t3, a, &t3)     // 18: t3 = a·t3
	A(&t3, &t3, &Z3)   // 19: t3 = t3 + Z3
	A(&Z3, &t0, &t0)   // 20: Z3 = t0 + t0
	A(&t0, &Z3, &t0)   // 21: t0 = Z3 + t0
	A(&t0, &t0, &t2)   // 22: t0 = t0 + t2
	M(&t0, &t0, &t3)   // 23: t0 = t0·t3
	A(&Y3, &Y3, &t0)   // 24: Y3 = Y3 + t0
	M(&t2, &q.y, &q.z) // 25: t2 = Y·Z
	A(&t2, &t2, &t2)   // 26: t2 = 2·t2
	M(&t0, &t2, &t3)   // 27: t0 = t2·t3
	S(&X3, &X3, &t0)   // 28: X3 = X3 - t0
	M(&Z3, &t2, &t1)   // 29: Z3 = t2·t1
	A(&Z3, &Z3, &Z3)   // 30: Z3 = 2·Z3
	A(&Z3, &Z3, &Z3)   // 31: Z3 = 2·Z3

	p.x, p.y, p.z = X3, Y3, Z3
	return p
}

func (p *BP384Point) Negate(q *BP384Point) *BP384Point {
	p.x = q.x
	bp384.Opp(&p.y, &q.y)
	p.z = q.z
	return p
}

func (p *BP384Point) Select(a, b *BP384Point, cond int) *BP384Point {
	c := uint64(cond & 1)
	fe384Select(&p.x, &a.x, &b.x, c)
	fe384Select(&p.y, &a.y, &b.y, c)
	fe384Select(&p.z, &a.z, &b.z, c)
	return p
}

func ctLookupBP384(out *BP384Point, table []BP384Point, idx uint8) {
	var rx, ry, rz fe384
	for i := range table {
		diff := uint32(uint8(i)) ^ uint32(idx)
		diff = (diff | (0 - diff)) >> 31
		mask := uint64(diff) - 1
		for j := 0; j < 6; j++ {
			rx[j] |= table[i].x[j] & mask
			ry[j] |= table[i].y[j] & mask
			rz[j] |= table[i].z[j] & mask
		}
	}
	out.x, out.y, out.z = rx, ry, rz
}

func (p *BP384Point) ScalarMult(q *BP384Point, scalar []byte) (*BP384Point, error) {
	var k [48]byte
	if err := scalarReduce384(&k, scalar); err != nil {
		return nil, err
	}
	var table [16]BP384Point
	table[0].SetIdentity()
	table[1].Set(q)
	for i := 2; i < 16; i++ {
		table[i].Add(&table[i-1], q)
	}
	result := NewBP384Point()
	var sel BP384Point
	for w := 95; w >= 0; w-- {
		result.Double(result)
		result.Double(result)
		result.Double(result)
		result.Double(result)
		byteIdx := 47 - w/2
		shift := uint(w&1) * 4
		win := (k[byteIdx] >> shift) & 0x0F
		ctLookupBP384(&sel, table[:], win)
		result.Add(result, &sel)
	}
	p.Set(result)
	return p, nil
}

func (p *BP384Point) ScalarBaseMult(scalar []byte) (*BP384Point, error) {
	G := NewBP384Generator()
	return p.ScalarMult(G, scalar)
}
