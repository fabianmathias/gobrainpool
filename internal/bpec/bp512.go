package bpec

import (
	"errors"

	"github.com/fabianmathias/gobrainpool/internal/fiat/bp512"
)

// Domain parameters of brainpoolP512r1 (RFC 5639 §3.7). See bp256.go
// for the init pattern: byte literals + fiat FromBytes / ToMontgomery,
// no math/big.

type fe512 = bp512.MontgomeryDomainFieldElement

var (
	bp512One fe512
	bp512AM  fe512
	bp512BM  fe512
	bp512B3M fe512
	bp512GxM fe512
	bp512GyM fe512
)

var bp512PBE = [64]byte{
	0xaa, 0xdd, 0x9d, 0xb8, 0xdb, 0xe9, 0xc4, 0x8b, 0x3f, 0xd4, 0xe6, 0xae, 0x33, 0xc9, 0xfc, 0x07,
	0xcb, 0x30, 0x8d, 0xb3, 0xb3, 0xc9, 0xd2, 0x0e, 0xd6, 0x63, 0x9c, 0xca, 0x70, 0x33, 0x08, 0x71,
	0x7d, 0x4d, 0x9b, 0x00, 0x9b, 0xc6, 0x68, 0x42, 0xae, 0xcd, 0xa1, 0x2a, 0xe6, 0xa3, 0x80, 0xe6,
	0x28, 0x81, 0xff, 0x2f, 0x2d, 0x82, 0xc6, 0x85, 0x28, 0xaa, 0x60, 0x56, 0x58, 0x3a, 0x48, 0xf3,
}

var bp512ABE = [64]byte{
	0x78, 0x30, 0xa3, 0x31, 0x8b, 0x60, 0x3b, 0x89, 0xe2, 0x32, 0x71, 0x45, 0xac, 0x23, 0x4c, 0xc5,
	0x94, 0xcb, 0xdd, 0x8d, 0x3d, 0xf9, 0x16, 0x10, 0xa8, 0x34, 0x41, 0xca, 0xea, 0x98, 0x63, 0xbc,
	0x2d, 0xed, 0x5d, 0x5a, 0xa8, 0x25, 0x3a, 0xa1, 0x0a, 0x2e, 0xf1, 0xc9, 0x8b, 0x9a, 0xc8, 0xb5,
	0x7f, 0x11, 0x17, 0xa7, 0x2b, 0xf2, 0xc7, 0xb9, 0xe7, 0xc1, 0xac, 0x4d, 0x77, 0xfc, 0x94, 0xca,
}

var bp512BBE = [64]byte{
	0x3d, 0xf9, 0x16, 0x10, 0xa8, 0x34, 0x41, 0xca, 0xea, 0x98, 0x63, 0xbc, 0x2d, 0xed, 0x5d, 0x5a,
	0xa8, 0x25, 0x3a, 0xa1, 0x0a, 0x2e, 0xf1, 0xc9, 0x8b, 0x9a, 0xc8, 0xb5, 0x7f, 0x11, 0x17, 0xa7,
	0x2b, 0xf2, 0xc7, 0xb9, 0xe7, 0xc1, 0xac, 0x4d, 0x77, 0xfc, 0x94, 0xca, 0xdc, 0x08, 0x3e, 0x67,
	0x98, 0x40, 0x50, 0xb7, 0x5e, 0xba, 0xe5, 0xdd, 0x28, 0x09, 0xbd, 0x63, 0x80, 0x16, 0xf7, 0x23,
}

var bp512B3BE = [64]byte{
	0x0f, 0x0d, 0xa4, 0x79, 0x1c, 0xb3, 0x00, 0xd5, 0x7f, 0xf4, 0x44, 0x86, 0x55, 0xfe, 0x1c, 0x08,
	0x2d, 0x3f, 0x22, 0x2f, 0x6a, 0xc3, 0x03, 0x4d, 0xcc, 0x6c, 0xbd, 0x56, 0x0d, 0x00, 0x3e, 0x84,
	0x06, 0x8a, 0xbc, 0x2d, 0x1b, 0x7e, 0x9c, 0xa5, 0xb9, 0x28, 0x1d, 0x35, 0xad, 0x75, 0x3a, 0x50,
	0xa0, 0x3e, 0xf2, 0xf6, 0xee, 0xad, 0xeb, 0x12, 0x4f, 0x72, 0xd7, 0xd4, 0x28, 0x0a, 0x9c, 0x76,
}

var bp512GxBE = [64]byte{
	0x81, 0xae, 0xe4, 0xbd, 0xd8, 0x2e, 0xd9, 0x64, 0x5a, 0x21, 0x32, 0x2e, 0x9c, 0x4c, 0x6a, 0x93,
	0x85, 0xed, 0x9f, 0x70, 0xb5, 0xd9, 0x16, 0xc1, 0xb4, 0x3b, 0x62, 0xee, 0xf4, 0xd0, 0x09, 0x8e,
	0xff, 0x3b, 0x1f, 0x78, 0xe2, 0xd0, 0xd4, 0x8d, 0x50, 0xd1, 0x68, 0x7b, 0x93, 0xb9, 0x7d, 0x5f,
	0x7c, 0x6d, 0x50, 0x47, 0x40, 0x6a, 0x5e, 0x68, 0x8b, 0x35, 0x22, 0x09, 0xbc, 0xb9, 0xf8, 0x22,
}

var bp512GyBE = [64]byte{
	0x7d, 0xde, 0x38, 0x5d, 0x56, 0x63, 0x32, 0xec, 0xc0, 0xea, 0xbf, 0xa9, 0xcf, 0x78, 0x22, 0xfd,
	0xf2, 0x09, 0xf7, 0x00, 0x24, 0xa5, 0x7b, 0x1a, 0xa0, 0x00, 0xc5, 0x5b, 0x88, 0x1f, 0x81, 0x11,
	0xb2, 0xdc, 0xde, 0x49, 0x4a, 0x5f, 0x48, 0x5e, 0x5b, 0xca, 0x4b, 0xd8, 0x8a, 0x27, 0x63, 0xae,
	0xd1, 0xca, 0x2b, 0x2f, 0xa8, 0xf0, 0x54, 0x06, 0x78, 0xcd, 0x1e, 0x0f, 0x3a, 0xd8, 0x08, 0x92,
}

var bp512PM2BE = []byte{
	0xaa, 0xdd, 0x9d, 0xb8, 0xdb, 0xe9, 0xc4, 0x8b, 0x3f, 0xd4, 0xe6, 0xae, 0x33, 0xc9, 0xfc, 0x07,
	0xcb, 0x30, 0x8d, 0xb3, 0xb3, 0xc9, 0xd2, 0x0e, 0xd6, 0x63, 0x9c, 0xca, 0x70, 0x33, 0x08, 0x71,
	0x7d, 0x4d, 0x9b, 0x00, 0x9b, 0xc6, 0x68, 0x42, 0xae, 0xcd, 0xa1, 0x2a, 0xe6, 0xa3, 0x80, 0xe6,
	0x28, 0x81, 0xff, 0x2f, 0x2d, 0x82, 0xc6, 0x85, 0x28, 0xaa, 0x60, 0x56, 0x58, 0x3a, 0x48, 0xf1,
}

var bp512PP1D4BE = []byte{
	0x2a, 0xb7, 0x67, 0x6e, 0x36, 0xfa, 0x71, 0x22, 0xcf, 0xf5, 0x39, 0xab, 0x8c, 0xf2, 0x7f, 0x01,
	0xf2, 0xcc, 0x23, 0x6c, 0xec, 0xf2, 0x74, 0x83, 0xb5, 0x98, 0xe7, 0x32, 0x9c, 0x0c, 0xc2, 0x1c,
	0x5f, 0x53, 0x66, 0xc0, 0x26, 0xf1, 0x9a, 0x10, 0xab, 0xb3, 0x68, 0x4a, 0xb9, 0xa8, 0xe0, 0x39,
	0x8a, 0x20, 0x7f, 0xcb, 0xcb, 0x60, 0xb1, 0xa1, 0x4a, 0x2a, 0x98, 0x15, 0x96, 0x0e, 0x92, 0x3d,
}

func init() {
	bp512.SetOne(&bp512One)
	for _, entry := range []struct {
		dst *fe512
		src []byte
		tag string
	}{
		{&bp512AM, bp512ABE[:], "A"},
		{&bp512BM, bp512BBE[:], "B"},
		{&bp512B3M, bp512B3BE[:], "3B"},
		{&bp512GxM, bp512GxBE[:], "Gx"},
		{&bp512GyM, bp512GyBE[:], "Gy"},
	} {
		if !fe512FromBytesBE(entry.dst, entry.src) {
			panic("bpec: bp512 init: " + entry.tag + " not in [0, P)")
		}
	}
}

func fe512FromBytesBE(z *fe512, be []byte) bool {
	if len(be) != 64 {
		return false
	}
	if bytesGE64(be, bp512PBE[:]) {
		return false
	}
	var le [64]byte
	for i := 0; i < 64; i++ {
		le[i] = be[63-i]
	}
	var nm bp512.NonMontgomeryDomainFieldElement
	bp512.FromBytes((*[8]uint64)(&nm), &le)
	bp512.ToMontgomery(z, &nm)
	return true
}

func fe512ToBytesBE(be []byte, z *fe512) {
	var nm bp512.NonMontgomeryDomainFieldElement
	bp512.FromMontgomery(&nm, z)
	var le [64]byte
	bp512.ToBytes(&le, (*[8]uint64)(&nm))
	for i := 0; i < 64; i++ {
		be[i] = le[63-i]
	}
}

func fe512IsZero(z *fe512) int {
	var r uint64
	bp512.Nonzero(&r, (*[8]uint64)(z))
	nz := (r | -r) >> 63
	return int(1 ^ nz)
}

func fe512Equal(a, b *fe512) int {
	var d fe512
	bp512.Sub(&d, a, b)
	return fe512IsZero(&d)
}

func fe512ExpBE(out, a *fe512, expBE []byte) {
	var r fe512 = bp512One
	for _, b := range expBE {
		for bit := 7; bit >= 0; bit-- {
			bp512.Square(&r, &r)
			if (b>>uint(bit))&1 == 1 {
				bp512.Mul(&r, &r, a)
			}
		}
	}
	*out = r
}

func fe512Inv(out, a *fe512) { fe512ExpBE(out, a, bp512PM2BE) }

func fe512Select(out, a, b *fe512, cond uint64) {
	mask := -cond
	for i := 0; i < 8; i++ {
		out[i] = a[i] ^ (mask & (a[i] ^ b[i]))
	}
}

func bytesGE64(a, b []byte) bool {
	var borrow uint64
	for i := 63; i >= 0; i-- {
		d := uint64(a[i]) - uint64(b[i]) - borrow
		borrow = (d >> 63) & 1
	}
	return borrow == 0
}

// BP512Point is a projective point on brainpoolP512r1.
type BP512Point struct {
	x, y, z fe512
}

func NewBP512Point() *BP512Point {
	var p BP512Point
	p.y = bp512One
	return &p
}

func NewBP512Generator() *BP512Point {
	return &BP512Point{x: bp512GxM, y: bp512GyM, z: bp512One}
}

func (p *BP512Point) Set(q *BP512Point) *BP512Point {
	p.x, p.y, p.z = q.x, q.y, q.z
	return p
}

func (p *BP512Point) SetIdentity() *BP512Point {
	var z fe512
	p.x = z
	p.y = bp512One
	p.z = z
	return p
}

func (p *BP512Point) SetGenerator() *BP512Point {
	p.x = bp512GxM
	p.y = bp512GyM
	p.z = bp512One
	return p
}

func (p *BP512Point) IsIdentity() int { return fe512IsZero(&p.z) }

func (p *BP512Point) Bytes() []byte {
	out := make([]byte, 129)
	out[0] = 0x04
	var x, y fe512
	if fe512IsZero(&p.z) == 0 {
		var zInv fe512
		fe512Inv(&zInv, &p.z)
		bp512.Mul(&x, &p.x, &zInv)
		bp512.Mul(&y, &p.y, &zInv)
	}
	fe512ToBytesBE(out[1:65], &x)
	fe512ToBytesBE(out[65:129], &y)
	return out
}

func (p *BP512Point) BytesX() ([]byte, error) {
	if fe512IsZero(&p.z) == 1 {
		return nil, errors.New("bpec: BytesX of identity")
	}
	var zInv, x fe512
	fe512Inv(&zInv, &p.z)
	bp512.Mul(&x, &p.x, &zInv)
	out := make([]byte, 64)
	fe512ToBytesBE(out, &x)
	return out, nil
}

func (p *BP512Point) BytesCompressed() []byte {
	out := make([]byte, 65)
	var x, y fe512
	if fe512IsZero(&p.z) == 0 {
		var zInv fe512
		fe512Inv(&zInv, &p.z)
		bp512.Mul(&x, &p.x, &zInv)
		bp512.Mul(&y, &p.y, &zInv)
	}
	var yBE [64]byte
	fe512ToBytesBE(yBE[:], &y)
	out[0] = 0x02 | (yBE[63] & 1)
	fe512ToBytesBE(out[1:65], &x)
	return out
}

func (p *BP512Point) SetBytes(in []byte) (*BP512Point, error) {
	switch {
	case len(in) == 1 && in[0] == 0x00:
		return p.SetIdentity(), nil
	case len(in) == 129 && in[0] == 0x04:
		var xf, yf fe512
		if !fe512FromBytesBE(&xf, in[1:65]) {
			return nil, errors.New("bpec: x out of range")
		}
		if !fe512FromBytesBE(&yf, in[65:129]) {
			return nil, errors.New("bpec: y out of range")
		}
		if !bp512OnCurve(&xf, &yf) {
			return nil, errors.New("bpec: point not on curve")
		}
		p.x, p.y, p.z = xf, yf, bp512One
		return p, nil
	case len(in) == 65 && (in[0] == 0x02 || in[0] == 0x03):
		var xf fe512
		if !fe512FromBytesBE(&xf, in[1:65]) {
			return nil, errors.New("bpec: x out of range")
		}
		var alpha, t fe512
		bp512.Square(&alpha, &xf)
		bp512.Mul(&alpha, &alpha, &xf)
		bp512.Mul(&t, &bp512AM, &xf)
		bp512.Add(&alpha, &alpha, &t)
		bp512.Add(&alpha, &alpha, &bp512BM)

		var y, y2 fe512
		fe512ExpBE(&y, &alpha, bp512PP1D4BE)
		bp512.Square(&y2, &y)
		if fe512Equal(&y2, &alpha) == 0 {
			return nil, errors.New("bpec: x has no square root")
		}
		var yBE [64]byte
		fe512ToBytesBE(yBE[:], &y)
		wantOdd := in[0] == 0x03
		isOdd := (yBE[63] & 1) == 1
		if wantOdd != isOdd {
			bp512.Opp(&y, &y)
		}
		p.x, p.y, p.z = xf, y, bp512One
		return p, nil
	default:
		return nil, errors.New("bpec: invalid point encoding")
	}
}

func bp512OnCurve(x, y *fe512) bool {
	var lhs, rhs, t fe512
	bp512.Square(&lhs, y)
	bp512.Square(&rhs, x)
	bp512.Mul(&rhs, &rhs, x)
	bp512.Mul(&t, &bp512AM, x)
	bp512.Add(&rhs, &rhs, &t)
	bp512.Add(&rhs, &rhs, &bp512BM)
	return fe512Equal(&lhs, &rhs) == 1
}

func (p *BP512Point) Add(p1, p2 *BP512Point) *BP512Point {
	var t0, t1, t2, t3, t4, t5, X3, Y3, Z3, tmp fe512
	a := &bp512AM
	b3 := &bp512B3M
	M := bp512.Mul
	A := bp512.Add
	S := bp512.Sub

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
func (p *BP512Point) Double(q *BP512Point) *BP512Point {
	var t0, t1, t2, t3, X3, Y3, Z3 fe512
	a := &bp512AM
	b3 := &bp512B3M
	M := bp512.Mul
	Sq := bp512.Square
	A := bp512.Add
	S := bp512.Sub

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

func (p *BP512Point) Negate(q *BP512Point) *BP512Point {
	p.x = q.x
	bp512.Opp(&p.y, &q.y)
	p.z = q.z
	return p
}

func (p *BP512Point) Select(a, b *BP512Point, cond int) *BP512Point {
	c := uint64(cond & 1)
	fe512Select(&p.x, &a.x, &b.x, c)
	fe512Select(&p.y, &a.y, &b.y, c)
	fe512Select(&p.z, &a.z, &b.z, c)
	return p
}

func ctLookupBP512(out *BP512Point, table []BP512Point, idx uint8) {
	var rx, ry, rz fe512
	for i := range table {
		diff := uint32(uint8(i)) ^ uint32(idx)
		diff = (diff | (0 - diff)) >> 31
		mask := uint64(diff) - 1
		for j := 0; j < 8; j++ {
			rx[j] |= table[i].x[j] & mask
			ry[j] |= table[i].y[j] & mask
			rz[j] |= table[i].z[j] & mask
		}
	}
	out.x, out.y, out.z = rx, ry, rz
}

func (p *BP512Point) ScalarMult(q *BP512Point, scalar []byte) (*BP512Point, error) {
	var k [64]byte
	if err := scalarReduce512(&k, scalar); err != nil {
		return nil, err
	}
	var table [16]BP512Point
	table[0].SetIdentity()
	table[1].Set(q)
	for i := 2; i < 16; i++ {
		table[i].Add(&table[i-1], q)
	}
	result := NewBP512Point()
	var sel BP512Point
	for w := 127; w >= 0; w-- {
		result.Double(result)
		result.Double(result)
		result.Double(result)
		result.Double(result)
		byteIdx := 63 - w/2
		shift := uint(w&1) * 4
		win := (k[byteIdx] >> shift) & 0x0F
		ctLookupBP512(&sel, table[:], win)
		result.Add(result, &sel)
	}
	p.Set(result)
	return p, nil
}

func (p *BP512Point) ScalarBaseMult(scalar []byte) (*BP512Point, error) {
	G := NewBP512Generator()
	return p.ScalarMult(G, scalar)
}
