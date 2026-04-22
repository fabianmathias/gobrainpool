package bpec

import (
	"errors"

	"github.com/fabianmathias/gobrainpool/internal/fiat/bp256"
)

// Domain parameters of brainpoolP256r1 (RFC 5639 §3.4) stored as fixed
// big-endian byte literals. The Montgomery-form field elements bp256AM,
// bp256BM, bp256B3M, bp256GxM and bp256GyM are derived in init() via the
// fiat FromBytes / ToMontgomery primitives (no math/big) — this mirrors
// the crypto/internal/fips140 pattern of keeping all curve constants
// in the cryptographic boundary.

type fe256 = bp256.MontgomeryDomainFieldElement

var (
	bp256One fe256 // 1 in Montgomery form
	bp256AM  fe256 // curve coefficient a (Montgomery)
	bp256BM  fe256 // curve coefficient b (Montgomery)
	bp256B3M fe256 // 3·b (Montgomery)
	bp256GxM fe256 // generator X (Montgomery)
	bp256GyM fe256 // generator Y (Montgomery)
)

var bp256PBE = [32]byte{
	0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, 0x72,
	0x6e, 0x3b, 0xf6, 0x23, 0xd5, 0x26, 0x20, 0x28, 0x20, 0x13, 0x48, 0x1d, 0x1f, 0x6e, 0x53, 0x77,
}

var bp256ABE = [32]byte{
	0x7d, 0x5a, 0x09, 0x75, 0xfc, 0x2c, 0x30, 0x57, 0xee, 0xf6, 0x75, 0x30, 0x41, 0x7a, 0xff, 0xe7,
	0xfb, 0x80, 0x55, 0xc1, 0x26, 0xdc, 0x5c, 0x6c, 0xe9, 0x4a, 0x4b, 0x44, 0xf3, 0x30, 0xb5, 0xd9,
}

var bp256BBE = [32]byte{
	0x26, 0xdc, 0x5c, 0x6c, 0xe9, 0x4a, 0x4b, 0x44, 0xf3, 0x30, 0xb5, 0xd9, 0xbb, 0xd7, 0x7c, 0xbf,
	0x95, 0x84, 0x16, 0x29, 0x5c, 0xf7, 0xe1, 0xce, 0x6b, 0xcc, 0xdc, 0x18, 0xff, 0x8c, 0x07, 0xb6,
}

// bp256B3BE = 3·B mod P, precomputed offline.
var bp256B3BE = [32]byte{
	0x74, 0x95, 0x15, 0x46, 0xbb, 0xde, 0xe1, 0xce, 0xd9, 0x92, 0x21, 0x8d, 0x33, 0x86, 0x76, 0x3e,
	0xc0, 0x8c, 0x42, 0x7c, 0x16, 0xe7, 0xa5, 0x6b, 0x43, 0x66, 0x94, 0x4a, 0xfe, 0xa4, 0x17, 0x22,
}

var bp256GxBE = [32]byte{
	0x8b, 0xd2, 0xae, 0xb9, 0xcb, 0x7e, 0x57, 0xcb, 0x2c, 0x4b, 0x48, 0x2f, 0xfc, 0x81, 0xb7, 0xaf,
	0xb9, 0xde, 0x27, 0xe1, 0xe3, 0xbd, 0x23, 0xc2, 0x3a, 0x44, 0x53, 0xbd, 0x9a, 0xce, 0x32, 0x62,
}

var bp256GyBE = [32]byte{
	0x54, 0x7e, 0xf8, 0x35, 0xc3, 0xda, 0xc4, 0xfd, 0x97, 0xf8, 0x46, 0x1a, 0x14, 0x61, 0x1d, 0xc9,
	0xc2, 0x77, 0x45, 0x13, 0x2d, 0xed, 0x8e, 0x54, 0x5c, 0x1d, 0x54, 0xc7, 0x2f, 0x04, 0x69, 0x97,
}

// bp256PM2BE = P-2 big-endian (Fermat exponent for field inversion).
var bp256PM2BE = []byte{
	0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, 0x72,
	0x6e, 0x3b, 0xf6, 0x23, 0xd5, 0x26, 0x20, 0x28, 0x20, 0x13, 0x48, 0x1d, 0x1f, 0x6e, 0x53, 0x75,
}

// bp256PP1D4BE = (P+1)/4 big-endian (sqrt exponent; valid because P ≡ 3 mod 4).
var bp256PP1D4BE = []byte{
	0x2a, 0x7e, 0xd5, 0xf6, 0xe8, 0x7b, 0xaa, 0x6f, 0x0f, 0x99, 0x82, 0xa4, 0x27, 0x60, 0xe3, 0x5c,
	0x9b, 0x8e, 0xfd, 0x88, 0xf5, 0x49, 0x88, 0x0a, 0x08, 0x04, 0xd2, 0x07, 0x47, 0xdb, 0x94, 0xde,
}

func init() {
	bp256.SetOne(&bp256One)
	for _, entry := range []struct {
		dst *fe256
		src []byte
		tag string
	}{
		{&bp256AM, bp256ABE[:], "A"},
		{&bp256BM, bp256BBE[:], "B"},
		{&bp256B3M, bp256B3BE[:], "3B"},
		{&bp256GxM, bp256GxBE[:], "Gx"},
		{&bp256GyM, bp256GyBE[:], "Gy"},
	} {
		if !fe256FromBytesBE(entry.dst, entry.src) {
			panic("bpec: bp256 init: " + entry.tag + " not in [0, P)")
		}
	}
}

// fe256FromBytesBE sets z from big-endian bytes and returns true iff the
// input encodes a value in [0, p). Rejects out-of-range inputs in
// constant time w.r.t. the input value.
func fe256FromBytesBE(z *fe256, be []byte) bool {
	if len(be) != 32 {
		return false
	}
	if bytesGE32(be, bp256PBE[:]) {
		return false
	}
	var le [32]byte
	for i := 0; i < 32; i++ {
		le[i] = be[31-i]
	}
	var nm bp256.NonMontgomeryDomainFieldElement
	bp256.FromBytes((*[4]uint64)(&nm), &le)
	bp256.ToMontgomery(z, &nm)
	return true
}

// fe256ToBytesBE writes z as 32 big-endian bytes into be.
func fe256ToBytesBE(be []byte, z *fe256) {
	var nm bp256.NonMontgomeryDomainFieldElement
	bp256.FromMontgomery(&nm, z)
	var le [32]byte
	bp256.ToBytes(&le, (*[4]uint64)(&nm))
	for i := 0; i < 32; i++ {
		be[i] = le[31-i]
	}
}

// fe256IsZero returns 1 if z == 0 (mod p) else 0, in constant time.
func fe256IsZero(z *fe256) int {
	var r uint64
	bp256.Nonzero(&r, (*[4]uint64)(z))
	nz := (r | -r) >> 63
	return int(1 ^ nz)
}

// fe256Equal returns 1 iff a == b as field elements.
func fe256Equal(a, b *fe256) int {
	var d fe256
	bp256.Sub(&d, a, b)
	return fe256IsZero(&d)
}

// fe256ExpBE sets out = a^exp (mod p) using public exponent bits.
// Square-and-multiply over a public bit pattern is CT on a.
func fe256ExpBE(out, a *fe256, expBE []byte) {
	var r fe256 = bp256One
	for _, b := range expBE {
		for bit := 7; bit >= 0; bit-- {
			bp256.Square(&r, &r)
			if (b>>uint(bit))&1 == 1 {
				bp256.Mul(&r, &r, a)
			}
		}
	}
	*out = r
}

// fe256Inv sets out = a^(p-2) mod p via Fermat.
func fe256Inv(out, a *fe256) { fe256ExpBE(out, a, bp256PM2BE) }

// fe256Select sets out = b if cond == 1 and out = a if cond == 0.
// cond MUST be 0 or 1.
func fe256Select(out, a, b *fe256, cond uint64) {
	mask := -cond
	for i := 0; i < 4; i++ {
		out[i] = a[i] ^ (mask & (a[i] ^ b[i]))
	}
}

// bytesGE32 reports in constant time whether a >= b as big-endian
// unsigned integers. Both inputs are exactly 32 bytes.
func bytesGE32(a, b []byte) bool {
	// Compute a - b; no underflow iff a >= b.
	var borrow uint64
	for i := 31; i >= 0; i-- {
		d := uint64(a[i]) - uint64(b[i]) - borrow
		borrow = (d >> 63) & 1
	}
	return borrow == 0
}

// BP256Point is a point on brainpoolP256r1 in projective coordinates.
// The identity is represented by Z = 0.
//
// Zero value is not a valid point. Use NewBP256Point (identity) or
// NewBP256Generator before any other operation.
type BP256Point struct {
	x, y, z fe256
}

// NewBP256Point returns a new point set to the identity (point at
// infinity), encoded as (0 : 1 : 0).
func NewBP256Point() *BP256Point {
	var p BP256Point
	p.y = bp256One
	return &p
}

// NewBP256Generator returns a new point set to the RFC 5639 generator G.
func NewBP256Generator() *BP256Point {
	return &BP256Point{x: bp256GxM, y: bp256GyM, z: bp256One}
}

// Set copies q into p and returns p.
func (p *BP256Point) Set(q *BP256Point) *BP256Point {
	p.x, p.y, p.z = q.x, q.y, q.z
	return p
}

// SetIdentity sets p to the identity and returns p.
func (p *BP256Point) SetIdentity() *BP256Point {
	var z fe256
	p.x = z
	p.y = bp256One
	p.z = z
	return p
}

// SetGenerator sets p to G and returns p.
func (p *BP256Point) SetGenerator() *BP256Point {
	p.x = bp256GxM
	p.y = bp256GyM
	p.z = bp256One
	return p
}

// IsIdentity returns 1 iff p is the point at infinity.
func (p *BP256Point) IsIdentity() int { return fe256IsZero(&p.z) }

// Bytes returns the SEC1 uncompressed encoding of p: 0x04 || X || Y.
// If p is the identity the result is 0x04 followed by 64 zero bytes,
// matching the semantics of crypto/internal/fips140/nistec. Callers
// that need a distinct encoding for the identity (single 0x00 byte)
// should check IsIdentity() first.
func (p *BP256Point) Bytes() []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	var x, y fe256
	if fe256IsZero(&p.z) == 0 {
		var zInv fe256
		fe256Inv(&zInv, &p.z)
		bp256.Mul(&x, &p.x, &zInv)
		bp256.Mul(&y, &p.y, &zInv)
	}
	fe256ToBytesBE(out[1:33], &x)
	fe256ToBytesBE(out[33:65], &y)
	return out
}

// BytesX returns the affine X coordinate of p as 32 big-endian bytes.
// Returns an error if p is the identity. The arithmetic stays inside
// the Montgomery limb representation — X never transits math/big.
func (p *BP256Point) BytesX() ([]byte, error) {
	if fe256IsZero(&p.z) == 1 {
		return nil, errors.New("bpec: BytesX of identity")
	}
	var zInv, x fe256
	fe256Inv(&zInv, &p.z)
	bp256.Mul(&x, &p.x, &zInv)
	out := make([]byte, 32)
	fe256ToBytesBE(out, &x)
	return out, nil
}

// BytesCompressed returns the SEC1 compressed encoding of p:
// 0x02 || X when the affine Y is even, 0x03 || X when odd. For the
// identity the result is 0x02 followed by 32 zero bytes.
func (p *BP256Point) BytesCompressed() []byte {
	out := make([]byte, 33)
	var x, y fe256
	if fe256IsZero(&p.z) == 0 {
		var zInv fe256
		fe256Inv(&zInv, &p.z)
		bp256.Mul(&x, &p.x, &zInv)
		bp256.Mul(&y, &p.y, &zInv)
	}
	var yBE [32]byte
	fe256ToBytesBE(yBE[:], &y)
	out[0] = 0x02 | (yBE[31] & 1)
	fe256ToBytesBE(out[1:33], &x)
	return out
}

// SetBytes decodes a SEC1 point encoding into p:
//   - a single 0x00 byte is the identity
//   - 0x04 || X || Y is uncompressed
//   - 0x02 || X or 0x03 || X is compressed
//
// Rejects encodings whose point does not lie on the curve. Returns p
// on success.
func (p *BP256Point) SetBytes(in []byte) (*BP256Point, error) {
	switch {
	case len(in) == 1 && in[0] == 0x00:
		return p.SetIdentity(), nil
	case len(in) == 65 && in[0] == 0x04:
		var xf, yf fe256
		if !fe256FromBytesBE(&xf, in[1:33]) {
			return nil, errors.New("bpec: x out of range")
		}
		if !fe256FromBytesBE(&yf, in[33:65]) {
			return nil, errors.New("bpec: y out of range")
		}
		if !bp256OnCurve(&xf, &yf) {
			return nil, errors.New("bpec: point not on curve")
		}
		p.x, p.y, p.z = xf, yf, bp256One
		return p, nil
	case len(in) == 33 && (in[0] == 0x02 || in[0] == 0x03):
		var xf fe256
		if !fe256FromBytesBE(&xf, in[1:33]) {
			return nil, errors.New("bpec: x out of range")
		}
		// alpha = x^3 + a*x + b  (Montgomery)
		var alpha, t fe256
		bp256.Square(&alpha, &xf)
		bp256.Mul(&alpha, &alpha, &xf)
		bp256.Mul(&t, &bp256AM, &xf)
		bp256.Add(&alpha, &alpha, &t)
		bp256.Add(&alpha, &alpha, &bp256BM)

		// y candidate = alpha^((p+1)/4)
		var y, y2 fe256
		fe256ExpBE(&y, &alpha, bp256PP1D4BE)
		bp256.Square(&y2, &y)
		if fe256Equal(&y2, &alpha) == 0 {
			return nil, errors.New("bpec: x has no square root")
		}
		// Fix parity.
		var yBE [32]byte
		fe256ToBytesBE(yBE[:], &y)
		wantOdd := in[0] == 0x03
		isOdd := (yBE[31] & 1) == 1
		if wantOdd != isOdd {
			bp256.Opp(&y, &y)
		}
		p.x, p.y, p.z = xf, y, bp256One
		return p, nil
	default:
		return nil, errors.New("bpec: invalid point encoding")
	}
}

// bp256OnCurve returns true iff (x, y) satisfies y² = x³ + a·x + b in
// the Montgomery domain.
func bp256OnCurve(x, y *fe256) bool {
	var lhs, rhs, t fe256
	bp256.Square(&lhs, y)
	bp256.Square(&rhs, x)
	bp256.Mul(&rhs, &rhs, x)
	bp256.Mul(&t, &bp256AM, x)
	bp256.Add(&rhs, &rhs, &t)
	bp256.Add(&rhs, &rhs, &bp256BM)
	return fe256Equal(&lhs, &rhs) == 1
}

// Add sets p = p1 + p2 and returns p. Uses the Renes-Costello-Batina
// 2015 complete projective addition formula (Algorithm 1, general a).
// Branch-free, valid for all inputs including p1 == p2 and the identity.
func (p *BP256Point) Add(p1, p2 *BP256Point) *BP256Point {
	var t0, t1, t2, t3, t4, t5, X3, Y3, Z3, tmp fe256
	a := &bp256AM
	b3 := &bp256B3M
	M := bp256.Mul
	A := bp256.Add
	S := bp256.Sub

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
func (p *BP256Point) Double(q *BP256Point) *BP256Point {
	var t0, t1, t2, t3, X3, Y3, Z3 fe256
	a := &bp256AM
	b3 := &bp256B3M
	M := bp256.Mul
	Sq := bp256.Square
	A := bp256.Add
	S := bp256.Sub

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

// Negate sets p = -q and returns p.
func (p *BP256Point) Negate(q *BP256Point) *BP256Point {
	p.x = q.x
	bp256.Opp(&p.y, &q.y)
	p.z = q.z
	return p
}

// Select sets p to a if cond == 0 and to b if cond == 1, in constant
// time w.r.t. cond. cond MUST be 0 or 1.
func (p *BP256Point) Select(a, b *BP256Point, cond int) *BP256Point {
	c := uint64(cond & 1)
	fe256Select(&p.x, &a.x, &b.x, c)
	fe256Select(&p.y, &a.y, &b.y, c)
	fe256Select(&p.z, &a.z, &b.z, c)
	return p
}

// ctLookupBP256 sets out to table[idx] in constant time w.r.t. idx. All
// table entries are read on every call. Table length must be <= 256.
func ctLookupBP256(out *BP256Point, table []BP256Point, idx uint8) {
	var rx, ry, rz fe256
	for i := range table {
		diff := uint32(uint8(i)) ^ uint32(idx)
		diff = (diff | (0 - diff)) >> 31 // 0 iff equal
		mask := uint64(diff) - 1         // all-ones iff equal
		for j := 0; j < 4; j++ {
			rx[j] |= table[i].x[j] & mask
			ry[j] |= table[i].y[j] & mask
			rz[j] |= table[i].z[j] & mask
		}
	}
	out.x, out.y, out.z = rx, ry, rz
}

// ScalarMult sets p = scalar · q and returns p. scalar is a big-endian
// unsigned integer at most 32 bytes long; longer inputs are rejected.
// The schedule runs a fixed 4-bit window over exactly 64 nibbles: its
// timing and memory access depend only on the curve.
func (p *BP256Point) ScalarMult(q *BP256Point, scalar []byte) (*BP256Point, error) {
	var k [32]byte
	if err := scalarReduce256(&k, scalar); err != nil {
		return nil, err
	}
	// Precompute table T[i] = i·q, 0 ≤ i < 16.
	var table [16]BP256Point
	table[0].SetIdentity()
	table[1].Set(q)
	for i := 2; i < 16; i++ {
		table[i].Add(&table[i-1], q)
	}
	result := NewBP256Point()
	var sel BP256Point
	for w := 63; w >= 0; w-- {
		result.Double(result)
		result.Double(result)
		result.Double(result)
		result.Double(result)
		byteIdx := 31 - w/2
		shift := uint(w&1) * 4
		win := (k[byteIdx] >> shift) & 0x0F
		ctLookupBP256(&sel, table[:], win)
		result.Add(result, &sel)
	}
	p.Set(result)
	return p, nil
}

// ScalarBaseMult sets p = scalar · G and returns p.
func (p *BP256Point) ScalarBaseMult(scalar []byte) (*BP256Point, error) {
	G := NewBP256Generator()
	return p.ScalarMult(G, scalar)
}
