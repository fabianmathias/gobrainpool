package bpec

import (
	"errors"

	"github.com/fabianmathias/gobrainpool/internal/fiat/bp512n"
)

type scalar512 = bp512n.MontgomeryDomainFieldElement

var sc512One scalar512

var bp512NBE = [64]byte{
	0xaa, 0xdd, 0x9d, 0xb8, 0xdb, 0xe9, 0xc4, 0x8b, 0x3f, 0xd4, 0xe6, 0xae, 0x33, 0xc9, 0xfc, 0x07,
	0xcb, 0x30, 0x8d, 0xb3, 0xb3, 0xc9, 0xd2, 0x0e, 0xd6, 0x63, 0x9c, 0xca, 0x70, 0x33, 0x08, 0x70,
	0x55, 0x3e, 0x5c, 0x41, 0x4c, 0xa9, 0x26, 0x19, 0x41, 0x86, 0x61, 0x19, 0x7f, 0xac, 0x10, 0x47,
	0x1d, 0xb1, 0xd3, 0x81, 0x08, 0x5d, 0xda, 0xdd, 0xb5, 0x87, 0x96, 0x82, 0x9c, 0xa9, 0x00, 0x69,
}

var bp512NM2BE = []byte{
	0xaa, 0xdd, 0x9d, 0xb8, 0xdb, 0xe9, 0xc4, 0x8b, 0x3f, 0xd4, 0xe6, 0xae, 0x33, 0xc9, 0xfc, 0x07,
	0xcb, 0x30, 0x8d, 0xb3, 0xb3, 0xc9, 0xd2, 0x0e, 0xd6, 0x63, 0x9c, 0xca, 0x70, 0x33, 0x08, 0x70,
	0x55, 0x3e, 0x5c, 0x41, 0x4c, 0xa9, 0x26, 0x19, 0x41, 0x86, 0x61, 0x19, 0x7f, 0xac, 0x10, 0x47,
	0x1d, 0xb1, 0xd3, 0x81, 0x08, 0x5d, 0xda, 0xdd, 0xb5, 0x87, 0x96, 0x82, 0x9c, 0xa9, 0x00, 0x67,
}

func init() {
	bp512n.SetOne(&sc512One)
}

func scalarReduce512(out *[64]byte, scalar []byte) error {
	if len(scalar) > 64 {
		return errors.New("bpec: scalar longer than 64 bytes")
	}
	var s [64]byte
	copy(s[64-len(scalar):], scalar)
	var tmp [64]byte
	var borrow uint64
	for i := 63; i >= 0; i-- {
		d := uint64(s[i]) - uint64(bp512NBE[i]) - borrow
		tmp[i] = byte(d)
		borrow = (d >> 63) & 1
	}
	mask := byte(0) - byte(1-borrow)
	for i := 0; i < 64; i++ {
		out[i] = s[i] ^ (mask & (s[i] ^ tmp[i]))
	}
	return nil
}

// NScalar512 is a scalar modulo the brainpoolP512r1 group order N.
type NScalar512 struct {
	v scalar512
}

func (s *NScalar512) SetBytes(b []byte) (*NScalar512, error) {
	var r [64]byte
	if err := scalarReduce512(&r, b); err != nil {
		return nil, err
	}
	var le [64]byte
	for i := 0; i < 64; i++ {
		le[i] = r[63-i]
	}
	var nm bp512n.NonMontgomeryDomainFieldElement
	bp512n.FromBytes((*[8]uint64)(&nm), &le)
	bp512n.ToMontgomery(&s.v, &nm)
	return s, nil
}

func (s *NScalar512) Bytes() []byte {
	var nm bp512n.NonMontgomeryDomainFieldElement
	bp512n.FromMontgomery(&nm, &s.v)
	var le [64]byte
	bp512n.ToBytes(&le, (*[8]uint64)(&nm))
	out := make([]byte, 64)
	for i := 0; i < 64; i++ {
		out[i] = le[63-i]
	}
	return out
}

func (s *NScalar512) Add(a, b *NScalar512) *NScalar512 {
	bp512n.Add(&s.v, &a.v, &b.v)
	return s
}

func (s *NScalar512) Mul(a, b *NScalar512) *NScalar512 {
	bp512n.Mul(&s.v, &a.v, &b.v)
	return s
}

func (s *NScalar512) Invert(a *NScalar512) *NScalar512 {
	var r scalar512 = sc512One
	for _, b := range bp512NM2BE {
		for bit := 7; bit >= 0; bit-- {
			bp512n.Square(&r, &r)
			if (b>>uint(bit))&1 == 1 {
				bp512n.Mul(&r, &r, &a.v)
			}
		}
	}
	s.v = r
	return s
}

func (s *NScalar512) IsZero() int {
	var r uint64
	bp512n.Nonzero(&r, (*[8]uint64)(&s.v))
	nz := (r | -r) >> 63
	return int(1 ^ nz)
}
