package bpec

import (
	"errors"

	"github.com/fabianmathias/gobrainpool/internal/fiat/bp384n"
)

type scalar384 = bp384n.MontgomeryDomainFieldElement

var sc384One scalar384

var bp384NBE = [48]byte{
	0x8c, 0xb9, 0x1e, 0x82, 0xa3, 0x38, 0x6d, 0x28, 0x0f, 0x5d, 0x6f, 0x7e, 0x50, 0xe6, 0x41, 0xdf,
	0x15, 0x2f, 0x71, 0x09, 0xed, 0x54, 0x56, 0xb3, 0x1f, 0x16, 0x6e, 0x6c, 0xac, 0x04, 0x25, 0xa7,
	0xcf, 0x3a, 0xb6, 0xaf, 0x6b, 0x7f, 0xc3, 0x10, 0x3b, 0x88, 0x32, 0x02, 0xe9, 0x04, 0x65, 0x65,
}

var bp384NM2BE = []byte{
	0x8c, 0xb9, 0x1e, 0x82, 0xa3, 0x38, 0x6d, 0x28, 0x0f, 0x5d, 0x6f, 0x7e, 0x50, 0xe6, 0x41, 0xdf,
	0x15, 0x2f, 0x71, 0x09, 0xed, 0x54, 0x56, 0xb3, 0x1f, 0x16, 0x6e, 0x6c, 0xac, 0x04, 0x25, 0xa7,
	0xcf, 0x3a, 0xb6, 0xaf, 0x6b, 0x7f, 0xc3, 0x10, 0x3b, 0x88, 0x32, 0x02, 0xe9, 0x04, 0x65, 0x63,
}

func init() {
	bp384n.SetOne(&sc384One)
}

func scalarReduce384(out *[48]byte, scalar []byte) error {
	if len(scalar) > 48 {
		return errors.New("bpec: scalar longer than 48 bytes")
	}
	var s [48]byte
	copy(s[48-len(scalar):], scalar)
	var tmp [48]byte
	var borrow uint64
	for i := 47; i >= 0; i-- {
		d := uint64(s[i]) - uint64(bp384NBE[i]) - borrow
		tmp[i] = byte(d)
		borrow = (d >> 63) & 1
	}
	mask := byte(0) - byte(1-borrow)
	for i := 0; i < 48; i++ {
		out[i] = s[i] ^ (mask & (s[i] ^ tmp[i]))
	}
	return nil
}

// NScalar384 is a scalar modulo the brainpoolP384r1 group order N.
type NScalar384 struct {
	v scalar384
}

func (s *NScalar384) SetBytes(b []byte) (*NScalar384, error) {
	var r [48]byte
	if err := scalarReduce384(&r, b); err != nil {
		return nil, err
	}
	var le [48]byte
	for i := 0; i < 48; i++ {
		le[i] = r[47-i]
	}
	var nm bp384n.NonMontgomeryDomainFieldElement
	bp384n.FromBytes((*[6]uint64)(&nm), &le)
	bp384n.ToMontgomery(&s.v, &nm)
	return s, nil
}

func (s *NScalar384) Bytes() []byte {
	var nm bp384n.NonMontgomeryDomainFieldElement
	bp384n.FromMontgomery(&nm, &s.v)
	var le [48]byte
	bp384n.ToBytes(&le, (*[6]uint64)(&nm))
	out := make([]byte, 48)
	for i := 0; i < 48; i++ {
		out[i] = le[47-i]
	}
	return out
}

func (s *NScalar384) Add(a, b *NScalar384) *NScalar384 {
	bp384n.Add(&s.v, &a.v, &b.v)
	return s
}

func (s *NScalar384) Mul(a, b *NScalar384) *NScalar384 {
	bp384n.Mul(&s.v, &a.v, &b.v)
	return s
}

func (s *NScalar384) Invert(a *NScalar384) *NScalar384 {
	var r scalar384 = sc384One
	for _, b := range bp384NM2BE {
		for bit := 7; bit >= 0; bit-- {
			bp384n.Square(&r, &r)
			if (b>>uint(bit))&1 == 1 {
				bp384n.Mul(&r, &r, &a.v)
			}
		}
	}
	s.v = r
	return s
}

func (s *NScalar384) IsZero() int {
	var r uint64
	bp384n.Nonzero(&r, (*[6]uint64)(&s.v))
	nz := (r | -r) >> 63
	return int(1 ^ nz)
}
