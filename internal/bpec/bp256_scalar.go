package bpec

import (
	"errors"

	"github.com/fabianmathias/gobrainpool/internal/fiat/bp256n"
)

// Group order N of brainpoolP256r1 (RFC 5639 §3.4) and the Fermat
// inversion exponent N-2 are stored as fixed big-endian byte literals.
// No math/big is executed at init — same shape as
// crypto/internal/fips140/ecdsa. KAT tests in internal/bpec and the
// parent package RFC 7027 vectors fail loudly if a byte is wrong.

type scalar256 = bp256n.MontgomeryDomainFieldElement

var sc256One scalar256

var bp256NBE = [32]byte{
	0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, 0x71,
	0x8c, 0x39, 0x7a, 0xa3, 0xb5, 0x61, 0xa6, 0xf7, 0x90, 0x1e, 0x0e, 0x82, 0x97, 0x48, 0x56, 0xa7,
}

var bp256NM2BE = []byte{
	0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, 0x71,
	0x8c, 0x39, 0x7a, 0xa3, 0xb5, 0x61, 0xa6, 0xf7, 0x90, 0x1e, 0x0e, 0x82, 0x97, 0x48, 0x56, 0xa5,
}

func init() {
	bp256n.SetOne(&sc256One)
}

// scalarReduce256 normalises scalar to a 32-byte big-endian representation
// in [0, N). Inputs longer than 32 bytes are rejected.
//
// For 32-byte inputs the reduction is a single conditional subtract of N:
// that is sufficient because N > 2^255 for brainpoolP256r1, so any value
// representable in 32 bytes is strictly less than 2N. The subtract runs
// unconditionally; the result is blended in masked, so the reduction is
// constant-time w.r.t. the input value.
func scalarReduce256(out *[32]byte, scalar []byte) error {
	if len(scalar) > 32 {
		return errors.New("bpec: scalar longer than 32 bytes")
	}
	var s [32]byte
	copy(s[32-len(scalar):], scalar)
	var tmp [32]byte
	var borrow uint64
	for i := 31; i >= 0; i-- {
		d := uint64(s[i]) - uint64(bp256NBE[i]) - borrow
		tmp[i] = byte(d)
		borrow = (d >> 63) & 1
	}
	// borrow == 1 -> s < N (keep s). borrow == 0 -> s >= N (use tmp).
	// mask = 0xFF iff borrow == 0.
	mask := byte(0) - byte(1-borrow)
	for i := 0; i < 32; i++ {
		out[i] = s[i] ^ (mask & (s[i] ^ tmp[i]))
	}
	return nil
}

// NScalar256 is a scalar modulo the brainpoolP256r1 group order N, held
// in Montgomery form. The type is a thin wrapper over the fiat limbs so
// that scalar arithmetic does not leak through math/big.
type NScalar256 struct {
	v scalar256
}

// SetBytes sets s from a 32-byte big-endian encoding. Inputs are reduced
// mod N in constant time; it is the caller's responsibility to reject
// values outside the usable range (e.g. zero for ECDSA k).
func (s *NScalar256) SetBytes(b []byte) (*NScalar256, error) {
	var r [32]byte
	if err := scalarReduce256(&r, b); err != nil {
		return nil, err
	}
	var le [32]byte
	for i := 0; i < 32; i++ {
		le[i] = r[31-i]
	}
	var nm bp256n.NonMontgomeryDomainFieldElement
	bp256n.FromBytes((*[4]uint64)(&nm), &le)
	bp256n.ToMontgomery(&s.v, &nm)
	return s, nil
}

// Bytes returns the 32-byte big-endian encoding of s.
func (s *NScalar256) Bytes() []byte {
	var nm bp256n.NonMontgomeryDomainFieldElement
	bp256n.FromMontgomery(&nm, &s.v)
	var le [32]byte
	bp256n.ToBytes(&le, (*[4]uint64)(&nm))
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = le[31-i]
	}
	return out
}

// Add sets s = a + b (mod N) and returns s.
func (s *NScalar256) Add(a, b *NScalar256) *NScalar256 {
	bp256n.Add(&s.v, &a.v, &b.v)
	return s
}

// Mul sets s = a · b (mod N) and returns s.
func (s *NScalar256) Mul(a, b *NScalar256) *NScalar256 {
	bp256n.Mul(&s.v, &a.v, &b.v)
	return s
}

// Invert sets s = a^-1 (mod N) via Fermat (a^(N-2)). Constant-time on a.
func (s *NScalar256) Invert(a *NScalar256) *NScalar256 {
	var r scalar256 = sc256One
	for _, b := range bp256NM2BE {
		for bit := 7; bit >= 0; bit-- {
			bp256n.Square(&r, &r)
			if (b>>uint(bit))&1 == 1 {
				bp256n.Mul(&r, &r, &a.v)
			}
		}
	}
	s.v = r
	return s
}

// IsZero returns 1 if s == 0 (mod N) else 0.
func (s *NScalar256) IsZero() int {
	var r uint64
	bp256n.Nonzero(&r, (*[4]uint64)(&s.v))
	nz := (r | -r) >> 63
	return int(1 ^ nz)
}
