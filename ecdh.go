package gobrainpool

import (
	"errors"

	"github.com/fabianmathias/gobrainpool/internal/bpec"
)

// ECDH performs elliptic-curve Diffie–Hellman and returns the
// x-coordinate of priv·peer as a big-endian byte slice whose length
// equals the curve's byte size. Both sides must use the same curve.
//
// The full arithmetic path (scalar multiplication, projective-to-affine
// via Z⁻¹, byte encoding) runs inside internal/bpec on fiat-generated
// fixed-width Montgomery limbs — constant time on the secret scalar
// priv.d and on the secret shared x. Callers that need a symmetric key
// should feed the returned bytes into a KDF (HKDF is typical); ECDH
// does not hash the output.
func (priv *PrivateKey) ECDH(peer *PublicKey) ([]byte, error) {
	ensureSelfTestsPassed()
	if priv == nil || peer == nil {
		return nil, errors.New("gobrainpool: ECDH requires both keys")
	}
	if priv.curve != peer.curve {
		return nil, errors.New("gobrainpool: ECDH curve mismatch")
	}
	return ecdhShared(priv.curve, priv.d, peer.publicKey)
}

// ecdhShared computes the ECDH shared-secret x-coordinate for a pre-
// validated (curve, scalar, peer-encoded-pubkey) triple. Shared by the
// exported ECDH method and the pre-operational CAST, so that the CAST
// can exercise this code path without re-entering the exported
// *PrivateKey.ECDH wrapper.
func ecdhShared(c *Curve, d, peerEnc []byte) ([]byte, error) {
	switch c {
	case bp256r1:
		Q := new(bpec.BP256Point)
		if _, err := Q.SetBytes(peerEnc); err != nil {
			return nil, err
		}
		if Q.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: peer public key is point at infinity")
		}
		shared := new(bpec.BP256Point)
		if _, err := shared.ScalarMult(Q, d); err != nil {
			return nil, err
		}
		return shared.BytesX()
	case bp384r1:
		Q := new(bpec.BP384Point)
		if _, err := Q.SetBytes(peerEnc); err != nil {
			return nil, err
		}
		if Q.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: peer public key is point at infinity")
		}
		shared := new(bpec.BP384Point)
		if _, err := shared.ScalarMult(Q, d); err != nil {
			return nil, err
		}
		return shared.BytesX()
	case bp512r1:
		Q := new(bpec.BP512Point)
		if _, err := Q.SetBytes(peerEnc); err != nil {
			return nil, err
		}
		if Q.IsIdentity() == 1 {
			return nil, errors.New("gobrainpool: peer public key is point at infinity")
		}
		shared := new(bpec.BP512Point)
		if _, err := shared.ScalarMult(Q, d); err != nil {
			return nil, err
		}
		return shared.BytesX()
	}
	return nil, errors.New("gobrainpool: unknown curve")
}
