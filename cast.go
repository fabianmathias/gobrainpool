package gobrainpool

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Cryptographic Algorithm Self-Test (CAST) / pre-operational self-tests.
//
// Runs each cryptographic algorithm the package exposes against a
// frozen known-answer vector on first use; on mismatch, disable the
// package. In Go that translates to: run once at first-use via
// sync.OnceFunc and panic on mismatch, because there is no error-
// return slot on every exported entry point and a silent downgrade
// would defeat the purpose.
//
// The vectors below were produced by running SignDeterministicASN1 /
// ECDH on fixed inputs during development and freezing the output.
// They therefore validate the full ECDSA signing pipeline (RFC 6979
// DRBG, scalar arithmetic, r/s derivation, ASN.1 encoding), the verify
// path (point addition, scalar-mult on arbitrary points), and the ECDH
// path (scalar-mult, Z⁻¹, byte encoding) on each of the three curves.
//
// ensureSelfTestsPassed is called at the top of every exported service
// entry: SignASN1, SignDeterministicASN1, VerifyASN1, GenerateKey,
// NewPrivateKey, NewPublicKey, ECDH. A call that reaches the
// service-indicator recording has by construction passed the CAST.

var selfTestOnce = sync.OnceFunc(func() {
	if err := selfTest(); err != nil {
		panic("gobrainpool: CAST failure: " + err.Error())
	}
})

func ensureSelfTestsPassed() { selfTestOnce() }

// selfTest runs the full set of KATs and returns the first failure
// encountered, nil on success. Exported inside the package so tests
// can exercise the failure path independently of the OnceFunc.
func selfTest() error {
	for _, c := range []*Curve{bp256r1, bp384r1, bp512r1} {
		if err := castECDSA(c); err != nil {
			return fmt.Errorf("ECDSA %s: %w", c.name, err)
		}
		if err := castECDH(c); err != nil {
			return fmt.Errorf("ECDH %s: %w", c.name, err)
		}
	}
	return nil
}

// ecdsaCASTVector fully specifies a known-answer test for one curve.
// `privBytes` is the raw scalar (byteSize bytes), `digest` the message
// digest, `expectedSig` the ASN.1-DER signature produced by
// SignDeterministicASN1 on those inputs.
type ecdsaCASTVector struct {
	curve       *Curve
	privBytes   []byte
	digest      []byte
	expectedSig []byte
	pubBytes    []byte
}

type ecdhCASTVector struct {
	curve     *Curve
	privA     []byte
	privB     []byte
	pubB      []byte
	expectedZ []byte
}

func castECDSA(c *Curve) error {
	v := lookupECDSAVector(c)

	// Bypass NewPrivateKey so this path doesn't re-enter
	// ensureSelfTestsPassed (which would deadlock on sync.OnceFunc's
	// "in progress" state from the first caller).
	priv, err := newPrivateKeyFromScalar(c, bytes.Clone(v.privBytes))
	if err != nil {
		return fmt.Errorf("newPrivateKeyFromScalar: %w", err)
	}
	if !bytes.Equal(priv.publicKey.publicKey, v.pubBytes) {
		return fmt.Errorf("derived pubkey mismatch:\n got:  %x\n want: %x",
			priv.publicKey.publicKey, v.pubBytes)
	}

	var rBytes, sBytes []byte
	switch c {
	case bp256r1:
		rBytes, sBytes, err = sign256(priv, v.digest, nil)
	case bp384r1:
		rBytes, sBytes, err = sign384(priv, v.digest, nil)
	case bp512r1:
		rBytes, sBytes, err = sign512(priv, v.digest, nil)
	default:
		return errors.New("unknown curve")
	}
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	sig, err := encodeECDSASignature(rBytes, sBytes)
	if err != nil {
		return fmt.Errorf("encodeECDSASignature: %w", err)
	}
	if !bytes.Equal(sig, v.expectedSig) {
		return fmt.Errorf("signature mismatch:\n got:  %x\n want: %x", sig, v.expectedSig)
	}

	pub := &PublicKey{curve: c, publicKey: v.pubBytes}
	var ok bool
	switch c {
	case bp256r1:
		ok = verify256(pub, v.digest, rBytes, sBytes)
	case bp384r1:
		ok = verify384(pub, v.digest, rBytes, sBytes)
	case bp512r1:
		ok = verify512(pub, v.digest, rBytes, sBytes)
	}
	if !ok {
		return errors.New("verify rejected self-test signature")
	}
	return nil
}

func castECDH(c *Curve) error {
	v := lookupECDHVector(c)

	z, err := ecdhShared(c, v.privA, v.pubB)
	if err != nil {
		return fmt.Errorf("ecdhShared: %w", err)
	}
	if !bytes.Equal(z, v.expectedZ) {
		return fmt.Errorf("shared-secret mismatch:\n got:  %x\n want: %x", z, v.expectedZ)
	}
	return nil
}

// lookupECDSAVector / lookupECDHVector read the frozen KAT vectors.
// Kept as function variables (not plain func decls) so that tests in
// cast_test.go can substitute corrupted vectors to exercise the
// failure paths — the only way to verify the CAST itself isn't a
// silent no-op.
var lookupECDSAVector = func(c *Curve) ecdsaCASTVector {
	switch c {
	case bp256r1:
		return ecdsaCASTVector{
			curve:       c,
			privBytes:   hexMust("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
			digest:      hexMust("8eacdc4fe112712b4ad5756e13efa152c93fc7334f31c50c4fc2c37db846c79b"),
			expectedSig: hexMust("30450220328a37c2d8f6db538a081943c4fb01bf7918d1b6fb1cac2dc166d1684cd459c2022100997f5dc8cb5e80d547d6bab7e85a48f498a91fe3a9987692bf5b0f8056bad7fc"),
			pubBytes:    hexMust("044e366cf3c8a982e423831d6715e722acf03cab8452e3c64d1e3b038caf87fc48387a044328d34ce4eb16c6c885b8b82be2584c18b28fc38143cbbf2b9b3520f9"),
		}
	case bp384r1:
		return ecdsaCASTVector{
			curve:       c,
			privBytes:   hexMust("0102030405060708090A0B0C0D0E0F1011121314151617180102030405060708090A0B0C0D0E0F101112131415161718"),
			digest:      hexMust("d8980c7f65a2e1cb76bb5c49d74fa40ba9c637401e1e34c89bfe36f0f8cf29355e1a1fd4574d25920bf30fd08ecf7d60"),
			expectedSig: hexMust("306402306645581e535c607e8cd6003fe3d578f3ce03f2f01ebb755e8fae5fa9215c2d5ff0ee7aa8ce7ffcbe7889b98ece1b96ab023079a32b6bfc932c2c18a130d895109da1f9b4451581271260e2c92415ef8580d37e4fb9f8b59e3235cc73c698258e589a"),
			pubBytes:    hexMust("042fc6c117c48e81695f2d3906610e51098e6a855548110fdaf6b9406f953a48bbf42e08f881b6458dc609d7e4d1dfffe431eddd04b479f7077ac9b497e746083d3f3e46dfc33592c5f599c583a72018ed97415993e828cee7155114b2190ccfbc"),
		}
	case bp512r1:
		return ecdsaCASTVector{
			curve:       c,
			privBytes:   hexMust("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F200102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
			digest:      hexMust("b42098d65b5a094751e9db46d64bac0b145fe110084d6779954a856debf332555b9b4e57930b879c1265f6f52629f7b22b0629341b14f72894ceacce222ba919"),
			expectedSig: hexMust("30818502402041bed7f768979aca2066bc049f0203b46ff93dbd8e18bb53cfb56b9747ca8ff44d1fab39f72ad13258f2a57ee485c6282dae05a08bf25d6db6b2cc0b1c5ef40241008f4b272d05c6f988de2fd54b40396a419e56aec08daf627de5f1263d44e1a9315c54c4a0af4891e69d45f39d04160d9dfcb35d8b2004935630abe1ee502a18a4"),
			pubBytes:    hexMust("046e9a2a6dd3600a0e2918b428897c2157dc61996775f1721b36c741963657cd92b5939884afef32e85529780f212c533a92e07136bf7adad46c7636e93f2dfceaa247c81994192907b3c28985b209c2a866230a2c27121e683b112ff3ac727d4b2dd28b72f35eeef8dd057619d874e4de9302022253341c7ce217e3d5210b2daa"),
		}
	}
	panic("gobrainpool: unknown curve in CAST")
}

var lookupECDHVector = func(c *Curve) ecdhCASTVector {
	switch c {
	case bp256r1:
		return ecdhCASTVector{
			curve:     c,
			privA:     hexMust("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
			privB:     hexMust("0102030405060708090a0b0c0d0e0f1011121314151617180102030405060708"),
			pubB:      hexMust("04368a3f13e6992ece751e520a1e76e30f3f978886b11b6aff75e726f555f642297f28991770a4c90fa51e17939556d6db54371c8da92efdf5b5838abe549424ac"),
			expectedZ: hexMust("13a024d7f0ff99906220052e0bb94e332a9b50a40fe1dcff6ab4e7769a6a629b"),
		}
	case bp384r1:
		return ecdhCASTVector{
			curve:     c,
			privA:     hexMust("0102030405060708090a0b0c0d0e0f1011121314151617180102030405060708090a0b0c0d0e0f101112131415161718"),
			privB:     hexMust("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f10"),
			pubB:      hexMust("0451dd6c1534da680af53ab4fc9d2a728ca4a42c30708df7ed38114a9a010a1b56ecc4e9d246a95769651646411d65d2ab5029adab29fcf1300ed0be6eaf2a12192a3857afb1a4e46896dc1bcf742837626aec58b74c708ce9d4d86751961701a0"),
			expectedZ: hexMust("5028e3c3f943cb7ad41116f300135407c4b55b80ddb2659a58af0123076dd937f76aed391bc09fce75a266ae7489dbee"),
		}
	case bp512r1:
		return ecdhCASTVector{
			curve:     c,
			privA:     hexMust("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
			privB:     hexMust("0102030405060708090a0b0c0d0e0f1011121314151617180102030405060708090a0b0c0d0e0f1011121314151617180102030405060708090a0b0c0d0e0f10"),
			pubB:      hexMust("044b2a9b75215f7ae026cfdc6d68d62fb0eef7c9cca5dcc13159e41b8bf1a0664bab7091676e5a7192cfd0873f5ae171eb684be6cb616fcec535945ed1196c3be4518765b5b65ff1fd163385ade25a3e493d0895618492c2be17eadc777460232b03b923faececbdd1d6a4484542f9e49c42956bbc35cb10fba779cdd3f5f84bf2"),
			expectedZ: hexMust("3ba57d96d37db81f2e15b94a21242b7836f459335a604d14f25a043f76be42a9e7049a26d13bc1af25a0cb6255b250a8fdce9d7fc219783a7c41149900c7c9ef"),
		}
	}
	panic("gobrainpool: unknown curve in CAST")
}

func hexMust(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("gobrainpool: CAST vector decode: " + err.Error())
	}
	return b
}

// pairwiseConsistencyCheck runs a Pairwise Consistency Test on a
// freshly constructed keypair:
// sign a known digest with priv.d and require the resulting signature
// to verify against priv.publicKey. Any mismatch means (d, Q) are
// internally inconsistent — hardware fault, memory corruption, or a
// bug in the scalar-mult used to derive Q — and the keypair must be
// rejected before it ever leaves the module.
//
// Runs on every path that constructs a PrivateKey (GenerateKey and
// NewPrivateKey, both via newPrivateKeyFromScalar). Uses the
// package-internal sign/verify primitives directly to avoid re-
// entering the service-indicator wrapper; a PCT is module-internal
// plumbing, not a service the caller invoked.
//
// Mirrors stdlib fipsPCT in crypto/internal/fips140/ecdsa/cast.go.
func pairwiseConsistencyCheck(priv *PrivateKey) error {
	c := priv.curve
	// Fixed, non-zero digest of curve-matching length — enough to
	// drive bits2int + the full sign/verify arithmetic including a
	// non-trivial e value.
	digest := bytes.Repeat([]byte{0xA5}, c.byteSize)

	var rBytes, sBytes []byte
	var err error
	switch c {
	case bp256r1:
		rBytes, sBytes, err = sign256(priv, digest, nil)
	case bp384r1:
		rBytes, sBytes, err = sign384(priv, digest, nil)
	case bp512r1:
		rBytes, sBytes, err = sign512(priv, digest, nil)
	default:
		return errors.New("unknown curve")
	}
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	var ok bool
	switch c {
	case bp256r1:
		ok = verify256(priv.publicKey, digest, rBytes, sBytes)
	case bp384r1:
		ok = verify384(priv.publicKey, digest, rBytes, sBytes)
	case bp512r1:
		ok = verify512(priv.publicKey, digest, rBytes, sBytes)
	}
	if !ok {
		return errors.New("verify rejected freshly-signed digest")
	}
	return nil
}
