package gobrainpool

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

// selfTestPassed records whether the most recent CAST run succeeded.
// Set to true on the initial successful sync.OnceFunc run; flipped by
// RunSelfTests on subsequent invocations.
var selfTestPassed atomic.Bool

var selfTestOnce = sync.OnceFunc(func() {
	if err := selfTest(); err != nil {
		panic("gobrainpool: CAST failure: " + err.Error())
	}
	selfTestPassed.Store(true)
})

// ensureSelfTestsPassed runs the pre-operational CAST exactly once per
// process and panics on failure. Subsequent calls are zero-cost reads
// of the cached result. If a later RunSelfTests call has flipped the
// flag back to false (re-test failed), service entries panic so that no
// crypto is performed under a known-bad self-test result.
func ensureSelfTestsPassed() {
	selfTestOnce()
	if !selfTestPassed.Load() {
		panic("gobrainpool: CAST in failed state")
	}
}

// RunSelfTests re-runs the full CAST suite on demand and reports the
// first failure encountered. On success the package's "self-tests
// passed" flag is set; on failure it is cleared and any subsequent
// service call panics until a successful re-run flips the flag back.
//
// Required by FIPS 140-3 IG 10.3.A and AIS 20/31, which mandate that
// self-tests be re-runnable on operator demand. Safe to call
// concurrently with other crypto operations; on-going operations
// complete under whatever state was in effect at their entry.
func RunSelfTests() error {
	if err := selfTest(); err != nil {
		selfTestPassed.Store(false)
		return err
	}
	selfTestPassed.Store(true)
	return nil
}

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

// ECDH CAST vectors are taken verbatim from RFC 7027 §2 (the
// authoritative test-vector source for Brainpool curves), so the
// pre-operational self-test exercises the ECDH primitive against an
// independent reference rather than internal-consistency-only.
//
//   - bp256r1: RFC 7027 §2.1
//   - bp384r1: RFC 7027 §2.2
//   - bp512r1: RFC 7027 §2.3
//
// privA / pubB / expectedZ are the inputs and expected output of one
// half of the RFC's symmetric exchange (dA · QB → xZ).
var lookupECDHVector = func(c *Curve) ecdhCASTVector {
	switch c {
	case bp256r1:
		return ecdhCASTVector{
			curve:     c,
			privA:     hexMust("81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D"),
			privB:     hexMust("55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3"),
			pubB:      hexMust("048D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A"),
			expectedZ: hexMust("89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B"),
		}
	case bp384r1:
		return ecdhCASTVector{
			curve:     c,
			privA:     hexMust("1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042"),
			privB:     hexMust("032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670"),
			pubB:      hexMust("044D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB462D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48"),
			expectedZ: hexMust("0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42"),
		}
	case bp512r1:
		return ecdhCASTVector{
			curve:     c,
			privA:     hexMust("16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422"),
			privB:     hexMust("230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CFABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429"),
			pubB:      hexMust("049D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCBAAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA"),
			expectedZ: hexMust("A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F"),
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

	// Two sign/verify roundtrips are exercised so that both signing
	// service paths the package exposes are covered:
	//
	//   - hedge == nil → pure RFC 6979 deterministic path
	//   - hedge != nil → hedged (draft-irtf-cfrg-det-sigs-with-noise)
	//
	// AIS 20/31 expects PCT to cover every service path that may be
	// reached via the public API; FIPS 140-3 IG D.G permits one path
	// but exercising both is strictly stronger. The fixed Z block keeps
	// the test deterministic while still flowing through the hedged
	// DRBG construction.
	hedgeBlock := bytes.Repeat([]byte{0x5A}, c.byteSize)
	for _, hedge := range [][]byte{nil, hedgeBlock} {
		var rBytes, sBytes []byte
		var err error
		switch c {
		case bp256r1:
			rBytes, sBytes, err = sign256(priv, digest, hedge)
		case bp384r1:
			rBytes, sBytes, err = sign384(priv, digest, hedge)
		case bp512r1:
			rBytes, sBytes, err = sign512(priv, digest, hedge)
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
	}
	return nil
}
