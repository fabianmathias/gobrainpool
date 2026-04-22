package gobrainpool

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
)

// TestHMACDRBG_CAVS pins our HMAC-DRBG implementation against NIST
// CAVS 14.3 known-answer vectors from drbgvectors_no_reseed /
// HMAC_DRBG.rsp. These vectors are the authoritative reference for
// SP 800-90A conformance.
//
// CAVS protocol (Readme.txt in the CAVS archive):
//
//  1. Instantiate(EntropyInput, Nonce, PersonalizationString)
//  2. Generate(ReturnedBitsLen, AdditionalInput=empty)   ← result discarded
//  3. Generate(ReturnedBitsLen, AdditionalInput=empty)   ← ReturnedBits
//
// Our hmacDRBG.generate(n) implements SP 800-90A §10.1.2.5 Generate
// with additional_input = Null. The end-of-gen Update step is lazily
// executed at the top of the *next* generate() call — equivalent to
// eager application at the end of the current call for the
// Null-additional-input case, which is what CAVS exercises here.
//
// Failures here indicate either a bug in instantiation (K/V derivation
// from the seed material) or in the Generate loop. Either would
// invalidate the module's cryptographic claims.
func TestHMACDRBG_CAVS(t *testing.T) {
	for _, tc := range drbgCAVSVectors {
		t.Run(tc.name, func(t *testing.T) {
			entropy := mustHex(t, tc.entropyHex)
			nonce := mustHex(t, tc.nonceHex)
			pers := mustHex(t, tc.persHex)
			want := mustHex(t, tc.returnedBitsHex)

			g := newPlainHMACDRBG(tc.newHash, entropy, nonce, pers, 1, nil)
			// First generate — output discarded per CAVS protocol.
			_ = g.generate(len(want))
			// Second generate — compared to ReturnedBits.
			got := g.generate(len(want))
			if !bytesEqual(got, want) {
				t.Errorf("CAVS vector mismatch\n  got:  %x\n  want: %x", got, want)
			}
		})
	}
}

// TestHMACDRBG_CAVSRejectsTampered pins that the KAT comparison is
// strict: mutating any bit of the expected output must surface as a
// mismatch. Guards against a hypothetical bug where the test harness
// accepts any result — a self-test of the self-test.
func TestHMACDRBG_CAVSRejectsTampered(t *testing.T) {
	tc := drbgCAVSVectors[0]
	entropy := mustHex(t, tc.entropyHex)
	nonce := mustHex(t, tc.nonceHex)
	pers := mustHex(t, tc.persHex)
	want := mustHex(t, tc.returnedBitsHex)

	g := newPlainHMACDRBG(tc.newHash, entropy, nonce, pers, 1, nil)
	_ = g.generate(len(want))
	got := g.generate(len(want))
	// Flip the first byte of `want` and expect inequality.
	want[0] ^= 0x01
	if bytesEqual(got, want) {
		t.Error("bytesEqual accepted a tampered expected value; test harness is broken")
	}
}

type drbgCAVSVector struct {
	name            string
	newHash         func() hash.Hash
	entropyHex      string
	nonceHex        string
	persHex         string
	returnedBitsHex string
}

// drbgCAVSVectors: selected entries from CAVS 14.3 HMAC_DRBG.rsp
// (drbgvectors_no_reseed). Coverage:
//
//   - SHA-256, PersonalizationString = empty (COUNT 0, 1)
//   - SHA-256, PersonalizationString = 32 bytes (COUNT 0)
//   - SHA-384, PersonalizationString = empty (COUNT 0, 1)
//   - SHA-512, PersonalizationString = empty (COUNT 0, 1)
//
// All vectors have PredictionResistance = False, AdditionalInputLen =
// 0, and ReturnedBitsLen = 4*hlen bits (CAVS default for no-reseed).
var drbgCAVSVectors = []drbgCAVSVector{
	{
		name:            "SHA256/PSempty/C0",
		newHash:         sha256.New,
		entropyHex:      "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488",
		nonceHex:        "659ba96c601dc69fc902940805ec0ca8",
		persHex:         "",
		returnedBitsHex: "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
	},
	{
		name:            "SHA256/PSempty/C1",
		newHash:         sha256.New,
		entropyHex:      "79737479ba4e7642a221fcfd1b820b134e9e3540a35bb48ffae29c20f5418ea3",
		nonceHex:        "3593259c092bef4129bc2c6c9e19f343",
		persHex:         "",
		returnedBitsHex: "cf5ad5984f9e43917aa9087380dac46e410ddc8a7731859c84e9d0f31bd43655b924159413e2293b17610f211e09f770f172b8fb693a35b85d3b9e5e63b1dc252ac0e115002e9bedfb4b5b6fd43f33b8e0eafb2d072e1a6fee1f159df9b51e6c8da737e60d5032dd30544ec51558c6f080bdbdab1de8a939e961e06b5f1aca37",
	},
	{
		name:            "SHA256/PSfull/C0",
		newHash:         sha256.New,
		entropyHex:      "5cacc68165a2e2ee20812f35ec73a79dbf30fd475476ac0c44fc6174cdac2b55",
		nonceHex:        "6f885496c1e63af620becd9e71ecb824",
		persHex:         "e72dd8590d4ed5295515c35ed6199e9d211b8f069b3058caa6670b96ef1208d0",
		returnedBitsHex: "f1012cf543f94533df27fedfbf58e5b79a3dc517a9c402bdbfc9a0c0f721f9d53faf4aafdc4b8f7a1b580fcaa52338d4bd95f58966a243cdcd3f446ed4bc546d9f607b190dd69954450d16cd0e2d6437067d8b44d19a6af7a7cfa8794e5fbd728e8fb2f2e8db5dd4ff1aa275f35886098e80ff844886060da8b1e7137846b23b",
	},
	{
		name:            "SHA384/PSempty/C0",
		newHash:         sha512.New384,
		entropyHex:      "a1dc2dfeda4f3a1124e0e75ebfbe5f98cac11018221dda3fdcf8f9125d68447a",
		nonceHex:        "bae5ea27166540515268a493a96b5187",
		persHex:         "",
		returnedBitsHex: "228293e59b1e4545a4ff9f232616fc5108a1128debd0f7c20ace837ca105cbf24c0dac1f9847dafd0d0500721ffad3c684a992d110a549a264d14a8911c50be8cd6a7e8fac783ad95b24f64fd8cc4c8b649eac2b15b363e30df79541a6b8a1caac238949b46643694c85e1d5fcbcd9aaae6260acee660b8a79bea48e079ceb6a5eaf4993a82c3f1b758d7c53e3094eeac63dc255be6dcdcc2b51e5ca45d2b20684a5a8fa5806b96f8461ebf51bc515a7dd8c5475c0e70f2fd0faf7869a99ab6c",
	},
	{
		name:            "SHA384/PSempty/C1",
		newHash:         sha512.New384,
		entropyHex:      "067fa0e25d71ea392671c24f38ef782ab3587a7b3c77ea756f7bd496b445b7a3",
		nonceHex:        "ce6acc722768ca0e03784b2217bc60e4",
		persHex:         "",
		returnedBitsHex: "16eaa49510ffad8cc21ec32858640a0d6f34cb03e8649022aa5c3f566b44e8ace7c3b056cf2a44b242de09ae21dba4275418933611875841b4f0944a8272848c5dc1aad685935e12511d5ee27e9162d4bb968afab53c4b338269c1c77da9d78617911ed4390cb20e88bf30b74fda66fe05df5537a759061d3ffd9231d811e8b34213f22ab0b0ddafff7749a40243a901c310776e09d2e529806d4d6f0655178953c16707519c3c19b9aaa0d09fb676a9d23525c8bc388053bfccfbc368e3eb04",
	},
	{
		name:            "SHA512/PSempty/C0",
		newHash:         sha512.New,
		entropyHex:      "35049f389a33c0ecb1293238fd951f8ffd517dfde06041d32945b3e26914ba15",
		nonceHex:        "f7328760be6168e6aa9fb54784989a11",
		persHex:         "",
		returnedBitsHex: "e76491b0260aacfded01ad39fbf1a66a88284caa5123368a2ad9330ee48335e3c9c9ba90e6cbc9429962d60c1a6661edcfaa31d972b8264b9d4562cf18494128a092c17a8da6f3113e8a7edfcd4427082bd390675e9662408144971717303d8dc352c9e8b95e7f35fa2ac9f549b292bc7c4bc7f01ee0a577859ef6e82d79ef23892d167c140d22aac32b64ccdfeee2730528a38763b24227f91ac3ffe47fb11538e435307e77481802b0f613f370ffb0dbeab774fe1efbb1a80d01154a9459e73ad361108bbc86b0914f095136cbe634555ce0bb263618dc5c367291ce0825518987154fe9ecb052b3f0a256fcc30cc14572531c9628973639beda456f2bddf6",
	},
	{
		name:            "SHA512/PSempty/C1",
		newHash:         sha512.New,
		entropyHex:      "4cc8214cd7e85a76bfa735bbbfce926c0323fc348de6c05ed1800c2c8f58c6b1",
		nonceHex:        "001eb1f6b29b35242a3f8fa2e90003f4",
		persHex:         "",
		returnedBitsHex: "1efa15d644e1bdf34eade3ff2f5e9ca45203ccaa1e534ac9b4287a846b71292b03102286d99f2be64b898fe909238f540ebc25f49522f60ef723a4c428ead530a97c62405cd5d9ecc54ac5baa47ac4f6195d637833f462d21a659b4903d9cfa6c9fd4512445f9abb5782899a6bb64592f3c2b3c745b18645301fdb09a6a331e9fb6d9654fc79c14ed83ac1684c755b9cb209885f86ff290a71f08a848b960152f05b1aa8566bd382ddd45521062831d7a0fb3a8bd8e112a91b5960690cd8585c1aa104514e3b9cbf52f6384e84c27bda2802fe9fb952cbf2bd607f869d0aeaa6b136c6a5f6e9b0522b6019b7ba6af6cff99fda612e024867decd8c0c6fde2034",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
