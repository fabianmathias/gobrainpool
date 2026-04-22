package gobrainpool

// TestWycheproofECDSA runs Project Wycheproof's ECDSA test vectors for
// brainpoolP{256,384,512}r1 against VerifyASN1. It is the closest
// equivalent to stdlib's TestVectors (which consumes NIST CAVS SigVer
// vectors) — external, adversarial signatures collected by Google's
// crypto audit team, designed to flush out classical ECDSA
// implementation bugs (see
// https://github.com/C2SP/wycheproof/blob/main/doc/ecdsa.md).
//
// The vectors live gzipped under testdata/wycheproof/ and are not
// modified from upstream. Each vector carries an expected result:
//   - "valid"      — VerifyASN1 must accept
//   - "invalid"    — VerifyASN1 must reject
//   - "acceptable" — either outcome is permissible (non-DER quirks),
//     so the result is recorded but does not fail the test.

import (
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"hash"
	"os"
	"path/filepath"
	"testing"
)

type wpGroup struct {
	PublicKey struct {
		Uncompressed string `json:"uncompressed"`
		Curve        string `json:"curve"`
	} `json:"publicKey"`
	SHA   string   `json:"sha"`
	Tests []wpTest `json:"tests"`
}

type wpTest struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
}

type wpFile struct {
	Algorithm     string    `json:"algorithm"`
	NumberOfTests int       `json:"numberOfTests"`
	TestGroups    []wpGroup `json:"testGroups"`
}

func TestWycheproofECDSA(t *testing.T) {
	cases := []struct {
		curve *Curve
		file  string
		hash  func() hash.Hash
	}{
		{BP256r1(), "ecdsa_brainpoolP256r1_sha256.json.gz", sha256.New},
		{BP384r1(), "ecdsa_brainpoolP384r1_sha384.json.gz", sha512.New384},
		{BP512r1(), "ecdsa_brainpoolP512r1_sha512.json.gz", sha512.New},
	}
	for _, tc := range cases {
		t.Run(tc.curve.name, func(t *testing.T) {
			runWycheproofFile(t, tc.curve, tc.file, tc.hash)
		})
	}
}

func runWycheproofFile(t *testing.T, c *Curve, fname string, newHash func() hash.Hash) {
	t.Helper()
	path := filepath.Join("testdata", "wycheproof", fname)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip %s: %v", path, err)
	}
	defer zr.Close()

	var file wpFile
	if err := json.NewDecoder(zr).Decode(&file); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}

	var total, okValid, okInvalid, acceptable int
	for _, g := range file.TestGroups {
		pubBytes, err := hex.DecodeString(g.PublicKey.Uncompressed)
		if err != nil {
			t.Errorf("bad pub hex: %v", err)
			continue
		}
		pub, err := c.NewPublicKey(pubBytes)
		if err != nil {
			// Wycheproof occasionally includes "edge-case" public keys
			// that a conforming parser may refuse outright (e.g.
			// infinity or out-of-curve coords). Every test in such a
			// group should then be "invalid" — count them all as
			// correctly rejected and move on.
			for _, tv := range g.Tests {
				total++
				if tv.Result == "valid" {
					t.Errorf("tcId=%d: pubkey rejected but vector is valid: %v", tv.TcID, err)
				}
			}
			continue
		}
		for _, tv := range g.Tests {
			total++
			msg, err := hex.DecodeString(tv.Msg)
			if err != nil {
				t.Errorf("tcId=%d: bad msg hex: %v", tv.TcID, err)
				continue
			}
			sig, err := hex.DecodeString(tv.Sig)
			if err != nil {
				t.Errorf("tcId=%d: bad sig hex: %v", tv.TcID, err)
				continue
			}
			h := newHash()
			h.Write(msg)
			digestBytes := h.Sum(nil)

			got := VerifyASN1(pub, digestBytes, sig)
			switch tv.Result {
			case "valid":
				if !got {
					t.Errorf("tcId=%d valid vector rejected (%s: %s)", tv.TcID, tv.Flags, tv.Comment)
				} else {
					okValid++
				}
			case "invalid":
				if got {
					t.Errorf("tcId=%d invalid vector accepted (%s: %s)", tv.TcID, tv.Flags, tv.Comment)
				} else {
					okInvalid++
				}
			case "acceptable":
				// Either outcome is allowed. Count for reporting.
				acceptable++
			default:
				t.Errorf("tcId=%d: unknown result %q", tv.TcID, tv.Result)
			}
		}
	}
	t.Logf("%s: %d total (valid %d, invalid %d, acceptable %d)", c.name, total, okValid, okInvalid, acceptable)
	if total != file.NumberOfTests {
		t.Errorf("ran %d vectors, manifest says %d", total, file.NumberOfTests)
	}
}
