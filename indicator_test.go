package gobrainpool

import (
	"crypto/rand"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestEnforce_BlocksNonApprovedSign pins that under approved-parameter
// enforcement every exported Sign entry point refuses a digest whose
// length doesn't match the curve, across all three curves and via
// every path the crypto.Signer / stdlib-shaped API exposes.
func TestEnforce_BlocksNonApprovedSign(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve *Curve
	}{
		{"bp256", BP256r1()},
		{"bp384", BP384r1()},
		{"bp512", BP512r1()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			short := make([]byte, tc.curve.byteSize-1)

			// Default mode: short digest accepted, signature produced.
			// Pins that the guard isn't always-on.
			if sig, err := SignDeterministicASN1(priv, short); err != nil || len(sig) == 0 {
				t.Fatalf("default mode: SignDeterministicASN1 short digest: sig=%x err=%v", sig, err)
			}

			SetEnforceApproved(true)
			t.Cleanup(func() { SetEnforceApproved(false) })

			// SignDeterministicASN1
			if _, err := SignDeterministicASN1(priv, short); err == nil {
				t.Error("SignDeterministicASN1 short digest: err = nil, want blocked")
			} else if !strings.Contains(err.Error(), "approved-parameter enforcement") {
				t.Errorf("SignDeterministicASN1 error does not mention enforcement: %v", err)
			}

			// SignASN1 (hedged)
			if _, err := SignASN1(rand.Reader, priv, short); err == nil {
				t.Error("SignASN1 short digest: err = nil, want blocked")
			}

			// SignASN1 with nil rand (delegates to crypto/rand.Reader)
			if _, err := SignASN1(nil, priv, short); err == nil {
				t.Error("SignASN1(nil rand) short digest: err = nil, want blocked")
			}

			// crypto.Signer interface path: priv.Sign(rand, digest, opts)
			if _, err := priv.Sign(rand.Reader, short, nil); err == nil {
				t.Error("priv.Sign short digest: err = nil, want blocked")
			}

			// Approved-length digest still works under enforcement.
			approved := make([]byte, tc.curve.byteSize)
			d := sha256.Sum256([]byte(tc.name))
			copy(approved, d[:]) // non-zero leading bytes
			if _, err := SignDeterministicASN1(priv, approved); err != nil {
				t.Errorf("SignDeterministicASN1 approved digest: %v", err)
			}
		})
	}
}

// TestEnforce_BlocksNonApprovedVerify pins that VerifyASN1 returns
// false in enforced mode without running the cryptographic verify,
// across all three curves. Default-mode behaviour is pinned for
// contrast: a valid-but-non-approved verify still returns true.
func TestEnforce_BlocksNonApprovedVerify(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve *Curve
	}{
		{"bp256", BP256r1()},
		{"bp384", BP384r1()},
		{"bp512", BP512r1()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			short := make([]byte, tc.curve.byteSize-1)

			sig, err := SignDeterministicASN1(priv, short)
			if err != nil {
				t.Fatalf("SignDeterministicASN1 default short: %v", err)
			}

			// Default: valid-on-short-digest signature verifies true.
			if !VerifyASN1(priv.PublicKey(), short, sig) {
				t.Fatal("default mode: valid signature rejected")
			}

			SetEnforceApproved(true)
			t.Cleanup(func() { SetEnforceApproved(false) })

			if VerifyASN1(priv.PublicKey(), short, sig) {
				t.Error("enforced mode: short-digest verify = true, want false")
			}
		})
	}
}

// TestEnforce_KeyOpsUnaffected pins that GenerateKey / NewPrivateKey /
// NewPublicKey / ECDH have no parameter variability at this layer and
// are therefore not gated by enforcement.
func TestEnforce_KeyOpsUnaffected(t *testing.T) {
	SetEnforceApproved(true)
	t.Cleanup(func() { SetEnforceApproved(false) })

	for _, tc := range []struct {
		name  string
		curve *Curve
	}{
		{"bp256", BP256r1()},
		{"bp384", BP384r1()},
		{"bp512", BP512r1()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("enforced GenerateKey: %v", err)
			}
			if _, err := tc.curve.NewPrivateKey(priv.Bytes()); err != nil {
				t.Errorf("enforced NewPrivateKey: %v", err)
			}
			if _, err := tc.curve.NewPublicKey(priv.PublicKey().Bytes()); err != nil {
				t.Errorf("enforced NewPublicKey: %v", err)
			}
			if _, err := priv.ECDH(priv.PublicKey()); err != nil {
				t.Errorf("enforced ECDH: %v", err)
			}
		})
	}
}

// TestEnforce_Toggle pins that SetEnforceApproved round-trips via
// EnforceApproved.
func TestEnforce_Toggle(t *testing.T) {
	t.Cleanup(func() { SetEnforceApproved(false) })

	if EnforceApproved() {
		t.Fatal("test precondition: enforcement should be off at start")
	}
	SetEnforceApproved(true)
	if !EnforceApproved() {
		t.Error("after SetEnforceApproved(true): EnforceApproved() = false")
	}
	SetEnforceApproved(false)
	if EnforceApproved() {
		t.Error("after SetEnforceApproved(false): EnforceApproved() = true")
	}
}

// TestEnforce_PrimitiveCallSitesAreGated is a structural audit test:
// it parses the non-test source of the package and asserts that calls
// to the per-curve ECDSA primitives (sign256/384/512, verify256/384/512)
// only occur inside an allowlisted set of functions. This prevents a
// future refactor from silently routing around the approved-parameter
// enforcement gate that lives in signASN1 and VerifyASN1.
//
// Allowlist:
//
//   - signASN1        : the single Sign service core; runs the gate
//   - VerifyASN1      : the single Verify entry; runs the gate
//   - castECDSA       : module-internal self-test, approved-length by
//     construction (uses fixed vectors)
//   - pairwiseConsistencyCheck : PCT on a freshly-derived keypair,
//     approved-length by construction (fixed 0xA5...0xA5 digest sized
//     to the curve)
//
// Any other caller of these primitives would bypass enforcement and
// must not be added without adding its own gate.
func TestEnforce_PrimitiveCallSitesAreGated(t *testing.T) {
	primitives := map[string]struct{}{
		"sign256": {}, "sign384": {}, "sign512": {},
		"verify256": {}, "verify384": {}, "verify512": {},
	}
	allowedCallers := map[string]struct{}{
		"signASN1":                 {},
		"VerifyASN1":               {},
		"castECDSA":                {},
		"pairwiseConsistencyCheck": {},
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	seen := make(map[string]struct{})
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				caller := fn.Name.Name
				ast.Inspect(fn, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					ident, ok := call.Fun.(*ast.Ident)
					if !ok {
						return true
					}
					if _, isPrim := primitives[ident.Name]; !isPrim {
						return true
					}
					seen[caller] = struct{}{}
					if _, allowed := allowedCallers[caller]; !allowed {
						t.Errorf("disallowed primitive call: %s() calls %s() at %s",
							caller, ident.Name, fset.Position(call.Pos()))
					}
					return true
				})
			}
		}
	}

	// Belt-and-suspenders: make sure every allowed caller actually calls
	// a primitive. If an entry on the allowlist stops needing the
	// exemption (e.g. a refactor removes the call) we want the allowlist
	// to shrink with it, not to accrue stale entries.
	for caller := range allowedCallers {
		if _, ok := seen[caller]; !ok {
			t.Errorf("allowed caller %s no longer calls any per-curve primitive; remove from allowlist", caller)
		}
	}
}
