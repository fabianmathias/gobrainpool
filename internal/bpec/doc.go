// Package bpec is the internal per-curve elliptic-curve engine for
// gobrainpool. It exposes a byte-only API that mirrors the shape of
// crypto/internal/fips140/nistec from the Go standard library: each
// curve has its own projective Point type, all inputs and outputs are
// fixed-width byte slices, no *big.Int appears in any hot path.
//
// The curve arithmetic is the Renes-Costello-Batina complete projective
// addition formula (Algorithm 1, general a), scheduled through a fixed
// 4-bit window with constant-time table selection. Field arithmetic is
// the fiat-crypto generated Montgomery code in internal/fiat. Scalar
// arithmetic modulo the group order uses the corresponding fiat "n"
// package.
//
// This package is internal. External callers use the top-level
// gobrainpool package or the curve-specific bp256 / bp384 / bp512
// frontends, which wrap this engine.
package bpec
