//! Constant-time primitives for `R = Z_q[x]/(x^m+1)`.
//!
//! All operations avoid data-dependent branches and variable-time
//! division. Modeled on the Dilithium reference implementation
//! (Apache License, pq-crystals/dilithium).
//!
//! # Design notes
//!
//! - [`barrett_reduce`] uses `i128` intermediate arithmetic to handle
//!   products up to `Q^2 ≈ 7×10^13` without overflow. It also handles
//!   negative inputs (subtraction results) by conditional addition of
//!   `Q`, which is the critical trap flagged in the hardening plan.
//! - [`montgomery_reduce`] mirrors Dilithium's `montgomery_reduce` using
//!   only `i64` arithmetic (fast path for NTT twiddle multiplication).
//!   `QINV = Q^{-1} mod 2^32` (verified: `Q * QINV ≡ 1 (mod 2^32)`).
//! - [`csubq`] / [`caddq`] are lightweight conditional subtract/add for
//!   the NTT butterfly, where inputs are already in `(-Q, 2Q)`.

use crate::params::Q;

/// `R = 2^32` (Montgomery radix).
pub const R: i64 = 1i64 << 32;

/// `R mod Q = 2^32 mod Q`.
pub const R_MOD_Q: i64 = 4_193_792; // (1 << 32) % Q

/// `Q^{-1} mod 2^32`.
///
/// Note: Dilithium documentation labels this `-Q^{-1} mod 2^32`, but
/// `Q * QINV ≡ 1 (mod 2^32)`, making it the positive modular inverse.
/// The `montgomery_reduce` formula `t = (a - u*Q) >> 32` requires this
/// positive-inverse convention (verified numerically).
pub const QINV: i64 = 58_728_449;

/// Barrett precomputed constant: `V = floor(2^52 / Q)`.
///
/// Using a 52-bit shift gives enough precision to reduce inputs up to
/// `Q^2 ≈ 2^46` (the product of two reduced coefficients) with at most
/// one conditional add and one conditional subtract of `Q`. The
/// intermediate product `a * V` is computed in `i128` to avoid overflow
/// since `Q^2 * V ≈ 2^69` exceeds `i64` range.
const BARRETT_V: i128 = (1i128 << 52) / Q as i128; // 537405648

/// Barrett rounding constant: `2^51` (half of the Barrett shift).
const BARRETT_HALF: i128 = 1i128 << 51;

/// Constant-time Barrett reduction: maps `a` to `a mod Q` in `[0, Q)`.
///
/// Handles inputs in the range `[-Q^2, Q^2]`:
/// - Products of two reduced values (up to `Q^2 ≈ 7×10^13`)
/// - Sums of two reduced values (up to `2Q`)
/// - Differences of two reduced values (down to `-Q`)
///
/// All operations (multiply, shift, compare, conditional add/subtract)
/// are branchless and data-independent in execution time. The `i128`
/// multiplication is emulated by a fixed sequence of `i64` multiplies
/// on x86_64, with no data-dependent branches.
#[inline(always)]
pub const fn barrett_reduce(a: i64) -> i64 {
    // t = round(a * V / 2^52)
    let t = ((a as i128) * BARRETT_V + BARRETT_HALF) >> 52;
    // r = a - t * Q, approximately in [-0.52*Q, 0.52*Q] for |a| <= Q^2
    let r = a - (t * Q as i128) as i64;
    // Bring r into [0, Q) using constant-time conditional add/subtract.
    // Two of each covers the worst-case rounding for negative inputs.
    let neg = ((r < 0) as i64).wrapping_neg();
    let r = r + (neg & Q);
    let neg = ((r < 0) as i64).wrapping_neg();
    let r = r + (neg & Q);
    let ge = ((r >= Q) as i64).wrapping_neg();
    let r = r - (ge & Q);
    let ge = ((r >= Q) as i64).wrapping_neg();
    r - (ge & Q)
}

/// Constant-time Montgomery reduction.
///
/// Computes `a * R^{-1} mod Q` where `R = 2^32`. Input `a` should
/// satisfy `|a| < Q * R` (i.e., a product of two reduced values scaled
/// by at most `R`). Output is in `[0, Q)`.
///
/// Mirrors Dilithium's `montgomery_reduce` but adds explicit sign
/// handling to guarantee `[0, Q)` output. Uses only `i64` arithmetic
/// (fast path for NTT).
#[inline(always)]
pub const fn montgomery_reduce(a: i64) -> i64 {
    // u = (a mod 2^32) * QINV mod 2^32
    let u = ((a as i32 as i64).wrapping_mul(QINV as i32 as i64)) as i32 as i64;
    // t = (a - u * Q) >> 32 — (a - u*Q) is exactly divisible by 2^32
    let t = (a - u.wrapping_mul(Q)) >> 32;
    // Bring t into [0, Q)
    let neg = ((t < 0) as i64).wrapping_neg();
    let t = t + (neg & Q);
    let ge = ((t >= Q) as i64).wrapping_neg();
    let t = t - (ge & Q);
    let ge = ((t >= Q) as i64).wrapping_neg();
    t - (ge & Q)
}

/// Constant-time conditional subtract Q: if `a >= Q`, returns `a - Q`,
/// else `a`. For inputs in `[0, 2Q)`, output is in `[0, Q)`.
#[inline(always)]
pub const fn csubq(a: i64) -> i64 {
    let ge = ((a >= Q) as i64).wrapping_neg();
    a - (ge & Q)
}

/// Constant-time conditional add Q: if `a < 0`, returns `a + Q`, else
/// `a`. For inputs in `(-Q, Q)`, output is in `[0, Q)`.
#[inline(always)]
pub const fn caddq(a: i64) -> i64 {
    let neg = ((a < 0) as i64).wrapping_neg();
    a + (neg & Q)
}

/// Constant-time conditional select: returns `b` if `cond == -1` (all
/// ones), else `a`. `cond` must be `0` or `-1`.
#[inline(always)]
pub const fn ct_select(a: i64, b: i64, cond: i64) -> i64 {
    a ^ (cond & (a ^ b))
}

/// Constant-time "center" reduction: maps `c in [0, Q)` to
/// `[-(Q-1)/2, (Q-1)/2]`.
///
/// Replaces the data-dependent branch `if c > Q/2 { c - Q } else { c }`.
/// Used by `norm_l2` and `norm_inf` to compute centered norms without
/// branching on secret coefficient values.
#[inline(always)]
pub const fn center(c: i64) -> i64 {
    const HALF: i64 = (Q - 1) / 2; // 4190208
    let cond = ((c > HALF) as i64).wrapping_neg();
    ct_select(c, c - Q, cond)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrett_correctness() {
        // Test products (large positive inputs up to Q^2)
        for a in [0, 1, Q - 1, Q, Q + 1, 2 * Q,
                 Q * Q, (Q - 1) * (Q - 1), Q * (Q / 2),
                 1 << 24, (1 << 24) - 1] {
            let result = barrett_reduce(a);
            assert!((0..Q).contains(&result),
                "barrett_reduce({}) = {} not in [0, Q)", a, result);
            let expected = a.rem_euclid(Q);
            assert_eq!(result, expected,
                "barrett_reduce({}) = {} != expected {}", a, result, expected);
        }
        // Critical: negative inputs (subtraction results)
        for a in [-1, -Q, -(Q / 2), -Q + 1, -(Q - 1), -2 * Q, -(Q * Q)] {
            let result = barrett_reduce(a);
            assert!((0..Q).contains(&result),
                "barrett_reduce({}) = {} not in [0, Q)", a, result);
            let expected = a.rem_euclid(Q);
            assert_eq!(result, expected,
                "barrett_reduce({}) = {} != expected {}", a, result, expected);
        }
    }

    #[test]
    fn montgomery_round_trip() {
        // montgomery_reduce(a * R) should equal a mod Q
        for a in [0i64, 1, 42, Q - 1, Q / 2, 1 << 20] {
            let prod = a.wrapping_mul(R);
            let result = montgomery_reduce(prod);
            assert_eq!(result, a % Q,
                "montgomery_reduce({} * R) = {} != {}", a, result, a % Q);
        }
        // Also test a general product: montgomery_reduce(x * y) == x*y * R^{-1} mod Q
        // Verify by multiplying back by R: (mont * R) mod Q should give x*y mod Q
        // (Note: mont * R fits in i64 since mont < Q and R = 2^32, product < Q*2^32 < i64::MAX)
        for (x, y) in [(3i64, 7), (Q - 1, Q - 1), (100, 200), (1, Q - 1)] {
            let prod = x.wrapping_mul(y);
            let mont = montgomery_reduce(prod);
            // mont = x * y * R^{-1} mod Q. Multiply by R mod Q: should get x*y mod Q
            let recovered = (mont * R) % Q;
            assert_eq!(recovered, (x * y) % Q,
                "montgomery round-trip failed for x={}, y={}: got {}, expected {}",
                x, y, recovered, (x * y) % Q);
        }
    }

    #[test]
    fn center_branchless_matches_naive() {
        for c in [0, 1, 100, 4_190_208, 4_190_209, Q - 1, Q / 2, Q / 2 + 1] {
            let naive = if c > (Q - 1) / 2 { c - Q } else { c };
            assert_eq!(center(c), naive,
                "center({}) = {} != naive {}", c, center(c), naive);
        }
        // Verify |center(c)| matches the original norm pattern: min(c, Q-c)
        for c in [0, 1, 100, 4_190_208, 4_190_209, Q - 1] {
            let abs_centered = center(c).abs();
            let naive_abs = if c > (Q - 1) / 2 { Q - c } else { c };
            assert_eq!(abs_centered, naive_abs,
                "|center({})| = {} != |naive| {}", c, abs_centered, naive_abs);
        }
    }
}
