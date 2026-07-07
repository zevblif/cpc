//! Tests targeting specific uncovered branches identified by cargo-llvm-cov.
//!
//! These tests cover edge cases not exercised by the main test suite
//! (`tests/correctness.rs`, `tests/security.rs`, `tests/integration.rs`).
//! They were written as part of Task 3 of the hardening plan to push
//! line coverage toward the 90% target.
//!
//! Coverage gaps targeted (per `docs/hardening-plan-zh.md` §3.3):
//! - `Poly::from_bytes` rejection of *wrong-length* input (oversized-coeff
//!   rejection is already covered by `ring_bytes_round_trip`).
//! - `rejection_acceptance_ratio` `log_rho >= 0.0` branch (returns `1.0`)
//!   — the existing `rejection_ratio_bounded` test only hits the `exp()`
//!   branch.
//! - `log_rejection_m` at non-nominal `tau_ratio` (only called with `12.0`
//!   elsewhere).
//! - `MerkleTree::build` padding branch for non-power-of-2 leaf counts.
//! - `MerkleTree::generate_path` odd-index sibling branch (`idx - 1`).
//! - `MerkleTree` with a single leaf (empty `siblings` path; the build
//!   loop `while level_size > 1` never executes).
//! - `Poly::neg` on a *non-zero* polynomial (existing test only covers
//!   `neg` of zero).

use cpc::gauss::{log_rejection_m, rejection_acceptance_ratio};
use cpc::merkle::{verify_path, MerkleTree};
use cpc::params::{M, Q, SIGMA};
use cpc::ring::Poly;

#[test]
fn poly_from_bytes_rejects_wrong_length() {
    // Too short
    assert!(Poly::from_bytes(&[0u8; 10]).is_none());
    // Too long
    assert!(Poly::from_bytes(&[0u8; 1024]).is_none());
    // Exactly one byte short of 3*M
    assert!(Poly::from_bytes(&[0u8; 3 * M - 1]).is_none());
    // Exactly one byte over 3*M
    assert!(Poly::from_bytes(&[0u8; 3 * M + 1]).is_none());
}

#[test]
fn poly_from_bytes_rejects_coefficient_equal_to_q() {
    // Boundary: coefficient exactly equal to `q` must be rejected
    // (the `>= q` branch). `q = 8_380_417 = 0x7FE001`.
    let mut bytes = vec![0u8; 3 * M];
    bytes[0] = 0x01;
    bytes[1] = 0xE0;
    bytes[2] = 0x7F;
    let c = (bytes[0] as u64) | ((bytes[1] as u64) << 8) | ((bytes[2] as u64) << 16);
    assert_eq!(c, Q as u64, "test setup: bytes must encode exactly q");
    assert!(
        Poly::from_bytes(&bytes).is_none(),
        "coefficient == q must be rejected (must be < q)"
    );
}

#[test]
fn rejection_acceptance_ratio_clamped_to_one() {
    // When `||z||^2 < ||z_minus_cd||^2`, the term
    // `-pi * (z_norm_sq - zd_norm_sq) / sigma^2` becomes positive and can
    // dominate `log_m`, making `log_rho >= 0.0` and triggering the
    // `return 1.0` branch in `rejection_acceptance_ratio`.
    //
    // With z = 0 and z_minus_cd having all coeffs = Q/4 (centered = Q/4 ~ 2.1e6),
    // zd_norm_sq = 256 * (Q/4)^2 ~ 1.1e15, which far exceeds
    // log_m * sigma^2 / pi ~ 3.4e8, so log_rho >> 0.
    let z = Poly::zero();
    let mut z_minus_cd = Poly::zero();
    for c in z_minus_cd.coeffs.iter_mut() {
        *c = Q / 4;
    }
    let log_m = log_rejection_m(12.0);
    let r = rejection_acceptance_ratio(&z, &z_minus_cd, SIGMA, log_m);
    assert_eq!(
        r, 1.0,
        "when log_rho >= 0, ratio must be clamped to 1.0 (got {})", r
    );
}

#[test]
fn log_rejection_m_at_nominal_and_small_ratios() {
    // Nominal tau_ratio = 12 -> log_m = 1 + 1/288 ~= 1.00347
    let nominal = log_rejection_m(12.0);
    assert!(
        (nominal - 1.00347).abs() < 1e-4,
        "log_m(12) should be ~1.00347, got {}",
        nominal
    );
    // Smaller tau_ratio yields a strictly larger log_m (worse rejection rate).
    let small = log_rejection_m(1.0);
    assert!(
        small > nominal,
        "log_m must decrease as tau_ratio increases (got small={}, nominal={})",
        small,
        nominal
    );
    // tau_ratio = 1 -> 12 + 0.5 = 12.5 exactly.
    assert!(
        (small - 12.5).abs() < 1e-9,
        "log_m(1) should be 12.5, got {}",
        small
    );
}

#[test]
fn merkle_tree_odd_leaf_count_uses_padding_branch() {
    // 3 leaves -> next_power_of_two = 4, so `build` takes the
    // `else { nodes.push([0u8; 32]); }` padding branch once.
    // `generate_path(2)` (an odd index) also exercises the
    // `if idx % 2 == 0 { idx + 1 } else { idx - 1 }` odd branch.
    let leaves: Vec<Vec<u8>> = (0..3).map(|i| vec![i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    assert_eq!(tree.leaf_count(), 3);

    let root = tree.root();
    // Every real leaf must verify.
    for (i, leaf) in leaves.iter().enumerate() {
        let path = tree.generate_path(i);
        assert!(
            verify_path(&root, leaf, &path),
            "valid path for leaf {} must verify under odd-leaf tree",
            i
        );
    }
    // Tampered leaf at the odd index 2 (exercises `hash_pair(&sibling, &h)`
    // direction in `verify_path`).
    let path2 = tree.generate_path(2);
    let mut bad = leaves[2].clone();
    bad[0] ^= 0xFF;
    assert!(
        !verify_path(&root, &bad, &path2),
        "tampered leaf at odd index must be rejected"
    );
}

#[test]
fn merkle_tree_single_leaf_yields_empty_path() {
    // 1 leaf -> next_power_of_two = 1, the `while level_size > 1` loop in
    // `build` never executes, and `generate_path` produces an empty
    // `siblings` vec. `verify_path` with an empty sibling list reduces to
    // `hash_leaf(leaf) == root`.
    let leaves: Vec<Vec<u8>> = vec![vec![42u8; 32]];
    let tree = MerkleTree::build(&leaves);
    assert_eq!(tree.leaf_count(), 1);

    let root = tree.root();
    let path = tree.generate_path(0);
    assert!(
        path.siblings.is_empty(),
        "single-leaf tree path must have no siblings"
    );
    assert!(
        verify_path(&root, &leaves[0], &path),
        "single-leaf path must verify"
    );
    // A different leaf must NOT verify against this root.
    let mut wrong = leaves[0].clone();
    wrong[0] ^= 0xFF;
    assert!(
        !verify_path(&root, &wrong, &path),
        "wrong leaf under single-leaf tree must be rejected"
    );
}

#[test]
fn poly_neg_of_nonzero_polynomial() {
    // `neg` computes `(Q - c) % Q` per coefficient. For c in (0, Q) this is
    // `Q - c`; for c = 0 this is 0. The existing `ring_neg_of_zero_is_zero`
    // test only covers the all-zero case; this extends coverage to nonzero
    // coefficients including the boundary `c = Q - 1`.
    let p = Poly::from_coefficients(&[1, 2, 3, (Q - 1) as i32, 0]);
    let n = p.neg();
    assert_eq!(n.coeffs[0], Q - 1, "neg(1) = Q-1");
    assert_eq!(n.coeffs[1], Q - 2);
    assert_eq!(n.coeffs[2], Q - 3);
    assert_eq!(n.coeffs[3], 1, "neg(Q-1) = 1");
    assert_eq!(n.coeffs[4], 0, "neg(0) = 0");
    // Double negation is the identity.
    let nn = n.neg();
    assert_eq!(nn.coeffs, p.coeffs, "neg(neg(p)) == p");
}
