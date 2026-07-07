//! End-to-end integration tests for the full CPC pipeline.
//!
//! These tests exercise the complete commit → prove → verify round-trip
//! across different path lengths and indices, and verify that the
//! rejection-sampling loop terminates within budget for honest inputs.

use cpc::commitment::commit;
use cpc::params::{PublicParams, M};
use cpc::prove::{prove, prove_with_iteration_count};
use cpc::ring::Poly;
use cpc::verify::verify;

/// Build a path `v_0, v_1, ..., v_L` where each step `d_i = v_i - v_{i-1}`
/// is a unit vector `e_{(i-1) mod 256}` (norm 1, well within `beta = 45`).
fn build_test_path(l: usize) -> Vec<Poly> {
    assert!(l >= 1, "test path length must be >= 1");
    let mut path = vec![Poly::zero()];
    let mut current = Poly::zero();
    for i in 0..l {
        let mut step = Poly::zero();
        step.coeffs[i % 256] = 1;
        current = &current + &step;
        path.push(current.clone());
    }
    path
}

#[test]
fn end_to_end_l8_all_indices() {
    // For L=8: commit, then prove+verify at every i in 1..=8.
    let pp = PublicParams::setup(b"integration-l8");
    let path = build_test_path(8);
    let (com, aux) = commit(&pp, &path);
    assert_eq!(aux.d_vec.len(), 8);
    assert_eq!(aux.deltas.len(), 8);

    let mu = b"integration-test-nonce";
    for i in 1..=8 {
        let proof = prove(&pp, &aux, i, mu);
        assert!(
            verify(&pp, &com, &aux.deltas, i, &proof, mu),
            "proof for index {i} must verify"
        );
    }
}

#[test]
fn end_to_end_l1024_random_index() {
    // For L=1024: commit, prove+verify at an index in the middle of the tree
    // (exercises a non-trivial Merkle authentication path).
    let pp = PublicParams::setup(b"integration-l1024");
    let path = build_test_path(1024);
    let (com, aux) = commit(&pp, &path);
    assert_eq!(aux.d_vec.len(), 1024);

    let mu = b"integration-test-nonce";
    let i = 512;
    let proof = prove(&pp, &aux, i, mu);
    assert!(
        verify(&pp, &com, &aux.deltas, i, &proof, mu),
        "proof for index {i} (L=1024) must verify"
    );

    // Also exercise a leaf near the end (tests Merkle padding boundary).
    let i = 1024;
    let proof = prove(&pp, &aux, i, mu);
    assert!(
        verify(&pp, &com, &aux.deltas, i, &proof, mu),
        "proof for index {i} (L=1024) must verify"
    );
}

#[test]
fn prove_completes_within_iteration_budget() {
    // 100 honest prove() calls; each must terminate without hitting
    // MAX_REJECT_ITERATIONS (a panic). If prove returns at all, it did so
    // within the budget. Uses minimal L=2 paths to keep the test fast.
    let pp = PublicParams::setup(b"integration-budget");
    let mu = b"budget-test-nonce";

    let n = 100;
    for trial in 0..n {
        // Minimal path: v_0 = 0, v_1 = e_{trial mod 256}.
        let mut step = Poly::zero();
        step.coeffs[(trial as usize) % 256] = 1;
        let v0 = Poly::zero();
        let v1 = &v0 + &step;
        let path = vec![v0, v1];

        let (com, aux) = commit(&pp, &path);
        let proof = prove(&pp, &aux, 1, mu);
        assert!(
            verify(&pp, &com, &aux.deltas, 1, &proof, mu),
            "trial {trial}: proof must verify"
        );
    }
}

#[test]
fn rejection_sampling_statistics() {
    // Run prove 200 times, collect iteration counts to characterize the
    // Fiat-Shamir-with-aborts loop. Prints stats via --nocapture.
    let pp = PublicParams::setup(b"stats-test");
    let path = build_test_path(8);
    let (_com, aux) = commit(&pp, &path);

    let n = 200;
    let mut counts = Vec::with_capacity(n);
    for _ in 0..n {
        let (_, iters) = prove_with_iteration_count(&pp, &aux, 1, b"mu");
        counts.push(iters);
    }

    let avg = counts.iter().sum::<usize>() as f64 / n as f64;
    let max = *counts.iter().max().unwrap();
    let min = *counts.iter().min().unwrap();
    let acceptance_rate = 1.0 / avg;
    // P99: 99th percentile
    let mut sorted = counts.clone();
    sorted.sort_unstable();
    let p99_idx = ((n as f64) * 0.99).ceil() as usize - 1;
    let p99 = sorted[p99_idx];

    println!("\n=== Rejection Sampling Statistics (n={n}, L=8) ===");
    println!("  Average iterations : {avg:.2}");
    println!("  Min iterations     : {min}");
    println!("  Max iterations     : {max}");
    println!("  P99 iterations     : {p99}");
    println!("  Acceptance rate    : {:.2}%", acceptance_rate * 100.0);
    println!("  Note: low iter count because ||d||=1 << sigma=32400");
    println!("  Theory (||d||~beta*sqrt(m)): M≈2.7, accept≈37%");

    // Sanity: average should be in a reasonable range around the theoretical ~2.7
    assert!(avg > 1.0 && avg < 10.0, "average iterations {avg} out of expected range");
    assert!(max < 50, "max iterations {max} unexpectedly high");
}

#[test]
fn proof_size_at_l1024() {
    // Measure serialized proof size at L=1024 and confirm it is ~3.3 KB.
    let pp = PublicParams::setup(b"size-test");
    let path = build_test_path(1024);
    let (_com, aux) = commit(&pp, &path);

    let proof = prove(&pp, &aux, 512, b"mu");

    let z_bytes = proof.z.to_bytes().len();
    let u_bytes = proof.u_i.to_bytes().len();
    let t1_bytes = proof.t1.to_bytes().len();
    let t2_bytes = proof.t2.to_bytes().len();
    // Merkle path: 1 usize (index) + log2(1024)=10 sibling hashes
    let path_bytes = std::mem::size_of_val(&proof.path.index) + proof.path.siblings.len() * 32;
    let total = z_bytes + u_bytes + t1_bytes + t2_bytes + path_bytes;

    println!("\n=== Proof Size Breakdown (L=1024) ===");
    println!("  z       : {z_bytes} bytes");
    println!("  u_i     : {u_bytes} bytes");
    println!("  t1      : {t1_bytes} bytes (Option B)");
    println!("  t2      : {t2_bytes} bytes (Option B)");
    println!("  path    : {path_bytes} bytes ({} siblings + index)", proof.path.siblings.len());
    println!("  total   : {total} bytes (~{:.2} KB)", total as f64 / 1024.0);

    // Each polynomial serializes to 3*M = 768 bytes
    assert_eq!(z_bytes, 3 * M);
    assert_eq!(u_bytes, 3 * M);
    assert_eq!(t1_bytes, 3 * M);
    assert_eq!(t2_bytes, 3 * M);
    // Merkle tree with 1024 leaves has log2(1024) = 10 levels
    assert_eq!(proof.path.siblings.len(), 10);

    // Total should be ~3.3 KB (4 * 768 + 10*32 + 8 = 3072 + 320 + 8 = 3400)
    assert_eq!(total, 4 * 3 * M + 10 * 32 + std::mem::size_of::<usize>());
    assert!(
        (3200..=3500).contains(&total),
        "proof size {total} not in expected ~3.3 KB range"
    );
}
