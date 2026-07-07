//! Security / negative tests (binding, soundness, ZK sanity).
//!
//! Each test constructs an honest commit+prove+verify triple, then tampers
//! with exactly one component and asserts that `verify` returns `false`.

use cpc::commitment::commit;
use cpc::params::{B, Q, PublicParams};
use cpc::prove::prove;
use cpc::ring::Poly;
use cpc::verify::verify;

/// Build a path `v_0, v_1, ..., v_L` where each step `d_i = v_i - v_{i-1}`
/// is a unit vector `e_{i-1}` (norm 1, well within `beta = 45`).
fn build_test_path(l: usize) -> Vec<Poly> {
    assert!((1..=256).contains(&l), "test path length must be in [1, 256]");
    let mut path = vec![Poly::zero()];
    let mut current = Poly::zero();
    for i in 0..l {
        let mut step = Poly::zero();
        step.coeffs[i] = 1;
        current = &current + &step;
        path.push(current.clone());
    }
    path
}

#[test]
fn tampered_leaf_rejected() {
    // Tamper with the revealed leaf u_i in the proof -> Merkle / equation check fails.
    let pp = PublicParams::setup(b"security-test-tamper");
    let path = build_test_path(4);
    let (com, aux) = commit(&pp, &path);
    let mu = b"context-nonce";

    let proof = prove(&pp, &aux, 2, mu);
    assert!(verify(&pp, &com, &aux.deltas, 2, &proof, mu), "baseline must verify");

    // Flip one coefficient of u_i: breaks both the Sigma-protocol equation
    // (b*z == t2 + c*u_i) and the Merkle authentication path.
    let mut tampered = proof.clone();
    tampered.u_i.coeffs[0] = (tampered.u_i.coeffs[0] + 1) % Q;
    assert!(
        !verify(&pp, &com, &aux.deltas, 2, &tampered, mu),
        "tampered u_i must be rejected"
    );
}

#[test]
fn wrong_index_rejected() {
    // Proof for index i, verify against j != i -> false.
    let pp = PublicParams::setup(b"security-test-wrong-index");
    let path = build_test_path(4);
    let (com, aux) = commit(&pp, &path);
    let mu = b"context-nonce";

    let proof = prove(&pp, &aux, 2, mu);
    assert!(verify(&pp, &com, &aux.deltas, 2, &proof, mu), "baseline must verify");

    // The challenge c is re-derived from the index; a different index yields
    // a different c, breaking the response equation z = r + c*d_i.
    assert!(
        !verify(&pp, &com, &aux.deltas, 3, &proof, mu),
        "proof for i=2 must not verify at j=3"
    );
    assert!(
        !verify(&pp, &com, &aux.deltas, 1, &proof, mu),
        "proof for i=2 must not verify at j=1"
    );
}

#[test]
fn wrong_nonce_rejected() {
    // Prove with mu, verify with mu' != mu -> false.
    let pp = PublicParams::setup(b"security-test-wrong-nonce");
    let path = build_test_path(4);
    let (com, aux) = commit(&pp, &path);
    let mu = b"context-nonce-1";

    let proof = prove(&pp, &aux, 1, mu);
    assert!(verify(&pp, &com, &aux.deltas, 1, &proof, mu), "baseline must verify");

    // The nonce mu is mixed into the Fiat-Shamir hash; changing it produces a
    // different challenge c, so the response equation no longer holds.
    assert!(
        !verify(&pp, &com, &aux.deltas, 1, &proof, b"context-nonce-2"),
        "proof with mu1 must not verify with mu2"
    );
}

#[test]
fn oversized_z_rejected() {
    // Craft z with ||z||_2 > B -> verify returns false at the norm gate.
    let pp = PublicParams::setup(b"security-test-oversized-z");
    let path = build_test_path(4);
    let (com, aux) = commit(&pp, &path);
    let mu = b"context-nonce";

    let proof = prove(&pp, &aux, 1, mu);
    assert!(verify(&pp, &com, &aux.deltas, 1, &proof, mu), "baseline must verify");

    // Replace z with a polynomial whose L2 norm exceeds B = 622080.
    // A single coefficient of B+1 suffices (centered L2 norm = B+1 > B).
    let mut bad = proof.clone();
    bad.z = Poly::zero();
    bad.z.coeffs[0] = B + 1;
    assert!(
        bad.z.norm_l2() > B as f64,
        "test setup: crafted z must actually exceed the norm bound"
    );
    assert!(
        !verify(&pp, &com, &aux.deltas, 1, &bad, mu),
        "z with ||z|| > B must be rejected"
    );
}

#[test]
fn two_responses_same_index_do_not_break_binding() {
    // Honest prover can emit multiple proofs (different challenges) for the
    // same (com, i); this must NOT violate binding as defined in the paper.
    //
    // Binding here means: the commitment `com` uniquely determines the leaf
    // sequence `{u_i}`. Multiple valid proofs for the same index are expected
    // (different masking r, different challenge c, different response z), but
    // they all open the *same* u_i under the *same* com.
    let pp = PublicParams::setup(b"security-test-binding");
    let path = build_test_path(4);
    let (com, aux) = commit(&pp, &path);
    let mu1 = b"nonce-1";
    let mu2 = b"nonce-2";

    // Two proofs for the same index i=2, with different nonces (hence
    // different Fiat-Shamir challenges and independent masking r).
    let proof1 = prove(&pp, &aux, 2, mu1);
    let proof2 = prove(&pp, &aux, 2, mu2);

    // Both must verify.
    assert!(verify(&pp, &com, &aux.deltas, 2, &proof1, mu1), "proof1 must verify");
    assert!(verify(&pp, &com, &aux.deltas, 2, &proof2, mu2), "proof2 must verify");

    // Binding invariant: both proofs open the *same* u_i under the *same* com.
    // (u_i comes from aux, not from the random r, so it is bound to com.)
    assert_eq!(proof1.u_i.coeffs, proof2.u_i.coeffs, "u_i must be the same (binding)");

    // The transcripts differ: different r produces different t1, t2, z.
    assert_ne!(proof1.z.coeffs, proof2.z.coeffs, "z must differ (different r/c)");
    assert_ne!(proof1.t1.coeffs, proof2.t1.coeffs, "t1 must differ (different r)");
    assert_ne!(proof1.t2.coeffs, proof2.t2.coeffs, "t2 must differ (different r)");
}
