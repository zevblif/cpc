//! Round-trip tests for Proof serialization.

use cpc::commitment::commit;
use cpc::params::PublicParams;
use cpc::prove::{prove, Proof};
use cpc::ring::Poly;
use cpc::verify::verify;

fn build_demo_path(l: usize) -> Vec<Poly> {
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
fn proof_to_from_bytes_round_trip() {
    let pp = PublicParams::setup(b"serialization-test");
    let path = build_demo_path(8);
    let (com, aux) = commit(&pp, &path);
    let mu = b"verifier-nonce";
    let proof = prove(&pp, &aux, 3, mu);

    let bytes = proof.to_bytes();
    let restored = Proof::from_bytes(&bytes).expect("from_bytes must succeed");

    assert_eq!(restored.z.coeffs, proof.z.coeffs, "z mismatch");
    assert_eq!(restored.u_i.coeffs, proof.u_i.coeffs, "u_i mismatch");
    assert_eq!(restored.t1.coeffs, proof.t1.coeffs, "t1 mismatch");
    assert_eq!(restored.t2.coeffs, proof.t2.coeffs, "t2 mismatch");
    assert_eq!(restored.path.index, proof.path.index, "path.index mismatch");
    assert_eq!(
        restored.path.siblings, proof.path.siblings,
        "siblings mismatch"
    );

    // Verify the restored proof is still valid
    assert!(
        verify(&pp, &com, &aux.deltas, 3, &restored, mu),
        "restored proof must verify"
    );
}

#[test]
fn proof_to_bytes_size_matches_target() {
    let pp = PublicParams::setup(b"size-test");
    let path = build_demo_path(8);
    let (_com, aux) = commit(&pp, &path);
    let proof = prove(&pp, &aux, 1, b"mu");
    let bytes = proof.to_bytes();
    // For L=8, tree depth = 3, so 3 siblings.
    // Expected: 4*768 + 8 + 1 + 3*32 = 3193 bytes.
    assert_eq!(bytes.len(), 4 * 768 + 8 + 1 + 3 * 32);
}

#[test]
fn proof_from_bytes_rejects_malformed() {
    // Too short
    assert!(Proof::from_bytes(&[0u8; 10]).is_none());
    // Truncated siblings
    let pp = PublicParams::setup(b"malformed-test");
    let path = build_demo_path(8);
    let (_com, aux) = commit(&pp, &path);
    let proof = prove(&pp, &aux, 1, b"mu");
    let mut bytes = proof.to_bytes();
    bytes.truncate(bytes.len() - 1); // chop off last byte
    assert!(
        Proof::from_bytes(&bytes).is_none(),
        "truncated input must be rejected"
    );
    // Bad n_siblings
    let mut bad = proof.to_bytes();
    let n_sib_offset = 4 * 768 + 8;
    bad[n_sib_offset] = 100; // > 32
    assert!(
        Proof::from_bytes(&bad).is_none(),
        "oversized n_siblings must be rejected"
    );
}
