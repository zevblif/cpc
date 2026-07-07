//! Example: CPC + Ed25519 = authenticatable selective-disclosure credential.
//!
//! Demonstrates the "plug-and-play" composition from paper Section 6:
//!
//! 1. Issuer generates a path, runs `CPC.Commit`, publishes
//!    `(com, {Delta_j}, vk_sigma)`.
//! 2. Verifier sends a fresh nonce `mu`.
//! 3. User selects index `i`, runs `CPC.Prove`, signs `(com, i, pi, mu)`
//!    with Ed25519, sends `(pi, sigma)`.
//! 4. Verifier checks the Ed25519 signature and `CPC.Verify`.

use cpc::commitment::commit;
use cpc::params::{PublicParams, Q};
use cpc::prove::prove;
use cpc::ring::Poly;
use cpc::verify::verify;

use ed25519_dalek::{Signer, SigningKey, Verifier};
use rand::RngCore;

/// Build a small demo path: `v_0 = 0`, `v_i = v_{i-1} + e_{i-1}` (unit steps).
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

/// Lowercase hex encoding of a byte slice.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    // ---- Setup (shared system parameters) ----
    let pp = PublicParams::setup(b"cpc-credential-demo");

    // ---- Issuer: commit to a path of length L=8 ----
    let l = 8;
    let path = build_demo_path(l);
    let (com, aux) = commit(&pp, &path);
    println!("=== CPC + Ed25519 Credential Demo ===\n");
    println!("Issuer: committed to path of length L={l}");
    println!("  com (32 bytes)        = {}", hex(&com));
    println!("  {{Delta_j}} published  ({} polys, {} bytes)", l, l * 768);

    // Issuer's Ed25519 signing key (in practice, generated once and kept secret).
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let issuer_sk = SigningKey::from_bytes(&secret);
    let issuer_vk = issuer_sk.verifying_key();
    println!("  issuer vk (32 bytes)  = {}", hex(&issuer_vk.to_bytes()));

    // ---- Verifier: send a fresh nonce mu ----
    let mu = b"verifier-nonce-12345";
    println!("\nVerifier: sent nonce mu = {:?}", std::str::from_utf8(mu).unwrap());

    // ---- User: select index i=3, prove, and sign ----
    let i = 3;
    let proof = prove(&pp, &aux, i, mu);
    println!("\nUser: selected index i={i}");

    let z_bytes = proof.z.to_bytes().len();
    let u_bytes = proof.u_i.to_bytes().len();
    let t1_bytes = proof.t1.to_bytes().len();
    let t2_bytes = proof.t2.to_bytes().len();
    let path_bytes = proof.path.siblings.len() * 32 + 8; // siblings + index
    let proof_size = z_bytes + u_bytes + t1_bytes + t2_bytes + path_bytes;
    println!("  z       : {} bytes", z_bytes);
    println!("  u_i     : {} bytes", u_bytes);
    println!("  t1      : {} bytes (Option B)", t1_bytes);
    println!("  t2      : {} bytes (Option B)", t2_bytes);
    println!("  path    : {} bytes ({} siblings)", path_bytes, proof.path.siblings.len());
    println!("  total   : {} bytes (~{:.2} KB)", proof_size, proof_size as f64 / 1024.0);

    // ---- User: serialize proof for network transmission ----
    let proof_bytes = proof.to_bytes();
    println!("\n  proof serialized to {} bytes (~{:.2} KB)",
        proof_bytes.len(),
        proof_bytes.len() as f64 / 1024.0);

    // Simulate network: restore on verifier side
    let restored_proof = cpc::prove::Proof::from_bytes(&proof_bytes)
        .expect("proof deserialization must succeed");
    assert_eq!(restored_proof.z.coeffs, proof.z.coeffs);
    println!("  proof round-trip: OK");

    // Sign (com || i || proof || mu) with Ed25519.
    let mut signed_msg = Vec::new();
    signed_msg.extend_from_slice(&com);
    signed_msg.extend_from_slice(&(i as u64).to_le_bytes());
    signed_msg.extend_from_slice(&proof.z.to_bytes());
    signed_msg.extend_from_slice(&proof.u_i.to_bytes());
    signed_msg.extend_from_slice(&proof.t1.to_bytes());
    signed_msg.extend_from_slice(&proof.t2.to_bytes());
    signed_msg.extend_from_slice(mu);
    let signature = issuer_sk.sign(&signed_msg);
    println!("  Ed25519 sig (64 bytes) = {}", hex(&signature.to_bytes()));

    // ---- Verifier: check signature, then CPC.Verify ----
    println!("\nVerifier:");
    let sig_ok = issuer_vk.verify(&signed_msg, &signature).is_ok();
    println!("  Ed25519 signature valid = {sig_ok}");

    let cpc_ok = verify(&pp, &com, &aux.deltas, i, &proof, mu);
    println!("  CPC.Verify              = {cpc_ok}");

    if sig_ok && cpc_ok {
        println!("\n>>> ACCEPT: user authenticated index i={i} under com with issuer's key.");
    } else {
        println!("\n>>> REJECT");
    }

    // ---- Negative case: tampered proof must be rejected ----
    let mut bad = proof.clone();
    bad.u_i.coeffs[0] = (bad.u_i.coeffs[0] + 1) % Q;
    let tampered_ok = verify(&pp, &com, &aux.deltas, i, &bad, mu);
    println!("\nNegative check: tampered u_i -> CPC.Verify = {tampered_ok} (expected false)");
}
