//! Correctness tests for CPC primitives.

use cpc::params::{B, BETA, EXTRACT_NORM_BOUND, M, MAX_PATH_LEN, Q, SIGMA, TAU};

#[test]
fn params_consistency() {
    // NTT-friendliness: q ≡ 1 (mod 2m)
    assert_eq!(Q % (2 * M as i64), 1, "q must be 1 mod 2m for NTT");
    // q ≡ 1 (mod 512) for primitive 512th root of unity to exist
    assert_eq!(Q % 512, 1, "q must be 1 mod 512");

    // sigma = 12 * tau * beta
    let sigma_expected = 12.0 * (TAU as f64) * (BETA as f64);
    assert!((SIGMA - sigma_expected).abs() < 1.0, "sigma must equal 12*tau*beta");

    // B ≈ 1.2 * sigma * sqrt(m)
    let b_expected = 1.2 * SIGMA * (M as f64).sqrt();
    assert!((B as f64 - b_expected).abs() < 1.0, "B must equal 1.2*sigma*sqrt(m)");

    // Extract norm bound = 4 * tau * m * B
    assert_eq!(EXTRACT_NORM_BOUND, 4 * (TAU as i64) * (M as i64) * B);

    // Sanity on path length
    assert!(
        MAX_PATH_LEN.is_power_of_two(),
        "MAX_PATH_LEN should be a power of two for clean Merkle padding"
    );
}

#[test]
fn q_is_prime() {
    let q = Q;
    assert!(q > 1);
    let mut i = 2i64;
    while i * i <= q {
        assert_ne!(q % i, 0, "q is not prime: divisible by {i}");
        i += 1;
    }
}

#[test]
fn ring_add_sub_neg_consistency() {
    use cpc::ring::Poly;

    let a = Poly::from_coefficients(&[1, 2, 3, 0, -5, 0, 0, 0]);
    let b = Poly::from_coefficients(&[-1, 1, -1, 1, 5, 0, 0, 0]);

    // (a + b) - b == a
    let sum = &a + &b;
    let recovered = &sum - &b;
    assert_eq!(recovered.coeffs, a.coeffs);

    // (-a) + a == 0
    let neg_a = a.neg();
    let zero = &neg_a + &a;
    assert!(zero.coeffs.iter().all(|&c| c % Q == 0));

    // zero() is all zeros
    assert!(Poly::zero().coeffs.iter().all(|&c| c == 0));
}

#[test]
fn ring_neg_of_zero_is_zero() {
    use cpc::ring::Poly;
    assert!(Poly::zero().neg().coeffs.iter().all(|&c| c == 0));
}

#[test]
fn ring_mul_by_zero_is_zero() {
    use cpc::ring::Poly;
    let a = Poly::from_coefficients(&[1, 2, 3, 0, 0, 0, 0, 0]);
    let z = Poly::zero();
    let r = &a * &z;
    assert!(r.coeffs.iter().all(|&c| c == 0));
}

#[test]
fn ring_ntt_round_trip() {
    use cpc::ring::Poly;
    let mut p = Poly::from_coefficients(&[1, 2, 3, 4, 5, 6, 7, 8, -1, -2, -3, -4, 0, 0, 0, 0]);
    let original = p.clone();
    p.ntt();
    p.inv_ntt();
    assert_eq!(p.coeffs, original.coeffs, "inv_ntt(ntt(p)) must equal p");
}

#[test]
fn ring_mul_ntt_equals_schoolbook() {
    use cpc::ring::Poly;
    // a = 1 + 2x, b = 3 + 4x  ->  a*b = 3 + 10x + 8x^2  (mod x^m+1 no wrap for small deg)
    let a = Poly::from_coefficients(&[1, 2]);
    let b = Poly::from_coefficients(&[3, 4]);
    let got = &a * &b;

    let mut want = [0i64; M];
    for i in 0..M {
        for j in 0..M {
            let k = i + j;
            let v = a.coeffs[i] * b.coeffs[j];
            if k < M {
                want[k] = (want[k] + v) % Q;
            } else {
                // x^(k) = -x^(k-m)  under x^m = -1
                want[k - M] = (want[k - M] - v).rem_euclid(Q);
            }
        }
    }
    assert_eq!(got.coeffs, want);
}

#[test]
fn ring_bytes_round_trip() {
    use cpc::ring::Poly;
    let p = Poly::from_coefficients(&[1, 2, 3, 8380416, 0, 5, 8380415, 7]);
    let bytes = p.to_bytes();
    assert_eq!(bytes.len(), 3 * M);
    let q = Poly::from_bytes(&bytes).expect("round trip");
    assert_eq!(q.coeffs, p.coeffs);

    // out-of-range coefficient rejected
    let mut bad = bytes.clone();
    bad[0] = 0xFF;
    bad[1] = 0xFF;
    bad[2] = 0x7F; // >= q
    assert!(Poly::from_bytes(&bad).is_none());
}

#[test]
fn ring_norms() {
    use cpc::ring::Poly;
    let p = Poly::from_coefficients(&[3, 0, 0, 0]); // single nonzero = 3
    assert_eq!(p.norm_inf(), 3);
    assert!((p.norm_l2() - 3.0).abs() < 1e-9);

    // large positive coeff centers to negative: q-5 -> -5 centered
    let q_poly = Poly::from_coefficients(&[(Q - 5) as i32]);
    assert_eq!(q_poly.norm_inf(), 5);
}

#[test]
fn gauss_sampler_distribution() {
    use cpc::gauss::sample_gauss_poly;

    let mut rng = rand::thread_rng();
    let n = 1_000;
    let mut sum = [0f64; M];
    for _ in 0..n {
        let p = sample_gauss_poly(SIGMA, &mut rng);
        for i in 0..M {
            let c = p.coeffs[i];
            let centered = if c > Q / 2 { c - Q } else { c } as f64;
            sum[i] += centered;
        }
    }
    // mean ~ 0 (with 1000 samples and sigma=32400, std of mean is sigma/sqrt(1000) ~ 1024;
    // allow 5x margin)
    for i in 0..M {
        let mean = sum[i] / n as f64;
        assert!(
            mean.abs() < SIGMA * 0.2,
            "coeff {i} mean {mean} too far from 0 (sigma={SIGMA})"
        );
    }

    // tail bound: |x| <= 6*sigma with overwhelming probability
    let p = sample_gauss_poly(SIGMA, &mut rng);
    for c in &p.coeffs {
        let centered = if *c > Q / 2 { Q - *c } else { *c };
        assert!(centered <= (6.0 * SIGMA) as i64, "sample exceeds 6*sigma tail");
    }
}

#[test]
fn rejection_ratio_bounded() {
    use cpc::gauss::{log_rejection_m, rejection_acceptance_ratio};
    use cpc::ring::Poly;

    let z = Poly::zero();
    let z_minus_cd = Poly::zero();
    let log_m = log_rejection_m(12.0);
    let r = rejection_acceptance_ratio(&z, &z_minus_cd, SIGMA, log_m);
    assert!((0.0..=1.0).contains(&r));
}

#[test]
fn public_params_setup() {
    use cpc::params::PublicParams;
    let pp = PublicParams::setup(b"test-seed-12345");
    assert_eq!(pp.m, M);
    assert_eq!(pp.q, Q);
    // determinism: same seed -> same a, b
    let pp2 = PublicParams::setup(b"test-seed-12345");
    assert_eq!(pp.a.coeffs, pp2.a.coeffs);
    assert_eq!(pp.b_elem.coeffs, pp2.b_elem.coeffs);
    // different seed -> (almost certainly) different
    let pp3 = PublicParams::setup(b"different-seed");
    assert_ne!(pp.a.coeffs, pp3.a.coeffs);
}

#[test]
fn challenge_sample_in_ball() {
    use cpc::prove::hash_to_challenge;
    use cpc::ring::Poly;

    let com = [0u8; 32];
    let deltas = vec![Poly::zero()];
    let t1 = Poly::zero();
    let t2 = Poly::zero();
    let c = hash_to_challenge(&com, &deltas, 1, &t1, &t2, b"mu");

    // count nonzero coefficients
    let nonzero: usize = c.coeffs.iter().filter(|&&x| x != 0).count();
    assert_eq!(nonzero, TAU, "challenge must have exactly tau nonzeros");

    // all coeffs in {-1, 0, 1}
    for &x in &c.coeffs {
        let centered = if x > Q / 2 { x - Q } else { x };
        assert!(
            centered == 0 || centered == 1 || centered == -1,
            "coeff out of {{-1,0,1}}: {centered}"
        );
    }

    // determinism: same input -> same output
    let c2 = hash_to_challenge(&com, &deltas, 1, &t1, &t2, b"mu");
    assert_eq!(c.coeffs, c2.coeffs);
}

#[test]
fn commit_returns_distinct_roots_for_distinct_paths() {
    use cpc::commitment::commit;
    use cpc::params::PublicParams;
    use cpc::ring::Poly;

    let pp = PublicParams::setup(b"commit-test");
    let v0 = Poly::from_coefficients(&[1; 8]);
    let v1 = Poly::from_coefficients(&[2; 8]);
    let path_a = vec![v0.clone(), v1.clone()];
    let path_b = vec![v0, Poly::from_coefficients(&[3; 8])];

    let (com_a, aux_a) = commit(&pp, &path_a);
    let (com_b, _aux_b) = commit(&pp, &path_b);
    assert_ne!(com_a, com_b, "distinct paths must yield distinct commitments");

    // aux has L = path.len() - 1 = 1 entries
    assert_eq!(aux_a.d_vec.len(), 1);
    assert_eq!(aux_a.u_vec.len(), 1);
    assert_eq!(aux_a.deltas.len(), 1);

    // step difference is short
    assert!(aux_a.d_vec[0].norm_l2() <= BETA as f64);
}
