//! Statistical timing regression tests for constant-time ring operations.
//!
//! These tests verify that NTT and polynomial multiplication have timing
//! that is approximately independent of the input data. They are NOT
//! formal side-channel analysis — they are regression tests that catch
//! gross violations of constant-time properties (e.g., if a data-dependent
//! branch is reintroduced).
//!
//! Threshold: 3.0x ratio (generous to avoid CI flakiness while still
//! catching gross regressions; a true constant-time implementation should
//! have a ratio near 1.0).

use std::time::Instant;

use cpc::params::Q;
use cpc::ring::Poly;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Number of iterations per timing measurement.
const ITERATIONS: usize = 2000;

/// Maximum allowed timing ratio between "best case" (zeros) and "worst case"
/// (random) inputs. A true constant-time implementation has ratio ≈ 1.0.
/// 3.0x is generous to avoid CI flakiness while catching gross regressions.
const THRESHOLD: f64 = 3.0;

/// Build a polynomial with pseudo-random coefficients in `[0, Q)`.
fn random_poly() -> Poly {
    let mut rng = StdRng::seed_from_u64(0xC0DE_C0DE_u64);
    let mut p = Poly::zero();
    for c in p.coeffs.iter_mut() {
        *c = rng.gen_range(0..Q);
    }
    p
}

#[test]
fn ntt_timing_independent_of_input() {
    // Warm up (stabilize CPU frequency, fill caches)
    for _ in 0..100 {
        let mut w = Poly::zero();
        w.ntt();
    }

    let zero = Poly::zero();
    let rand_poly = random_poly();

    // Time NTT on all-zero coefficients (best case for non-CT code)
    let t_zero = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut p = zero.clone();
            p.ntt();
        }
        start.elapsed().as_secs_f64()
    };

    // Time NTT on random coefficients (worst case for non-CT code)
    let t_rand = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut p = rand_poly.clone();
            p.ntt();
        }
        start.elapsed().as_secs_f64()
    };

    let ratio = if t_zero > t_rand {
        t_zero / t_rand
    } else {
        t_rand / t_zero
    };
    println!(
        "NTT timing: zero={:.3}ms, random={:.3}ms, ratio={:.2}x (threshold={:.1}x)",
        t_zero * 1000.0,
        t_rand * 1000.0,
        ratio,
        THRESHOLD
    );
    assert!(
        ratio < THRESHOLD,
        "NTT timing ratio {ratio:.2}x exceeds threshold {THRESHOLD}x: \
         zero={t_zero:.3}ms, random={t_rand:.3}ms"
    );
}

#[test]
fn mul_timing_independent_of_secret() {
    // Warm up
    let warmup = Poly::zero();
    for _ in 0..20 {
        let _ = &warmup * &warmup;
    }

    let zero = Poly::zero();
    let rand_poly = random_poly();

    // Time multiplication of zero * zero (best case for non-CT code)
    let t_zero = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = &zero * &zero;
        }
        start.elapsed().as_secs_f64()
    };

    // Time multiplication of random * random (worst case for non-CT code)
    let t_rand = {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = &rand_poly * &rand_poly;
        }
        start.elapsed().as_secs_f64()
    };

    let ratio = if t_zero > t_rand {
        t_zero / t_rand
    } else {
        t_rand / t_zero
    };
    println!(
        "Mul timing: zero={:.3}ms, random={:.3}ms, ratio={:.2}x (threshold={:.1}x)",
        t_zero * 1000.0,
        t_rand * 1000.0,
        ratio,
        THRESHOLD
    );
    assert!(
        ratio < THRESHOLD,
        "Mul timing ratio {ratio:.2}x exceeds threshold {THRESHOLD}x: \
         zero={t_zero:.3}ms, random={t_rand:.3}ms"
    );
}

#[test]
fn gauss_sampling_timing_independent_of_rng_state() {
    use cpc::gauss::sample_gauss_poly;
    use cpc::params::SIGMA;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    let mut warm = StdRng::seed_from_u64(0);
    for _ in 0..20 {
        let _ = sample_gauss_poly(SIGMA, &mut warm);
    }

    let t_zero = {
        let start = Instant::now();
        for _ in 0..200 {
            let mut rng = StdRng::seed_from_u64(0);
            let _ = sample_gauss_poly(SIGMA, &mut rng);
        }
        start.elapsed().as_secs_f64()
    };

    let t_rand = {
        let mut seeds = StdRng::seed_from_u64(1);
        let start = Instant::now();
        for _ in 0..200 {
            let s = seeds.next_u64();
            let mut rng = StdRng::seed_from_u64(s);
            let _ = sample_gauss_poly(SIGMA, &mut rng);
        }
        start.elapsed().as_secs_f64()
    };

    let ratio = if t_zero > t_rand { t_zero / t_rand } else { t_rand / t_zero };
    println!(
        "Gauss sampling: fixed-seed={:.3}ms, rand-seed={:.3}ms, ratio={:.2}x (threshold={:.1}x)",
        t_zero * 1000.0, t_rand * 1000.0, ratio, THRESHOLD
    );
    assert!(ratio < THRESHOLD,
        "Gauss sampling ratio {ratio:.2}x exceeds {THRESHOLD}x");
}

#[test]
fn rejection_ratio_timing_independent_of_secret() {
    use cpc::gauss::{log_rejection_m, rejection_acceptance_ratio};
    use cpc::params::{M, Q, SIGMA};

    let mk = |seed: u64| -> Poly {
        let mut p = Poly::zero();
        let mut s = seed;
        for c in p.coeffs.iter_mut() {
            s = s.wrapping_mul(0x5851F42D4C957F2D).wrapping_add(0x14057B7EF767814F);
            *c = (s % Q as u64) as i64;
        }
        p
    };
    let z = mk(42);
    let z_minus_cd_a = mk(1);
    let z_minus_cd_b = mk(999);

    let t_bound = (cpc::params::BETA as f64) * (M as f64).sqrt();
    let tau_ratio = SIGMA / t_bound;
    let log_m = log_rejection_m(tau_ratio);

    // Use a large iteration count with black_box: rejection_acceptance_ratio is
    // a pure function (no side effects), so `let _ = ...` lets the optimizer
    // eliminate the entire loop in release builds (observed: 0.000ms, NaN/inf
    // ratios). black_box forces the compiler to execute every iteration.
    const RR_ITERS: usize = 50_000;
    for _ in 0..200 {
        std::hint::black_box(rejection_acceptance_ratio(&z, &z_minus_cd_a, SIGMA, log_m));
    }

    let t_a = {
        let start = Instant::now();
        for _ in 0..RR_ITERS {
            std::hint::black_box(rejection_acceptance_ratio(&z, &z_minus_cd_a, SIGMA, log_m));
        }
        start.elapsed().as_secs_f64()
    };
    let t_b = {
        let start = Instant::now();
        for _ in 0..RR_ITERS {
            std::hint::black_box(rejection_acceptance_ratio(&z, &z_minus_cd_b, SIGMA, log_m));
        }
        start.elapsed().as_secs_f64()
    };

    let ratio = if t_a > t_b { t_a / t_b } else { t_b / t_a };
    println!(
        "rejection_ratio: secret_a={:.3}ms, secret_b={:.3}ms, ratio={:.2}x (threshold={:.1}x)",
        t_a * 1000.0, t_b * 1000.0, ratio, THRESHOLD
    );
    assert!(ratio < THRESHOLD,
        "rejection_ratio timing ratio {ratio:.2}x exceeds {THRESHOLD}x");
}
