//! CPC performance benchmarks (criterion).
//!
//! Measures the three core operations across path lengths:
//! - `commit/L={8,32,1024}` — `CPC.Commit` (NTT + Merkle build)
//! - `prove/L={8,32,1024}`  — `CPC.Prove` (rejection-sampling loop)
//! - `verify/L={8,32,1024}` — `CPC.Verify` (equation check + Merkle path)

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use cpc::commitment::commit;
use cpc::params::PublicParams;
use cpc::prove::prove;
use cpc::ring::Poly;
use cpc::verify::verify;

/// Build a path `v_0, ..., v_L` with unit-vector steps (norm 1, within `beta`).
fn build_test_path(l: usize) -> Vec<Poly> {
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

fn bench_commit(c: &mut Criterion) {
    let pp = PublicParams::setup(b"bench-seed");
    let mut group = c.benchmark_group("commit");
    for l in [8usize, 32, 1024] {
        let path = build_test_path(l);
        group.bench_function(format!("L={l}"), |b| {
            b.iter(|| {
                commit(black_box(&pp), black_box(&path));
            });
        });
    }
    group.finish();
}

fn bench_prove(c: &mut Criterion) {
    let pp = PublicParams::setup(b"bench-seed");
    let mut group = c.benchmark_group("prove");
    for l in [8usize, 32, 1024] {
        let path = build_test_path(l);
        let (_com, aux) = commit(&pp, &path);
        let i = l / 2;
        group.bench_function(format!("L={l}"), |b| {
            b.iter(|| {
                prove(black_box(&pp), black_box(&aux), black_box(i), b"mu");
            });
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let pp = PublicParams::setup(b"bench-seed");
    let mut group = c.benchmark_group("verify");
    for l in [8usize, 32, 1024] {
        let path = build_test_path(l);
        let (com, aux) = commit(&pp, &path);
        let i = l / 2;
        let proof = prove(&pp, &aux, i, b"mu");
        group.bench_function(format!("L={l}"), |b| {
            b.iter(|| {
                verify(
                    black_box(&pp),
                    black_box(&com),
                    black_box(&aux.deltas),
                    black_box(i),
                    black_box(&proof),
                    b"mu",
                );
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_commit, bench_prove, bench_verify);
criterion_main!(benches);
