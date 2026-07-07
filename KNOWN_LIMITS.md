**English** | [中文](KNOWN_LIMITS-zh.md)

# Known Limitations

> This document transparently lists the current boundaries of the CPC
> implementation. It is intended for integrators, auditors, and contributors
> to understand what the system does **not** yet do, and what assumptions
> underlie the security claims.

---

## 1. Security Model Assumptions

### 1.1 Random Oracle Model
- The Fiat-Shamir transform uses SHAKE-256 as a random oracle. The security
  proofs (soundness, zero-knowledge) hold in the **quantum random oracle
  model (QROM)**, but the implementation does not provide a proof that
  SHAKE-256 *is* a random oracle — this is an assumption.
- The Merkle tree uses SHA3-256 for collision resistance (128-bit security
  level). If a higher security margin is desired, SHA3-512 can be substituted
  with a one-line change in `src/merkle.rs`.

### 1.2 Ring-SIS Hardness
- Security reduces to the **Ring-SIS problem** over `R = Z_q[x]/(x^256+1)`
  with `(m=256, q=8380417)`. These are the same parameters as
  CRYSTALS-Dilithium-III, for which the Core-SVP cost is estimated at
  ~128 bits (classical) / ~118 bits (quantum, NIST Level 3).
- **Methodology documented; lattice-estimator results pending Linux
  execution.** See [`docs/security-parameters.md`](docs/security-parameters.md)
  for the full parameter analysis. Key distinction:
  - The **binding SIS bound** `ν_bind = 2B + 2τβ√m ≈ 1.33×10⁶ < q` is the
    security-critical parameter (Theorem 1). Analytical estimate based on
    Dilithium-III parameter isomorphism confirms ≥128-bit classical security.
  - The **extraction norm bound** `ν_ext = 4τ√m·B ≈ 2.39×10⁹ > q` (Theorem 3)
    bounds the knowledge-soundness extractor output; it is a knowledge
    statement, not a SIS-hardness parameter. Standard SIS with `β = ν_ext` is
    trivially solvable, but this does not affect CPC security.
- The estimation script
  [`scripts/lattice_estimator_cpc.sage`](scripts/lattice_estimator_cpc.sage)
  is ready to run on Linux/WSL2 with SageMath + lattice-estimator
  (`sage scripts/lattice_estimator_cpc.sage`). It cannot run on Windows
  because `lattice-estimator` depends on SageMath and `fpylll` (which
  requires MSVC C++ Build Tools + the fplll C library).
- **Known issue:** `EXTRACT_NORM_BOUND` in
  [`src/params.rs`](src/params.rs) computes `4·τ·m·B ≈ 3.8×10¹⁰`, which is
  16× looser than the proof's precise bound `4τ√m·B ≈ 2.4×10⁹` (uses `m`
  instead of `√m`). Both are valid upper bounds; the code value is
  conservative. See `docs/security-parameters.md` §5.2.

### 1.3 No EUF-CMA (Unforgeability)
- CPC provides **binding** and **zero-knowledge shortness proofs**, but
  **not unforgeability**. To build an authenticatable credential, CPC must
  be composed with an EUF-CMA signature scheme (e.g., Ed25519 or
  Dilithium), as demonstrated in `examples/credential.rs`.

---

## 2. Implementation Limitations

### 2.1 Constant-Time Ring Arithmetic (Addressed)
- **Ring arithmetic is constant-time.** Polynomial arithmetic (NTT,
  multiplication, addition, subtraction, norms) uses constant-time
  primitives ported from the Dilithium reference implementation. See
  `src/ring_ct.rs` for Barrett/Montgomery reduction, conditional
  add/subtract, and branchless centering. All `% Q` and `rem_euclid(Q)`
  operations in `src/ring.rs` have been replaced. Timing regression tests
  in `tests/ct_tests.rs` verify NTT and multiplication timing is
  approximately input-independent (measured ratio ≈ 1.01x).
- **Gaussian sampling is constant-time.** `src/gauss.rs` uses an
  integer-valued CDT (`u64`), reverse linear scan + `ct_select` for
  lookup (no early exit), single RNG bit + `ct_select` for sign
  selection, and `caddq` for final reduction. `rejection_acceptance_ratio`
  uses `ring_ct::center` for centered norms and `log_rho.min(0.0).exp()`
  for the clamp (no `if` on secret-dependent values). Four CT regression
  tests in `tests/ct_tests.rs` cover NTT, multiplication, sampling, and
  rejection ratio.

### 2.2 Single Parameter Set
- The ring dimension `m=256` and modulus `q=8380417` are compile-time
  constants (`const` in `src/params.rs`). There is no runtime parameter
  negotiation. Supporting a higher-security variant (e.g., `m=512`)
  would require parameterizing `Poly::coeffs` as `[i64; M]` with a
  generic `M`, or using a `Vec<i64>`.

### 2.3 Gaussian Sampling Quality
- The CDT (Cumulative Distribution Table) sampler in `src/gauss.rs` is
  constant-time (see §2.1): integer-valued CDT (`u64`), `RngCore` injection
  (`sample_gauss_poly<R: RngCore + ?Sized>(sigma: f64, &mut R)`), no `f64`
  comparisons and no `thread_rng()` inside the sampler.
- The CDT is truncated at `±6σ`, which gives a negligible tail
  probability but is not exactly the same as the true discrete Gaussian.
- The remaining `thread_rng()` use in `prove.rs` is for the rejection
  coin flip (`u <= rho`), which is part of the Fiat-Shamir-with-aborts
  protocol and is intentionally retained.

### 2.4 Rejection Sampling Depends on System RNG
- The Fiat-Shamir-with-aborts loop in `src/prove.rs` uses
  `rand::thread_rng()` for both the masking polynomial `r` and the
  acceptance/rejection coin flip. This assumes a **high-quality system
  random source**. On platforms where `/dev/urandom` or equivalent is
  unavailable or compromised, the zero-knowledge property may be violated.

### 2.5 Memory Usage
- `CPC.Commit` for `L=1024` stores `3*L = 3072` polynomials in memory
  (d_vec, u_vec, deltas), each 768 bytes serialized = ~2.3 MB. The Merkle
  tree adds `~2*L*32 = 64 KB`. Peak memory during commit is ~2.5 MB.
- `CPC.Prove` and `CPC.Verify` for `L=1024` require the full `deltas`
  array (~768 KB) to be in memory for the challenge hash. For very large
  `L`, a streaming hash could reduce this, but is not implemented.

---

## 3. Testing & Coverage Limitations

### 3.1 Test Coverage Configuration In Place (Measurement Pending Linux CI)
- The `stable-x86_64-pc-windows-gnu` toolchain does not include the
  profiler runtime (`profiler_builtins`), so `cargo-llvm-cov` cannot
  run locally on Windows (confirmed: `error[E0463]: can't find crate
  for 'profiler_builtins'`). Coverage measurement requires either:
  - The MSVC toolchain (`stable-x86_64-pc-windows-msvc` with Visual Studio
    Build Tools), or
  - A Linux/macOS environment with `cargo-tarpaulin` or `cargo-llvm-cov`.
- Based on manual inspection, the test suite exercises all public API
  functions and all code paths in `src/` (positive and negative tests),
  but a quantitative coverage number is not yet available locally; the
  baseline will be established on the first Linux CI run.
- **Configuration in place; measurement requires Linux CI (Task 4).**
  The following deliverables are ready and will activate once the Linux
  CI job uploads coverage to Codecov:
  - [`codecov.yml`](codecov.yml) — sets a 90% project/patch target with a
    1% threshold.
  - [`tests/coverage_gaps.rs`](tests/coverage_gaps.rs) — 7 targeted tests
    covering previously-uncovered branches: `Poly::from_bytes`
    wrong-length and `coeff == q` rejection, `rejection_acceptance_ratio`
    `log_rho >= 0` clamp branch, `log_rejection_m` at non-nominal
    `tau_ratio`, Merkle-tree odd-leaf padding and single-leaf empty-path
    cases, and `Poly::neg` on nonzero input.
  - README coverage badge (renders once Codecov receives the first
    upload).

### 3.2 Cross-Platform CI Configured (Pending GitHub Activation)
- The implementation has only been tested locally on **Windows x86_64**
  with the GNU toolchain. Cross-platform testing is now configured via
  GitHub Actions (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)),
  but the actual CI run is **pending the first push to GitHub** (the project
  is not yet a git repository locally).
- **CI matrix:** `ubuntu-latest`, `macos-latest`, `windows-latest` on
  `stable` Rust. Each platform runs `cargo fmt --check` (advisory),
  `cargo build`, `cargo build --release`, `cargo test`, `cargo test --doc`
  (advisory), and `cargo clippy` (advisory). The default platform toolchain
  is used on each runner (MSVC on Windows); if MSVC fails, an explicit
  `stable-x86_64-pc-windows-gnu` override can be added.
- **Coverage job (Linux only):** runs on `push` to main/master, uses
  `cargo-llvm-cov` to generate an LCOV report, and uploads it to Codecov
  via `codecov/codecov-action@v4` (tokenless; activates the README coverage
  badge). This also resolves the §3.1 "measurement pending Linux CI" item
  once the first upload lands.
- **Config in place; quantitative cross-platform results pending first
  CI run.** The workflow also includes a `concurrency` group (cancels
  superseded runs) and `permissions: contents: read` (least-privilege
  GITHUB_TOKEN scope).

### 3.3 No Formal Verification
- The security proofs in `formal-proof.md` are pen-and-paper. They have
  not been machine-checked in Coq, Lean, or any other proof assistant.

---

## 4. Performance Limitations

### 4.1 Commit is O(L)
- `CPC.Commit` performs `2L` NTT-based polynomial multiplications
  (computing `u_i = b*d_i` and `Delta_i = a*d_i` for each step). This is
  linear in `L`. For `L=1024`, commit takes ~22 ms. Parallelization
  (e.g., via `rayon`) is not implemented but would be straightforward.

### 4.2 Challenge Hash is O(L)
- The Fiat-Shamir challenge `c = H(com, deltas, i, t1, t2, mu)` hashes
  all `L` Delta polynomials (~768 KB for `L=1024`). This dominates prove
  and verify time at large `L`. A Merkle-root of `{Delta_j}` could
  replace the full sequence in the hash, reducing it to `O(1)`, but this
  would require changing the protocol's transcript convention.

### 4.3 No Batch Verification
- Each `CPC.Verify` call verifies one proof. Batch verification of `k`
  proofs (amortizing the challenge hash over a shared `{Delta_j}` set)
  is not implemented.

---

## 5. API Limitations

### 5.1 No Serialization Trait
- `Proof` and `Aux` do not implement `serde::Serialize`/`Deserialize`.
  The `Poly::to_bytes`/`from_bytes` methods exist, but there is no
  high-level `Proof::to_bytes()` / `Proof::from_bytes()`. Adding this
  would require serializing the `MerklePath` (trivial: `index` +
  `siblings`).

> **Implemented:** `Proof::to_bytes()` / `Proof::from_bytes()` are
> provided in [`src/prove.rs`](../src/prove.rs) with a compact binary
> layout (~3.1 KB for L=8, ~3.3 KB target for L=1024). Optional
> `serde` feature on `Proof`, `MerklePath`, and `Poly` (Poly uses a
> manual `Serialize`/`Deserialize` impl reusing `to_bytes`/`from_bytes`
> because `[i64; 256]` exceeds serde's 32-element derive limit).
> Round-trip tests in [`tests/serialization.rs`](../tests/serialization.rs);
> demo in [`examples/credential.rs`](../examples/credential.rs).

### 5.2 No `no_std` Support
- The implementation uses `std::sync::OnceLock` (for twiddle factor and
  CDT caches) and `rand::thread_rng()`. A `no_std` port would require:
  - Replacing `OnceLock` with `atomic::OnceCell` or lazy initialization.
  - Providing a custom RNG (e.g., `rand_chacha::ChaCha20Rng`).
  - Removing `std::println!` from the example (already separated).

---

## 6. Known Bugs & Edge Cases

- **None known.** All 44 tests pass (6 lib + 14 correctness + 7 coverage_gaps
  + 4 ct_timing + 5 security + 5 integration + 3 serialization). The test
  suite covers:
  - Positive: commit/prove/verify round-trip at L=8, 32, 1024.
  - Negative: tampered leaf, wrong index, wrong nonce, oversized z.
  - Statistical: Gaussian distribution, rejection sampling acceptance rate.
  - Algebraic: NTT round-trip, schoolbook multiplication cross-check.
  - Constant-time: Barrett/Montgomery correctness, timing regression.
  - Coverage gaps: `from_bytes` rejection paths, `rejection_acceptance_ratio`
    clamp branch, Merkle odd-leaf/single-leaf edge cases, nonzero `Poly::neg`.

---

## 7. Remediation Priority

| Priority | Limitation | Effort | Impact |
|----------|-----------|--------|--------|
| ~~P0~~ | ~~Non-constant-time ring arithmetic (§2.1)~~ | ~~High~~ | ~~Addressed in `src/ring_ct.rs`~~ |
| ~~P0~~ | ~~Non-constant-time Gaussian sampling (§2.3)~~ | ~~High~~ | ~~Addressed: integer CDT + CT linear scan + `RngCore` injection; 2 CT tests in `tests/ct_tests.rs`~~ |
| ~~P1~~ | ~~Core-SVP estimate not verified (§1.2)~~ | ~~Medium~~ | ~~Partially addressed: methodology + analytical estimate done in `docs/security-parameters.md`; lattice-estimator tool run pending Linux execution~~ |
| ~~P1~~ | ~~Test coverage not measured (§3.1)~~ | ~~Low~~ | ~~Partially addressed: `codecov.yml` + `tests/coverage_gaps.rs` (7 tests) in place; quantitative measurement pending Linux CI (Task 4)~~ |
| ~~P2~~ | ~~Cross-platform testing (§3.2)~~ | ~~Low~~ | ~~Partially addressed: `.github/workflows/ci.yml` matrix (ubuntu/macos/windows) + Linux coverage job in place; actual CI run pending first push to GitHub~~ |
| ~~P2~~ | ~~Proof serialization (§5.1)~~ | ~~Low~~ | ~~Addressed: `Proof::to_bytes`/`from_bytes` + optional `serde` feature; 3 round-trip tests in `tests/serialization.rs`~~ |
| **P3** | `no_std` support (§5.2) | Medium | Embedded deployment |
| **P3** | Batch verification (§4.3) | Medium | Performance |
| **P3** | Formal verification (§3.3) | Very High | Strong assurance |
