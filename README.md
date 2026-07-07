**English** | [中文](README-zh.md)

# CPC: Constrained Path Commitment

[![Build Status](https://github.com/zevblif/cpc/actions/workflows/ci.yml/badge.svg)](https://github.com/zevblif/cpc/actions)
[![Coverage](https://codecov.io/gh/zevblif/cpc/branch/main/graph/badge.svg)](https://codecov.io/gh/zevblif/cpc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)

**A post-quantum primitive for selectively disclosing structured paths with zero-knowledge shortness proofs.**

CPC allows you to commit to a sequence of short lattice vectors (a "path"), then later prove that you know a specific segment of it, while revealing *only* that segment and nothing else. The commitment is **constant-size (32 bytes)**, and the proof is **~3.3 KB** at 128-bit security.

Unlike general-purpose zero-knowledge proofs, CPC is specifically designed for paths where each step difference must be *short*—a property needed in supply-chain tracking, verifiable credentials with sequential constraints, and privacy-preserving location proofs.

## Why CPC?

- **Selective disclosure for paths** – Prove you own a valid chain (e.g., educational history, product journey) but reveal only the link you're challenged on.
- **Post-quantum security** – Based on the same ring assumptions as CRYSTALS-Dilithium (Ring‑SIS).
- **Compact and fast** – Constant-size commitment (32 B), proof size comparable to a Dilithium signature.
- **Plug-and-play with signatures** – CPC handles the *relationship* proof; combine with any EUF‑CMA signature to add *authentication*.
- **Formally verified security** – Complete proofs of binding, statistical zero-knowledge, and knowledge soundness in the random oracle model.

## How It Works (in one picture)

```
 Path:  v0 -> v1 -> ... -> vL   (each step ||vi - v(i-1)|| <= beta)

  1. Commit:
     For each step di = vi - v(i-1):
         ui = b * di          <- SIS-hiding commitment
     Build Merkle tree over {ui}, root = com (32 bytes)

  2. Prove (for index i):
     Run a 2-equation Sigma-protocol:
         a * di = Delta_i     <- public projection
         b * di = ui          <- hidden leaf commitment
     Challenge space: same as Dilithium (sparse +-1 polynomials)
     Use Fiat-Shamir with aborts -> non-interactive, zero-knowledge

  3. Verify:
     Check proof equations, Merkle path, and short-vector norm.
```

**Key insight:** The challenge difference `c - c'` is *invertible* in our ring with a *bounded* inverse—this lets us extract the witness from two different responses, closing the knowledge-soundness proof.

## Status

**Research prototype — fully implemented.** The scheme is fully specified (see [paper.md](paper.md) and [formal-proof.md](formal-proof.md)) and the implementation is complete: all 44 tests pass, benchmarks are available in [benches/results.txt](benches/results.txt), and known limitations are documented in [KNOWN_LIMITS.md](KNOWN_LIMITS.md). This code has not been audited. Use at your own risk.

## Getting Started

### Prerequisites
- Rust 1.70+ (developed on 1.93)
- A CPU with SHA-3 and NTT support (any modern x86-64 or ARM64)

### Installation
Add CPC to your `Cargo.toml`:
```toml
[dependencies]
cpc = { git = "https://github.com/zevblif/cpc" }
```

### Basic Usage
```rust
use cpc::{PublicParams, commit, prove, verify};
use cpc::ring::Poly;

// 1. Build a path (v0, v1, ..., vL) with short step differences
let pp = PublicParams::setup(b"demo-seed");
let path: Vec<Poly> = /* user-supplied, ||v_i - v_{i-1}|| <= beta */;
let (com, aux) = commit(&pp, &path);
// aux.deltas is the public projection {Delta_j = a * d_j}

// 2. Verifier sends a nonce
let nonce = b"verifier-challenge-123";

// 3. Prover selects an index and creates a proof
let i = 3;
let proof = prove(&pp, &aux, i, nonce);

// 4. Verifier checks
assert!(verify(&pp, &com, &aux.deltas, i, &proof, nonce));
```

### Integrating with Signatures
See [examples/credential.rs](examples/credential.rs) for a full example where a CPC proof is signed with Ed25519, producing an authenticatable selective-disclosure credential.

## Documentation

| Document | Description |
|----------|-------------|
| [paper.md](paper.md) | Readable paper explaining the scheme, security, and performance |
| [formal-proof.md](formal-proof.md) | Detailed, line-by-line security proofs |
| [docs/design.md](docs/design.md) | Architectural decisions and design rationale |
| [docs/parameters.md](docs/parameters.md) | Parameter selection methodology |
| [docs/comparison.md](docs/comparison.md) | Comparison with BBS+, Bulletproofs, Merkle trees |
| [docs/security-parameters.md](docs/security-parameters.md) | Parameter analysis and Core-SVP security estimates |
| [docs/cpc-flow.html](docs/cpc-flow.html) | Interactive protocol flow visualization (bilingual) |

**Chinese translations:** [README-zh.md](README-zh.md) | [KNOWN_LIMITS-zh.md](KNOWN_LIMITS-zh.md) (other docs are originally in Chinese)

## Security

CPC's security has been formally proven under the following assumptions:
- **Ring-SIS** (same parameters as Dilithium-III)
- **Collision-resistant hashing** (for the Merkle tree)
- **Random oracle model** (for Fiat-Shamir transformation)

The three core properties:
- **Binding** – No one can open the same index to two different values.
- **Statistical zero-knowledge** – Proofs leak nothing about other path segments.
- **Knowledge soundness** – Any valid prover *must know* a short vector satisfying the equations, or we can solve Ring-SIS.

**Status:** This implementation is a research prototype and has not been audited. Use at your own risk.

## Performance

All measurements on **Intel i5-12500H**, Rust 1.93.1 (`stable-x86_64-pc-windows-gnu`),
`bench` profile (opt-level=3, lto=thin). Full results: [benches/results.txt](benches/results.txt).

| Operation | L=8    | L=32   | L=1024   |
|-----------|--------|--------|----------|
| Commit    | 157 µs | 660 µs | 21.7 ms  |
| Prove     |  77 µs | 144 µs |  3.1 ms  |
| Verify    |  60 µs | 107 µs |  2.2 ms  |

- **Commitment size:** 32 bytes (constant, independent of L)
- **Proof size (L=1024):** 3,400 bytes (~3.32 KB) — matches theory target ~3.3 KB
- **Rejection sampling:** 76% acceptance rate (||d||=1); ~37% at worst-case ||d||≈β√m

### Comparison with Other Schemes

| Metric | CPC (L=1024) | Dilithium-2 | BBS+ (256-bit) | Merkle + Bulletproofs |
|--------|--------------|-------------|----------------|-----------------------|
| Signature/proof size | ~3.3 KB | ~2.4 KB | ~5-10 KB | ~1-2 KB |
| Commitment size | 32 bytes | N/A | ~128 bytes | 32 bytes |
| Prove time | ~3.1 ms | ~0.1 ms | ~10-50 ms | ~10-100 ms |
| Verify time | ~2.2 ms | ~0.05 ms | ~1-5 ms | ~10-50 ms |
| Post-quantum | Yes | Yes | No | No |
| Chain relationship proof | Native | No | No | Requires circuit |
| Constant-size commit | Yes | N/A | No | Yes |

See [benches/benchmark.rs](benches/benchmark.rs) for the criterion benchmark source code.

## Known Limitations

This is a research prototype. Key limitations include:
- **Single parameter set** (m=256, compile-time constant)
- **Coverage measurement pending** Linux CI run (configuration in place; GNU toolchain lacks profiler runtime)
- **No `no_std` support** (uses `std::sync::OnceLock` and `thread_rng`)

Constant-time ring arithmetic and Gaussian sampling are implemented and covered by timing regression tests (see [KNOWN_LIMITS.md](KNOWN_LIMITS.md) §2.1).

See [KNOWN_LIMITS.md](KNOWN_LIMITS.md) for the complete list with remediation priorities.

## References & Acknowledgments

This work builds directly on:
- **CRYSTALS-Dilithium** – Ring parameters, challenge space, and invertibility lemma.
- **Fiat-Shamir with Aborts** (Lyubashevsky, ASIACRYPT 2009) – Framework for lattice-based zero-knowledge proofs.
- **Lattice-based vector commitments** (Libert-Peters-Yung, EUROCRYPT 2021) – Background on pure-lattice alternatives.

We also compared against BBS+ credentials and Merkle tree + Bulletproofs approaches; see [docs/comparison.md](docs/comparison.md).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or pull request. For major changes, let's discuss first.

---

*Built with Rust and love for the post-quantum future.*
