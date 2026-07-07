[English](README.md) | **中文**

# CPC：Constrained Path Commitment（受约束路径承诺）

[![Build Status](https://github.com/zevblif/cpc/actions/workflows/ci.yml/badge.svg)](https://github.com/zevblif/cpc/actions)
[![Coverage](https://codecov.io/gh/zevblif/cpc/branch/main/graph/badge.svg)](https://codecov.io/gh/zevblif/cpc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)

**一种后量子原语，用于选择性披露结构化路径并提供零知识短证明。**

CPC 允许你承诺一串短格向量（一条"路径"），随后证明你知晓其中某一段，且仅揭示该段内容，其余信息一概不泄露。承诺（commitment）是**常数大小（32 字节）**，在 128 位安全级别下证明大小约为 **3.3 KB**。

与通用零知识证明不同，CPC 专为每一步差值都必须是*短向量*的路径而设计——这一性质在供应链追踪、带有序列约束的可验证凭证（verifiable credentials）以及隐私保护的位置证明中十分必要。

## 为什么选择 CPC？

- **路径的选择性披露** —— 证明你拥有一条有效链（如教育经历、产品流转路径），但仅披露被挑战的那一环。
- **后量子安全** —— 基于与 CRYSTALS-Dilithium 相同的环假设（Ring-SIS）。
- **紧凑且高效** —— 常数大小的承诺（32 B），证明大小可与 Dilithium 签名相当。
- **与签名即插即用** —— CPC 负责*关系*证明；与任意 EUF-CMA 签名组合即可加入*认证*能力。
- **形式化验证的安全** —— 在随机预言机模型（random oracle model）下提供绑定性（binding）、统计零知识性（statistical zero-knowledge）和知识可靠性（knowledge soundness）的完整证明。

## 工作原理（一张图说明）

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

**关键洞察：** 在我们选定的环中，挑战差 `c - c'` 是*可逆的*且其逆元*有界*——这使我们能够从两个不同的响应中提取出见证（witness），从而完成知识可靠性证明。

## 状态

**研究原型——已完整实现。** 方案已完整规范（参见 [paper.md](paper.md) 与 [formal-proof.md](formal-proof.md)），实现也已完整：全部 44 项测试通过，基准测试结果见 [benches/results.txt](benches/results.txt)，已知限制记录于 [KNOWN_LIMITS-zh.md](KNOWN_LIMITS-zh.md)。本代码尚未经过审计，使用风险自负。

## 快速上手

### 前置条件
- Rust 1.70+（开发环境为 1.93）
- 支持 SHA-3 与 NTT 的 CPU（任意现代 x86-64 或 ARM64 均可）

### 安装
将 CPC 加入你的 `Cargo.toml`：
```toml
[dependencies]
cpc = { git = "https://github.com/zevblif/cpc" }
```

### 基本用法
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

### 与签名集成
完整示例见 [examples/credential.rs](examples/credential.rs)，其中 CPC 证明由 Ed25519 签名，生成可认证的选择性披露凭证。

## 文档

| 文档 | 说明 |
|----------|-------------|
| [paper.md](paper.md) | 可读性强的论文，介绍方案、安全性与性能 |
| [formal-proof.md](formal-proof.md) | 逐行详尽的安全性证明 |
| [docs/design.md](docs/design.md) | 架构决策与设计理由 |
| [docs/parameters.md](docs/parameters.md) | 参数选择方法 |
| [docs/comparison.md](docs/comparison.md) | 与 BBS+、Bulletproofs、Merkle 树的对比 |
| [docs/security-parameters.md](docs/security-parameters.md) | 参数分析与 Core-SVP 安全估计 |
| [docs/cpc-flow.html](docs/cpc-flow.html) | 交互式协议流程可视化（中英双语） |

## 安全性

CPC 的安全性在以下假设下已得到形式化证明：
- **Ring-SIS**（参数与 Dilithium-III 相同）
- **抗碰撞哈希**（用于 Merkle 树）
- **随机预言机模型**（用于 Fiat-Shamir 变换）

三个核心性质：
- **绑定性（Binding）** —— 无人能将同一索引打开为两个不同的值。
- **统计零知识性（Statistical zero-knowledge）** —— 证明不会泄露关于其他路径段的任何信息。
- **知识可靠性（Knowledge soundness）** —— 任何有效的证明者都*必须知晓*一个满足方程组的短向量，否则我们即可求解 Ring-SIS。

**状态：** 本实现为研究原型，尚未经过审计，使用风险自负。

## 性能

所有测量均在 **Intel i5-12500H** 上完成，Rust 1.93.1（`stable-x86_64-pc-windows-gnu`），使用 `bench` profile（opt-level=3, lto=thin）。完整结果见 [benches/results.txt](benches/results.txt)。

| 操作 | L=8    | L=32   | L=1024   |
|-----------|--------|--------|----------|
| 承诺（Commit）    | 157 µs | 660 µs | 21.7 ms  |
| 证明（Prove）     |  77 µs | 144 µs |  3.1 ms  |
| 验证（Verify）    |  60 µs | 107 µs |  2.2 ms  |

- **承诺大小：** 32 字节（常数，与 L 无关）
- **证明大小（L=1024）：** 3,400 字节（约 3.32 KB）—— 与理论目标约 3.3 KB 一致
- **拒绝采样（Rejection sampling）：** 76% 接受率（||d||=1）；最坏情况 ||d||≈β√m 下约 37%

### 与其他方案的对比

| 指标 | CPC (L=1024) | Dilithium-2 | BBS+ (256-bit) | Merkle + Bulletproofs |
|--------|--------------|-------------|----------------|-----------------------|
| 签名/证明大小 | ~3.3 KB | ~2.4 KB | ~5-10 KB | ~1-2 KB |
| 承诺大小 | 32 bytes | N/A | ~128 bytes | 32 bytes |
| 证明时间 | ~3.1 ms | ~0.1 ms | ~10-50 ms | ~10-100 ms |
| 验证时间 | ~2.2 ms | ~0.05 ms | ~1-5 ms | ~10-50 ms |
| 后量子 | 是 | 是 | 否 | 否 |
| 链关系证明 | 原生支持 | 否 | 否 | 需要电路 |
| 常数大小承诺 | 是 | N/A | 否 | 是 |

criterion 基准测试源码见 [benches/benchmark.rs](benches/benchmark.rs)。

## 已知限制

本项目为研究原型。主要限制包括：
- **单一参数集**（m=256，编译期常量）
- **覆盖率测量待 Linux CI 首次运行**（配置已就绪；GNU 工具链缺少覆盖率运行时）
- **不支持 `no_std`**（使用了 `std::sync::OnceLock` 与 `thread_rng`）

常数时间环算术与高斯采样已实现，并由时序回归测试覆盖（详见 [KNOWN_LIMITS-zh.md](KNOWN_LIMITS-zh.md) §2.1）。

含修复优先级的完整列表见 [KNOWN_LIMITS-zh.md](KNOWN_LIMITS-zh.md)。

## 参考与致谢

本工作直接建立于以下成果之上：
- **CRYSTALS-Dilithium** —— 环参数、挑战空间与可逆性引理。
- **Fiat-Shamir with Aborts**（Lyubashevsky, ASIACRYPT 2009）—— 基于格的零知识证明框架。
- **Lattice-based vector commitments**（Libert-Peters-Yung, EUROCRYPT 2021）—— 纯格方案的背景。

我们也与 BBS+ 凭证及 Merkle 树 + Bulletproofs 方案做了对比，详见 [docs/comparison.md](docs/comparison.md)。

## 许可证

本项目基于 MIT 许可证授权。详情见 [LICENSE](LICENSE)。

## 贡献

欢迎贡献！请提交 issue 或 pull request。对于重大变更，请先讨论。

---

*以 Rust 与热爱构建，面向后量子未来。*
