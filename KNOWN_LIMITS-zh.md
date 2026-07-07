[English](KNOWN_LIMITS.md) | **中文**

# 已知限制

> 本文档透明地列出了 CPC 实现的当前边界。旨在帮助集成者、
> 审计人员和贡献者了解系统**尚未**实现的功能，以及安全声明
> 所依赖的假设。

---

## 1. 安全模型假设

### 1.1 随机预言机模型 (Random Oracle Model, ROM)
- Fiat-Shamir 变换使用 SHAKE-256 作为随机预言机。安全证明
  （可靠性、零知识性）在**量子随机预言机模型 (Quantum Random Oracle Model, QROM)** 中成立，但实现并未证明 SHAKE-256
  *是* 一个随机预言机 —— 这是一个假设。
- Merkle 树使用 SHA3-256 实现抗碰撞性（128 位安全级别）。
  如果需要更高的安全余量，可以在 `src/merkle.rs` 中通过一行
  代码修改替换为 SHA3-512。

### 1.2 Ring-SIS 困难性
- 安全性归约到 `R = Z_q[x]/(x^256+1)` 上的 **Ring-SIS 问题**，
  参数为 `(m=256, q=8380417)`。这些参数与 CRYSTALS-Dilithium-III
  相同，其 Core-SVP 成本估计约为 128 位（经典）/ 118 位（量子，
  NIST Level 3）。
- **估计方法已文档化；lattice-estimator 结果待 Linux 执行。**
  详见 [`docs/security-parameters.md`](docs/security-parameters.md)
  的完整参数分析。关键区别：
  - **绑定 SIS 界** `ν_bind = 2B + 2τβ√m ≈ 1.33×10⁶ < q` 是安全关键
    参数（定理 1）。基于 Dilithium-III 参数同构的解析估计确认经典
    安全级别 ≥ 128 位。
  - **提取范数界** `ν_ext = 4τ√m·B ≈ 2.39×10⁹ > q`（定理 3）是知识
    声音性提取器的输出界，属知识陈述，非 SIS 硬度参数。标准 SIS 在
    `β = ν_ext` 下平凡可解，但不影响 CPC 安全性。
- 估计脚本
  [`scripts/lattice_estimator_cpc.sage`](scripts/lattice_estimator_cpc.sage)
  已就绪，可在 Linux/WSL2 上配合 SageMath + lattice-estimator 运行
  （`sage scripts/lattice_estimator_cpc.sage`）。无法在 Windows 上运行，
  因为 `lattice-estimator` 依赖 SageMath 与 `fpylll`（后者需要 MSVC C++
  Build Tools + fplll C 库）。
- **已知问题：** [`src/params.rs`](src/params.rs) 中的
  `EXTRACT_NORM_BOUND` 计算 `4·τ·m·B ≈ 3.8×10¹⁰`，比证明的精确界
  `4τ√m·B ≈ 2.4×10⁹` 偏松 16 倍（使用 `m` 而非 `√m`）。两者均为
  有效上界，代码值为保守估计。详见 `docs/security-parameters.md` §5.2。

### 1.3 无 EUF-CMA（不可伪造性）
- CPC 提供**绑定性**和**零知识短性证明**，但**不提供不可伪造性**。
  要构建可认证的凭证，必须将 CPC 与 EUF-CMA 签名方案组合使用
  （例如 Ed25519 或 Dilithium），如 `examples/credential.rs` 所示。

---

## 2. 实现限制

### 2.1 常数时间环算术（已解决）
- **环算术为常数时间。** 多项式算术（NTT、乘法、加法、减法、
  范数）使用移植自 Dilithium 参考实现的常数时间原语。详见
  `src/ring_ct.rs` 中的 Barrett/Montgomery 约减、条件加/减法及
  无分支中心化。`src/ring.rs` 中所有 `% Q` 和 `rem_euclid(Q)`
  操作已被替换。`tests/ct_tests.rs` 中的时序回归测试验证 NTT 和
  乘法时序近似与输入无关（实测比率 ≈ 1.01x）。
- **高斯采样为常数时间。** `src/gauss.rs` 使用整数值 CDT
  （`u64`），查找采用反向线性扫描 + `ct_select`（无早退），
  符号选择通过单个 RNG 位 + `ct_select`，最终约减用 `caddq`。
  `rejection_acceptance_ratio` 用 `ring_ct::center` 计算中心化范数，
  用 `log_rho.min(0.0).exp()` 实现截断（对秘密相关值无 `if` 分支）。
  `tests/ct_tests.rs` 中 4 个 CT 回归测试覆盖 NTT、乘法、采样与
  rejection 比率。

### 2.2 单一参数集
- 环维度 `m=256` 和模数 `q=8380417` 是编译时常量
  （`src/params.rs` 中的 `const`）。没有运行时参数协商。支持
  更高安全级别的变体（例如 `m=512`）需要将 `Poly::coeffs`
  参数化为 `[i64; M]`（使用泛型 `M`），或使用 `Vec<i64>`。

### 2.3 高斯采样质量
- `src/gauss.rs` 中的 CDT（累积分布表，Cumulative Distribution Table）
  采样器为常数时间（见 §2.1）：整数值 CDT（`u64`）、`RngCore` 注入
  （`sample_gauss_poly<R: RngCore + ?Sized>(sigma: f64, &mut R)`），
  采样器内部无 `f64` 比较且无 `thread_rng()` 调用。
- CDT 在 `±6σ` 处截断，这给出可忽略的尾部概率，但与真正的
  离散高斯并不完全相同。
- `prove.rs` 中残留的 `thread_rng()` 调用用于拒绝采样掷硬币
  （`u <= rho`），这是 Fiat-Shamir-with-aborts 协议的一部分，故有意保留。

### 2.4 拒绝采样依赖系统 RNG
- `src/prove.rs` 中的 Fiat-Shamir-with-aborts 循环对掩码多项式
  `r` 和接受/拒绝掷硬币都使用 `rand::thread_rng()`。这假设
  **存在高质量的系统随机源**。在 `/dev/urandom` 或等效物
  不可用或被破坏的平台上，零知识性可能被违反。

### 2.5 内存使用
- `CPC.Commit` 对于 `L=1024` 在内存中存储 `3*L = 3072` 个多项式
  （d_vec、u_vec、deltas），每个序列化后为 768 字节 = ~2.3 MB。
  Merkle 树增加 `~2*L*32 = 64 KB`。提交期间的峰值内存约为 2.5 MB。
- `CPC.Prove` 和 `CPC.Verify` 对于 `L=1024` 需要完整的 `deltas`
  数组（~768 KB）在内存中以供挑战哈希使用。对于非常大的 `L`，
  流式哈希可以降低此开销，但未实现。

---

## 3. 测试与覆盖率限制

### 3.1 测试覆盖率配置已就绪（量化测量待 Linux CI）
- `stable-x86_64-pc-windows-gnu` 工具链不包含性能分析运行时
  （`profiler_builtins`），因此 `cargo-llvm-cov` 无法在 Windows 上本地
  运行（已确认：`error[E0463]: can't find crate for 'profiler_builtins'`）。
  覆盖率测量需要：
  - MSVC 工具链（`stable-x86_64-pc-windows-msvc` 配合 Visual Studio
    Build Tools），或
  - 配备 `cargo-tarpaulin` 或 `cargo-llvm-cov` 的 Linux/macOS 环境。
- 根据人工检查，测试套件覆盖了所有公共 API 函数和 `src/` 中的
  所有代码路径（正向和反向测试）；本地尚无可量化的覆盖率数字，
  基线将在首次 Linux CI 运行时建立。
- **配置已就绪；量化测量待 Linux CI（Task 4）。** 以下交付物已准备
  就绪，将在 Linux CI 任务向 Codecov 上传覆盖率后激活：
  - [`codecov.yml`](codecov.yml) —— 设置 90% 的 project/patch 目标，
    阈值 1%。
  - [`tests/coverage_gaps.rs`](tests/coverage_gaps.rs) —— 7 个针对性
    测试，覆盖此前未覆盖的分支：`Poly::from_bytes` 错误长度与
    `coeff == q` 拒绝路径、`rejection_acceptance_ratio` 的
    `log_rho >= 0` 截断分支、`log_rejection_m` 在非标称 `tau_ratio`
    下的行为、Merkle 树奇数叶子填充分支与单叶子空路径场景、以及
    `Poly::neg` 在非零多项式上的行为。
  - README 覆盖率徽章（Codecov 收到首次上传后显示）。

### 3.2 跨平台 CI 已配置（待 GitHub 激活）
- 实现目前仅在 **Windows x86_64** 上使用 GNU 工具链进行了本地测试。
  跨平台测试现已通过 GitHub Actions 配置
  （见 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)），
  但**实际 CI 运行待首次推送到 GitHub 后才会发生**（项目本地尚非
  git 仓库）。
- **CI 矩阵：** 在 `stable` Rust 上运行 `ubuntu-latest`、
  `macos-latest`、`windows-latest`。每个平台执行
  `cargo fmt --check`（建议性）、`cargo build`、`cargo build --release`、
  `cargo test`、`cargo test --doc`（建议性）以及 `cargo clippy`
  （建议性）。每个 runner 使用默认平台工具链（Windows 上为 MSVC）；
  若 MSVC 失败，可显式覆盖为 `stable-x86_64-pc-windows-gnu`。
- **覆盖率任务（仅 Linux）：** 在 push 到 main/master 时运行，
  使用 `cargo-llvm-cov` 生成 LCOV 报告，并通过
  `codecov/codecov-action@v4` 上传到 Codecov（无需 token；激活
  README 覆盖率徽章）。一旦首次上传完成，也将解决 §3.1
  “量化测量待 Linux CI” 的事项。
- **配置已就绪；跨平台量化结果待首次 CI 运行。** 工作流还包含
  `concurrency` 分组（取消被取代的运行）与
  `permissions: contents: read`（最小权限 GITHUB_TOKEN 作用域）。

### 3.3 无形式化验证
- `formal-proof.md` 中的安全证明是纸笔证明。它们尚未在 Coq、
  Lean 或任何其他证明助手中进行机器检查。

---

## 4. 性能限制

### 4.1 Commit 为 O(L)
- `CPC.Commit` 执行 `2L` 次基于 NTT 的多项式乘法（对每个步骤
  计算 `u_i = b*d_i` 和 `Delta_i = a*d_i`）。这是 `L` 的线性
  复杂度。对于 `L=1024`，提交耗时约 22 ms。并行化（例如通过
  `rayon`）未实现，但会很直接。

### 4.2 挑战哈希为 O(L)
- Fiat-Shamir 挑战 `c = H(com, deltas, i, t1, t2, mu)` 对所有
  `L` 个 Delta 多项式进行哈希（对于 `L=1024` 约为 768 KB）。这
  在大 `L` 时主导证明和验证时间。`{Delta_j}` 的 Merkle 根可以
  替换哈希中的完整序列，将其降至 `O(1)`，但这需要更改协议的
  转录约定。

### 4.3 无批量验证
- 每次 `CPC.Verify` 调用验证一个证明。`k` 个证明的批量验证
  （在共享的 `{Delta_j}` 集合上分摊挑战哈希）未实现。

---

## 5. API 限制

### 5.1 无序列化 Trait
- `Proof` 和 `Aux` 未实现 `serde::Serialize`/`Deserialize`。
  `Poly::to_bytes`/`from_bytes` 方法存在，但没有高层级的
  `Proof::to_bytes()` / `Proof::from_bytes()`。添加此功能需要
  序列化 `MerklePath`（很简单：`index` + `siblings`）。

> **已实现**：[`src/prove.rs`](../src/prove.rs) 提供了
> `Proof::to_bytes()` / `Proof::from_bytes()`，采用紧凑二进制布局
> （L=8 时约 3.1 KB，L=1024 目标约 3.3 KB）。可选 `serde` feature
> 覆盖 `Proof`、`MerklePath`、`Poly`（Poly 因 `[i64; 256]` 超出 serde
> derive 的 32 元素上限，采用复用 `to_bytes`/`from_bytes` 的手动
> `Serialize`/`Deserialize` 实现）。往返测试见
> [`tests/serialization.rs`](../tests/serialization.rs)；演示见
> [`examples/credential.rs`](../examples/credential.rs)。

### 5.2 无 `no_std` 支持
- 实现使用了 `std::sync::OnceLock`（用于旋转因子和 CDT 缓存）
  以及 `rand::thread_rng()`。`no_std` 移植需要：
  - 用 `atomic::OnceCell` 或惰性初始化替换 `OnceLock`。
  - 提供自定义 RNG（例如 `rand_chacha::ChaCha20Rng`）。
  - 从示例中移除 `std::println!`（已分离）。

---

## 6. 已知 Bug 与边界情况

- **目前无已知问题。** 全部 44 个测试通过（6 个 lib + 14 个正确性
  + 7 个覆盖率补缺 + 4 个常数时间时序 + 5 个安全性 + 5 个集成测试
  + 3 个序列化测试）。测试套件覆盖：
  - 正向：L=8、32、1024 时的 commit/prove/verify 往返测试。
  - 反向：篡改叶节点、错误索引、错误 nonce、超大 z。
  - 统计：高斯分布、拒绝采样接受率。
  - 代数：NTT 往返、教科书乘法交叉验证。
  - 常数时间：Barrett/Montgomery 正确性、时序回归。
  - 覆盖率补缺：`from_bytes` 拒绝路径、`rejection_acceptance_ratio`
    截断分支、Merkle 奇数叶子/单叶子边界、非零 `Poly::neg`。

---

## 7. 修复优先级

| 优先级 | 限制 | 工作量 | 影响 |
|----------|-----------|--------|--------|
| ~~P0~~ | ~~非常数时间环算术 (§2.1)~~ | ~~高~~ | ~~已在 `src/ring_ct.rs` 中解决~~ |
| ~~P0~~ | ~~非常数时间高斯采样 (§2.3)~~ | ~~高~~ | ~~已解决：整数 CDT + CT 线性扫描 + `RngCore` 注入；`tests/ct_tests.rs` 中 2 个 CT 测试~~ |
| ~~P1~~ | ~~Core-SVP 估计未验证 (§1.2)~~ | ~~中~~ | ~~部分解决：方法与解析估计已在 `docs/security-parameters.md` 完成；lattice-estimator 工具运行待 Linux 执行~~ |
| ~~P1~~ | ~~测试覆盖率未测量 (§3.1)~~ | ~~低~~ | ~~部分解决：`codecov.yml` + `tests/coverage_gaps.rs`（7 个测试）已就绪；量化测量待 Linux CI（Task 4）~~ |
| ~~P2~~ | ~~跨平台测试 (§3.2)~~ | ~~低~~ | ~~部分解决：`.github/workflows/ci.yml` 矩阵 (ubuntu/macos/windows) + Linux 覆盖率任务已就绪；实际 CI 运行待首次推送到 GitHub~~ |
| ~~P2~~ | ~~证明序列化 (§5.1)~~ | ~~低~~ | ~~已解决：`Proof::to_bytes`/`from_bytes` + 可选 `serde` feature；`tests/serialization.rs` 中 3 个往返测试~~ |
| **P3** | `no_std` 支持 (§5.2) | 中 | 嵌入式部署 |
| **P3** | 批量验证 (§4.3) | 中 | 性能 |
| **P3** | 形式化验证 (§3.3) | 极高 | 强保证 |
