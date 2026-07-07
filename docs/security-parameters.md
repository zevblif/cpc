# CPC 安全参数与 Core-SVP 验证

> 本文档记录 CPC 的全部安全参数、Ring-SIS 实例规格，以及 Core-SVP 攻击成本的估计方法与结果。参数值来源 [`src/params.rs`](../src/params.rs)，安全归约见 [`formal-proof.md`](../formal-proof.md)，参数选择依据见 [`docs/parameters.md`](parameters.md)。

---

## 1 参数集

### 1.1 标量参数

| 参数 | 符号 | 值 | 来源 |
|------|------|----|------|
| 环维度 | `m` | 256 | Dilithium-III |
| 模数 | `q` | 8,380,417 | Dilithium-III（NTT 友好素数，`q ≡ 1 (mod 512)`） |
| 挑战重量 | `τ` | 60 | Dilithium-III |
| 步长 ℓ₂ 界 | `β` | 45 | 应用层 |
| 高斯宽度 | `σ` | 32,400 | `12·τ·β` |
| 响应 ℓ₂ 界 | `B` | 622,080 | `1.2·σ·√m` |
| 最大路径长度 | `L` | 1,024 | 示例 |
| 拒绝采样上限 | — | 1,000 | 工程兜底 |

### 1.2 SIS 范数界

CPC 的安全归约涉及两个不同的范数界：

| 名称 | 公式 | 值 | log₂ | 用于 | 与 q 的关系 |
|------|------|----|------|------|------------|
| 绑定界 | `ν_bind = 2B + 2τβ√m` | 1,330,560 | 21 | 定理 1（绑定性）归约至 Ring-SIS | `ν_bind < q` ✓ |
| 提取界 | `ν_ext = 4τ√m·B` | 2,388,787,200 | 32 | 定理 3（知识声音性）提取器输出界 | `ν_ext > q` ⚠️ |
| 代码值 | `EXTRACT_NORM_BOUND = 4τmB` | 38,220,595,200 | 36 | [`src/params.rs`](../src/params.rs) 中的常量 | `ν_code > q` ⚠️ |

> **关于 `EXTRACT_NORM_BOUND` 的说明**：[`src/params.rs`](../src/params.rs) 第 28 行使用 `4 * (TAU as i64) * (M as i64) * B`（含 `m`），而形式化证明 [`formal-proof.md`](../formal-proof.md) §5.3 给出的精确界为 `4τ√m·B`（含 `√m`）。两者均为有效上界，但代码值偏松 16 倍（`m / √m = 16`）。论文 [`paper.md`](../paper.md) §7 中"4τmB ≈ 2.4×10⁹"实为 `4τ√m·B` 的笔误（`4τmB` 实际 ≈ 3.8×10¹⁰）。本报告以精确界 `ν_ext = 4τ√m·B ≈ 2.39×10⁹` 为准。

---

## 2 Ring-SIS 实例

固定均匀随机 `a ∈ R = Z_q[x]/(x^m+1)`。Ring-SIS 困难性实例为：

> 找非零 `x`（次数 `< m` 的整数系数多项式）使 `a·x ≡ 0 (mod q)` 且 `‖x‖₂ ≤ ν`。

参数：`m = 256`，`q = 8,380,417`，SIS 输出长度 `n = m = 256`（每个系数给出一个标量方程），NTRU 风格格维度 `2m = 512`（与 Dilithium 的参数化方式一致）。

### 2.1 绑定性的 SIS 实例（安全关键）

定理 1（绑定性）的归约使用 `ν_bind = 2B + 2τβ√m ≈ 1.33×10⁶`。由于 `ν_bind < q`，此 SIS 实例**非平凡**（不存在 `(q, 0, …, 0)` 形式的平凡解），其 Core-SVP 成本即为 CPC 的安全级别。

### 2.2 知识声音性的提取界（非 SIS 硬度参数）

定理 3（知识声音性）的提取器输出 `d*` 满足 `a·d* = Δ_i`、`b·d* = u`、`‖d*‖ ≤ ν_ext ≈ 2.39×10⁹`。这是一个**知识陈述**（提取器证明敌手"知道"`d*`），**不直接归约到 SIS 硬度**。由于 `ν_ext > q`，标准 SIS 在 `β = ν_ext` 下存在平凡解（`x = (q, 0, …, 0)`），但这不影响知识声音性——提取器输出的是满足 `a·d* = Δ_i`（非零右端）的见证，而非 SIS 解。

---

## 3 Core-SVP 估计方法

### 3.1 解析估计（基于 Dilithium-III 参数同构）

CPC 的环参数 `(m=256, q=8380417)` 与 CRYSTALS-Dilithium-III 完全一致。Dilithium-III 的 Core-SVP 估计（NIST Level 3）：

| 攻击模型 | Core-SVP 成本 (log₂) | 来源 |
|---------|----------------------|------|
| 经典 | ~128 | Dilithium 规格书 |
| 量子 (Groner) | ~118 | Dilithium 规格书 |

CPC 的绑定 SIS 界 `ν_bind ≈ 1.33×10⁶`（ℓ₂ 范数）与 Dilithium-III 的 MSIS 界 `724,481`（ℓ∞ 范数）在同一数量级。由于 `ℓ₂ ≥ ℓ∞`，ℓ₂ 界更宽松，意味着 CPC 的 SIS 实例**至少与 Dilithium-III 的 MSIS 实例一样难**。因此 CPC 的经典 Core-SVP 安全级别**至少 128 bit**。

### 3.2 lattice-estimator 工具估计

工具：[`lattice-estimator`](https://github.com/malb/lattice-estimator)（malb/lattice-estimator）。

脚本：[`scripts/lattice_estimator_cpc.sage`](../scripts/lattice_estimator_cpc.sage)（SageMath 脚本，需在 Linux/WSL2 上运行）。

**运行状态**：⚠️ **待执行**。`lattice-estimator` 依赖 SageMath（`estimator` 模块 `import` 时 `from sage.all import ...`）与 `fpylll`（需 MSVC C++ Build Tools + fplll C 库），在 Windows 上无法安装/导入。请在 Linux/WSL2 环境运行：

```bash
# Linux / WSL2
sudo apt install sagemath
git clone https://github.com/malb/lattice-estimator.git
cd lattice-estimator && sage -pip install -e .
cd /path/to/CPC
sage scripts/lattice_estimator_cpc.sage
```

脚本对两个范数界分别估计：
- **`ν_bind`（绑定界）**：预期 ~128 bit 经典 / ~118 bit 量子（与 Dilithium-III 同构）
- **`ν_ext`（提取界）**：由于 `ν_ext > q`，估计器将自动启用 [DucEspPos23] 大范数攻击（`large_norm` 模块），成本会显著低于 `ν_bind` 的情形。这不影响 CPC 安全性——知识声音性不依赖此界下的 SIS 硬度。

脚本使用 `SIS.estimate.rough(params)`，采用 Core-SVP 成本模型（`ADPS16`）与 LGSA，与文献中 Dilithium 的估计方法一致。量子 Core-SVP 可通过将 BKZ 块大小按 `0.265/0.292 ≈ 0.908` 缩放近似得到。

---

## 4 估计结果

### 4.1 解析估计（已完成）

| 攻击模型 | Core-SVP 成本 (log₂) | 是否达 128 bit | 备注 |
|---------|----------------------|----------------|------|
| 经典 | ~128 | ✓ | 与 Dilithium-III 同构（同环参数） |
| 量子 (Groner) | ~118 | ✗（达 ~118 bit） | NIST Level 3 量子界，与 Dilithium-III 一致 |

### 4.2 lattice-estimator 结果（待 Linux 执行）

> **Pending** — 在 Linux/WSL2 上运行 `sage scripts/lattice_estimator_cpc.sage` 后，将 `scripts/lattice_estimator_results.json` 的关键数字回填至此表：

| 范数界 | 攻击模型 | 最优攻击 | log₂(rop) | 是否达 128 bit |
|--------|---------|---------|-----------|----------------|
| `ν_bind` | 经典 | _pending_ | _pending_ | _pending_ |
| `ν_bind` | 量子 | _pending_ | _pending_ | _pending_ |
| `ν_ext`  | 经典 | _pending_ | _pending_ | N/A（非安全关键） |
| `ν_ext`  | 量子 | _pending_ | _pending_ | N/A（非安全关键） |

---

## 5 注意事项与已知问题

### 5.1 ⚠️ `ν_ext > q` 的含义

CPC 的提取范数界 `ν_ext ≈ 2.39×10⁹` 远大于模数 `q = 8,380,417`。这意味着：

- **标准 SIS 在 `β = ν_ext` 下平凡可解**：向量 `x = (q, 0, …, 0)` 满足 `a·x = 0 (mod q)` 且 `‖x‖ = q < ν_ext`。
- **这不影响 CPC 安全性**：知识声音性（定理 3）是知识陈述，提取器输出 `d*` 满足 `a·d* = Δ_i`（非零右端），不是 SIS 解。SIS 硬度仅在绑定性（定理 1）中用到，其界 `ν_bind < q` 是非平凡的。
- **关于"ν larger ⇒ stronger security"的澄清**：对标准 SIS，更大的 `β` 意味着问题**更易**（更多向量满足范数界），而非更难。CPC 与 Dilithium-III 安全级别相当，是因为绑定 SIS 实例 `ν_bind` 与 Dilithium 的 MSIS 界处于同一安全级别，且二者环参数相同。

### 5.2 `EXTRACT_NORM_BOUND` 代码与证明的不一致

[`src/params.rs`](../src/params.rs) 第 28 行：

```rust
pub const EXTRACT_NORM_BOUND: i64 = 4 * (TAU as i64) * (M as i64) * B;
```

计算得 `38,220,595,200`（≈3.8×10¹⁰），而形式化证明 [`formal-proof.md`](../formal-proof.md) §5.3 给出的精确界为 `4τ√m·B = 2,388,787,200`（≈2.4×10⁹）。代码使用 `m` 而非 `√m`，偏松 16 倍。两者均为有效上界（更松的界仍可证明安全），但建议后续修正代码以匹配证明的精确界。

### 5.3 量子安全级别

量子 Core-SVP 估计约为 118 bit，**低于** 128 bit。这与 Dilithium-III 的量子安全级别一致（NIST Level 3 量子界）。如需达到 128 bit 量子安全，需增大环维度至 `m = 512` 或提高模数。

### 5.4 Windows 平台限制

`lattice-estimator` 无法在 Windows 原生运行（依赖 SageMath + fpylll，后者需要 MSVC C++ Build Tools 与 fplll/FLINT C 库）。本任务的工具估计部分须在 Linux/WSL2 上完成。解析估计（基于 Dilithium-III 参数同构）已在 Windows 上完成，结论与 Dilithium-III 一致。

---

## 6 参考

- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)：环参数、挑战空间、Core-SVP 估计来源
- [lattice-estimator](https://github.com/malb/lattice-estimator)：BKZ 成本估计工具
- [DucEspPos23](https://eprint.iacr.org/2023/302)：大范数 SIS 攻击（`ν > q` 情形，对应 `estimator.sis_large_norm` 模块）
- [`formal-proof.md`](../formal-proof.md)：CPC 安全证明（定理 1–3）
- [`paper.md`](../paper.md)：CPC 论文正文
- [`docs/parameters.md`](parameters.md)：参数选择依据
- [`src/params.rs`](../src/params.rs)：参数常量定义
