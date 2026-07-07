# CPC 设计决策与架构

> 本文档记录 CPC（Constrained Path Commitment）方案的关键设计选择、备选方案与权衡。方案的完整构造见 [paper.md](../paper.md)，安全证明见 [formal-proof.md](../formal-proof.md)。

## 1 设计目标

CPC 旨在满足以下有时相互冲突的目标，最终方案是这一目标空间的帕累托最优点：

1. **后量子安全** —— 安全性归约至格问题（Ring‑SIS），不依赖配对或离散对数。
2. **恒定大小承诺** —— 不论路径长度 `L`，承诺固定为 32 字节。
3. **紧凑证明** —— 单次选择性打开证明 ~3.3 KB，与单条 Dilithium 签名同量级。
4. **原生支持短性约束** —— 路径步长 `||d_i|| ≤ β` 作为协议一等公民，无需额外范围证明。
5. **可与签名组合** —— 不自身提供不可伪造性，留作与 EUF‑CMA 签名方案的组合层。
6. **可实现性** —— 全部构件均有成熟的参考实现（NTT、SHAKE、Merkle 树、拒绝采样）。

## 2 关键架构决策

### 2.1 序列绑定：Merkle 树 vs. 多项式承诺

| 备选 | 优点 | 缺点 | 决策 |
|------|------|------|------|
| **抗碰撞 Merkle 树**（采用） | 承诺恒定 32 B；构造简单；绑定归约至 CRHF；与短性证明解耦 | 打开证明 `O(log L)`；本方案中 ≈ 0.32 KB（`L=1024`） | ✔ |
| 纯格向量承诺（Libert‑Peters‑Yung） | 单群元素承诺；代数上与短性证明同构 | 范数膨胀严重；证明在格维度上更大；构造复杂、无成熟实现 | ✘ |
| Merkle + Bulletproofs（短性作为范围证明电路） | 表达力强 | Bulletproofs 基于离散对数，**非后量子** | ✘ |
| KZG‑style 多项式承诺 | 单群元素；常数大小打开 | 需配对，**非后量子**； trusted setup | ✘ |

**结论**：Merkle 树用 CRHF 承担"序列绑定"，留代数结构给"短性证明"。这一解耦使两部分的安全性归约相互独立，且各自都有成熟工具。

### 2.2 短性证明环：Dilithium 式环

采用 `R = Z_q[x]/(x^m+1)`，`m=256`，`q=8380417`，与 CRYSTALS‑Dilithium 完全一致。原因：

- **NTT 友好**：`q ≡ 1 (mod 512)`，存在 512 次单位根，`m=256` 点 NTT 可在环内高效完成。
- **挑战可逆性**（关键）：Dilithium 已证明，系数在 `{-1,0,1}` 且重量 `τ` 的多项式与 `x^m+1` 互素，在 `R` 中可逆，且逆的 `ℓ∞` 范数 ≤ `τ`。这使知识声音性证明中的提取器 `d* = Δc^{-1}(z-z')` 范数可控（引理 2）。
- **可复用实现**：可直接复用 Dilithium 参考实现的 NTT、`SampleInBall`、拒绝采样代码，降低实现风险。
- **安全分析成熟**：Core‑SVP 估计在该参数下约 128 比特，与 NIST PQC 标准化方案对齐。

### 2.3 两方程 Σ‑协议

证明者需同时证明 `a·d = Δ_i`（公开投影一致性）和 `b·d = u_i`（叶子绑定）。两个方程共享同一秘密 `d` 和同一挑战 `c`，因此可在单个 Σ‑协议中并行处理：

```
t1 = a·r,  t2 = b·r                    // 承诺
c  = H(com, {Δ_j}, i, t1, t2, μ)       // 挑战
z  = r + c·d                            // 响应
```

验证者由 `z` 反推 `t1' = a·z - c·Δ_i`、`t2' = b·z - c·u_i`，验证哈希一致。**省略 `t1, t2` 不放入证明**，由验证者重算，节省约 1.6 KB。

### 2.4 Fiat‑Shamir with Aborts

采用 Lyubashevsky 2009 的"带中止的 Fiat‑Shamir"框架：

- 响应 `z = r + c·d` 经拒绝采样后，分布被清洗为与 `d` 无关的离散高斯 `D_{R,σ}`，从而获得**统计零知识**。
- 期望重复次数 `M ≈ 2.7`（`τ_ratio = 12`），最坏情况由 `MAX_REJECT_ITERATIONS = 1000` 兜底。

### 2.5 公开投影 `{Δ_j}` 的取舍

验证者需要 `{Δ_j = a·d_j}_{j=1..L}` 作为公共输入参与挑战哈希。这是必要的安全代价：若挑战不绑定所有 `Δ_j`，敌手可篡改其他位置的投影而不影响当前证明的哈希。

- **大小**：`L=1024` 时，`{Δ_j}` 序列化约 768 KB。这是一次性发布开销，不进入单次证明。
- **挑战哈希成本**：`SHA3-256` 在 768 KB 输入上 ~1 ms，可接受。若 `L` 极大，可预计算 `H({Δ_j})` 的中间 Merkle 化压缩，但当前规模无需。

## 3 模块边界

```
src/
├── params.rs      ← 编译期常量 + PublicParams（携带 a, b）
├── ring.rs        ← R 上的 Poly 类型：加减乘、NTT、序列化、范数
├── gauss.rs       ← D_{R,σ} 采样 + 拒绝采样接受比
├── merkle.rs      ← SHA3-256 Merkle 树 + 认证路径
├── commitment.rs  ← CPC.Commit：组装上述模块，输出 (com, Aux)
├── prove.rs       ← CPC.Prove：Σ‑协议主循环 + hash_to_challenge
└── verify.rs      ← CPC.Verify：复算 t1', t2' + 验证哈希与 Merkle 路径
```

**依赖方向**（无环）：

```
params ← ring ← gauss
        ↑       ↑
        merkle  |
          ↑     |
       commitment → prove ← verify
```

`commitment` 不依赖 `prove`/`verify`；`prove` 依赖 `commitment::Aux`；`verify` 依赖 `prove::{Proof, hash_to_challenge}`。这一方向使每层可独立单测。

## 4 风险与应对

| 风险 | 影响 | 应对 |
|------|------|------|
| NTT 实现错误（中心化、约简、位反转） | 乘法不一致 → 协议失败或安全漏洞 | 复用 Dilithium 验证过的 NTT；增加 `ring_ntt_round_trip` 与 `ring_mul_ntt_equals_schoolbook` 测试（见 [implementation-plan.md](implementation-plan.md) Task 1.2） |
| 拒绝采样实现偏差 | 零知识退化为计算零知识；或接受率偏离 `M ≈ 2.7` | 在对数空间计算接受比；统计测试采样分布的 `χ²` 检验（Task 2.2） |
| 挑战 `SampleInBall` 重量不足 `τ` | 挑战空间缩小 → 声音性下界变弱 | 复用 Dilithium `challenge` 模块；单测断言 `||c||_1 == τ` 且 `||c||_∞ ≤ 1`（Task 2.3） |
| Merkle 树叶子序列化歧义 | 绑定性论证失败 | 固定 3 字节小端序；前缀字节 `0x00`（叶）/ `0x01`（内部）防域混淆（Task 1.3） |
| 参数 `σ, B, τ` 与证明不一致 | 安全定理前提不成立 | 参数集中在 `params.rs`；证明中引用 `params::SIGMA` 等，编译期保证一致 |
| 大 `L` 下 Commit 时间 `O(L log L)` | 实用性下降 | NTT 与 Merkle 均可并行化；如需，可将叶子哈希批处理为 Merkle 化中间根（未来工作） |

## 5 与未来工作的接口

当前骨架为以下扩展预留了空间：

- **更高安全级别**（`m=512`）：仅需在 `params.rs` 增加参数集，`PublicParams::setup` 按 `m` 分派；环与 Merkle 代码参数化于 `M`。
- **纯格多项式承诺变体**：替换 `merkle.rs` 为格向量承诺，`commitment.rs` 接口不变。
- **批量证明**：`prove.rs` 的 Σ‑协议可推广为一次证明多个索引，复用同一 `r`（需重新审视零知识）。
- **形式化验证**：`formal-proof.md` 中的提取算法已写成伪代码，便于在 Coq/Lean 中复现。
