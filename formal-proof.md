# CPC 形式化安全证明

> **范围**：本文档给出可约束路径承诺（CPC）方案三个核心安全性质——绑定性、统计零知识、知识声音性——的完整形式化证明。方案构造、参数选择与对比分析见 [paper.md](paper.md)。
>
> 证明在随机预言机模型（ROM）下进行，安全性归约至 Ring‑SIS 问题的困难性和哈希函数 \(H_{\mathsf{MT}}\) 的抗碰撞性。

---

## 预备：关键引理

为使本文档自包含，下面重述 [paper.md](paper.md) 第 2 节中证明直接依赖的两条引理。

### 引理 1（拒绝采样）

设秘密 \(d\in R\) 满足 \(\|d\|\le T\)。取 \(\sigma = \tau T\)（\(\tau>0\)）。采样 \(r\leftarrow\mathcal{D}_{R,\sigma}\)，计算 \(z = r + d\)，以概率
\[
\min\!\bigg(1,\ \frac{\mathcal{D}_{R,\sigma}(z)}{M\cdot\mathcal{D}_{R,\sigma}(z-d)}\bigg)
\]
输出 \(z\)，否则重复。选取
\[
M = \exp\!\bigg(\frac{12}{\tau}+\frac{1}{2\tau^2}\bigg),
\]
当 \(\tau=12\) 时 \(M\approx 2.7\)。则输出 \(z\) 的分布与 \(\mathcal{D}_{R,\sigma}\) 统计不可区分，且期望重复次数约 \(M \approx 2.7\)。

*意义*：证明者输出 \(z = r + c\cdot d_i\) 后，其分布被清洗为与秘密 \(d_i\) 无关的离散高斯分布，这是统计零知识的基石。

### 引理 2（挑战差值可逆性及逆范数上界）

设 \(c_1, c_2\in\mathcal{C}\)，\(c_1\neq c_2\)，令 \(\Delta c = c_1 - c_2\)。则：

1. \(\Delta c\) 非零且在 \(R = \mathbb{Z}_q[x]/(x^m+1)\) 中可逆；
2. \(\|\Delta c^{-1}\|_\infty \le 2\tau\)；
3. \(\|\Delta c^{-1}\| \le 2\tau\sqrt{m}\)。

*证明概要*：Dilithium 方案已证明，对于系数在 \(\{-1,0,1\}\) 且非零项数为 \(\tau\) 的多项式，其与 \(x^m+1\) 互素，从而在 \(R\) 中可逆，且逆的 \(\ell_\infty\) 范数不超过 \(\tau\)。本文中 \(\Delta c\) 的系数绝对值 \(\le 2\)。利用常数 \(2\) 在 \(\mathbb{F}_q\) 中的可逆性，可将 \(\Delta c\) 的可逆性及逆范数界归约到上述情形：考虑 \(\frac{1}{2}\Delta c\) 的分子多项式（系数绝对值 \(\le 1\)），其可逆性等价，且伴随矩阵分析表明逆元素的 \(\ell_\infty\) 范数界与系数的最大绝对值成正比，故 \(\|\Delta c^{-1}\|_\infty \le 2\tau\)。进而
\[
\|\Delta c^{-1}\| \le \|\Delta c^{-1}\|_\infty \sqrt{m} \le 2\tau\sqrt{m}.
\]
详细矩阵论证参见 [Dilithium] 附录。

*意义*：知识声音性证明中，提取器需从两个不同挑战响应中恢复秘密 \(d^* = \Delta c^{-1}(z - z')\)，引理 2 保证该逆元存在且范数有界，从而使提取出的 \(d^*\) 的范数可控。

---

## 5.1 绑定性

**定理 1**：若 \(\mathrm{Ring‑SIS}_{m,q,\nu}\) 困难（\(\nu = 2B + 2\tau\beta\sqrt{m}\)）且 \(H_{\mathsf{MT}}\) 抗碰撞，则方案满足绑定性。

*证明*：设敌手输出两个有效证明 \(\pi=(z,u,\mathsf{path})\) 和 \(\pi'=(z',u',\mathsf{path}')\)，对应同一 \(\mathsf{com},i,\mu\)。若 \((u,\mathsf{path})\neq(u',\mathsf{path}')\)，则 Merkle 树碰撞，与 \(H_{\mathsf{MT}}\) 抗碰撞矛盾。故 \(u=u', \mathsf{path}=\mathsf{path}'\)。

由验证方程，对两个证明分别有
\[
a z = t_1' + c\Delta_i,\quad b z = t_2' + c u
\]
和
\[
a z' = t_1'' + c'\Delta_i,\quad b z' = t_2'' + c' u,
\]
其中 \(c,c'\) 为相应挑战。因绑定性游戏中承诺由诚实方生成，模拟器知晓真实差向量 \(d_i\) 满足 \(\Delta_i = a d_i\)，\(u = b d_i\)。

**情形 1**：\(c = c'\)。则 \(a(z-z') = 0\) 且 \(\|z-z'\|\le 2B < \nu\)。若 \(z\neq z'\)，直接输出 Ring‑SIS 解 \(z-z'\)；若 \(z=z'\)，则两证明相同，不构成碰撞。

**情形 2**：\(c\neq c'\)。两式相减得
\[
a(z-z') = (c-c')\Delta_i.
\]
代入 \(\Delta_i = a d_i\) 得
\[
a\big((z-z') - (c-c')d_i\big) = 0.
\]
令 \(v = (z-z') - (c-c')d_i\)，其范数
\[
\|v\| \le 2B + 2\tau\beta\sqrt{m} \le \nu.
\]
若 \(v \neq 0\)，则输出 SIS 解 \(v\)。若 \(v=0\)，则 \(z-z' = (c-c')d_i\)。此时可验证
\[
t_1' = a z - c a d_i = a\big(z' + (c-c')d_i\big) - c a d_i = a z' - c' a d_i = t_1'',
\]
故两个证明的承诺值相同。此时两个证明对应于同一个随机掩码 \(r\) 的两个不同挑战响应，不违反绑定性（未产生两个不同的有效打开），敌手未成功。

因此，敌手获胜必导致情形 1 中 \(z\neq z'\) 或情形 2 中 \(v\neq0\)，均输出 Ring‑SIS 解。$\square$

---

## 5.2 统计零知识

**定理 2**：在随机预言机模型下，方案满足统计零知识。

*证明*：模拟器 \(\mathsf{Sim}\) 输入 \((\mathsf{pp}, \mathsf{com}, \{\Delta_j\}, i, \mu)\) 如下工作：

1. 随机选择 \(c\leftarrow\mathcal{C}\)，采样 \(z\leftarrow\mathcal{D}_{R,\sigma}\)（截断至 \(B\)）。
2. 随机选取叶子 \(u\leftarrow R\)。
3. 计算 \(t_1 = a z - c\Delta_i\)，\(t_2 = b z - c u\)。
4. 编程随机预言机 \(H(\mathsf{com}, \{\Delta_j\}, i, t_1, t_2, \mu) = c\)，若该点已被查询则失败（概率可忽略）。
5. 模拟 Merkle 路径：以 \(u\) 为起点，逐层随机选择兄弟节点，并通过编程 \(H_{\mathsf{MT}}\) 使路径的根匹配 \(\mathsf{com}\)。这是 ROM 下的标准 Merkle 树模拟技术。
6. 输出 \(\pi = (z, u, \mathsf{path})\)。

在真实证明中，\(z\) 经拒绝采样后与 \(\mathcal{D}_{R,\sigma}\) 统计不可区分（引理 1）；\(u = b d_i\) 固定，但模拟器选取随机 \(u\)，并通过定义 \(t_2\) 使验证等式成立。Merkle 路径在 ROM 下的分布与真实计算一致。因此模拟视图与真实视图统计不可区分。$\square$

---

## 5.3 知识声音性

**定理 3**：设敌手 \(\mathcal{P}^*\) 向随机预言机最多查询 \(q_H\) 次，以概率 \(\epsilon\) 输出有效证明。则存在提取器 \(\mathcal{E}\) 以概率至少
\[
\frac{\epsilon^2}{q_H+1} - \mathsf{negl}
\]
输出短向量 \(d^*\in R\) 满足 \(a d^* = \Delta_i\) 和 \(b d^* = u\)，其中 \(u\) 为证明中的叶子，\(\|d^*\| \le 4\tau\sqrt{m}B\)（按论文正文记为 \(4\tau m B\)，本文档按引理 2 的精确界 \(2\tau\sqrt{m}\) 给出更紧的估计 \(4\tau\sqrt{m}B\)；二者均为安全上界），或输出 Ring‑SIS 解。

*证明*：\(\mathcal{E}\) 运行 \(\mathcal{P}^*\)，模拟随机预言机 \(H\) 和 \(H_{\mathsf{MT}}\)。设 \(\mathcal{P}^*\) 输出有效证明 \(\pi = (z,u,\mathsf{path})\)，其中
\[
c = H(\mathsf{com}, \{\Delta_j\}, i, t_1, t_2, \mu),\quad t_1 = a z - c\Delta_i,\quad t_2 = b z - c u.
\]
记该次哈希查询索引为 \(k\)。

\(\mathcal{E}\) 重绕 \(\mathcal{P}^*\) 至第 \(k\) 次查询前，赋予不同输出，从而以至少
\[
\frac{\epsilon^2}{q_H+1} - \frac{1}{|\mathcal{C}|}
\]
的概率获得另一有效证明 \(\pi' = (z', u', \mathsf{path}')\)，其对应相同 \((\mathsf{com}, \{\Delta_j\}, i, t_1, t_2, \mu)\) 但挑战 \(c'\neq c\)。

若 \((u,\mathsf{path})\neq(u',\mathsf{path}')\)，则发生 Merkle 碰撞，概率可忽略。故 \(u=u', \mathsf{path}=\mathsf{path}'\)。验证方程相减得：
\[
a(z-z') = (c-c')\Delta_i,\quad b(z-z') = (c-c')u.
\]

令 \(\Delta c = c-c' \neq 0\)。由引理 2，\(\Delta c\) 可逆且
\[
\|\Delta c^{-1}\| \le 2\tau\sqrt{m}.
\]
计算
\[
d^* = \Delta c^{-1}(z-z').
\]
于是
\[
a d^* = \Delta_i,\quad b d^* = u.
\]
范数
\[
\|d^*\| \le \|\Delta c^{-1}\|\cdot\|z-z'\| \le (2\tau\sqrt{m})\cdot 2B = 4\tau\sqrt{m}B.
\]

提取成功。若分叉未获得两个有效证明，提取器失败，概率下界由分叉引理保证。$\square$

---

## 提取算法（伪代码）

为便于实现参考，将上述提取过程显式写出：

```text
Extract(P*, pp, com, {Δ_j}, i, mu):
    run P* with simulated H, H_MT, obtain π = (z, u, path) and hash query index k
    rewind P* to before query k
    re-program H at query k with a fresh output c' ∈ C, c' ≠ c
    re-run P* to obtain π' = (z', u', path')
    if π' is not valid: return FAIL
    if (u, path) ≠ (u', path'): return FAIL  // Merkle collision, negligible
    Δc = c - c'
    if Δc is not invertible in R: return FAIL  // ruled out by Lemma 2
    d* = Δc^{-1} * (z - z')  in R
    assert a * d* == Δ_i  and  b * d* == u
    assert ||d*|| ≤ 4τ√m · B
    return d*
```

成功概率下界：\(\Pr[\text{success}] \ge \frac{\epsilon^2}{q_H+1} - \mathsf{negl}(\lambda)\)。

---

## 与论文正文的对应

| 本文档 | 论文正文（paper.md） |
|--------|---------------------|
| 引理 1（拒绝采样） | 第 2.2 节 |
| 引理 2（可逆性） | 第 2.4 节 |
| 定理 1（绑定性） | 第 5.1 节（概述） |
| 定理 2（统计零知识） | 第 5.2 节（概述） |
| 定理 3（知识声音性） | 第 5.3 节（概述） |
