# frost-custody —— 面向数字资产托管的 t-of-n 门限签名系统

把"完整私钥存在一台签名服务器上"改成 **私钥从生成起就分散在 n 台服务器、
任意 t 台同意才能签出有效签名** 的多方计算（MPC）方案。签出的签名是标准
Schnorr 签名，验证者只看到一个普通公钥和一个普通 `(R, s)`，**无法区分它是
单人签的还是 t 方合签的**。

## 一、为什么选这套协议（论文依据与选型理由）

### 1. 签名层：FROST（Flexible Round-Optimized Schnorr Threshold Signatures）

* **论文**：Komlo & Goldberg, *FROST: Flexible Round-Optimized Schnorr
  Threshold Signatures*, SAC 2020；标准化文档 **RFC 9591**（2024）。
* **选它的理由**：
  * **只要两轮通信**，是当前门限 Schnorr 方案里通信轮次最少的一档，
    对跨机房部署的延迟友好；
  * **签名份额可公开校验、可识别中止（identifiable abort）**：谁发了错误的
    分片签名，任何人都能用公开验证密钥 `VK_i` 独立复算并指认，不依赖
    协调者诚实——正好对应"参与方互不信任、有人故意发错数据"的要求；
  * **输出标准 Schnorr 签名**，与单签验证方程完全同构，链上/验签方零改造；
  * 允许灵活选择签名子集（任意 t 个即可，不固定成员）。
* **关键安全构件——绑定因子（binding factor）**：每方第二个 nonce 通过
  `ρ_i = H(PK, i, 全部承诺, msg)` 与消息、签名集合绑定，防止恶意协调者
  替换承诺做 chosen-message 攻击（论文 §3）。这是早期简单线性聚合方案
  （如直接用 `Σ d_i`）没有的防护。
* **nonce 安全性是生命线**：每轮一次性 `(d_i, e_i)`，用完即擦除
  （`SigningNonce` 实现了 `Drop` 清零）。nonce 复用会像单人 Schnorr 的
  `k` 复用一样直接泄露分片。

### 2. 密钥生成层：并行 Feldman VSS + PoK（GJKR 风格 DKG）

* **论文**：Gennaro, Jarecki, Krawczyk, Rabin, *Secure Distributed Key
  Generation for Discrete-Log Based Cryptosystems*, EUROCRYPT 1999（GJKR）。
* **结构**：每方选一个 `t-1` 次随机多项式，广播 **Feldman 承诺**
  （Feldman, 1987）`C_{i,j}=a_{i,j}·G`，并附一个 **Schnorr 式知识证明
  （PoK）** 证明自己知道 `C_{i,0}` 的离散对数；分片通过加密信道点对点发送。
* **PoK 的作用（GJKR 的核心教训）**：没有 PoK 时，rushing 攻击者可以等
  诚实方先公开承诺，再把自己的贡献设成 `H - C_honest`，把最终公钥偏置到
  自己选定的值。PoK 强制"先知道离散对数才能发布承诺"，封死该攻击。
* **Feldman 校验的作用**：接收方检查 `f_i(j)·G == Σ_k C_{i,k}·j^k`，
  作恶 dealer 发错误分片会被**当场精确指认**，无法靠"发错数据套信息"
  获利——错误数据在进入任何聚合前就被拒绝。
* **已知局限与升级路径**：并行 Feldman DKG 对公钥有可忽略的偏置
  （恶意方在 `2^-λ` 邻域内挑选贡献）。生产级、需要 UC 安全的实现应升级为
  **Pedersen DKG**（GJKR 1999；RFC 9591 §4 参考 Gurgenyan et al. 2022），
  用第二个盲化多项式消除偏置。本仓库的消息边界、中止语义与之兼容，
  可平滑替换 `dkg.rs` 内部而不动签名层。

### 3. 分片刷新层：Herzberg 主动秘密共享（PSS）

* **论文**：Herzberg, Jarecki, Krawczyk, Yung, *Proactive Secret Sharing
  Or: How to Cope With Perpetual Leaks*, CRYPTO 1995。
* **机制**：每方选**常数项为 0** 的随机多项式 `z_i(x)`（`z_i(0)=0`），
  复用 DKG 的承诺/加密/Feldman 流程分发增量分片。更新后
  `share'_j = share_j + Σ_i z_i(j)`，而 `(f+z)(0) = f(0) + 0 = s`，
  **群公钥纹丝不动，但所有分片都是新鲜随机值**。
* **安全收益**：攻击者必须在**单个刷新周期内**同时拿到 t 个分片才能
  恢复私钥；上一周期泄露的旧分片在刷新后对新分片零信息。这把"永久泄露"
  降级成"窗口期泄露"，是托管系统对抗长期渗透的标准手段。

### 4. 曲线与签名格式

* 曲线 **secp256k1**（Bitcoin/Ethereum 同曲线），纯 Rust 实现 `k256`。
* 签名用完整压缩点编码 `R`（33 字节）+ 标量 `s`（32 字节）的标准
  Schnorr 形态，而非 BIP-340 的 x-only 形态——选择它是为了让协议代数
  （聚合、Feldman、Lagrange）保持直观、避免 x-only 的偶数点归一化在
  门限聚合里引入的额外协调。要对接 Bitcoin Taproot 时，可在最后一跳
  做 x-only 归一化（见"生产化清单"）。
* 哈希到标量走 SHA-256 + 模 n 规约（与 RFC 9381 对挑战的处理一致），
  所有哈希带域分隔标签，防止不同子协议的哈希混用。

## 二、威胁模型与对应防线

| 威胁 | 防线 | 代码位置 |
|---|---|---|
| 攻破单机偷走完整私钥 | 私钥从未完整存在；单机只有一个 Shamir 分片，t-1 个分片信息论上无信息 | `shamir.rs`, `dkg.rs` |
| DKG 中发错误分片套信息 | Feldman 承诺公开校验 + 可识别中止 | `shamir.rs::verify_share`, `dkg.rs::finalize` |
| rushing 攻击者偏置公钥 | Round 1 强制 Schnorr PoK | `dkg.rs::Pok` |
| 广播链路上窃听分片 | ECDH(P-256k1)+HKDF+AES-256-GCM 端到端加密 | `channel.rs` |
| 签名 Round 2 发错分片签名 | 分片签名公开校验方程，精确指认作恶者 | `frost.rs::verify_partial` |
| 恶意协调者替换承诺/重放 | 绑定因子 `ρ` 绑定消息+承诺集合；挑战 `c` 绑定 R | `frost.rs::SigningContext` |
| 签到一半掉线 | 不足 t 方则协议干净失败，可换新集合重开（新 nonce） | `frost.rs::NotEnoughSigners` |
| 长期渗透累积分片 | 主动刷新，周期换新分片而公钥不变 | `refresh.rs` |
| 内存残留密钥 | `KeyShare`/`SigningNonce`/`StaticPrivate` Drop 清零 | `zeroize` |

**安全边界（诚实假设）**：本实现提供 **malicious security with abort +
identifiable abort**——作恶方能让协议中止，但无法伪造签名、无法窃取诚实方
分片，且会被指认。它不保证在作恶方存在时仍能输出签名（liveness）；要做到
恶意环境下不停机，需要额外的故障恢复/成员更替协议。门限参数保证：
`t-1` 台被攻破时机密性完好（Shamir 完美保密性，见测试
`t_minus_one_shares_hide_the_secret_information_theoretically`）。

## 三、代码结构

```
src/
├── curve.rs     # secp256k1 原语：标量/点、hash-to-scalar、标准 Schnorr 验证
├── shamir.rs    # Shamir 分片、Feldman VSS 校验、Lagrange 系数
├── channel.rs   # 静态身份密钥、ECDH+HKDF+AES-GCM 密文信道、身份注册表
├── dkg.rs       # GJKR 风格 DKG：PoK + 承诺 + 密文分片，输出 KeyShare
├── refresh.rs   # Herzberg PSS：零常数项多项式刷新，公钥不变
├── frost.rs     # FROST 两轮签名、绑定因子、分片校验、聚合、标准验证
└── net.rs       # 进程内模拟网络（支持篡改/扣压/重放注入）
tests/
├── common/mod.rs            # 多服务器协议编排测试设施
├── protocol_properties.rs   # 正确性/不可区分性/刷新/保密性测试（6 个）
└── malicious_parties.rs     # 作恶参与方测试（12 个，题目要求的核心交付）
examples/demo.rs             # 端到端生命周期演示
```

## 四、运行

```bash
cargo test --offline          # 20 个测试（含 12 个作恶场景）
cargo run --offline --example demo   # 端到端演示
cargo clippy --offline --all-targets # 零警告
```

### 作恶测试覆盖（`tests/malicious_parties.rs`）

| 测试 | 攻击动作 | 断言 |
|---|---|---|
| A | 伪造 DKG 知识证明 | `InvalidPok{offender=2}` |
| A2 | 发布非法曲线点编码 | `BadCommitmentEncoding{offender=2}` |
| B | 篡改 Round 2 密文分片 | AEAD/Feldman 拦截并指认 |
| B2 | 明文形态的错误分片 | Feldman 校验独立拒绝 |
| C | 分片签名 `z_i` 加 1 | `BadPartialSignature{offender=2}` |
| C2 | 分片签名换成随机垃圾 | 仅作恶方被指认，诚实方不误伤 |
| D | Round 1 后掉线 | `NotEnoughSigners`，可换新集合重试 |
| E | 刷新阶段篡改增量分片 | 刷新中止，旧分片仍可签名 |
| E2 | 刷新夹带非零常数项（漂移公钥） | 零常数项检查/PoK 拒绝并指认 |
| F | 跨上下文重放旧分片签名 | 新上下文全部校验失败 |
| G | PoK 跨参与方搬运 | 绑定 id/承诺的挑战使重放失效 |
| H | 网络观察者窃听 | 链路只有密文，无裸分片 |

## 五、生产化清单（本仓库是协议参考实现，上生产前必须处理）

1. **Pedersen DKG / RFC 9591 合规**：替换并行 Feldman DKG 以获得 UC 安全
   与无偏置公钥；考虑对接成熟审计过的实现（如 Zcash `frost-core` 生态）。
2. **BIP-340 兼容**：若用于 Bitcoin Taproot，聚合后做 x-only 归一化
   （偶数点调整 `s` 与分片符号），EVM 场景则保持当前完整点形态。
3. **真实网络与身份**：`net.rs` 是进程内模拟；生产用 mTLS/Noise 链路，
   静态公钥进 CA 或链上准入注册表，防中间人冒充。
4. **HSM/TEE 托管分片**：分片标量应驻留在 HSM 或隔离 enclave，
   `zeroize` 只防软件内存泄露，防不了整机内存转储。
5. **成员更替与 share recovery**：当前刷新要求 n 方全在线；需要容忍
   刷新期掉线、支持增减节点时，实现 Herzberg 1995 §5 的份额恢复与
   动态成员协议。
6. **确定性 nonce 的替代方案**：生产可考虑 RFC 9591 的 deterministic nonce
   派生（从分片 + 随机种子 + 消息派生），降低对 RNG 质量的依赖，
   但仍严格保证每轮不重复。
7. **审计与形式化验证**：门限签名实现应有第三方安全审计；关键不变量
   （Lagrange、Feldman、聚合方程）建议补充形式化证明。
8. **拒绝服务**：identifiable abort 给出作恶者身份后，需要链上/治理层的
   罚没或剔除机制配合，否则作恶方可以反复让协议中止实施 DoS。

## 六、参考文献

1. C. Komlo, I. Goldberg. *FROST: Flexible Round-Optimized Schnorr
   Threshold Signatures*. SAC 2020.
2. RFC 9591. *FROST: Two-Round Schnorr Threshold Signatures*. IETF, 2024.
3. R. Gennaro, S. Jarecki, H. Krawczyk, T. Rabin. *Secure Distributed Key
   Generation for Discrete-Log Based Cryptosystems*. EUROCRYPT 1999.
4. A. Herzberg, S. Jarecki, H. Krawczyk, M. Yung. *Proactive Secret Sharing
   Or: How to Cope With Perpetual Leaks*. CRYPTO 1995.
5. P. Feldman. *A Practical Scheme for Non-interactive Verifiable Secret
   Sharing*. FOCS 1987.
6. A. Shamir. *How to Share a Secret*. CACM 1979.
7. RFC 9381. *BIP-340-style Schnorr 与 FROST 挑战哈希规约*. IETF, 2023.
