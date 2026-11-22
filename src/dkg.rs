//! 分布式密钥生成（DKG）：完整私钥在任何机器上从未出现。
//!
//! # 协议（并行 Feldman VSS，Gennaro-Jarecki-Krawczyk-Rabin 1999 的基础形态）
//!
//! 参与方集合 P = {1..n}，门限 t。
//!
//! ## Round 1 —— 承诺 + 知识证明（公开广播）
//! 每方 i 独立选 t-1 次随机多项式 f_i(x)，常数项是它贡献的随机秘密 s_i，
//! 广播：
//!   * Feldman 承诺 C_{i,j} = a_{i,j}·G, j=0..t-1
//!   * 对 C_{i,0} 的 Schnorr 式知识证明 PoK_i（证明自己知道 s_i = log_G C_{i,0}）
//!
//! PoK 阻挡的是 GJKR 论文里的 rushing 攻击：没有 PoK 时，攻击者可以等
//! 诚实方先公开 C_{h,0}，再把自己的贡献设成 C_{m,0} = H - C_{h,0}，
//! 从而把最终公钥/私钥偏置到自己选定的值。有了 PoK，贡献必须先知道
//! 离散对数才能发布，攻击失效。
//!
//! ## Round 2 —— 密文分片（点对点）
//! 各方把分片 f_i(j) 用 j 的静态公钥加密后单播给 j。j 解密后做
//! Feldman 校验：f_i(j)·G == Σ_k C_{i,k}·j^k。不一致即可公开指控 i，
//! 协议带着作恶者身份中止（identifiable abort）。
//!
//! ## 输出
//! 全局私钥定义为 s = Σ_i s_i（无人知道 s）；每方 j 持有
//!   share_j = Σ_i f_i(j) = f(j)，其中 f = Σ_i f_i 是全局多项式，f(0) = s。
//! 验证密钥 VK_j = share_j·G = Σ_i Σ_k C_{i,k}·j^k（公开可复算）。
//! 群公钥 PK = s·G = Σ_i C_{i,0}。
//!
//! # 已知局限与生产升级路径（见 README）
//! 并行 Feldman DKG 对公钥有可忽略的偏置（恶意方贡献可在看到别人承诺后
//! 在 2^-λ 邻域内挑选）。生产级实现应升级为 Pedersen DKG
//! (Gennaro et al. 1999 / Gurgenyan et al. 2022, RFC 9581 第 4 章)，
//! 用第二个盲化多项式获得 UC 安全；本模块的消息边界与中止语义保持兼容。

use k256::elliptic_curve::{Field, Group};
use k256::{ProjectivePoint, Scalar};
use rand::RngCore;

use crate::channel::{Registry, StaticPrivate};
use crate::curve::{
    hash_concat_scalar, id_to_scalar, point_from_bytes, point_to_bytes, random_nonzero_scalar,
    scalar_from_bytes, scalar_mul_g, scalar_to_bytes, tags,
};
use crate::shamir::{verify_share, Polynomial};

/// 对承诺点 C = secret·G 的 Schnorr 式知识证明（Fiat-Shamir 非交互化）。
///
/// 证明者知道 secret：选 r 随机，R = r·G，c = H(ctx || R || C || 绑定身份)，
/// z = r + c·secret。验证方检查 z·G == R + c·C。
/// 绑定参与方 id 与全部承诺，防止证明被搬运到别的上下文重放。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pok {
    pub r_point: [u8; 33],
    pub z: [u8; 32],
}

impl Pok {
    pub fn prove(
        secret: &Scalar,
        dealer_id: u32,
        all_commitments: &[[u8; 33]],
        rng: &mut impl RngCore,
    ) -> Self {
        let r = random_nonzero_scalar(rng);
        let r_point = scalar_mul_g(&r);
        let c = pok_challenge(dealer_id, &point_to_bytes(&r_point), all_commitments);
        let z = r + c * secret;
        Self {
            r_point: point_to_bytes(&r_point),
            z: scalar_to_bytes(&z),
        }
    }

    pub fn verify(
        &self,
        dealer_id: u32,
        all_commitments: &[[u8; 33]],
        first_commitment: &ProjectivePoint,
    ) -> bool {
        let Some(r_point) = point_from_bytes(&self.r_point) else {
            return false;
        };
        let Some(z) = scalar_from_bytes(&self.z) else {
            return false;
        };
        let c = pok_challenge(dealer_id, &self.r_point, all_commitments);
        scalar_mul_g(&z) == r_point + first_commitment * &c
    }
}

fn pok_challenge(dealer_id: u32, r_point: &[u8], all_commitments: &[[u8; 33]]) -> Scalar {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(all_commitments.len() + 2);
    let id_bytes = dealer_id.to_be_bytes();
    parts.push(&id_bytes);
    parts.push(r_point);
    for c in all_commitments {
        parts.push(c);
    }
    hash_concat_scalar(tags::DKG_POK, &parts)
}

/// Round 1 广播消息：参与方 dealer 的 Feldman 承诺 + 知识证明。
#[derive(Clone, Debug)]
pub struct CommitmentMessage {
    pub dealer_id: u32,
    pub commitments: Vec<[u8; 33]>,
    pub pok: Pok,
}

/// Round 2 点对点密文消息（模拟网络上看到的就是这个，分片不裸露）。
#[derive(Clone, Debug)]
pub struct SealedShare {
    pub dealer_id: u32,
    pub recipient_id: u32,
    /// nonce(12) || AES-GCM(share 标量 32 字节)
    pub ciphertext: Vec<u8>,
}

/// DKG 结束后每方持有的私有状态。完整私钥 s 从不在这里出现。
#[derive(Clone)]
pub struct KeyShare {
    pub id: u32,
    pub threshold: usize,
    /// 私有分片 share_i = f(i)。
    pub share: Scalar,
    /// 群公钥 PK = s·G，所有参与方相同。
    pub group_pk: ProjectivePoint,
    /// 每方的公开验证密钥 VK_j = share_j·G（签名阶段校验分片签名用）。
    pub verification_keys: std::collections::BTreeMap<u32, ProjectivePoint>,
}

impl Drop for KeyShare {
    /// 尽力擦除私有的分片标量；群公钥/VK 是公开信息，无需清零。
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.share.zeroize();
    }
}

/// DKG 处理过程中可识别的故障——注意错误都带参与方 id，而不是笼统失败。
#[derive(Debug, PartialEq, Eq)]
pub enum DkgError {
    /// Round 1：某方的知识证明无效（拿不出对承诺的离散对数知识）。
    InvalidPok { offender: u32 },
    /// Round 1：承诺点编码非法。
    BadCommitmentEncoding { offender: u32 },
    /// Round 2：解密失败（密文被篡改或不是发给本方的）。
    CannotDecrypt { offender: u32 },
    /// Round 2：分片过不了 Feldman 校验——作恶者发了错误分片，当场识别。
    BadShare { offender: u32 },
    /// 协议实例参与方集合不一致。
    RegistryMismatch,
}

/// 单个参与方在 DKG 中的内存态。
pub struct DkgParty {
    pub id: u32,
    threshold: usize,
    polynomial: Polynomial,
    /// true = 主动刷新模式，多项式常数项强制为 0（对全局私钥贡献为零）
    zero_constant: bool,
    static_private: StaticPrivate,
    /// 收到并通过校验的 Round 1 承诺，dealer_id -> 承诺点向量
    commitments: std::collections::BTreeMap<u32, Vec<ProjectivePoint>>,
}

impl DkgParty {
    /// 初始化：生成本方随机多项式 f_id，常数项为随机非零秘密（标准 DKG）。
    pub fn new(id: u32, threshold: usize, mut rng: &mut impl RngCore, static_private: StaticPrivate) -> Self {
        // 常数项随机且非零（概率 1/n 为零，重抽到非零；全零私钥在群里无法签名）
        let secret = random_nonzero_scalar(&mut rng);
        let polynomial = Polynomial::random_with_secret(secret, threshold, rng);
        Self {
            id,
            threshold,
            polynomial,
            zero_constant: false,
            static_private,
            commitments: std::collections::BTreeMap::new(),
        }
    }

    /// 主动刷新模式初始化：常数项为 0 的随机多项式 z_i(x)，z_i(0)=0。
    ///
    /// Herzberg 等人 1995 的主动秘密共享思路：所有刷新多项式之和 z(x)
    /// 满足 z(0)=0，旧分片加上 z(i) 后对应同一个 f(0)=s，公钥因此不变；
    /// 而新分片本身是重新随机化的，旧分片泄露不再危害新分片
    /// （前提：两次刷新之间被攻破的参与方少于 t 个）。
    pub fn new_refresh(id: u32, threshold: usize, mut rng: &mut impl RngCore, static_private: StaticPrivate) -> Self {
        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(Scalar::ZERO); // z_i(0) = 0
        for _ in 1..threshold {
            coefficients.push(Scalar::random(&mut rng));
        }
        Self {
            id,
            threshold,
            polynomial: Polynomial { coefficients },
            zero_constant: true,
            static_private,
            commitments: std::collections::BTreeMap::new(),
        }
    }

    /// 产出 Round 1 广播。
    pub fn round1_commit(&self) -> CommitmentMessage {
        let commitments: Vec<[u8; 33]> = self
            .polynomial
            .commitments()
            .iter()
            .map(point_to_bytes)
            .collect();
        if self.zero_constant {
            // 刷新模式：常数项是 0，PoK 退化为对 0 的证明（C_0 = O, z = r）。
            // 直接构造而不是调用 Pok::prove（那里假设 secret 非零并绑定 DKG 标签）。
            let r = random_nonzero_scalar(&mut rand::rngs::OsRng);
            let r_point = scalar_mul_g(&r);
            let c = pok_challenge(self.id, &point_to_bytes(&r_point), &commitments);
            let pok = Pok {
                r_point: point_to_bytes(&r_point),
                z: scalar_to_bytes(&(r + c * Scalar::ZERO)),
            };
            CommitmentMessage {
                dealer_id: self.id,
                commitments,
                pok,
            }
        } else {
            let pok = Pok::prove(
                &self.polynomial.coefficients[0],
                self.id,
                &commitments,
                &mut rand::rngs::OsRng,
            );
            CommitmentMessage {
                dealer_id: self.id,
                commitments,
                pok,
            }
        }
    }

    /// 处理全部 Round 1 广播：校验编码与 PoK，缓存承诺。
    pub fn handle_round1(
        &mut self,
        messages: &[CommitmentMessage],
        registry: &Registry,
    ) -> Result<(), DkgError> {
        if messages.len() != registry.ids.len() {
            return Err(DkgError::RegistryMismatch);
        }
        for msg in messages {
            if !registry.static_pubkeys.contains_key(&msg.dealer_id) {
                return Err(DkgError::RegistryMismatch);
            }
            let points: Vec<ProjectivePoint> = msg
                .commitments
                .iter()
                .map(|b| point_from_bytes(b).ok_or(DkgError::BadCommitmentEncoding { offender: msg.dealer_id }))
                .collect::<Result<_, _>>()?;
            if points.len() != self.threshold {
                return Err(DkgError::BadCommitmentEncoding { offender: msg.dealer_id });
            }
            // 标准 DKG 模式下任何承诺点都不允许是无穷大点 O：
            // 全零 33 字节会被 k256 解码成 O，而 O = 0·G 意味着对应系数为 0，
            // 会降低多项式的实际次数/秘密熵。刷新模式的零常数项在 refresh 模块单独放行。
            if !self.zero_constant && points.iter().any(|p| bool::from(p.is_identity())) {
                return Err(DkgError::BadCommitmentEncoding { offender: msg.dealer_id });
            }
            if !msg
                .pok
                .verify(msg.dealer_id, &msg.commitments, &points[0])
            {
                return Err(DkgError::InvalidPok { offender: msg.dealer_id });
            }
            self.commitments.insert(msg.dealer_id, points);
        }
        Ok(())
    }

    /// 刷新模块复用的只读访问器：静态私钥引用。
    pub(crate) fn static_private_view(&self) -> &StaticPrivate {
        &self.static_private
    }

    /// 本方参与方 id。
    pub fn id(&self) -> u32 {
        self.id
    }

    /// 刷新模块复用的只读访问器：已校验的 Round 1 承诺表。
    pub(crate) fn commitments_view(
        &self,
    ) -> &std::collections::BTreeMap<u32, Vec<ProjectivePoint>> {
        &self.commitments
    }

    /// 产出 Round 2 给每个参与方的密文分片。
    pub fn round2_sealed_shares(&self, registry: &Registry) -> Vec<SealedShare> {        registry
            .ids
            .iter()
            .map(|&recipient| {
                let share = self.polynomial.share_for(recipient);
                let recipient_pk = registry
                    .pubkey_of(recipient)
                    .expect("registry contains every participant");
                let ciphertext = self.static_private.seal(recipient_pk, &scalar_to_bytes(&share));
                SealedShare {
                    dealer_id: self.id,
                    recipient_id: recipient,
                    ciphertext,
                }
            })
            .collect()
    }

    /// 处理发给本方的 Round 2 密文并完成 DKG，输出私有 KeyShare。
    pub fn finalize(
        &self,
        sealed_for_me: &[SealedShare],
        registry: &Registry,
    ) -> Result<KeyShare, DkgError> {
        if sealed_for_me.len() != registry.ids.len()
            || sealed_for_me.iter().any(|m| m.recipient_id != self.id)
        {
            return Err(DkgError::RegistryMismatch);
        }

        let mut my_share = Scalar::ZERO;
        for sealed in sealed_for_me {
            let dealer_pk = registry
                .pubkey_of(sealed.dealer_id)
                .ok_or(DkgError::RegistryMismatch)?;
            let plaintext = self
                .static_private
                .open(dealer_pk, &sealed.ciphertext)
                .ok_or(DkgError::CannotDecrypt { offender: sealed.dealer_id })?;
            let share_ij = scalar_from_bytes(&plaintext)
                .ok_or(DkgError::BadShare { offender: sealed.dealer_id })?;

            // Feldman 校验：作恶 dealer 发错分片在这里被精确指认
            let commitments = self
                .commitments
                .get(&sealed.dealer_id)
                .ok_or(DkgError::RegistryMismatch)?;
            if !verify_share(self.id, &share_ij, commitments) {
                return Err(DkgError::BadShare { offender: sealed.dealer_id });
            }
            my_share += share_ij;
        }

        // 群公钥 = Σ_i C_{i,0}
        let group_pk = self
            .commitments
            .values()
            .map(|c| c[0])
            .fold(ProjectivePoint::IDENTITY, |acc, c| acc + c);

        // VK_j = Σ_i (f_i 的承诺在 j 处的求值)，逐方公开复算
        let mut verification_keys = std::collections::BTreeMap::new();
        for &id in &registry.ids {
            let mut vk = ProjectivePoint::IDENTITY;
            for commitments in self.commitments.values() {
                let x = id_to_scalar(id);
                let mut evaluated = ProjectivePoint::IDENTITY;
                for c in commitments.iter().rev() {
                    evaluated = evaluated * x + c;
                }
                vk += evaluated;
            }
            verification_keys.insert(id, vk);
        }

        // 自检：VK_id 必须等于 share_id·G，否则本地状态已被污染
        assert_eq!(scalar_mul_g(&my_share), verification_keys[&self.id]);

        Ok(KeyShare {
            id: self.id,
            threshold: self.threshold,
            share: my_share,
            group_pk,
            verification_keys,
        })
    }
}
