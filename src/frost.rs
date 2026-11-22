//! FROST 门限 Schnorr 签名（Komlo & Goldberg, "FROST", RFC 9591 / SAC 2020）。
//!
//! # 两轮协议（t 个签名参与方 S ⊆ P，|S| = t）
//!
//! ## Round 1：nonce 承诺
//! 每方 i 生成两个一次性随机标量 (d_i, e_i)，公开
//!   D_i = d_i·G,  E_i = e_i·G
//! 私有的 (d_i, e_i) 只能保留在本轮内存里，签名结束即销毁；nonce 复用会
//! 直接导致分片泄露（与单人 Schnorr 的 k 复用同等级别灾难）。
//!
//! ## 协调者计算（确定性，任何人可复算）
//! 汇总 S 中各方的 (D_i, E_i)，对每方计算绑定因子
//!   ρ_i = H(binding || PK || i || {D_j,E_j}_{j∈S} || msg)
//! 组 nonce：
//!   R = Σ_i (D_i + ρ_i·E_i)
//! 挑战：
//!   c = H(challenge || R || PK || msg)
//!
//! 绑定因子是 FROST 安全性的关键：它把每方的第二个 nonce 与消息、
//! 参与方集合绑定，恶意协调者无法通过替换/重放承诺来做 chosen-input
//! 攻击（论文 §3 解释了无绑定时的攻击面）。
//!
//! ## Round 2：分片签名
//! 每方 i 用自己的 Lagrange 系数 λ_i（在集合 S、求值点 0 处）计算
//!   z_i = d_i + ρ_i·e_i + λ_i·c·share_i
//! 并公开 z_i。任何人可用公开验证密钥 VK_i 校验：
//!   z_i·G == D_i + ρ_i·E_i + λ_i·c·VK_i
//! 错误分片签名过不了这一关，作恶者被精确指认（identifiable abort）。
//!
//! ## 聚合
//!   s = Σ_i z_i,  输出 (R, s)
//! 代数上：
//!   s·G = Σ_i (d_i+ρ_i e_i)·G + c·Σ_i λ_i·(share_i·G)
//!       = R + c·(Σ_i λ_i share_i)·G = R + c·s_key·G
//! 其中 Σ_i λ_i share_i = f(0) = 全局私钥——它在聚合里**以代数等价的方式
//! 出现，却从未在任何一台机器上被显式计算**。
//!
//! 输出 (R, s) 满足标准 Schnorr 验证方程，验证者只需要群公钥 PK，
//! 对 t、n、参与方集合一无所知，门限签名与单人签名不可区分。

use std::collections::BTreeMap;

use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};
use rand::RngCore;

use crate::curve::{
    hash_concat_scalar, id_to_scalar, point_from_bytes, point_to_bytes, random_nonzero_scalar,
    scalar_from_bytes, scalar_mul_g, scalar_to_bytes, tags,
};
use crate::dkg::KeyShare;
use crate::shamir::lagrange_coefficients;

/// Round 1 广播：两个 nonce 承诺。
#[derive(Clone, Debug)]
pub struct NonceCommitment {
    pub signer_id: u32,
    pub d_commitment: [u8; 33],
    pub e_commitment: [u8; 33],
}

/// Round 2 广播：分片签名。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature {
    pub signer_id: u32,
    pub z: [u8; 32],
}

/// 最终签名：完整压缩点 R + 标量 s。任何验证方用同一 verify 方程校验。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 33],
    pub s: [u8; 32],
}

/// 签名过程中的可识别故障。
#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// 参与签名的人数不足门限。
    NotEnoughSigners { have: usize, need: usize },
    /// 某方 Round 1 承诺编码非法。
    BadCommitment { offender: u32 },
    /// 某方 Round 2 分片签名校验失败——作恶者被指认。
    BadPartialSignature { offender: u32 },
    /// 参与集合里出现了注册表之外的 id。
    UnknownSigner { offender: u32 },
    /// 聚合出来的组 nonce 退化（概率 2^-256，仍显式拒绝）。
    DegenerateNonce,
}

/// 每方 Round 1 之后持有的一次性私有状态，Round 2 结束即 Drop。
pub struct SigningNonce {
    signer_id: u32,
    d: Scalar,
    e: Scalar,
}

impl Drop for SigningNonce {
    /// nonce 用完即擦除；这是 FROST 安全的生命线（nonce 复用 => 分片泄露）。
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.d.zeroize();
        self.e.zeroize();
    }
}

/// 协调者视角的公开状态：本轮的绑定因子、组 nonce、挑战与 Lagrange 系数。
/// 全部由公开信息确定性推导，任何一方都能独立复算来审计协调者。
#[derive(Debug)]
pub struct SigningContext {
    pub signer_ids: Vec<u32>,
    pub group_pk: ProjectivePoint,
    pub message: Vec<u8>,
    pub nonce_commitments: BTreeMap<u32, (ProjectivePoint, ProjectivePoint)>,
    pub binding_factors: BTreeMap<u32, Scalar>,
    pub group_nonce: ProjectivePoint,
    pub challenge: Scalar,
    pub lambdas: BTreeMap<u32, Scalar>,
}

impl SigningContext {
    /// 由 Round 1 的全部承诺 + 消息构造公开上下文。
    pub fn new(
        signer_ids: &[u32],
        commitments: &[NonceCommitment],
        group_pk: &ProjectivePoint,
        message: &[u8],
        threshold: usize,
    ) -> Result<Self, SignError> {
        if signer_ids.len() < threshold {
            return Err(SignError::NotEnoughSigners {
                have: signer_ids.len(),
                need: threshold,
            });
        }
        let mut nonce_commitments = BTreeMap::new();
        for c in commitments {
            if !signer_ids.contains(&c.signer_id) {
                return Err(SignError::UnknownSigner { offender: c.signer_id });
            }
            let d = point_from_bytes(&c.d_commitment)
                .ok_or(SignError::BadCommitment { offender: c.signer_id })?;
            let e = point_from_bytes(&c.e_commitment)
                .ok_or(SignError::BadCommitment { offender: c.signer_id })?;
            // 承诺必须是真随机 nonce 的结果；无穷大承诺意味着 nonce=0，拒绝
            if bool::from(d.is_identity()) || bool::from(e.is_identity()) {
                return Err(SignError::BadCommitment { offender: c.signer_id });
            }
            nonce_commitments.insert(c.signer_id, (d, e));
        }
        if nonce_commitments.len() != signer_ids.len() {
            return Err(SignError::BadCommitment { offender: 0 });
        }

        // 绑定因子：输入包含完整承诺列表（按 id 排序，保证各方编码一致）
        let mut binding_factors = BTreeMap::new();
        let pk_bytes = point_to_bytes(group_pk);
        // 承诺编码先落到局部变量，避免临时值在 parts 借用期间被释放
        let encoded: BTreeMap<u32, ([u8; 33], [u8; 33])> = signer_ids
            .iter()
            .map(|&id| {
                let (d, e) = &nonce_commitments[&id];
                (id, (point_to_bytes(d), point_to_bytes(e)))
            })
            .collect();
        for &id in signer_ids {
            let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + 2 * signer_ids.len());
            let id_be = id.to_be_bytes();
            parts.push(&id_be);
            parts.push(&pk_bytes);
            parts.push(message);
            for &j in signer_ids {
                let (ref dj, ref ej) = encoded[&j];
                parts.push(dj);
                parts.push(ej);
            }
            let rho = hash_concat_scalar(tags::FROST_BINDING, &parts);
            binding_factors.insert(id, rho);
        }

        // R = Σ_i (D_i + ρ_i E_i)
        let mut group_nonce = ProjectivePoint::IDENTITY;
        for &id in signer_ids {
            let (d, e) = &nonce_commitments[&id];
            let rho = &binding_factors[&id];
            group_nonce += *d + (e * rho);
        }
        if bool::from(group_nonce.is_identity()) {
            return Err(SignError::DegenerateNonce);
        }

        let challenge = hash_concat_scalar(
            tags::FROST_CHALLENGE,
            &[
                &point_to_bytes(&group_nonce),
                &point_to_bytes(group_pk),
                message,
            ],
        );

        let lambda_vals = lagrange_coefficients(signer_ids);
        let lambdas: BTreeMap<u32, Scalar> = signer_ids
            .iter()
            .copied()
            .zip(lambda_vals)
            .collect();

        Ok(Self {
            signer_ids: signer_ids.to_vec(),
            group_pk: *group_pk,
            message: message.to_vec(),
            nonce_commitments,
            binding_factors,
            group_nonce,
            challenge,
            lambdas,
        })
    }
}

/// 签名参与方的本地操作。
pub struct Signer;

impl Signer {
    /// Round 1：生成一次性 nonce 与承诺。
    pub fn round1_commit(
        signer_id: u32,
        mut rng: &mut impl RngCore,
    ) -> (SigningNonce, NonceCommitment) {
        let d = random_nonzero_scalar(&mut rng);
        let e = random_nonzero_scalar(&mut rng);
        let nonce = SigningNonce {
            signer_id,
            d,
            e,
        };
        let commitment = NonceCommitment {
            signer_id,
            d_commitment: point_to_bytes(&scalar_mul_g(&d)),
            e_commitment: point_to_bytes(&scalar_mul_g(&e)),
        };
        (nonce, commitment)
    }

    /// Round 2：在公开上下文上生成分片签名。
    pub fn round2_sign(nonce: &SigningNonce, share: &KeyShare, ctx: &SigningContext) -> PartialSignature {
        assert_eq!(nonce.signer_id, share.id);
        let id = share.id;
        let rho = &ctx.binding_factors[&id];
        let lambda = &ctx.lambdas[&id];
        // z_i = d_i + ρ_i e_i + λ_i c share_i
        let z = nonce.d + *rho * nonce.e + *lambda * ctx.challenge * share.share;
        PartialSignature {
            signer_id: id,
            z: scalar_to_bytes(&z),
        }
    }
}

/// 公开校验单个分片签名（协调者和任何旁观方都能做，用于可识别中止）：
/// z_i·G == D_i + ρ_i E_i + λ_i c VK_i
pub fn verify_partial(
    partial: &PartialSignature,
    ctx: &SigningContext,
    verification_keys: &BTreeMap<u32, ProjectivePoint>,
) -> Result<(), SignError> {
    let id = partial.signer_id;
    let z = scalar_from_bytes(&partial.z)
        .ok_or(SignError::BadPartialSignature { offender: id })?;
    let (d_pt, e_pt) = ctx
        .nonce_commitments
        .get(&id)
        .ok_or(SignError::UnknownSigner { offender: id })?;
    let vk = verification_keys
        .get(&id)
        .ok_or(SignError::UnknownSigner { offender: id })?;
    let rho = &ctx.binding_factors[&id];
    let lambda = &ctx.lambdas[&id];

    let lhs = scalar_mul_g(&z);
    let rhs = *d_pt + (e_pt * rho) + *vk * (*lambda * ctx.challenge);
    if lhs == rhs {
        Ok(())
    } else {
        Err(SignError::BadPartialSignature { offender: id })
    }
}

/// 聚合全部通过校验的分片签名为标准 Schnorr (R, s)。
pub fn aggregate(
    ctx: &SigningContext,
    partials: &[PartialSignature],
) -> Result<Signature, SignError> {
    if partials.len() != ctx.signer_ids.len() {
        return Err(SignError::NotEnoughSigners {
            have: partials.len(),
            need: ctx.signer_ids.len(),
        });
    }
    let mut s = Scalar::ZERO;
    for p in partials {
        if !ctx.signer_ids.contains(&p.signer_id) {
            return Err(SignError::UnknownSigner { offender: p.signer_id });
        }
        let z = scalar_from_bytes(&p.z)
            .ok_or(SignError::BadPartialSignature { offender: p.signer_id })?;
        s += z;
    }
    Ok(Signature {
        r: point_to_bytes(&ctx.group_nonce),
        s: scalar_to_bytes(&s),
    })
}

/// 对外的标准签名验证。验证者只有群公钥 + 消息 + (R,s)，与单人签名同一方程。
pub fn verify(
    group_pk: &ProjectivePoint,
    message: &[u8],
    signature: &Signature,
) -> bool {
    let Some(r) = point_from_bytes(&signature.r) else {
        return false;
    };
    let Some(s) = scalar_from_bytes(&signature.s) else {
        return false;
    };
    crate::curve::schnorr_verify(group_pk, message, &r, &s)
}

/// id 标量的测试/审计辅助。
pub fn id_scalar(id: u32) -> Scalar {
    id_to_scalar(id)
}
