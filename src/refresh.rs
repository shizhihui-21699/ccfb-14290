//! 主动刷新（Proactive Refresh / Proactive Secret Sharing）。
//!
//! # 协议（Herzberg-Jarecki-Krawczyk-Yung, "Proactive Secret Sharing", 1995）
//!
//! 设当前分片是 (t-1) 次多项式 f 上的 share_i = f(i)，群公钥 PK = f(0)·G。
//! 刷新时每方 i 选一个**常数项为 0** 的随机 (t-1) 次多项式 z_i(x)：
//!   z_i(0) = 0
//! 并像 DKG 一样广播 Feldman 承诺、点对点加密发送 z_i(j)。
//! 令 z(x) = Σ_i z_i(x)，则 z(0) = 0。每方更新：
//!   share'_j = share_j + Σ_i z_i(j) = f(j) + z(j) = (f+z)(j)
//! 而新私钥位置：
//!   (f+z)(0) = f(0) + z(0) = f(0) = s
//! 所以群公钥 PK = s·G 完全不变，但所有分片都是新的随机值。
//!
//! # 安全含义
//! * 攻击者必须在**单个刷新周期内**同时拿到 t 个分片才能恢复私钥；
//!   上一周期偷到的旧分片在刷新后对新分片没有任何信息贡献。
//! * 刷新本身复用 DKG 的全部防作恶机制（PoK、密文信道、Feldman 可识别中止），
//!   作恶方在刷新里发坏增量分片同样会被精确指认。
//! * 刷新要求全部 n 方在线；这是 t-of-n PSS 的标准形态。若需要容忍
//!   刷新期掉线，要走 share recovery 协议（Herzberg 1995 §5，README 有说明）。
//!
//! 本模块把刷新编排成显式的 `RefreshSession`，与 DKG 共用消息类型，
//! 方便同一套网络/模拟设施驱动两个流程。

use std::collections::BTreeMap;

use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;

use crate::channel::{Registry, StaticPrivate};
use crate::curve::{id_to_scalar, point_from_bytes, scalar_mul_g};
use crate::dkg::{CommitmentMessage, DkgError, DkgParty, KeyShare, SealedShare};
use crate::shamir::verify_share;

/// 一次刷新会话中某方的本地状态。
pub struct RefreshParty {
    inner: DkgParty,
}

impl RefreshParty {
    pub fn new(id: u32, threshold: usize, static_private: StaticPrivate) -> Self {
        Self {
            inner: DkgParty::new_refresh(id, threshold, &mut OsRng, static_private),
        }
    }

    /// 本方参与方 id。
    pub fn party_id(&self) -> u32 {
        self.inner.id()
    }

    pub fn round1_commit(&self) -> CommitmentMessage {
        self.inner.round1_commit()
    }

    pub fn handle_round1(
        &mut self,
        messages: &[CommitmentMessage],
        registry: &Registry,
    ) -> Result<(), DkgError> {
        self.inner.handle_round1(messages, registry)?;
        // 刷新协议额外约束：每个 dealer 的首个承诺必须是无穷大点 O = 0·G，
        // 即 z_i(0)=0。任何夹带非零常数项的"刷新"都会改变公钥，必须拒绝。
        for msg in messages {
            let first = point_from_bytes(&msg.commitments[0])
                .ok_or(DkgError::BadCommitmentEncoding { offender: msg.dealer_id })?;
            if !bool::from(first.is_identity()) {
                return Err(DkgError::BadCommitmentEncoding { offender: msg.dealer_id });
            }
        }
        Ok(())
    }

    pub fn round2_sealed_shares(&self, registry: &Registry) -> Vec<SealedShare> {
        self.inner.round2_sealed_shares(registry)
    }

    /// 校验增量分片并把旧 KeyShare 原地更新为新 KeyShare。
    ///
    /// 返回的新 share 与旧 share 以压倒性概率不同（随机性来自各方 z_i），
    /// 而 group_pk 与全部 VK 的派生基准保持一致。
    pub fn apply(
        &self,
        old: &KeyShare,
        sealed_for_me: &[SealedShare],
        registry: &Registry,
    ) -> Result<KeyShare, DkgError> {
        if old.id != self.inner.id {
            return Err(DkgError::RegistryMismatch);
        }
        // 复用 DKG 的解密 + Feldman 校验逻辑：构造一个"全增量"的临时 share。
        // DkgParty::finalize 会做 PoK/承诺查表/Feldman，这里不能直接调用
        // （它会重算 group_pk），所以把校验步骤显式展开。
        let mut delta = Scalar::ZERO;
        for sealed in sealed_for_me {
            if sealed.recipient_id != old.id {
                return Err(DkgError::RegistryMismatch);
            }
            let dealer_pk = registry
                .pubkey_of(sealed.dealer_id)
                .ok_or(DkgError::RegistryMismatch)?;
            let static_private = self.inner.static_private_view();
            let plaintext = static_private
                .open(dealer_pk, &sealed.ciphertext)
                .ok_or(DkgError::CannotDecrypt { offender: sealed.dealer_id })?;
            let piece = crate::curve::scalar_from_bytes(&plaintext)
                .ok_or(DkgError::BadShare { offender: sealed.dealer_id })?;
            // 重新通过 Round 1 承诺做 Feldman 校验
            let commitments = self
                .inner
                .commitments_view()
                .get(&sealed.dealer_id)
                .ok_or(DkgError::RegistryMismatch)?;
            if !verify_share(old.id, &piece, commitments) {
                return Err(DkgError::BadShare { offender: sealed.dealer_id });
            }
            delta += piece;
        }

        let new_share = old.share + delta;

        // 重新复算全部 VK：VK'_j = VK_j + Σ_i (z_i 承诺在 j 处的求值)
        let mut verification_keys: BTreeMap<u32, ProjectivePoint> = BTreeMap::new();
        for &id in &registry.ids {
            let mut z_at_j = ProjectivePoint::IDENTITY;
            for commitments in self.inner.commitments_view().values() {
                let x = id_to_scalar(id);
                let mut evaluated = ProjectivePoint::IDENTITY;
                for c in commitments.iter().rev() {
                    evaluated = evaluated * x + c;
                }
                z_at_j += evaluated;
            }
            verification_keys.insert(id, old.verification_keys[&id] + z_at_j);
        }

        // 必须保证：新分片对应新 VK，且群公钥纹丝不动
        assert_eq!(scalar_mul_g(&new_share), verification_keys[&old.id]);

        Ok(KeyShare {
            id: old.id,
            threshold: old.threshold,
            share: new_share,
            group_pk: old.group_pk,
            verification_keys,
        })
    }
}
