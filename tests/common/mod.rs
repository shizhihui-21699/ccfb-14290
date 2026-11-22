//! 测试公共设施：把多台"签名服务器"的完整协议流程在单进程里编排出来。
//!
//! 每个 Party 对应一台真实部署中的服务器，持有自己的静态私钥、DKG 分片。
//! 作恶测试通过 mutate / suppress 等手段扭曲其中一方的行为。

// 该模块被两个独立 test target 共享，单个 target 只会用到其中一部分辅助函数
#![allow(dead_code)]

use std::collections::BTreeMap;

use frost_custody::channel::{Registry, StaticPrivate};
use frost_custody::curve::{scalar_from_bytes, scalar_mul_g, scalar_to_bytes};
use frost_custody::dkg::{
    CommitmentMessage, DkgError, DkgParty, KeyShare, SealedShare,
};
use frost_custody::frost::{
    self, NonceCommitment, PartialSignature, Signature, SigningContext, SigningNonce,
};
use frost_custody::refresh::RefreshParty;

/// 一台模拟签名服务器。
pub struct Party {
    pub id: u32,
    pub static_private: StaticPrivate,
    pub share: Option<KeyShare>,
}

impl Party {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            static_private: StaticPrivate::generate(),
            share: None,
        }
    }
}

/// 建 n 台服务器和身份注册表。
pub fn bootstrap(n: u32) -> (Vec<Party>, Registry) {
    let parties: Vec<Party> = (1..=n).map(Party::new).collect();
    let refs: Vec<(u32, &StaticPrivate)> = parties
        .iter()
        .map(|p| (p.id, &p.static_private))
        .collect();
    let ids: Vec<u32> = parties.iter().map(|p| p.id).collect();
    let registry = Registry::new(&ids, &refs);
    (parties, registry)
}

/// 诚实执行完整 DKG，返回每方的 KeyShare。
pub fn run_honest_dkg(
    parties: &[Party],
    registry: &Registry,
    threshold: usize,
) -> Result<Vec<KeyShare>, DkgError> {
    let mut dkg_states: BTreeMap<u32, DkgParty> = BTreeMap::new();
    let mut rng = rand::rngs::OsRng;
    for p in parties {
        // 复用注册表里的静态私钥，否则 ECDH 信道的公钥对不上
        dkg_states.insert(
            p.id,
            DkgParty::new(p.id, threshold, &mut rng, p.static_private.clone()),
        );
    }

    // Round 1
    let commits: Vec<CommitmentMessage> =
        dkg_states.values().map(|s| s.round1_commit()).collect();
    for s in dkg_states.values_mut() {
        s.handle_round1(&commits, registry)?;
    }

    // Round 2：每方发出 n 份密文分片，按收件人归集
    let mut mailboxes: BTreeMap<u32, Vec<SealedShare>> = BTreeMap::new();
    for s in dkg_states.values() {
        for sealed in s.round2_sealed_shares(registry) {
            mailboxes
                .entry(sealed.recipient_id)
                .or_default()
                .push(sealed);
        }
    }

    // Finalize
    let mut shares = Vec::new();
    for s in dkg_states.values() {
        let sealed_for_me = mailboxes.get(&s.id()).cloned().unwrap_or_default();
        shares.push(s.finalize(&sealed_for_me, registry)?);
    }
    Ok(shares)
}

/// 带 Round 1 / Round 2 故障注入钩子的 DKG。
///
/// * `tamper_commit`: 在 Round 1 消息广播后对消息列表做任意篡改
/// * `tamper_sealed`: 在 Round 2 密文归集后对某方信箱做任意篡改
pub fn run_dkg_with_hooks<C, S>(
    parties: &[Party],
    registry: &Registry,
    threshold: usize,
    mut tamper_commit: C,
    mut tamper_sealed: S,
) -> Result<Vec<KeyShare>, DkgError>
where
    C: FnMut(&mut Vec<CommitmentMessage>),
    S: FnMut(u32, &mut Vec<SealedShare>),
{
    let mut dkg_states: BTreeMap<u32, DkgParty> = BTreeMap::new();
    let mut rng = rand::rngs::OsRng;
    for p in parties {
        dkg_states.insert(
            p.id,
            DkgParty::new(p.id, threshold, &mut rng, p.static_private.clone()),
        );
    }

    let mut commits: Vec<CommitmentMessage> =
        dkg_states.values().map(|s| s.round1_commit()).collect();
    tamper_commit(&mut commits);

    for s in dkg_states.values_mut() {
        s.handle_round1(&commits, registry)?;
    }

    let mut mailboxes: BTreeMap<u32, Vec<SealedShare>> = BTreeMap::new();
    for s in dkg_states.values() {
        for sealed in s.round2_sealed_shares(registry) {
            mailboxes
                .entry(sealed.recipient_id)
                .or_default()
                .push(sealed);
        }
    }
    for (recipient, box_) in mailboxes.iter_mut() {
        tamper_sealed(*recipient, box_);
    }

    let mut shares = Vec::new();
    for s in dkg_states.values() {
        let sealed_for_me = mailboxes.get(&s.id()).cloned().unwrap_or_default();
        shares.push(s.finalize(&sealed_for_me, registry)?);
    }
    Ok(shares)
}

/// 诚实执行一次 t-of-n 门限签名。signer_ids 为本次参与签名的 t 方。
pub fn run_honest_signing(
    shares: &[KeyShare],
    signer_ids: &[u32],
    message: &[u8],
) -> Result<Signature, frost::SignError> {
    let by_id: BTreeMap<u32, &KeyShare> = shares.iter().map(|s| (s.id, s)).collect();
    let group_pk = shares[0].group_pk;
    let threshold = shares[0].threshold;
    let mut rng = rand::rngs::OsRng;

    // Round 1
    let mut nonces: BTreeMap<u32, SigningNonce> = BTreeMap::new();
    let mut commits: Vec<NonceCommitment> = Vec::new();
    for id in signer_ids {
        let (nonce, commit) = frost::Signer::round1_commit(*id, &mut rng);
        nonces.insert(*id, nonce);
        commits.push(commit);
    }

    let ctx = SigningContext::new(signer_ids, &commits, &group_pk, message, threshold)?;

    // Round 2
    let mut partials: Vec<PartialSignature> = Vec::new();
    for id in signer_ids {
        let share = by_id[id];
        let nonce = &nonces[id];
        partials.push(frost::Signer::round2_sign(nonce, share, &ctx));
    }

    // 每个分片签名先公开校验再聚合
    let vks = &shares[0].verification_keys;
    for p in &partials {
        frost::verify_partial(p, &ctx, vks)?;
    }
    frost::aggregate(&ctx, &partials)
}

/// 带 Round 2 故障注入的签名：允许替换/扣压某个分片签名。
pub fn run_signing_with_bad_partial(
    shares: &[KeyShare],
    signer_ids: &[u32],
    message: &[u8],
    bad_actor: u32,
) -> Result<Signature, frost::SignError> {
    let by_id: BTreeMap<u32, &KeyShare> = shares.iter().map(|s| (s.id, s)).collect();
    let group_pk = shares[0].group_pk;
    let threshold = shares[0].threshold;
    let mut rng = rand::rngs::OsRng;

    let mut nonces: BTreeMap<u32, SigningNonce> = BTreeMap::new();
    let mut commits: Vec<NonceCommitment> = Vec::new();
    for id in signer_ids {
        let (nonce, commit) = frost::Signer::round1_commit(*id, &mut rng);
        nonces.insert(*id, nonce);
        commits.push(commit);
    }
    let ctx = SigningContext::new(signer_ids, &commits, &group_pk, message, threshold)?;

    let mut partials: Vec<PartialSignature> = Vec::new();
    for id in signer_ids {
        let share = by_id[id];
        let nonce = &nonces[id];
        let mut p = frost::Signer::round2_sign(nonce, share, &ctx);
        if *id == bad_actor {
            // 作恶：分片签名标量直接加 1，造出一个代数上不成立的 z
            let mut z = scalar_from_bytes(&p.z).unwrap();
            z += k256::Scalar::ONE;
            p.z = scalar_to_bytes(&z);
        }
        partials.push(p);
    }

    let vks = &shares[0].verification_keys;
    for p in &partials {
        frost::verify_partial(p, &ctx, vks)?;
    }
    frost::aggregate(&ctx, &partials)
}

/// 中途掉线：某方 Round 1 之后彻底沉默，剩余诚实方不足 t。
pub fn run_signing_with_dropout(
    shares: &[KeyShare],
    signer_ids: &[u32],
    message: &[u8],
    dropped: u32,
) -> Result<Signature, frost::SignError> {
    let group_pk = shares[0].group_pk;
    let threshold = shares[0].threshold;
    let mut rng = rand::rngs::OsRng;

    let surviving: Vec<u32> = signer_ids.iter().copied().filter(|id| *id != dropped).collect();

    let mut nonces: BTreeMap<u32, SigningNonce> = BTreeMap::new();
    let mut commits: Vec<NonceCommitment> = Vec::new();
    for id in &surviving {
        let (nonce, commit) = frost::Signer::round1_commit(*id, &mut rng);
        nonces.insert(*id, nonce);
        commits.push(commit);
    }
    // 用幸存集合构造上下文；若人数 < t，这里直接报错
    SigningContext::new(&surviving, &commits, &group_pk, message, threshold)?;
    unreachable!("dropout case must fail at context construction when below threshold")
}

/// 诚实执行一次主动刷新，返回刷新后的新分片（公钥应保持不变）。
pub fn run_honest_refresh(
    parties: &[Party],
    shares: &[KeyShare],
    registry: &Registry,
) -> Result<Vec<KeyShare>, DkgError> {
    let mut refresh_states: BTreeMap<u32, RefreshParty> = BTreeMap::new();
    for (p, s) in parties.iter().zip(shares.iter()) {
        refresh_states.insert(
            s.id,
            RefreshParty::new(s.id, s.threshold, p.static_private.clone()),
        );
    }

    let commits: Vec<CommitmentMessage> =
        refresh_states.values().map(|r| r.round1_commit()).collect();
    for r in refresh_states.values_mut() {
        r.handle_round1(&commits, registry)?;
    }

    let mut mailboxes: BTreeMap<u32, Vec<SealedShare>> = BTreeMap::new();
    for r in refresh_states.values() {
        for sealed in r.round2_sealed_shares(registry) {
            mailboxes
                .entry(sealed.recipient_id)
                .or_default()
                .push(sealed);
        }
    }

    let old_by_id: BTreeMap<u32, &KeyShare> = shares.iter().map(|s| (s.id, s)).collect();
    let mut new_shares = Vec::new();
    for r in refresh_states.values() {
        let sealed_for_me = mailboxes.get(&r.party_id()).cloned().unwrap_or_default();
        let new_share = r.apply(old_by_id[&r.party_id()], &sealed_for_me, registry)?;
        new_shares.push(new_share);
    }
    Ok(new_shares)
}

/// 刷新过程中某方发送错误增量分片。
pub fn run_refresh_with_bad_delta(
    parties: &[Party],
    shares: &[KeyShare],
    registry: &Registry,
    bad_actor: u32,
    target: u32,
) -> Result<Vec<KeyShare>, DkgError> {
    let mut refresh_states: BTreeMap<u32, RefreshParty> = BTreeMap::new();
    for (p, s) in parties.iter().zip(shares.iter()) {
        refresh_states.insert(
            s.id,
            RefreshParty::new(s.id, s.threshold, p.static_private.clone()),
        );
    }

    let commits: Vec<CommitmentMessage> =
        refresh_states.values().map(|r| r.round1_commit()).collect();
    for r in refresh_states.values_mut() {
        r.handle_round1(&commits, registry)?;
    }

    let mut mailboxes: BTreeMap<u32, Vec<SealedShare>> = BTreeMap::new();
    for r in refresh_states.values() {
        for mut sealed in r.round2_sealed_shares(registry) {
            if sealed.dealer_id == bad_actor && sealed.recipient_id == target {
                // 篡改密文：翻转最后一个字节（GCM 标签位），解密/完整性校验必失败
                let last = sealed.ciphertext.len() - 1;
                sealed.ciphertext[last] ^= 0xff;
            }
            mailboxes
                .entry(sealed.recipient_id)
                .or_default()
                .push(sealed);
        }
    }

    let old_by_id: BTreeMap<u32, &KeyShare> = shares.iter().map(|s| (s.id, s)).collect();
    let mut new_shares = Vec::new();
    for r in refresh_states.values() {
        let sealed_for_me = mailboxes.get(&r.party_id()).cloned().unwrap_or_default();
        new_shares.push(r.apply(old_by_id[&r.party_id()], &sealed_for_me, registry)?);
    }
    Ok(new_shares)
}

/// 辅助：检查若干分片的 VK 与群公钥的关系（测试里做一致性断言用）。
pub fn assert_share_consistency(shares: &[KeyShare]) {
    let pk = shares[0].group_pk;
    for s in shares {
        assert_eq!(s.group_pk, pk);
        assert_eq!(scalar_mul_g(&s.share), s.verification_keys[&s.id]);
    }
}
