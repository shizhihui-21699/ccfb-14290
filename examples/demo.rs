//! 端到端演示：5 台签名服务器、门限 3，完整走一遍
//! 分布式密钥生成 -> 门限签名 -> 主动刷新 -> 刷新后继续签名 的生命周期，
//! 并穿插一次作恶演示（错误分片签名被精确指认）。
//!
//! 运行：cargo run --offline --example demo

use std::collections::BTreeMap;

use frost_custody::channel::{Registry, StaticPrivate};
use frost_custody::curve::point_to_bytes;
use frost_custody::dkg::{CommitmentMessage, DkgParty, KeyShare, SealedShare};
use frost_custody::frost;
use frost_custody::refresh::RefreshParty;
use rand::rngs::OsRng;

const N: u32 = 5;
const T: usize = 3;

struct Server {
    id: u32,
    static_private: StaticPrivate,
}

fn main() {
    println!("=== FROST 门限签名托管系统演示 (t={T}, n={N}) ===");

    // ---------- 0. 服务器入网：每台生成静态身份密钥，注册表记录公钥 ----------
    let servers: Vec<Server> = (1..=N)
        .map(|id| Server {
            id,
            static_private: StaticPrivate::generate(),
        })
        .collect();
    let ids: Vec<u32> = servers.iter().map(|s| s.id).collect();
    let refs: Vec<(u32, &StaticPrivate)> = servers
        .iter()
        .map(|s| (s.id, &s.static_private))
        .collect();
    let registry = Registry::new(&ids, &refs);

    // ---------- 1. DKG：完整私钥从未出现 ----------
    println!("\n[1] 分布式密钥生成（DKG）");
    let mut rng = OsRng;
    let mut dkg: BTreeMap<u32, DkgParty> = BTreeMap::new();
    for s in &servers {
        dkg.insert(
            s.id,
            DkgParty::new(s.id, T, &mut rng, s.static_private.clone()),
        );
    }
    let commits: Vec<CommitmentMessage> = dkg.values().map(|p| p.round1_commit()).collect();
    for p in dkg.values_mut() {
        p.handle_round1(&commits, &registry).expect("Round 1 校验");
    }
    let mut mail: BTreeMap<u32, Vec<SealedShare>> = BTreeMap::new();
    for p in dkg.values() {
        for sealed in p.round2_sealed_shares(&registry) {
            mail.entry(sealed.recipient_id).or_default().push(sealed);
        }
    }
    let mut shares: Vec<KeyShare> = Vec::new();
    for p in dkg.values() {
        shares.push(
            p.finalize(mail.get(&p.id()).unwrap(), &registry)
                .expect("Round 2 校验"),
        );
    }
    let pk = shares[0].group_pk;
    println!("  群公钥（所有服务器一致）: {}…", hex::encode(point_to_bytes(&pk)));
    println!("  每台服务器只持有自己的分片标量，完整私钥 s 从未在任何内存中出现");

    // ---------- 2. 门限签名：3 台合签一笔提现 ----------
    println!("\n[2] 门限签名：服务器 1、3、5 合签提现消息");
    let message = b"withdraw 2.0 BTC, policy id 777";
    let sig = sign(&shares, &[1, 3, 5], message);
    let ok = frost::verify(&pk, message, &sig);
    println!("  签名 (R, s) 验证结果: {}", if ok { "通过 ✓" } else { "失败 ✗" });
    assert!(ok);

    // ---------- 3. 作恶演示：服务器 3 发出错误分片签名 ----------
    println!("\n[3] 作恶演示：服务器 3 在 Round 2 发送伪造分片签名");
    let attack = sign_with_malicious(&shares, &[1, 3, 5], message, 3);
    match attack {
        Err(frost::SignError::BadPartialSignature { offender }) => {
            println!("  协议拒绝签名并精确指认作恶者：服务器 {offender} ✓");
        }
        other => panic!("未预期结果: {other:?}"),
    }

    // ---------- 4. 主动刷新：分片全换，公钥不变 ----------
    println!("\n[4] 主动刷新（proactive refresh）：周期更换分片，公钥保持不变");
    let old_scalars: BTreeMap<u32, _> = shares.iter().map(|s| (s.id, s.share)).collect();
    shares = refresh(&servers, &shares, &registry);
    for s in &shares {
        assert_ne!(s.share, old_scalars[&s.id]);
        assert_eq!(s.group_pk, pk);
    }
    println!("  全部 {} 台服务器的分片已更换，群公钥不变 ✓", N);

    // ---------- 5. 刷新后用新分片继续签名 ----------
    println!("\n[5] 刷新后再次签名：服务器 2、3、4 用新分片合签");
    let sig2 = sign(&shares, &[2, 3, 4], message);
    let ok2 = frost::verify(&pk, message, &sig2);
    println!("  新分片签名验证结果: {}", if ok2 { "通过 ✓" } else { "失败 ✗" });
    assert!(ok2);

    // ---------- 6. 掉线演示：不足 t 台无法签出 ----------
    println!("\n[6] 可用性演示：签名组只剩 2 台（< t=3），协议拒绝输出签名");
    let result = try_sign_insufficient(&shares, &[1, 2], message);
    match result {
        Err(frost::SignError::NotEnoughSigners { have, need }) => {
            println!("  拒绝签名：have={have}, need={need} ✓");
        }
        other => panic!("未预期结果: {other:?}"),
    }

    println!("\n=== 全部生命周期演示完成 ===");
}

fn sign(shares: &[KeyShare], signer_ids: &[u32], message: &[u8]) -> frost::Signature {
    let by_id: BTreeMap<u32, &KeyShare> = shares.iter().map(|s| (s.id, s)).collect();
    let mut rng = OsRng;
    let mut nonces = BTreeMap::new();
    let mut commits = Vec::new();
    for id in signer_ids {
        let (nonce, commit) = frost::Signer::round1_commit(*id, &mut rng);
        nonces.insert(*id, nonce);
        commits.push(commit);
    }
    let ctx = frost::SigningContext::new(
        signer_ids,
        &commits,
        &shares[0].group_pk,
        message,
        T,
    )
    .unwrap();
    let partials: Vec<_> = signer_ids
        .iter()
        .map(|id| frost::Signer::round2_sign(&nonces[id], by_id[id], &ctx))
        .collect();
    let vks = &shares[0].verification_keys;
    for p in &partials {
        frost::verify_partial(p, &ctx, vks).unwrap();
    }
    frost::aggregate(&ctx, &partials).unwrap()
}

fn sign_with_malicious(
    shares: &[KeyShare],
    signer_ids: &[u32],
    message: &[u8],
    bad_actor: u32,
) -> Result<frost::Signature, frost::SignError> {
    use frost_custody::curve::{scalar_from_bytes, scalar_to_bytes};
    use k256::Scalar;

    let by_id: BTreeMap<u32, &KeyShare> = shares.iter().map(|s| (s.id, s)).collect();
    let mut rng = OsRng;
    let mut nonces = BTreeMap::new();
    let mut commits = Vec::new();
    for id in signer_ids {
        let (nonce, commit) = frost::Signer::round1_commit(*id, &mut rng);
        nonces.insert(*id, nonce);
        commits.push(commit);
    }
    let ctx = frost::SigningContext::new(
        signer_ids,
        &commits,
        &shares[0].group_pk,
        message,
        T,
    )?;
    let partials: Vec<_> = signer_ids
        .iter()
        .map(|id| {
            let mut p = frost::Signer::round2_sign(&nonces[id], by_id[id], &ctx);
            if *id == bad_actor {
                let mut z = scalar_from_bytes(&p.z).unwrap();
                z += Scalar::ONE; // 故意发错
                p.z = scalar_to_bytes(&z);
            }
            p
        })
        .collect();
    let vks = &shares[0].verification_keys;
    for p in &partials {
        frost::verify_partial(p, &ctx, vks)?;
    }
    frost::aggregate(&ctx, &partials)
}

fn refresh(
    servers: &[Server],
    shares: &[KeyShare],
    registry: &Registry,
) -> Vec<KeyShare> {
    let mut states: BTreeMap<u32, RefreshParty> = BTreeMap::new();
    for s in shares {
        let server = servers.iter().find(|srv| srv.id == s.id).unwrap();
        states.insert(
            s.id,
            RefreshParty::new(s.id, s.threshold, server.static_private.clone()),
        );
    }
    let commits: Vec<CommitmentMessage> = states.values().map(|r| r.round1_commit()).collect();
    for r in states.values_mut() {
        r.handle_round1(&commits, registry).expect("刷新 Round 1");
    }
    let mut mail: BTreeMap<u32, Vec<SealedShare>> = BTreeMap::new();
    for r in states.values() {
        for sealed in r.round2_sealed_shares(registry) {
            mail.entry(sealed.recipient_id).or_default().push(sealed);
        }
    }
    let old: BTreeMap<u32, &KeyShare> = shares.iter().map(|s| (s.id, s)).collect();
    let mut out = Vec::new();
    for r in states.values() {
        let new_share = r
            .apply(old[&r.party_id()], mail.get(&r.party_id()).unwrap(), registry)
            .expect("刷新 Round 2");
        out.push(new_share);
    }
    out
}

fn try_sign_insufficient(
    shares: &[KeyShare],
    signer_ids: &[u32],
    message: &[u8],
) -> Result<frost::Signature, frost::SignError> {
    let mut rng = OsRng;
    let mut commits = Vec::new();
    for id in signer_ids {
        let (_, commit) = frost::Signer::round1_commit(*id, &mut rng);
        commits.push(commit);
    }
    match frost::SigningContext::new(
        signer_ids,
        &commits,
        &shares[0].group_pk,
        message,
        T,
    ) {
        Ok(_) => panic!("不足门限应当报错"),
        Err(e) => Err(e),
    }
}
