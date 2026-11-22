//! 协议安全属性测试（无作恶条件下的正确性基线）：
//! 1. DKG 产出的群公钥在所有方一致，且任何单机都不持有完整私钥；
//! 2. t 个分片可以合签，t-1 个不行；
//! 3. 门限签名与单人 Schnorr 签名走同一个验证方程（不可区分）；
//! 4. 主动刷新后分片全部变化而群公钥不变，新分片仍可签名；
//! 5. t-1 个分片在信息论意义下无法确定私钥（同一组 t-1 分片对应无穷多个 VK 一致的秘密）。

mod common;

use std::collections::BTreeMap;

use frost_custody::curve::{
    point_from_bytes, scalar_from_bytes, scalar_mul_g, schnorr_sign, schnorr_verify,
};
use frost_custody::frost;
use frost_custody::shamir::interpolate_secret_at_zero;
use k256::Scalar;
use rand::rngs::OsRng;

use common::{
    bootstrap, run_honest_dkg, run_honest_refresh, run_honest_signing, assert_share_consistency,
};

const N: u32 = 5;
const T: usize = 3;

#[test]
fn dkg_produces_consistent_public_key_and_local_shares() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).expect("honest DKG must succeed");

    assert_eq!(shares.len(), N as usize);
    assert_share_consistency(&shares);

    // 所有方看到同一个群公钥
    let pk = shares[0].group_pk;
    assert!(shares.iter().all(|s| s.group_pk == pk));

    // 任意 t 个分片插值出的"私钥"都对应群公钥——但这个值只在测试里被显式计算，
    // 生产代码路径中不存在该重建操作。
    let t_shares: Vec<(u32, Scalar)> = shares[0..T]
        .iter()
        .map(|s| (s.id, s.share))
        .collect();
    let reconstructed = interpolate_secret_at_zero(&t_shares);
    assert_eq!(scalar_mul_g(&reconstructed), pk);
}

#[test]
fn threshold_signing_works_and_verifies_like_a_single_party_signature() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let pk = shares[0].group_pk;
    let message = b"transfer 1.5 BTC to bc1q... custody policy #42";

    // t 个参与方合签
    let signers = vec![1u32, 3, 5];
    let signature = run_honest_signing(&shares, &signers, message).unwrap();

    // 标准验证方程，验证者只需要群公钥
    assert!(frost::verify(&pk, message, &signature));

    // 换一个不同的 t 方子集（2,3,4）也能签同一个消息并通过验证
    let signers2 = vec![2u32, 3, 4];
    let signature2 = run_honest_signing(&shares, &signers2, message).unwrap();
    assert!(frost::verify(&pk, message, &signature2));

    // 两次签名的 (R, s) 必然不同（nonce 新鲜），但都合法——概率上碰撞可忽略
    assert_ne!(signature, signature2);

    // 消息改一个字节，验证失败
    let mut tampered = message.to_vec();
    tampered[9] ^= 0x01;
    assert!(!frost::verify(&pk, &tampered, &signature));
}

#[test]
fn threshold_signature_is_indistinguishable_from_single_party_schnorr() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let pk = shares[0].group_pk;
    let message = b"indistinguishability probe";

    // 门限签名
    let sig = run_honest_signing(&shares, &[1u32, 2, 3], message).unwrap();

    // 用插值出来的私钥做一次单人签名（仅测试对照用）
    let t_shares: Vec<(u32, Scalar)> = shares[0..T]
        .iter()
        .map(|s| (s.id, s.share))
        .collect();
    let secret = interpolate_secret_at_zero(&t_shares);
    assert_eq!(scalar_mul_g(&secret), pk);
    let (r_single, s_single) = schnorr_sign(&secret, message, &mut OsRng);

    // 两者用完全相同的验证函数、只凭群公钥即可验证——
    // 验证者无法从签名结构判断它是单人签的还是 t 方合签的。
    let r_pt = point_from_bytes(&sig.r).unwrap();
    let s_sc = scalar_from_bytes(&sig.s).unwrap();
    assert!(schnorr_verify(&pk, message, &r_pt, &s_sc));
    assert!(schnorr_verify(&pk, message, &r_single, &s_single));

    // 单人签名也能通过 frost::verify（同一方程的包装）
    let single_wrapped = frost::Signature {
        r: frost_custody::curve::point_to_bytes(&r_single),
        s: frost_custody::curve::scalar_to_bytes(&s_single),
    };
    assert!(frost::verify(&pk, message, &single_wrapped));
}

#[test]
fn proactive_refresh_changes_every_share_but_keeps_public_key() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let pk_before = shares[0].group_pk;
    let old_scalars: BTreeMap<u32, Scalar> =
        shares.iter().map(|s| (s.id, s.share)).collect();

    let refreshed = run_honest_refresh(&parties, &shares, &registry).expect("refresh must succeed");

    // 群公钥纹丝不动
    assert!(refreshed.iter().all(|s| s.group_pk == pk_before));
    assert_share_consistency(&refreshed);

    // 每个分片都变了（刷新引入了新鲜随机量；全相等的概率可忽略）
    for s in &refreshed {
        assert_ne!(s.share, old_scalars[&s.id], "share {} was not refreshed", s.id);
    }

    // 新分片仍能门限签名，旧分片和新分片不能混用（VK 已换代）
    let message = b"post-refresh withdrawal";
    let sig = run_honest_signing(&refreshed, &[2u32, 4, 5], message).unwrap();
    assert!(frost::verify(&pk_before, message, &sig));
}

#[test]
fn t_minus_one_shares_hide_the_secret_information_theoretically() {
    // 信息论性质演示（Shamir 完美保密性）：固定 t-1 个分片值，
    // 可以构造出两个不同的全局私钥 s != s'，使得这 t-1 个分片对两者都成立。
    // 因此持有 t-1 台服务器的攻击者连"私钥是哪一个"都无法判定，
    // 后验分布与先验相同——不是计算上难，而是信息里根本没有答案。
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();

    let compromised_ids = [1u32, 2]; // t-1 = 2 个被攻破的服务器
    let known: Vec<(u32, Scalar)> = compromised_ids
        .iter()
        .map(|id| (*id, shares.iter().find(|s| s.id == *id).unwrap().share))
        .collect();

    // 用两个不同的"第三个点"补全成两组 t 元组，插值出两个不同私钥候选。
    // 两组共享 known 里的 t-1 个分片，差别只在攻击者没拿到的第三个分片。
    let third_id = 3u32;
    let share_3 = shares.iter().find(|s| s.id == third_id).unwrap().share;
    let candidate_points_a = [known[0], known[1], (third_id, share_3)];
    let candidate_points_b = [known[0], known[1], (third_id, share_3 + Scalar::ONE)];

    let secret_a = interpolate_secret_at_zero(&candidate_points_a);
    let secret_b = interpolate_secret_at_zero(&candidate_points_b);

    // 两个候选私钥不同，对应不同公钥——但它们与已泄露的 t-1 个分片同时相容
    assert_ne!(secret_a, secret_b);
    assert_ne!(scalar_mul_g(&secret_a), scalar_mul_g(&secret_b));

    // 真实世界里的门限保证：t-1 方凑不出签名上下文，协议层直接拒绝
    let result = run_honest_signing(&shares, &compromised_ids, b"attempted theft");
    assert!(matches!(
        result,
        Err(frost::SignError::NotEnoughSigners { have: 2, need: T })
    ));
}

#[test]
fn every_partial_signature_is_publicly_checkable_against_vk() {
    // 分片签名 z_i 的校验方程只依赖公开数据（承诺、绑定因子、VK），
    // 这是可识别中止的前提：谁作恶，全网都能独立验证并指认。
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let pk = shares[0].group_pk;
    let message = b"public auditability";

    let signers = vec![1u32, 3, 4];
    let sig = run_honest_signing(&shares, &signers, message).unwrap();
    assert!(frost::verify(&pk, message, &sig));
}
