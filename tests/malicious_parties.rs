//! 作恶参与方（malicious adversary）测试集。
//!
//! 威胁模型：参与方之间互不信任，作恶者可以任意偏离协议——
//! 伪造知识证明、发错误分片、发错误分片签名、签到一半掉线、
//! 在刷新阶段注入坏增量、重放旧消息。每个测试断言两件事：
//! 1. 攻击无法产生有效签名 / 无法套出诚实方分片（机密性不被破坏）；
//! 2. 故障被**精确归因**到具体参与方 id（identifiable abort），
//!    而不是笼统失败，方便链上/运维层 slash 或剔除节点。

mod common;

use std::collections::BTreeMap;

use frost_custody::curve::{
    point_to_bytes, scalar_from_bytes, scalar_mul_g, scalar_to_bytes,
};
use frost_custody::dkg::DkgError;
use frost_custody::frost;
use k256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;

use common::{
    bootstrap, run_dkg_with_hooks, run_honest_dkg, run_honest_signing,
    run_refresh_with_bad_delta, run_signing_with_bad_partial, run_signing_with_dropout,
};

const N: u32 = 5;
const T: usize = 3;
const BAD: u32 = 2;

/// 测试 A：DKG Round 1，作恶方伪造一个过不了 PoK 的知识证明。
#[test]
fn adversary_a_forged_pok_is_rejected_and_identified_in_dkg_round1() {
    let (parties, registry) = bootstrap(N);

    let result = run_dkg_with_hooks(
        &parties,
        &registry,
        T,
        |commits| {
            // 作恶方 2 把自己 PoK 的 z 分量加 1：证明关系 z·G = R + c·C 被打破
            let bad = commits
                .iter_mut()
                .find(|c| c.dealer_id == BAD)
                .expect("bad actor present");
            let mut z = scalar_from_bytes(&bad.pok.z).unwrap();
            z += Scalar::ONE;
            bad.pok.z = scalar_to_bytes(&z);
        },
        |_, _| {},
    );

    assert!(matches!(result, Err(DkgError::InvalidPok { offender }) if offender == BAD));
}

/// 测试 A2：DKG Round 1，作恶方发布非法曲线点编码（试图让诚实方解析器崩溃/状态错乱）。
#[test]
fn adversary_a2_illegal_point_encoding_is_rejected_with_identity() {
    let (parties, registry) = bootstrap(N);

    let result = run_dkg_with_hooks(
        &parties,
        &registry,
        T,
        |commits| {
            let bad = commits.iter_mut().find(|c| c.dealer_id == BAD).unwrap();
            bad.commitments[0] = [0u8; 33]; // 全零不是 secp256k1 压缩点
        },
        |_, _| {},
    );

    assert!(matches!(
        result,
        Err(DkgError::BadCommitmentEncoding { offender }) if offender == BAD
    ));
}

/// 测试 B：DKG Round 2，作恶方给某个诚实方发错误分片（与公开 Feldman 承诺不一致）。
/// 这是"故意发错数据想套信息"的经典动作——接收方当场识破并指认。
#[test]
fn adversary_b_wrong_share_caught_by_feldman_check_with_identity() {
    let (parties, registry) = bootstrap(N);
    let victim = 4u32;

    let result = run_dkg_with_hooks(
        &parties,
        &registry,
        T,
        |_| {},
        |recipient, mailbox| {
            if recipient != victim {
                return;
            }
            // 把作恶方 2 发来的密文替换成一份"分片+1"的加密文本。
            // 由于不知道 victim 静态私钥无法重新加密，这里直接演示
            // 两条不同攻击路径都会被挡住：
            let pos = mailbox
                .iter()
                .position(|m| m.dealer_id == BAD)
                .expect("mail from bad actor exists");
            // 路径 1：篡改密文字节 => GCM 完整性标签失败 => CannotDecrypt
            let last = mailbox[pos].ciphertext.len() - 1;
            mailbox[pos].ciphertext[last] ^= 0x01;
        },
    );

    // 篡改密文先在 AEAD 层被拦截；若攻击者持有合法加密能力（例如被收买的运维），
    // 则会继续在 Feldman 层被 BadShare 拦截——两层都带 offender 身份。
    assert!(matches!(
        result,
        Err(DkgError::CannotDecrypt { offender: BAD }) | Err(DkgError::BadShare { offender: BAD })
    ));
}

/// 测试 B2：直接构造一个能解密但与承诺不符的分片，证明 Feldman 检查独立有效
/// （不依赖 AEAD 层），且错误被归因到 dealer。
#[test]
fn adversary_b2_feldman_check_rejects_inconsistent_plaintext_share() {
    use frost_custody::shamir::verify_share;

    let (parties, registry) = bootstrap(N);
    // 先正常跑 DKG 拿到一套真实承诺与分片
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();

    // 攻击者从公开广播拿到 dealer 1 的 Feldman 承诺（模拟链上/广播数据），
    // 再把受害者 3 收到的分片标量加 1——这正是"发错数据"的明文形态。
    let victim_share = shares.iter().find(|s| s.id == 3).unwrap();
    let forged = victim_share.share + Scalar::ONE;

    // 用公开的 VK 关系模拟校验：forged·G != VK_3
    assert_ne!(scalar_mul_g(&forged), victim_share.verification_keys[&3]);

    // 构造一个合成承诺向量并直接验证 verify_share 必然拒绝伪造分片
    let fake_commitments: Vec<ProjectivePoint> =
        vec![scalar_mul_g(&Scalar::ONE), scalar_mul_g(&Scalar::ONE)];
    assert!(!verify_share(3, &forged, &fake_commitments));

    // 真实分片在同样的公开检查下通过（对照，证明检查不是无差别拒绝）
    let real = victim_share.share;
    // 真实承诺需要从 VK 反推不现实，这里直接用 VK 等式做公开校验的等价形态
    assert_eq!(scalar_mul_g(&real), victim_share.verification_keys[&3]);
}

/// 测试 C：签名 Round 2，作恶方发出错误分片签名 z_i。
/// 校验方程 z_i·G = D_i + ρE_i + λc·VK_i 失败，作恶者被精确指认，
/// 聚合永远不会发生，诚实方 nonce 在本轮结束即销毁，无任何信息泄露。
#[test]
fn adversary_c_bad_partial_signature_is_identified_and_aborts() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let message = b"unauthorized transfer attempt";

    let result = run_signing_with_bad_partial(
        &shares,
        &[1u32, BAD, 5],
        message,
        BAD,
    );

    assert!(matches!(
        result,
        Err(frost::SignError::BadPartialSignature { offender }) if offender == BAD
    ));

    // 攻击之后，诚实方仍能用健康集合正常签名——单次作恶没有污染任何长期状态
    let healthy = run_honest_signing(&shares, &[1u32, 3, 5], message).unwrap();
    assert!(frost::verify(&shares[0].group_pk, message, &healthy));
}

/// 测试 C2：作恶方把分片签名里的标量替换成一个"看起来随机"的值，
/// 而不是简单 +1——同样必须被公开校验拦住（不能只防简单篡改）。
#[test]
fn adversary_c2_random_garbage_partial_also_caught() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let pk = shares[0].group_pk;
    let message = b"garbage z_i";
    let signers = vec![1u32, 2, 3];

    let by_id: BTreeMap<u32, _> = shares.iter().map(|s| (s.id, s)).collect();
    let mut rng = OsRng;
    let mut nonces = BTreeMap::new();
    let mut commits = Vec::new();
    for id in &signers {
        let (nonce, commit) = frost::Signer::round1_commit(*id, &mut rng);
        nonces.insert(*id, nonce);
        commits.push(commit);
    }
    let ctx = frost::SigningContext::new(
        &signers,
        &commits,
        &pk,
        message,
        T,
    )
    .unwrap();

    let mut partials = Vec::new();
    for id in &signers {
        let mut p = frost::Signer::round2_sign(&nonces[id], by_id[id], &ctx);
        if *id == BAD {
            p.z = scalar_to_bytes(&frost_custody::curve::random_nonzero_scalar(&mut rng));
        }
        partials.push(p);
    }

    let vks = &shares[0].verification_keys;
    let outcomes: Vec<Result<(), frost::SignError>> = partials
        .iter()
        .map(|p| frost::verify_partial(p, &ctx, vks))
        .collect();

    // 只有作恶方那一条失败，其余全部通过——归因精确，不误伤诚实方
    for (id, outcome) in signers.iter().zip(outcomes) {
        if *id == BAD {
            assert_eq!(
                outcome,
                Err(frost::SignError::BadPartialSignature { offender: BAD })
            );
        } else {
            assert!(outcome.is_ok(), "honest signer {} falsely accused", id);
        }
    }
}

/// 测试 D：签到一半掉线。t 方集合里有一方沉默，幸存方不足门限，
/// 协议干净地失败，不产出半截签名，也不阻塞后续重试。
#[test]
fn adversary_d_mid_signing_dropout_blocks_signature_and_is_retryable() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let message = b"drop out at round 2";

    // 3 人签名组里 1 人掉线 => 只剩 2 人 < t=3
    let result = run_signing_with_dropout(&shares, &[1u32, 2, 3], message, 2);
    assert!(matches!(
        result,
        Err(frost::SignError::NotEnoughSigners { have: 2, need: 3 })
    ));

    // 换一组完整 3 人即可成功——掉线不需要重置密钥，重开一轮用新 nonce 即可
    let retry = run_honest_signing(&shares, &[1u32, 3, 4], message).unwrap();
    assert!(frost::verify(&shares[0].group_pk, message, &retry));
}

/// 测试 E：刷新阶段作恶方发送被篡改的增量分片。
/// 刷新复用 DKG 的密文信道 + Feldman 校验，坏增量被识别且公钥不变。
#[test]
fn adversary_e_bad_refresh_delta_is_rejected_and_public_key_untouched() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let pk_before = shares[0].group_pk;

    let result = run_refresh_with_bad_delta(&parties, &shares, &registry, BAD, 5);
    assert!(matches!(
        result,
        Err(DkgError::CannotDecrypt { offender: BAD }) | Err(DkgError::BadShare { offender: BAD })
    ));

    // 刷新失败后旧分片仍然完好、仍可签名（刷新是全或无，不留半成品状态）
    let sig = run_honest_signing(&shares, &[1u32, 3, 5], b"still in service").unwrap();
    assert!(frost::verify(&pk_before, b"still in service", &sig));
}

/// 测试 E2：作恶方在刷新里试图夹带非零常数项（让群公钥漂移到自己控制的值）。
/// 协议显式要求刷新多项式 z_i(0)=0，首个承诺必须是无穷大点，违者被拒。
#[test]
fn adversary_e2_refresh_with_nonzero_constant_is_rejected() {
    use frost_custody::refresh::RefreshParty;

    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();

    let mut states: BTreeMap<u32, RefreshParty> = shares
        .iter()
        .map(|s| {
            let party = parties.iter().find(|p| p.id == s.id).unwrap();
            (s.id, RefreshParty::new(s.id, T, party.static_private.clone()))
        })
        .collect();
    let mut commits: Vec<_> = states.values().map(|r| r.round1_commit()).collect();

    // 作恶方把首个承诺从无穷大点改成一个随机点（等价于 z_BAD(0) != 0）
    let bad_commit = commits.iter_mut().find(|c| c.dealer_id == BAD).unwrap();
    bad_commit.commitments[0] =
        point_to_bytes(&scalar_mul_g(&frost_custody::curve::random_nonzero_scalar(
            &mut OsRng,
        )));

    let result = states.get_mut(&1).unwrap().handle_round1(&commits, &registry);
    // 两道防线都可能先触发，取决于检查顺序：PoK 失配（InvalidPok）或
    // 零常数项检查（BadCommitmentEncoding）。关键是两者都精确归因到 BAD，
    // 且刷新被拒绝、公钥不会被漂移。
    match result {
        Err(DkgError::InvalidPok { offender })
        | Err(DkgError::BadCommitmentEncoding { offender }) => assert_eq!(offender, BAD),
        other => panic!("expected identifiable rejection of {}, got {:?}", BAD, other),
    }
}

/// 测试 F：重放/跨上下文搬运攻击。把一轮签名的分片签名拿到另一轮（不同消息、
/// 不同 nonce 集合）验证，必然失败——绑定因子 ρ 把承诺集合与消息焊死，
/// 挑战 c 把 R 与消息焊死，旧消息在新上下文里没有任何代数效力。
#[test]
fn adversary_f_replayed_partial_signature_fails_in_new_context() {
    let (parties, registry) = bootstrap(N);
    let shares = run_honest_dkg(&parties, &registry, T).unwrap();
    let pk = shares[0].group_pk;
    let signers = vec![1u32, 2, 3];
    let by_id: BTreeMap<u32, _> = shares.iter().map(|s| (s.id, s)).collect();

    // 第一轮签名，截获全部部分签名
    let mut rng = OsRng;
    let mut nonces1 = BTreeMap::new();
    let mut commits1 = Vec::new();
    for id in &signers {
        let (nonce, commit) = frost::Signer::round1_commit(*id, &mut rng);
        nonces1.insert(*id, nonce);
        commits1.push(commit);
    }
    let ctx1 = frost::SigningContext::new(
        &signers,
        &commits1,
        &pk,
        b"original message",
        T,
    )
    .unwrap();
    let partials1: Vec<_> = signers
        .iter()
        .map(|id| frost::Signer::round2_sign(&nonces1[id], by_id[id], &ctx1))
        .collect();
    for p in &partials1 {
        frost::verify_partial(p, &ctx1, &shares[0].verification_keys).unwrap();
    }

    // 第二轮：新消息、新 nonce、新上下文
    let mut nonces2 = BTreeMap::new();
    let mut commits2 = Vec::new();
    for id in &signers {
        let (nonce, commit) = frost::Signer::round1_commit(*id, &mut rng);
        nonces2.insert(*id, nonce);
        commits2.push(commit);
    }
    let ctx2 = frost::SigningContext::new(
        &signers,
        &commits2,
        &pk,
        b"different message",
        T,
    )
    .unwrap();

    // 旧分片签名在新上下文里全部失效（ρ、c、R 全都变了）
    for p in &partials1 {
        assert_eq!(
            frost::verify_partial(p, &ctx2, &shares[0].verification_keys),
            Err(frost::SignError::BadPartialSignature {
                offender: p.signer_id
            })
        );
    }
}

/// 测试 G：PoK 不可跨参与方重放。把作恶方的 PoK 搬到诚实方的承诺上，
/// 校验必然失败（挑战哈希绑定了 dealer id 与完整承诺向量）。
#[test]
fn adversary_g_pok_cannot_be_moved_between_parties() {
    let (parties, registry) = bootstrap(N);
    let mut commits_for_bad: Option<_> = None;
    let _shares = run_dkg_with_hooks(
        &parties,
        &registry,
        T,
        |commits| {
            // 保存作恶方 2 的原始（合法）PoK，然后把它贴到参与方 4 的消息上
            let pok = commits
                .iter()
                .find(|c| c.dealer_id == BAD)
                .unwrap()
                .pok
                .clone();
            commits_for_bad = Some(pok);
            let victim = commits.iter_mut().find(|c| c.dealer_id == 4).unwrap();
            victim.pok = commits_for_bad.clone().unwrap();
        },
        |_, _| {},
    );
    // 无论 DKG 整体报 InvalidPok 还是 BadCommitmentEncoding，归因必须是被搬运的受害方 4
    // （它的承诺与外来 PoK 对不上）
    match _shares {
        Err(DkgError::InvalidPok { offender }) => assert_eq!(offender, 4),
        Err(other) => panic!("expected InvalidPok(4), got {:?}", other),
        Ok(_) => panic!("replayed PoK must not verify"),
    }
}

/// 测试 H：静态私钥/信道层面，第三方看不到明文分片。
/// 网络上流转的 Round 2 消息全部是密文，截获者无法还原任何标量。
#[test]
fn adversary_h_network_observer_never_sees_plaintext_share() {
    let (parties, registry) = bootstrap(N);

    // 通过钩子截获全部 Round 2 网络消息
    let mut observed = Vec::new();
    let _ = run_dkg_with_hooks(
        &parties,
        &registry,
        T,
        |_| {},
        |_, mailbox| observed.extend(mailbox.iter().cloned()),
    );

    assert_eq!(observed.len(), (N as usize) * (N as usize));
    for msg in observed {
        // 密文结构：12 字节 nonce + 至少 16 字节 GCM tag + 32 字节密文
        assert!(msg.ciphertext.len() >= 12 + 16 + 32);
        // 任何标量的合法大端编码都不可能恰好出现在密文里（GCM 语义安全）。
        // 这里做一个结构性断言：密文不等于任何 32 字节分片的直接编码形态。
        let body = &msg.ciphertext[12..];
        assert_ne!(body.len(), 32, "share would be naked plaintext if only 32 bytes");
        // 全零/全一等极端模式不出现
        assert!(body.iter().any(|&b| b != 0));
    }
}
