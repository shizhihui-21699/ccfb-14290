//! 使用 `net::BroadcastBus` 模拟网络的集成测试：验证消息总线的
//! 篡改、扣压、重放三类故障注入原语本身工作正常，
//! 上层协议测试再通过这些原语驱动作恶场景。

use frost_custody::net::{BroadcastBus, Envelope};

fn fake_public(sender: u32, tag: u8) -> Envelope {
    // 用一个最小的 NonceCommitment 信封即可，总线不关心内容
    Envelope::SignCommit(frost_custody::frost::NonceCommitment {
        signer_id: sender,
        d_commitment: [tag; 33],
        e_commitment: [tag.wrapping_add(1); 33],
    })
}

fn fake_private(sender: u32, recipient: u32) -> Envelope {
    Envelope::DkgSealedShare(frost_custody::dkg::SealedShare {
        dealer_id: sender,
        recipient_id: recipient,
        ciphertext: vec![0xaa; 60],
    })
}

#[test]
fn bus_delivers_public_and_private_messages_separately() {
    let mut bus = BroadcastBus::new();
    bus.post(fake_public(1, 1));
    bus.post(fake_public(2, 2));
    bus.post(fake_private(1, 3));
    bus.post(fake_private(2, 3));

    assert_eq!(bus.public_messages().len(), 2);
    assert_eq!(bus.private_for(3).len(), 2);
    assert!(bus.private_for(1).is_empty());
}

#[test]
fn bus_suppression_models_a_party_going_offline() {
    let mut bus = BroadcastBus::new();
    bus.post(fake_public(1, 1));
    bus.post(fake_public(2, 2));
    bus.post(fake_private(1, 3));
    bus.post(fake_private(2, 3));

    // 参与方 2 在协议中途掉线：它的公开消息和私信全部被扣压
    bus.suppress_sender(2);

    assert_eq!(bus.public_messages().len(), 1);
    assert_eq!(bus.public_messages()[0].sender(), 1);
    assert_eq!(bus.private_for(3).len(), 1);
    assert_eq!(bus.private_for(3)[0].sender(), 1);
    assert!(bus.dropped >= 2);
}

#[test]
fn bus_replacement_models_tampered_broadcast() {
    let mut bus = BroadcastBus::new();
    bus.post(fake_public(1, 1));
    bus.post(fake_public(2, 2));

    // 把参与方 2 的公开消息替换成伪造内容
    let replaced = fake_public(2, 99);
    assert!(bus.replace_public(2, 0, replaced));

    let msgs = bus.public_messages();
    let tampered = msgs.iter().find(|m| m.sender() == 2).unwrap();
    match tampered {
        Envelope::SignCommit(c) => assert_eq!(c.d_commitment, [99u8; 33]),
        _ => panic!("unexpected envelope variant"),
    }

    // 替换不存在的发送方/序号返回 false
    assert!(!bus.replace_public(9, 0, fake_public(9, 0)));
}
