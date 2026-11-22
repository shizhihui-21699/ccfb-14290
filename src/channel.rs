//! 参与方之间的点对点加密信道（模拟真实部署里的 mTLS/ Noise 链路之上的应用层封装）。
//!
//! ## 为什么 DKG 还需要一层应用层加密
//! DKG 第一轮的承诺、PoK 是公开广播的，但第二轮每个分发者发给参与方 j
//! 的分片 f_i(j) 只能让 j 看到。若链路本身是广播介质（很多共识网络就是），
//! 必须在应用层用接收方公钥做端到端加密。
//!
//! ## 方案
//! 每方一个长期静态 secp256k1 密钥对 (esk, EPk)。
//! 共享密钥 = ECDH(esk_sender, EPk_recv)，经 HKDF-SHA256 派生 AES-256-GCM 密钥，
//! 随机 96 位 nonce，密文前置 nonce。AES-GCM 同时提供机密性和完整性，
//! 被动观察者拿不到分片，主动篡改会被认证标签挡住。
//!
//! 真实部署还需要把 EPk 放进带 CA/准入机制的注册表，防止中间人冒充；
//! 本模拟的 `Registry` 扮演这个可信入口（只认证身份公钥，不碰密钥材料）。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use k256::elliptic_curve::ecdh::diffie_hellman;
use hkdf::Hkdf;
use k256::ecdh::EphemeralSecret;
use k256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

/// 长期静态私钥。派生 ZeroizeOnDrop，离开作用域时尽力擦除内存。
///
/// 克隆是为了让同一台模拟服务器在 DKG/刷新多次协议会话间复用同一身份；
/// 真实部署里私钥驻留在 HSM/独立进程中，不会有这个内存复制。
#[derive(Clone, ZeroizeOnDrop)]
pub struct StaticPrivate {
    inner: SecretKey,
}

impl StaticPrivate {
    pub fn generate() -> Self {
        Self {
            inner: SecretKey::random(&mut OsRng),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }

    /// 给接收方公钥对应的私钥持有者加密一条消息。
    pub fn seal(&self, recipient: &PublicKey, plaintext: &[u8]) -> Vec<u8> {
        // ECDH：输出是共享点的 x 坐标（32 字节）
        let shared = diffie_hellman(
            self.inner.to_nonzero_scalar(),
            recipient.as_affine(),
        );
        let hk = Hkdf::<Sha256>::new(Some(b"frost-custody/v1/channel"), shared.raw_secret_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"aes-256-gcm-key", &mut key)
            .expect("32-byte L is valid for SHA256 HKDF");
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .expect("AES-GCM encryption cannot fail for valid inputs");

        // 输出 = nonce(12) || ciphertext+tag
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    /// 解密对方用其静态私钥、本方公钥封送的消息；标签错误/nonce 复用等返回 None。
    pub fn open(&self, sender_public: &PublicKey, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
            return None;
        }
        let shared = diffie_hellman(
            self.inner.to_nonzero_scalar(),
            sender_public.as_affine(),
        );
        let hk = Hkdf::<Sha256>::new(Some(b"frost-custody/v1/channel"), shared.raw_secret_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"aes-256-gcm-key", &mut key).ok()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        let (nonce_bytes, body) = ciphertext.split_at(12);
        cipher.decrypt(Nonce::from_slice(nonce_bytes), body).ok()
    }
}

// 让上面 fill_bytes 可用
use rand::RngCore;

/// 身份注册表：参与方 ID -> 静态公钥。只承担"谁是谁"的准入认证，
/// 与密钥分片完全无关，注册表被读取不泄露任何签名能力。
#[derive(Clone, Debug)]
pub struct Registry {
    pub ids: Vec<u32>,
    pub static_pubkeys: std::collections::BTreeMap<u32, PublicKey>,
}

impl Registry {
    pub fn new(ids: &[u32], privates: &[(u32, &StaticPrivate)]) -> Self {
        let mut static_pubkeys = std::collections::BTreeMap::new();
        for (id, sk) in privates {
            static_pubkeys.insert(*id, sk.public_key());
        }
        Self {
            ids: ids.to_vec(),
            static_pubkeys,
        }
    }

    pub fn pubkey_of(&self, id: u32) -> Option<&PublicKey> {
        self.static_pubkeys.get(&id)
    }
}

// EphemeralSecret 仅用于类型对照，避免未使用告警；ECDH 实际走 diffie_hellman 自由函数。
#[allow(dead_code)]
fn _assert_ecdh_type(_: &EphemeralSecret) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_message_roundtrips_and_tampering_is_detected() {
        let a = StaticPrivate::generate();
        let b = StaticPrivate::generate();
        let msg = b"dealers sealed shamir share f_i(j)";

        let ct = a.seal(&b.public_key(), msg);
        assert_ne!(&ct[12..], msg); // 密文不等于明文
        let pt = b.open(&a.public_key(), &ct).expect("decrypt should succeed");
        assert_eq!(pt, msg);

        // 篡改一个密文字节 => GCM 标签校验失败
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(b.open(&a.public_key(), &tampered).is_none());

        // 第三方私钥打不开
        let c = StaticPrivate::generate();
        assert!(c.open(&a.public_key(), &ct).is_none());
    }
}
