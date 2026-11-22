//! 进程内模拟网络：把多台"签名服务器"压缩成同一进程里的多个对象，
//! 让正常流程和作恶流程都能在一个测试二进制里确定性驱动。
//!
//! 真实部署里这些消息走的是服务器间的 mTLS 链路；这里用 BTreeMap 信箱替代，
//! 并显式提供三种故障注入手段，对应题目里的威胁模型：
//! * 篡改/替换消息（发错数据套分片）
//! * 扣压消息（签到一半掉线）
//! * 重复/重放（试图诱导 nonce 复用）

use std::collections::{BTreeMap, VecDeque};

use crate::dkg::{CommitmentMessage, SealedShare};
use crate::frost::{NonceCommitment, PartialSignature};

/// 带轮次标签的网络信封。
#[derive(Clone, Debug)]
pub enum Envelope {
    DkgCommit(CommitmentMessage),
    DkgSealedShare(SealedShare),
    SignCommit(NonceCommitment),
    SignPartial(PartialSignature),
}

impl Envelope {
    pub fn sender(&self) -> u32 {
        match self {
            Envelope::DkgCommit(m) => m.dealer_id,
            Envelope::DkgSealedShare(m) => m.dealer_id,
            Envelope::SignCommit(m) => m.signer_id,
            Envelope::SignPartial(m) => m.signer_id,
        }
    }

    pub fn recipient(&self) -> Option<u32> {
        match self {
            Envelope::DkgSealedShare(m) => Some(m.recipient_id),
            _ => None,
        }
    }
}

/// 广播总线：公开消息（None 收件人）所有人可读。
pub struct BroadcastBus {
    pub public: Vec<Envelope>,
    pub private: BTreeMap<u32, VecDeque<Envelope>>,
    /// 被主动丢弃的消息计数（掉线注入用）。
    pub dropped: usize,
}

impl Default for BroadcastBus {
    fn default() -> Self {
        Self::new()
    }
}

impl BroadcastBus {
    pub fn new() -> Self {
        Self {
            public: Vec::new(),
            private: BTreeMap::new(),
            dropped: 0,
        }
    }

    pub fn post(&mut self, msg: Envelope) {
        match msg.recipient() {
            Some(to) => self.private.entry(to).or_default().push_back(msg),
            None => self.public.push(msg),
        }
    }

    /// 广播一批公开消息。
    pub fn post_all(&mut self, msgs: impl IntoIterator<Item = Envelope>) {
        for m in msgs {
            self.post(m);
        }
    }

    pub fn public_messages(&self) -> Vec<Envelope> {
        self.public.clone()
    }

    /// 取某方的全部私信（按发送顺序）。
    pub fn private_for(&self, id: u32) -> Vec<Envelope> {
        self.private
            .get(&id)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// 故障注入：扣压某个发送方的全部消息（模拟中途掉线）。
    pub fn suppress_sender(&mut self, sender: u32) {
        let before_pub = self.public.len();
        self.public.retain(|m| m.sender() != sender);
        self.dropped += before_pub - self.public.len();
        for queue in self.private.values_mut() {
            let before = queue.len();
            queue.retain(|m| m.sender() != sender);
            self.dropped += before - queue.len();
        }
    }

    /// 故障注入：替换某个发送方的某条公开消息（模拟故意发错数据）。
    /// 返回是否找到并替换。
    pub fn replace_public(
        &mut self,
        sender: u32,
        which: usize,
        replacement: Envelope,
    ) -> bool {
        let mut seen = 0usize;
        for slot in self.public.iter_mut() {
            if slot.sender() == sender {
                if seen == which {
                    *slot = replacement;
                    return true;
                }
                seen += 1;
            }
        }
        false
    }
}
