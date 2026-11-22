//! # frost-custody
//!
//! 面向数字资产托管的 t-of-n 门限 Schnorr 签名系统：
//!
//! * [`dkg`] —— 分布式密钥生成，完整私钥从生成时刻起就不在任何单机出现
//! * [`shamir`] —— Shamir 秘密分享与 Feldman 可验证秘密分享（VSS）
//! * [`frost`] —— FROST 两轮门限签名，输出与单人 Schnorr 同构的 (R, s)
//! * [`refresh`] —— Herzberg 主动刷新，周期更换分片而群公钥不变
//! * [`channel`] —— ECDH + HKDF + AES-GCM 点对点密文信道与身份注册表
//! * [`net`] —— 进程内模拟网络，支持篡改/扣压/重放故障注入
//!
//! 协议选型理由、威胁模型与生产化注意事项见仓库 `README.md`。

pub mod channel;
pub mod curve;
pub mod dkg;
pub mod frost;
pub mod net;
pub mod refresh;
pub mod shamir;

pub use dkg::{DkgError, DkgParty, KeyShare, Pok};
pub use frost::{Signature, SignError};
