//! 曲线层原语：把 k256(secp256k1) 的 API 收敛成协议需要的几个基本操作。
//!
//! 协议全程只使用：
//! * 标量域 `Scalar`（私钥、Shamir 系数、nonce 都活在标量域 mod n 里）
//! * 曲线点 `ProjectivePoint`（承诺、公钥、nonce 承诺都活在群里）
//! * 哈希到标量 `hash_to_scalar`（把任意字节串经 SHA-256 后规约 mod n）
//!
//! 这里刻意不使用 BIP-340 的 x-only 规则，而是用完整压缩点编码 R。
//! 产出的 (R, s) 仍然是标准 Schnorr 签名，任何持公钥的人都能用同一套
//! verify 方程验证，验证者完全感知不到签名是 t 个分片合签出来的。

use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::{Field, Group};
use group::GroupEncoding;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// secp256k1 压缩点长度：1 字节前缀 + 32 字节 x。
pub const POINT_BYTES: usize = 33;
/// 标量长度：32 字节大端。
pub const SCALAR_BYTES: usize = 32;

/// 域分隔标签，保证不同用途的哈希互不混用（FROST 草案的 domain separation 要求）。
pub mod tags {
    pub const FROST_CHALLENGE: &[u8] = b"frost-custody/v1/challenge";
    pub const FROST_BINDING: &[u8] = b"frost-custody/v1/binding-factor";
    pub const DKG_POK: &[u8] = b"frost-custody/v1/dkg-pok";
    pub const REFRESH_POK: &[u8] = b"frost-custody/v1/refresh-pok";
}

/// 带域分隔标签的哈希，输出 32 字节。
pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(data);
    h.finalize().into()
}

/// SHA-256 后按大端整数规约到标量域 mod n。
///
/// 规约是满射但非均匀（偏置最多 2^-128 量级，可忽略）；
/// FROST/RFC9381 对挑战哈希也是同样处理（`Reduce` 而非拒绝采样）。
pub fn hash_to_scalar(tag: &[u8], data: &[u8]) -> Scalar {
    let digest = tagged_hash(tag, data);
    <Scalar as Reduce<U256>>::reduce_bytes(&digest.into())
}

/// 多段数据顺序拼接后再哈希（避免手写一堆 buffer）。
pub fn hash_concat_scalar(tag: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut h = Sha256::new();
    let tag_hash = Sha256::digest(tag);
    h.update(tag_hash);
    h.update(tag_hash);
    for p in parts {
        // 每段前加 4 字节长度，消除长度歧义：H(a||bc) != H(ab||c)
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    let digest: [u8; 32] = h.finalize().into();
    <Scalar as Reduce<U256>>::reduce_bytes(&digest.into())
}

/// 生成一个随机非零标量。
pub fn random_nonzero_scalar(mut rng: impl rand::RngCore) -> Scalar {
    loop {
        let s = Scalar::random(&mut rng);
        if bool::from(!s.is_zero()) {
            return s;
        }
    }
}

/// 标量 -> 32 字节大端。
pub fn scalar_to_bytes(s: &Scalar) -> [u8; SCALAR_BYTES] {
    let b = s.to_bytes();
    let mut out = [0u8; SCALAR_BYTES];
    out.copy_from_slice(b.as_slice());
    out
}

/// 32 字节大端 -> 标量，非法编码（>= n 或非规范）返回 None。
pub fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    use k256::elliptic_curve::ff::PrimeField;
    if bytes.len() != SCALAR_BYTES {
        return None;
    }
    let mut arr = <k256::FieldBytes as Default>::default();
    arr.copy_from_slice(bytes);
    Option::from(Scalar::from_repr(arr))
}

/// 点 -> 33 字节 SEC1 压缩编码。
pub fn point_to_bytes(p: &ProjectivePoint) -> [u8; POINT_BYTES] {
    let b = GroupEncoding::to_bytes(p);
    let mut out = [0u8; POINT_BYTES];
    out.copy_from_slice(b.as_slice());
    out
}

/// 33 字节 -> 点，非法点（不在曲线上/非规范/无穷大视情况）返回 None。
pub fn point_from_bytes(bytes: &[u8]) -> Option<ProjectivePoint> {
    if bytes.len() != POINT_BYTES {
        return None;
    }
    let mut arr = <k256::CompressedPoint as Default>::default();
    arr.copy_from_slice(bytes);
    Option::from(<ProjectivePoint as GroupEncoding>::from_bytes(&arr))
}

/// s * G（标量乘生成元），私钥推导公钥的基本运算。
pub fn scalar_mul_g(s: &Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * s
}

/// 参与方 ID（1..=n 的小整数）转成标量。
///
/// FROST 要求参与方身份互不相同且非零；用 1..=n 而不是 0..=n-1，
/// 这样 ID 标量天然非零，Lagrange 插值在 x=0 处也不会和某个 ID 撞点。
pub fn id_to_scalar(id: u32) -> Scalar {
    Scalar::from(id as u64)
}

/// 标准 Schnorr 验证方程：s*G == R + c*PK。
///
/// 这是最终签名对外唯一需要暴露的校验逻辑——验证者只看到一个普通
/// 公钥和一个普通 (R, s) 签名，不需要知道 t、n，也不需要知道 FROST。
pub fn schnorr_verify(
    pk: &ProjectivePoint,
    message: &[u8],
    r: &ProjectivePoint,
    s: &Scalar,
) -> bool {
    if bool::from(r.is_identity()) || bool::from(s.is_zero()) {
        return false;
    }
    let c = hash_concat_scalar(
        tags::FROST_CHALLENGE,
        &[&point_to_bytes(r), &point_to_bytes(pk), message],
    );
    let lhs = scalar_mul_g(s);
    let rhs = *r + pk * &c;
    lhs == rhs
}

/// 单人为测试/对照而做的标准 Schnorr 签名，用于证明门限签名与单人签名
/// 在验证方程层面完全同构、不可区分。
pub fn schnorr_sign(secret: &Scalar, message: &[u8], rng: &mut impl rand::RngCore) -> (ProjectivePoint, Scalar) {
    // 确定性测试里也强制走新鲜随机数；nonce 绝不能复用（FROST 安全的生命线）。
    let k = random_nonzero_scalar(rng);
    let r = scalar_mul_g(&k);
    let c = hash_concat_scalar(
        tags::FROST_CHALLENGE,
        &[&point_to_bytes(&r), &point_to_bytes(&scalar_mul_g(secret)), message],
    );
    let s = k + c * secret;
    (r, s)
}

/// 清零辅助：标量内部为普通内存，Drop 时尽力擦除（见各 key 结构的 Zeroize 派生）。
pub fn zeroize_slice(buf: &mut [u8]) {
    buf.zeroize();
}
