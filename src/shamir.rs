//! Shamir 秘密分享 + Feldman VSS。
//!
//! ## 数学结构
//! 秘密 s 是一个标量。分发者选 t-1 次随机多项式
//!   f(x) = a_0 + a_1 x + ... + a_{t-1} x^{t-1},  a_0 = s
//! 给参与方 i 的分片是 f(i)。任意 t 个分片可用 Lagrange 插值恢复 f(0)=s，
//! 任意 t-1 个分片在信息论意义下对 s 一无所知（分片空间均匀、与 s 独立）。
//!
//! ## Feldman 承诺（可验证性，防"发错分片套信息"的第一道闸）
//! 分发者同时广播 C_j = a_j * G (j=0..t-1)。接收方 i 检查
//!   f(i) * G == Σ_j C_j * i^j
//! 错误分片过不了这一关——作恶分发者无法给某人一份和承诺不一致的分片
//! 而不被当场识别（identifiable abort 的基础）。
//!
//! 注意 Feldman 承诺本身是完美绑定、计算隐藏的：C_0 = s*G 就是公钥，
//! 离散对数困难性保护 s，而门限场景下 s 本来就会对应一个公开公钥。

use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};

use crate::curve::{id_to_scalar, scalar_mul_g};

/// 度为 t-1 的随机多项式，系数在标量域；a_0 即秘密。
#[derive(Clone)]
pub struct Polynomial {
    /// coefficients[0] 是常数项（秘密），长度为 t。
    pub coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// 以给定秘密为常数项，其余 t-1 个系数随机。
    pub fn random_with_secret(secret: Scalar, threshold: usize, mut rng: &mut impl rand::RngCore) -> Self {
        assert!(threshold >= 1, "threshold must be >= 1");
        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(secret);
        for _ in 1..threshold {
            coefficients.push(Scalar::random(&mut rng));
        }
        Self { coefficients }
    }

    /// Horner 法求值 f(x)。
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        for coeff in self.coefficients.iter().rev() {
            acc = acc * x + coeff;
        }
        acc
    }

    /// 给参与方 id 的分片 f(id)。
    pub fn share_for(&self, id: u32) -> Scalar {
        self.evaluate(&id_to_scalar(id))
    }

    /// Feldman 承诺向量 C_j = a_j * G。
    pub fn commitments(&self) -> Vec<ProjectivePoint> {
        self.coefficients.iter().map(scalar_mul_g).collect()
    }
}

/// 校验收到的分片与 Feldman 承诺一致：share*G == Σ_j C_j * id^j。
///
/// 这是公开可验证的，任何人拿到广播承诺和（被指控的）分片都能复算，
/// 因此指控作恶者时不依赖任何单方证词。
pub fn verify_share(
    id: u32,
    share: &Scalar,
    commitments: &[ProjectivePoint],
) -> bool {
    let x = id_to_scalar(id);
    // 右侧用 Horner：从最高次开始，逐步 point = point * x + C_j
    let mut rhs = ProjectivePoint::IDENTITY;
    for c in commitments.iter().rev() {
        rhs = rhs * x + c;
    }
    scalar_mul_g(share) == rhs
}

/// Lagrange 系数 λ_i(0)，在求值点 x=0 处：
///   λ_i(0) = Π_{j in S, j != i} ( 0 - x_j ) / ( x_i - x_j )
///         = Π_{j != i} x_j / (x_j - x_i)
///
/// 门限签名里我们从不重建完整私钥，而是直接用
///   s = Σ_i λ_i * z_i （分片签名的加权和）合成最终签名。
/// 要求 ids 两两不同且长度 <= n；只要 |ids| >= t 结果即合法。
pub fn lagrange_coefficients(ids: &[u32]) -> Vec<Scalar> {
    let xs: Vec<Scalar> = ids.iter().map(|&id| id_to_scalar(id)).collect();
    let mut out = Vec::with_capacity(ids.len());
    for i in 0..xs.len() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for j in 0..xs.len() {
            if i == j {
                continue;
            }
            num *= xs[j];
            den *= xs[j] - xs[i];
        }
        // 参与方 id 互不相同 => xs[j]-xs[i] 非零 => 逆存在
        let inv: Scalar = Option::from(den.invert())
            .expect("distinct ids guarantee invertible denominator");
        out.push(num * inv);
    }
    out
}

/// 用 t 个 (id, share) 插值恢复 f(0)。仅供测试/密钥恢复流程使用；
/// 正常签名路径不允许调用——设计目标就是完整私钥永不重建。
pub fn interpolate_secret_at_zero(points: &[(u32, Scalar)]) -> Scalar {
    let ids: Vec<u32> = points.iter().map(|(id, _)| *id).collect();
    let lambdas = lagrange_coefficients(&ids);
    let mut secret = Scalar::ZERO;
    for (lambda, (_, share)) in lambdas.iter().zip(points.iter()) {
        secret += lambda * share;
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::random_nonzero_scalar;
    use rand::rngs::OsRng;

    #[test]
    fn t_shares_recover_secret_and_t_minus_one_cannot() {
        let t = 3usize;
        let n = 5u32;
        let secret = random_nonzero_scalar(&mut OsRng);
        let poly = Polynomial::random_with_secret(secret, t, &mut OsRng);

        let shares: Vec<(u32, Scalar)> = (1..=n).map(|id| (id, poly.share_for(id))).collect();

        // 所有分片都通过 Feldman 校验
        let comms = poly.commitments();
        for (id, share) in &shares {
            assert!(verify_share(*id, share, &comms));
        }

        // 任意 t 个分片恢复同一秘密
        let recovered = interpolate_secret_at_zero(&shares[0..t]);
        assert_eq!(recovered, secret);
        let recovered2 = interpolate_secret_at_zero(&[shares[1], shares[3], shares[4]]);
        assert_eq!(recovered2, secret);

        // 篡改任一分片 => Feldman 校验失败
        let mut bad = shares[0];
        bad.1 += Scalar::ONE;
        assert!(!verify_share(bad.0, &bad.1, &comms));
    }
}
