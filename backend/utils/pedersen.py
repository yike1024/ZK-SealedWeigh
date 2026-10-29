# -*- coding: utf-8 -*-
"""
Pedersen 承诺 —— alt_bn128（BN254）曲线实现（协议 v3）

为什么从 secp256k1 换成 alt_bn128：
  链上要做**真正的椭圆曲线校验**，而 EVM 只提供 alt_bn128 的预编译
  （EIP-196: 0x06 ecAdd、EIP-197: 0x07 ecMul）。secp256k1 在链上没有预编译，
  纯 Solidity 实现一次点乘要几十万 gas，不可用。

曲线：y² = x³ + 3 over F_p
  p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
  n = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  G = (1, 2)   ← 标准生成元
  H = hash_to_point(sha256(b"ZK-SealedWeigh.Pedersen.H.v3" || counter))  ← NUMS

H 必须满足“无人知晓 log_G(H)”：否则知道 k（H = k·G）的人可令
C = v·G + r·H = (v + rk)·G，从而用不同的 (v', r') 打开同一承诺，绑定性被破坏。
因此 H 由公开种子、公开算法派生，任何第三方都能复算验证。
"""
import hashlib
import secrets
from typing import List

import logging

logger = logging.getLogger(__name__)

CURVE_NAME = 'alt_bn128'


class PedersenCommitment:
    """Pedersen 承诺（alt_bn128 / BN254，y² = x³ + 3）"""

    # 基域素数 p
    P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    # 群的阶 n（标量模）
    N = 21888242871839275222246405745257275088548364400416034343698204186575808495617

    # 标准生成元 G = (1, 2)：2² = 1³ + 3 = 4
    Gx = 1
    Gy = 2

    # 第二生成元 H（NUMS）：种子 + 4 字节大端计数器，counter=2 时命中二次剩余
    Hx = 0x23AE7E827609887FF1721F43EFED23E0D3941CEF3A524E28576A8C165B0B23C1
    Hy = 0x09485BCE1C81E4F60D2852F4AB22F9A79997CC8A19F87AFBFCEE998CC818B5F6
    H_SEED = b"ZK-SealedWeigh.Pedersen.H.v3"

    def __init__(self):
        self.G = (self.Gx, self.Gy)
        self.H = (self.Hx, self.Hy)
        # 自检：固化常量必须与公开派生结果逐字节一致（防止有人误改常量）
        if self._derive_h() != self.H:
            raise RuntimeError("Pedersen H 生成元与公开派生结果不一致，请检查 utils/pedersen.py")

    # ---------------------------------------------------------------- 域运算
    def mod_inverse(self, a, n):
        """扩展欧几里得求模逆"""
        a %= n
        if a == 0:
            raise ZeroDivisionError("0 在模意义下不可逆")
        lm, hm = 1, 0
        low, high = a, n
        while low > 1:
            r = high // low
            nm = hm - lm * r
            new = high - low * r
            hm, lm = lm, nm
            high, low = low, new
        return lm % n

    # ---------------------------------------------------------------- 曲线运算
    def is_on_curve(self, x, y):
        """点是否落在 y² = x³ + 3 上（用于拒绝伪造承诺点）"""
        if x is None or y is None:
            return False
        if not (0 <= x < self.P and 0 <= y < self.P):
            return False
        return (y * y - (pow(x, 3, self.P) + 3)) % self.P == 0

    def point_add(self, p1, p2):
        """椭圆曲线点加法；None 表示无穷远点"""
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2:
            if (y1 + y2) % self.P == 0:
                return None                      # 互为逆元 → 无穷远点
            if y1 == 0:
                return None
            s = (3 * x1 * x1) * self.mod_inverse(2 * y1, self.P) % self.P
        else:
            s = (y2 - y1) * self.mod_inverse(x2 - x1, self.P) % self.P

        x3 = (s * s - x1 - x2) % self.P
        y3 = (s * (x1 - x3) - y1) % self.P
        return (x3, y3)

    def point_mult(self, point, scalar):
        """椭圆曲线标量乘法（double-and-add）"""
        scalar %= self.N
        if scalar == 0 or point is None:
            return None

        result = None
        addend = point
        while scalar:
            if scalar & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            scalar >>= 1
        return result

    def point_neg(self, point):
        if point is None:
            return None
        return (point[0], (-point[1]) % self.P)

    # ---------------------------------------------------------------- hash → 曲线
    def hash_to_point(self, data):
        """把字节串确定性地映射到曲线上（试增计数器直到 x³+3 为二次剩余）

        BN254 的 p ≡ 3 (mod 4)，故平方根可直接用 a^((p+1)/4) 求得，无需 Tonelli-Shanks。
        结果规范化为**偶数 y**，保证三端派生到同一个点（(x,y) 与 (x,-y) 都在曲线上）。
        """
        counter = 0
        while True:
            h = hashlib.sha256(data + counter.to_bytes(4, 'big')).digest()
            x = int.from_bytes(h, 'big') % self.P
            y_sq = (pow(x, 3, self.P) + 3) % self.P
            y = pow(y_sq, (self.P + 1) // 4, self.P)
            if y and (y * y - y_sq) % self.P == 0:
                if y % 2 != 0:
                    y = self.P - y
                return (x, y)
            counter += 1

    def _derive_h(self):
        """按公开种子与算法派生 H（仅用于启动自检）"""
        return self.hash_to_point(self.H_SEED)

    # ---------------------------------------------------------------- 承诺
    def commit(self, value, blinding_factor=None):
        """C = value·G + blinding·H"""
        if blinding_factor is None:
            blinding_factor = secrets.randbelow(self.N)

        commitment = self.point_add(
            self.point_mult(self.G, value),
            self.point_mult(self.H, blinding_factor)
        )
        return {
            'commitment': commitment,
            'blinding_factor': blinding_factor,
            'value': value
        }

    def verify(self, commitment, value, blinding_factor):
        """校验 C 是否等于 value·G + blinding·H"""
        if commitment is None:
            return False
        recomputed = self.point_add(
            self.point_mult(self.G, value),
            self.point_mult(self.H, blinding_factor)
        )
        return commitment == recomputed

    # ---------------------------------------------------------------- 序列化
    def serialize_point(self, point):
        """x||y 各 32 字节 → 128 位十六进制（与链上 uint256[2] 一致）"""
        if point is None:
            return None
        return f"{point[0]:064x}{point[1]:064x}"

    def deserialize_point(self, point_str):
        if not point_str or len(point_str) != 128:
            return None
        try:
            x = int(point_str[:64], 16)
            y = int(point_str[64:], 16)
        except ValueError:
            return None
        return (x, y)


class ZKPCommitment:
    """按评委维度生成/校验一组 Pedersen 承诺"""

    def __init__(self):
        self.pedersen = PedersenCommitment()

    @staticmethod
    def derive_blinding(secret: str, index: int, count: int) -> int:
        """确定性盲化因子：r_i = sha256("secret:i:count") mod n

        确定性派生的好处：揭晓阶段只需 (scores, secret) 即可复算全部 r_i，
        无需在数据库里存盲化因子（存了就等于把开锁钥匙写进库里）。
        """
        seed = f"{secret}:{index}:{count}".encode()
        return int.from_bytes(hashlib.sha256(seed).digest(), 'big') % PedersenCommitment.N

    def generate_score_commitments(self, scores: List[int], secret: str, max_score: int):
        """为一组分数生成承诺点（C_i = score_i·G + r_i·H）"""
        try:
            for score in scores:
                if score < 0 or score > max_score:
                    raise ValueError(f"分数 {score} 超出范围 0-{max_score}")

            commitments = []
            blinding_factors = []
            count = len(scores)

            for i, score in enumerate(scores):
                blinding = self.derive_blinding(secret, i, count)
                data = self.pedersen.commit(score, blinding)
                commitments.append(self.pedersen.serialize_point(data['commitment']))
                blinding_factors.append(blinding)

            return {
                'success': True,
                'curve': CURVE_NAME,
                'commitments': commitments,
                'blinding_factors': blinding_factors,
                'scores': scores,
                'type': 'pedersen'
            }

        except Exception as e:
            logger.error(f"生成 Pedersen 承诺失败: {e}")
            return {'success': False, 'error': str(e)}

    def verify_commitments(self, scores: List[int], secret: str,
                           stored_commitments: List[str], max_score: int):
        """用 (scores, secret) 重算承诺并与存储值比对（包含逐点 on-curve 检查）"""
        try:
            if len(scores) != len(stored_commitments):
                return {'success': False, 'is_valid': False,
                        'error': '评分数量与承诺数量不匹配'}

            # 先检查存储点本身是否在曲线上，避免畸形点进入后续运算
            for i, point_str in enumerate(stored_commitments):
                point = self.pedersen.deserialize_point(point_str)
                if point is None or not self.pedersen.is_on_curve(*point):
                    return {'success': False, 'is_valid': False,
                            'error': f'承诺 {i} 不是 alt_bn128 上的合法点'}

            regeneration = self.generate_score_commitments(scores, secret, max_score)
            if not regeneration['success']:
                return regeneration

            regenerated = regeneration['commitments']
            for i, (expected, actual) in enumerate(zip(regenerated, stored_commitments)):
                if expected.lower() != str(actual).lower():
                    return {'success': False, 'is_valid': False,
                            'error': f'承诺 {i} 与 (分数, 密码) 不一致'}

            # 再做一次代数校验（防御 deserialize 层面的边界问题）
            for i, (score, blinding, point_str) in enumerate(
                    zip(scores, regeneration['blinding_factors'], stored_commitments)):
                point = self.pedersen.deserialize_point(point_str)
                if not self.pedersen.verify(point, score, blinding):
                    return {'success': False, 'is_valid': False,
                            'error': f'承诺 {i} 代数校验失败'}

            return {'success': True, 'is_valid': True,
                    'message': 'Pedersen 承诺验证成功（alt_bn128）'}

        except Exception as e:
            logger.error(f"验证 Pedersen 承诺失败: {e}")
            return {'success': False, 'error': str(e)}


# 全局实例
zkp_commitment = ZKPCommitment()
