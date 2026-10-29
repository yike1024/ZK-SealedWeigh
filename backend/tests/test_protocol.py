# -*- coding: utf-8 -*-
"""协议向量与 Pedersen 原语的单元测试（零外部依赖，不需要链/库/后端）。

运行：
    cd backend
    $env:PYTHONUTF8='1'; python tests\\test_protocol.py -v

这些断言与 spec.md 第 7 节、合约测试、前端 zk-crypto.js 共用同一组夹具；
任何一端改坏都会在这里先暴露。
"""
import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from utils import protocol                          # noqa: E402
from utils.pedersen import PedersenCommitment, zkp_commitment   # noqa: E402

VOTER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
SCORES = [7, 9, 0]
SECRET = "correct horse battery staple"
MAX_SCORE = 10
NULLIFIER = "0xc1da3c3588b03fbe83be605534c6a9f58ceba3081c58c041a0a9ae0a9111a8fc"
RANGE_COMMITMENT = 2187125169807282827423416889253800045206127458618452263738622424698383698062

# spec.md 第 7 节：r_i 与 C_i 向量（Python 生成，JS/Solidity 逐字节一致）
BLINDINGS = [
    11331531710196327524856561149319088737098671986330248307203685176617335942994,
    2800419421753264120076415202257965566892541408650663719876681182483906309872,
    4804764372245660068797630501824517595943658061948539868936512225051414332963,
]
POINTS = [
    "06ae23dbd2b2c323dd377f3ebcd6ddab72d8ae7f5634bd39bdbfecd92ef9b3fc"
    "0ef6987c64195d008237f32797de0433c236225a13cd6b0873ea09d68258d4fb",
    "25ab8fba6599243fb05c1c8c6532d9ade3a1fa51109f91b189dc06e09ea5a90e"
    "0d2bc03efdd457045885e6c2dde903bcee50494b28315fcfddf24da1ee7d38f3",
    "14b081aec82aa9c3e4c4a2444b566eaaba63a4083a2d67d8594a18fdd7932bff"
    "244f9fad0994da303dd67ac4b6da94d1d17ad4a3a923e71713fa329755721510",
]


class TestSpecVectors(unittest.TestCase):
    """spec.md 第 7 节的 9 个向量必须逐字节一致。"""

    def test_all_vectors(self):
        actual = protocol.compute_spec_vectors()
        for name, expected in protocol.SPEC_VECTORS.items():
            with self.subTest(vector=name):
                self.assertEqual(actual[name], expected)

    def test_self_check_returns_true(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(protocol.self_check())


class TestDigestBinding(unittest.TestCase):
    """摘要必须绑定上下文，防止跨活动/跨评委复用。"""

    def test_commitment_hash_binds_voting_id(self):
        a = protocol.commitment_hash(1, VOTER, SCORES, SECRET, MAX_SCORE)
        b = protocol.commitment_hash(2, VOTER, SCORES, SECRET, MAX_SCORE)
        self.assertNotEqual(a, b)

    def test_commitment_hash_binds_voter(self):
        other = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        a = protocol.commitment_hash(1, VOTER, SCORES, SECRET, MAX_SCORE)
        b = protocol.commitment_hash(1, other, SCORES, SECRET, MAX_SCORE)
        self.assertNotEqual(a, b)

    def test_commitment_hash_binds_max_score(self):
        a = protocol.commitment_hash(1, VOTER, SCORES, SECRET, 10)
        b = protocol.commitment_hash(1, VOTER, SCORES, SECRET, 100)
        self.assertNotEqual(a, b)

    def test_reveal_digest_binds_nullifier(self):
        a = protocol.reveal_digest(1, VOTER, SCORES, NULLIFIER)
        b = protocol.reveal_digest(1, VOTER, SCORES, "0x" + "11" * 32)
        self.assertNotEqual(a, b)

    def test_derived_nullifier_binds_voting_and_voter(self):
        base = protocol.derive_nullifier(1, VOTER)
        self.assertEqual(base.hex(), protocol.SPEC_VECTORS["derivedNullifier"])
        self.assertNotEqual(base, protocol.derive_nullifier(2, VOTER))
        self.assertNotEqual(base, protocol.derive_nullifier(
            1, "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"))

    def test_range_digest_binds_commitment_and_voter(self):
        base = protocol.range_digest(1, VOTER, RANGE_COMMITMENT)
        self.assertEqual(base.hex(), protocol.SPEC_VECTORS["rangeDigest"])
        self.assertEqual(len(base), 32)
        self.assertNotEqual(base, protocol.range_digest(2, VOTER, RANGE_COMMITMENT))
        self.assertNotEqual(base, protocol.range_digest(1, VOTER, RANGE_COMMITMENT + 1))
        self.assertNotEqual(base, protocol.range_digest(
            1, "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", RANGE_COMMITMENT))

    def test_digest_is_32_bytes(self):
        ch = protocol.commitment_hash(1, VOTER, SCORES, SECRET, MAX_SCORE)
        self.assertEqual(len(protocol.commit_digest(1, VOTER, ch)), 32)
        self.assertEqual(len(protocol.reveal_digest(1, VOTER, SCORES, NULLIFIER)), 32)
        self.assertEqual(len(protocol.eth_hash(b"\x00" * 32)), 32)

    def test_hex0x(self):
        self.assertEqual(protocol.hex0x(b"\x01\x02"), "0x0102")
        self.assertEqual(protocol.hex0x("0xabc"), "0xabc")
        self.assertEqual(protocol.hex0x("abc"), "0xabc")


class TestBlinding(unittest.TestCase):
    """确定性盲化派生：三端必须一致，且不能入库。"""

    def test_derived_blindings_match_vectors(self):
        for index, expected in enumerate(BLINDINGS):
            with self.subTest(index=index):
                self.assertEqual(
                    zkp_commitment.derive_blinding(SECRET, index, len(SCORES)), expected)

    def test_blinding_is_deterministic(self):
        self.assertEqual(
            zkp_commitment.derive_blinding(SECRET, 0, 3),
            zkp_commitment.derive_blinding(SECRET, 0, 3))

    def test_blinding_changes_with_secret(self):
        self.assertNotEqual(
            zkp_commitment.derive_blinding(SECRET, 0, 3),
            zkp_commitment.derive_blinding(SECRET + "x", 0, 3))

    def test_blinding_changes_with_index_and_count(self):
        base = zkp_commitment.derive_blinding(SECRET, 0, 3)
        self.assertNotEqual(base, zkp_commitment.derive_blinding(SECRET, 1, 3))
        self.assertNotEqual(base, zkp_commitment.derive_blinding(SECRET, 0, 2))


class TestCommitments(unittest.TestCase):
    """C_i = v_i·G + r_i·H 的生成、校验与拒绝路径。"""

    def test_commitment_points_match_vectors(self):
        result = zkp_commitment.generate_score_commitments(SCORES, SECRET, MAX_SCORE)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["commitments"]), len(SCORES))
        for index, expected in enumerate(POINTS):
            with self.subTest(index=index):
                self.assertEqual(result["commitments"][index].lower(), expected)

    def test_points_are_on_curve(self):
        pedersen = PedersenCommitment()
        result = zkp_commitment.generate_score_commitments(SCORES, SECRET, MAX_SCORE)
        for point_hex in result["commitments"]:
            point = pedersen.deserialize_point(point_hex)
            self.assertIsNotNone(point)
            self.assertTrue(pedersen.is_on_curve(*point))

    def test_verify_accepts_consistent_values(self):
        points = zkp_commitment.generate_score_commitments(SCORES, SECRET, MAX_SCORE)["commitments"]
        self.assertTrue(zkp_commitment.verify_commitments(
            SCORES, SECRET, points, MAX_SCORE)["is_valid"])

    def test_verify_rejects_tampered_score(self):
        points = zkp_commitment.generate_score_commitments(SCORES, SECRET, MAX_SCORE)["commitments"]
        result = zkp_commitment.verify_commitments([8, 9, 0], SECRET, points, MAX_SCORE)
        self.assertFalse(result["is_valid"])

    def test_verify_rejects_wrong_secret(self):
        points = zkp_commitment.generate_score_commitments(SCORES, SECRET, MAX_SCORE)["commitments"]
        result = zkp_commitment.verify_commitments(SCORES, "wrong-secret", points, MAX_SCORE)
        self.assertFalse(result["is_valid"])

    def test_verify_rejects_point_not_on_curve(self):
        points = zkp_commitment.generate_score_commitments(SCORES, SECRET, MAX_SCORE)["commitments"]
        points[0] = "00" * 64            # (0,0) 是无穷远点，必须拒绝
        result = zkp_commitment.verify_commitments(SCORES, SECRET, points, MAX_SCORE)
        self.assertFalse(result["is_valid"])

    def test_verify_rejects_count_mismatch(self):
        points = zkp_commitment.generate_score_commitments(SCORES, SECRET, MAX_SCORE)["commitments"]
        result = zkp_commitment.verify_commitments(SCORES[:2], SECRET, points, MAX_SCORE)
        self.assertFalse(result["is_valid"])

    def test_out_of_range_score_is_rejected(self):
        result = zkp_commitment.generate_score_commitments([11, 9, 0], SECRET, MAX_SCORE)
        self.assertFalse(result["success"])

    def test_negative_score_is_rejected(self):
        result = zkp_commitment.generate_score_commitments([-1, 9, 0], SECRET, MAX_SCORE)
        self.assertFalse(result["success"])


class TestGeneratorH(unittest.TestCase):
    """NUMS 生成元必须是公开派生的固定值，不能被悄悄替换。"""

    def test_h_matches_published_constants(self):
        pedersen = PedersenCommitment()
        self.assertEqual(pedersen.H, (PedersenCommitment.Hx, PedersenCommitment.Hy))

    def test_h_is_on_curve_and_not_g(self):
        pedersen = PedersenCommitment()
        self.assertTrue(pedersen.is_on_curve(*pedersen.H))
        self.assertNotEqual(pedersen.H, pedersen.G)


if __name__ == "__main__":
    unittest.main(verbosity=2)
