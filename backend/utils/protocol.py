# -*- coding: utf-8 -*-
"""
协议摘要构造的**唯一实现**（见 spec.md 第 4 节）。

合约（Solidity `abi.encode`）、后端（本模块 `eth_abi.encode`）、前端（`zk-crypto.js` 手写 ABI 编码器）
三方必须与本模块逐字节一致；本模块底部带有对 spec.md 第 7 节测试向量的自检，可直接运行：

    python -m utils.protocol            # 或  python backend/utils/protocol.py

编码规则（规范性，禁止修改而不更新 spec.md）：
  R1 一律 abi.encode（类型化、动态类型带 offset/length），禁止 abi.encodePacked 组合动态类型
  R2 首字段必须是域分隔标签
  R3 禁止 JSON 序列化参与摘要计算
  R4 承诺哈希必须绑定 votingId 与 voter
  R5 变长字段以 UTF-8 作为 string 类型参与编码
"""
from eth_abi import encode
from web3 import Web3

# ---------------------------------------------------------------- 域分隔标签
TAG_COMMITMENT = Web3.keccak(text="ZK-SealedWeigh.commitment.v3")
TAG_COMMIT_SIG = Web3.keccak(text="ZK-SealedWeigh.sig.commit.v3")
TAG_REVEAL_SIG = Web3.keccak(text="ZK-SealedWeigh.sig.reveal.v3")
TAG_RANGE_SIG = Web3.keccak(text="ZK-SealedWeigh.sig.range.v3")
TAG_NULLIFIER = Web3.keccak(text="ZK-SealedWeigh.nullifier.v3")

SIG_PREFIX = b"\x19Ethereum Signed Message:\n32"

_COMMITMENT_HASH_TYPES = ["bytes32", "uint256", "address", "uint256[]", "string", "uint256"]
_COMMIT_DIGEST_TYPES = ["bytes32", "uint256", "address", "bytes32"]
_REVEAL_DIGEST_TYPES = ["bytes32", "uint256", "address", "uint256[]", "bytes32"]
_RANGE_DIGEST_TYPES = ["bytes32", "uint256", "address", "uint256"]
_NULLIFIER_TYPES = ["bytes32", "uint256", "address"]


def _norm_bytes32(value):
    """把 0x 十六进制串 / bytes 归一化为 32 字节，等价于 Solidity 的 bytes32 参数"""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        s = str(value)
        if s.startswith(("0x", "0X")):
            s = s[2:]
        raw = bytes.fromhex(s)
    if len(raw) > 32:
        return raw[-32:]
    return raw.rjust(32, b"\x00")


def commitment_hash(voting_id, voter, scores, secret, max_score):
    """承诺哈希：keccak256(abi.encode(TAG_COMMITMENT, votingId, voter, scores, secret, maxScore))"""
    return Web3.keccak(encode(
        _COMMITMENT_HASH_TYPES,
        [TAG_COMMITMENT, int(voting_id), str(voter), [int(s) for s in scores],
         str(secret), int(max_score)]
    ))


def commit_digest(voting_id, voter, commitment_hash_value):
    """承诺阶段待签名摘要：keccak256(abi.encode(TAG_COMMIT_SIG, votingId, voter, commitmentHash))"""
    return Web3.keccak(encode(
        _COMMIT_DIGEST_TYPES,
        [TAG_COMMIT_SIG, int(voting_id), str(voter), _norm_bytes32(commitment_hash_value)]
    ))


def reveal_digest(voting_id, voter, scores, nullifier):
    """揭示阶段待签名摘要：keccak256(abi.encode(TAG_REVEAL_SIG, votingId, voter, scores, nullifier))"""
    return Web3.keccak(encode(
        _REVEAL_DIGEST_TYPES,
        [TAG_REVEAL_SIG, int(voting_id), str(voter), [int(s) for s in scores],
         _norm_bytes32(nullifier)]
    ))


def derive_nullifier(voting_id, voter):
    """活动内唯一揭晓标识：keccak256(abi.encode(TAG_NULLIFIER, votingId, voter))"""
    return Web3.keccak(encode(
        _NULLIFIER_TYPES,
        [TAG_NULLIFIER, int(voting_id), str(voter)]
    ))


def range_digest(voting_id, voter, commitment):
    """范围证明待签名摘要：keccak256(abi.encode(TAG_RANGE_SIG, votingId, voter, commitment))"""
    return Web3.keccak(encode(
        _RANGE_DIGEST_TYPES,
        [TAG_RANGE_SIG, int(voting_id), str(voter), int(commitment)]
    ))


def eth_hash(digest):
    """EIP-191 包裹：keccak256(SIG_PREFIX || digest)"""
    return Web3.keccak(SIG_PREFIX + _norm_bytes32(digest))


def hex0x(value):
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    s = str(value)
    return s if s.startswith("0x") else "0x" + s


# ------------------------------------------------- spec.md 第 7 节测试向量自检
SPEC_VECTORS = {
    "TAG_COMMITMENT": "f989c362dc9cceb77b838df72487e54a41bd549faa230a87932d4fb9b04f08b7",
    "TAG_COMMIT_SIG": "735f961bc7874a87e44d11e265946ea355f478906fb5489ec1b8739bcc00c6ab",
    "TAG_REVEAL_SIG": "67d980de8ae16cf5ab80b48362d15dcd4c2d9d207672346e98847066da301db6",
    "TAG_RANGE_SIG": "1693686b05e4d5b7a1091a1e4260ff5886009af024017cf6b75fd91772dd8404",
    "TAG_NULLIFIER": "07eee5bbe23d4225614099ecb14510f5168bf7c194bc0ffb673ae42164adcfe2",
    "nullifier": "c1da3c3588b03fbe83be605534c6a9f58ceba3081c58c041a0a9ae0a9111a8fc",
    "derivedNullifier": "e5f5161b4b98890d723fa3d596954ba85525c9b44b319e6e53c772142d932eb7",
    "commitmentHash": "3bb8f63ff26c8f455588b1f6b55363f628b71f5eaef4673ab5cee01de282be0c",
    "commitDigest": "2cd580910aa9acbee0e0956def252fbae3468764ba7b60cad9946d3f34a9f609",
    "revealDigest": "7e5db8ac0976c7e409c94b3a0f236919362c5a396f871d79228fbd7b43e1e4fb",
    "rangeDigest": "c100ac7c9d3bef526ff22abb1d71e675ddc8bc7245eff729b7cefa7b30ddd835",
    "ethHash(commitDigest)": "7ef3526c709c8032a11bf5acb0cd3143fd3b496301691f36614ce7c697dc320e",
    "ethHash(revealDigest)": "2aeaafac315557ce362323195cc003aa5d304fe532249320d30b8d6dedec7a73",
}

# 承诺点测试向量（alt_bn128）：votingId=1 / voter=0x7099... / scores=[7,9,0]
# fixture 与 SPEC_VECTORS 相同；用于校验 Python 与浏览器端曲线实现逐字节一致。
SPEC_COMMITMENT_POINTS = [
    "06ae23dbd2b2c323dd377f3ebcd6ddab72d8ae7f5634bd39bdbfecd92ef9b3fc"
    "0ef6987c64195d008237f32797de0433c236225a13cd6b0873ea09d68258d4fb",
]

_VECTOR_FIXTURE = dict(
    voting_id=1,
    voter="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    scores=[7, 9, 0],
    secret="correct horse battery staple",
    max_score=10,
    nullifier="0xc1da3c3588b03fbe83be605534c6a9f58ceba3081c58c041a0a9ae0a9111a8fc",
    range_commitment=2187125169807282827423416889253800045206127458618452263738622424698383698062,
)


def compute_spec_vectors():
    f = _VECTOR_FIXTURE
    ch = commitment_hash(f["voting_id"], f["voter"], f["scores"], f["secret"], f["max_score"])
    cd = commit_digest(f["voting_id"], f["voter"], ch)
    rd = reveal_digest(f["voting_id"], f["voter"], f["scores"], f["nullifier"])
    nd = derive_nullifier(f["voting_id"], f["voter"])
    rg = range_digest(f["voting_id"], f["voter"], f["range_commitment"])
    return {
        "TAG_COMMITMENT": TAG_COMMITMENT.hex(),
        "TAG_COMMIT_SIG": TAG_COMMIT_SIG.hex(),
        "TAG_REVEAL_SIG": TAG_REVEAL_SIG.hex(),
        "TAG_RANGE_SIG": TAG_RANGE_SIG.hex(),
        "TAG_NULLIFIER": TAG_NULLIFIER.hex(),
        "nullifier": f["nullifier"][2:],
        "derivedNullifier": nd.hex(),
        "commitmentHash": ch.hex(),
        "commitDigest": cd.hex(),
        "revealDigest": rd.hex(),
        "rangeDigest": rg.hex(),
        "ethHash(commitDigest)": eth_hash(cd).hex(),
        "ethHash(revealDigest)": eth_hash(rd).hex(),
    }


def self_check():
    actual = compute_spec_vectors()
    ok = True
    for name, expected in SPEC_VECTORS.items():
        got = actual.get(name)
        flag = "OK " if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"  [{flag}] {name}\n         expected {expected}\n         actual   {got}")
    print("spec.md 测试向量自检:", "全部通过" if ok else "存在不一致，请检查编码实现")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if self_check() else 1)
