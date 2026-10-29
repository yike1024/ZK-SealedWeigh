# services/blockchain.py - 修复版本

import os
import json
import logging
from web3 import Web3
from eth_account import Account
from utils import protocol
import time

logger = logging.getLogger(__name__)

# 修复 Web3 v6 兼容性问题的辅助函数
def encode_abi_packed(types, values):
    """模拟 abi.encodePacked 功能"""
    result = b''
    for t, v in zip(types, values):
        if t == 'address':
            # 地址类型：20字节，去除0x前缀
            addr = v[2:].lower().zfill(40) if v.startswith('0x') else v.zfill(40)
            result += bytes.fromhex(addr)
        elif t == 'uint256':
            # uint256类型：32字节
            if isinstance(v, str) and v.startswith('0x'):
                v = int(v, 16)
            result += v.to_bytes(32, 'big')
        elif t == 'bytes32':
            # bytes32类型：32字节
            if isinstance(v, str) and v.startswith('0x'):
                v = v[2:]
            result += bytes.fromhex(v.zfill(64))
    return result


def derive_placeholder_address(username):
    """未绑定钱包的用户：按用户名派生一个确定性的 20 字节占位地址。

    不能把用户名直接拼成地址 —— 用户名不是十六进制串，
    keccak256(abi.encodePacked(address)) 会因非十六进制字符直接抛错，整条链上流程中断。
    """
    return '0x' + Web3.keccak(text=str(username))[12:].hex()


def signed_raw_transaction(signed_txn):
    """取出签名后的原始交易字节。

    eth-account 0.9.x 用 camelCase 的 `rawTransaction`，0.10+ 改为 snake_case 的
    `raw_transaction`；这里两种都兼容，避免升级依赖后 relayer 静默失败。
    """
    raw = getattr(signed_txn, 'raw_transaction', None)
    if raw is None:
        raw = getattr(signed_txn, 'rawTransaction', None)
    if raw is None:
        raise AttributeError('签名结果中找不到原始交易字段（raw_transaction / rawTransaction）')
    return raw


def to_uint(value):
    """把证明参数转成 int。

    snarkjs 的 exportSolidityCallData 在不同版本里分别输出十进制字符串或 0x 十六进制，
    前端直接透传，所以这里两种都要认，否则 int('0x…') 会直接抛错。
    """
    if isinstance(value, str):
        s = value.strip()
        return int(s, 16) if s.lower().startswith('0x') else int(s)
    return int(value)


class BlockchainService:
    def __init__(self):
        try:
            # 从环境变量读取配置
            # 默认 127.0.0.1：Windows 下 localhost 会先尝试 IPv6(::1)，
            # Hardhat 只监听 IPv4，每次连接约多等 2s（实测 2091ms vs 24ms）。
            rpc_url = os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")
            self.w3 = Web3(Web3.HTTPProvider(rpc_url))

            if not self.w3.is_connected():
                logger.warning("⚠️ 无法连接到区块链网络，使用模拟模式")
                self._setup_mock()
                return

            # 从环境变量获取私钥和合约地址
            self.private_key = os.getenv("DEPLOYER_PRIVATE_KEY")
            self.contract_address = os.getenv("CONTRACT_ADDRESS")

            if not self.private_key or not self.contract_address:
                logger.error("❌ 区块链配置不完整，缺少私钥或合约地址")
                self._setup_mock()
                return

            self.account = Account.from_key(self.private_key)

            # 加载合约
            self.contract = self._load_contract()

            logger.info(f"✅ 区块链服务初始化成功 - 账户: {self.account.address}")

        except Exception as e:
            logger.error(f"❌ 区块链服务初始化失败: {e}")
            self._setup_mock()

    def _load_contract(self):
        """加载智能合约 - 使用完整 ABI"""
        logger.info("🔍 加载智能合约...")

        # 完整的合约 ABI
        abi = [
            {
                "inputs": [
                    {"internalType": "string", "name": "_title", "type": "string"},
                    {"internalType": "string", "name": "_description", "type": "string"},
                    {"internalType": "uint256", "name": "_maxScore", "type": "uint256"},
                    {"internalType": "uint256", "name": "_commitDuration", "type": "uint256"},
                    {"internalType": "uint256", "name": "_scoreDuration", "type": "uint256"},
                    {"internalType": "string[]", "name": "_candidates", "type": "string[]"},
                    {"internalType": "address[]", "name": "_voters", "type": "address[]"},
                    {"internalType": "uint256[]", "name": "_weights", "type": "uint256[]"},
                    {"internalType": "bytes32", "name": "_merkleRoot", "type": "bytes32"},
                    {"internalType": "address", "name": "_creator", "type": "address"}
                ],
                "name": "createVoting",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "votingCount",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "name": "votings",
                "outputs": [
                    {"internalType": "string", "name": "title", "type": "string"},
                    {"internalType": "string", "name": "description", "type": "string"},
                    {"internalType": "address", "name": "creator", "type": "address"},
                    {"internalType": "uint256", "name": "maxScore", "type": "uint256"},
                    {"internalType": "uint256", "name": "commitDuration", "type": "uint256"},
                    {"internalType": "uint256", "name": "scoreDuration", "type": "uint256"},
                    {"internalType": "uint256", "name": "startTime", "type": "uint256"},
                    {"internalType": "bool", "name": "isActive", "type": "bool"},
                    {"internalType": "uint8", "name": "phase", "type": "uint8"},
                    {"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "_votingId", "type": "uint256"}],
                "name": "getCandidates",
                "outputs": [{"internalType": "string[]", "name": "", "type": "string[]"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "_votingId", "type": "uint256"}],
                "name": "getVoters",
                "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "uint256", "name": "_votingId", "type": "uint256"},
                    {"internalType": "address", "name": "_voter", "type": "address"}
                ],
                "name": "getVoterWeight",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "uint256", "name": "_votingId", "type": "uint256"},
                    {"internalType": "address", "name": "_voter", "type": "address"},
                    {"internalType": "bytes32", "name": "_overallHash", "type": "bytes32"}
                ],
                "name": "commitDigest",
                "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
                "stateMutability": "pure",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "uint256", "name": "_votingId", "type": "uint256"},
                    {"internalType": "address", "name": "_voter", "type": "address"},
                    {"internalType": "uint256[]", "name": "_scores", "type": "uint256[]"},
                    {"internalType": "bytes32", "name": "_nullifier", "type": "bytes32"}
                ],
                "name": "revealDigest",
                "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
                "stateMutability": "pure",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "_votingId", "type": "uint256"}],
                "name": "getVotingResults",
                "outputs": [{"internalType": "uint256[]", "name": "", "type": "uint256[]"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "uint256", "name": "_votingId", "type": "uint256"},
                    {"internalType": "address", "name": "_voter", "type": "address"},
                    {"internalType": "bytes32", "name": "_overallHash", "type": "bytes32"},
                    {"internalType": "uint256[]", "name": "_commitmentX", "type": "uint256[]"},
                    {"internalType": "uint256[]", "name": "_commitmentY", "type": "uint256[]"},
                    {"internalType": "bytes32[]", "name": "_merkleProof", "type": "bytes32[]"},
                    {"internalType": "bytes", "name": "_signature", "type": "bytes"}
                ],
                "name": "submitPedersenCommitment",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "uint256", "name": "_votingId", "type": "uint256"},
                    {"internalType": "address", "name": "_voter", "type": "address"},
                    {"internalType": "uint256[]", "name": "_scores", "type": "uint256[]"},
                    {"internalType": "string", "name": "_secret", "type": "string"},
                    {"internalType": "bytes32", "name": "_nullifier", "type": "bytes32"},
                    {"internalType": "bytes", "name": "_signature", "type": "bytes"}
                ],
                "name": "revealPedersenScores",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "uint256", "name": "_votingId", "type": "uint256"},
                    {"internalType": "uint8", "name": "_phase", "type": "uint8"}
                ],
                "name": "updateVotingPhase",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "_votingId", "type": "uint256"}],
                "name": "calculateResults",
                "outputs": [{"internalType": "uint256[]", "name": "", "type": "uint256[]"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "_votingId", "type": "uint256"}],
                "name": "endVoting",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "uint256", "name": "_votingId", "type": "uint256"}],
                "name": "isVoter",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]

        # 以编译产物为单一真源：合约 ABI 变更（如 v3 改签名）后无需手工同步内联副本。
        # 内联 ABI 仅作为产物缺失时的兜底，避免后端因缺少编译产物而完全不可用。
        try:
            import json as _json
            from pathlib import Path as _Path
            _artifact = (_Path(__file__).resolve().parents[2] / 'frontend' / 'contract-artifacts'
                         / 'contracts' / 'ZKVoting.sol' / 'ZKVoting.json')
            if _artifact.exists():
                with open(_artifact, 'r', encoding='utf-8') as _f:
                    abi = _json.load(_f)['abi']
                logger.info(f"✅ 使用编译产物 ABI: {_artifact.name}")
        except Exception as _e:
            logger.warning(f"读取编译产物 ABI 失败，回退内联 ABI: {_e}")

        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.contract_address),
                abi=abi
            )
            logger.info("✅ 智能合约加载成功")
            return contract
        except Exception as e:
            logger.error(f"❌ 智能合约加载失败: {e}")
            raise

    def _setup_mock(self):
        """设置模拟模式"""
        self.w3 = None
        self.contract = None
        self.account = None
        self.contract_address = None
        logger.info("🔄 使用模拟区块链模式")

    def is_connected(self):
        return self.w3 is not None and self.w3.is_connected()

    def create_voting_on_chain(self, voting_data):
        """在区块链上创建投票"""
        if not self.is_connected():
            logger.warning("区块链未连接，无法创建链上投票")
            return None

        try:
            logger.info("🚀 开始在区块链上创建投票...")

            # 准备参数
            title = str(voting_data.get('title', '默认标题'))[:50]
            description = str(voting_data.get('description', ''))[:100]
            max_score = int(voting_data.get('max_score', 10))
            commit_duration = int(voting_data.get('commit_duration', 3600))
            score_duration = int(voting_data.get('score_duration', 7200))

            candidates = [str(c)[:50] for c in voting_data.get('candidates', ['候选1', '候选2'])]

            # 处理投票者地址
            voters = voting_data.get('voters', [])
            # 路由层传来的权重（已放大 100 倍）；若缺失则按 dict 内的 weight，再退化为 100
            raw_weights = voting_data.get('weights') or []
            valid_voters = []
            weights = []

            for idx, voter_info in enumerate(voters):
                if isinstance(voter_info, dict):
                    wallet_address = voter_info.get('wallet_address', '')
                    weight = int(voter_info.get('weight', 1.0) * 100)
                else:
                    wallet_address = str(voter_info)
                    # 关键：优先采用路由传入的权重，否则链上权重会一律变成 100，
                    # 自定义加权评审在链上就失效了（DB 与链上计票口径不一致）。
                    weight = int(raw_weights[idx]) if idx < len(raw_weights) else 100

                if wallet_address and wallet_address.startswith('0x') and len(wallet_address) == 42:
                    try:
                        checksum_address = Web3.to_checksum_address(wallet_address)
                        valid_voters.append(checksum_address)
                        weights.append(weight)
                    except Exception as e:
                        logger.error(f"❌ 无效的地址格式: {wallet_address} - {e}")

            if not valid_voters:
                # 使用默认账户
                valid_voters = [self.account.address]
                weights = [100]

            # 生成Merkle根
            merkle_leaves = [Web3.keccak(encode_abi_packed(['address'], [voter])) for voter in valid_voters]
            merkle_root = self.calculate_merkle_root(merkle_leaves)

            # 链上 creator（发布者钱包），缺省回退到 relayer
            creator_address = voting_data.get('creator') or self.account.address
            try:
                creator_address = Web3.to_checksum_address(creator_address)
            except Exception:
                creator_address = self.account.address

            logger.info(f"创建投票: {title}")
            logger.info(f"候选人: {candidates}")
            logger.info(f"投票者: {valid_voters}")
            logger.info(f"权重: {weights}")

            # 构建交易
            transaction = self.contract.functions.createVoting(
                title,
                description,
                max_score,
                commit_duration,
                score_duration,
                candidates,
                valid_voters,
                weights,
                merkle_root,
                creator_address
            ).build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 5000000,
                'gasPrice': self.w3.eth.gas_price,
                'chainId': self.w3.eth.chain_id
            })

            # 签名交易
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)

            # 发送交易
            tx_hash = self.w3.eth.send_raw_transaction(signed_raw_transaction(signed_txn))

            logger.info(f"交易已发送: {tx_hash.hex()}")

            # 等待确认
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if receipt.status == 1:
                voting_count = self.contract.functions.votingCount().call()
                voting_id = voting_count - 1

                logger.info(f"✅ 区块链投票创建成功! ID: {voting_id}")
                return voting_id
            else:
                logger.error("❌ 交易失败")
                return None

        except Exception as e:
            logger.error(f"❌ 区块链创建投票失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

    def calculate_merkle_root(self, leaves):
        """计算Merkle根"""
        if not leaves:
            return Web3.keccak(b"")

        if len(leaves) == 1:
            return leaves[0]

        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])

            new_leaves = []
            for i in range(0, len(leaves), 2):
                left = leaves[i]
                right = leaves[i + 1]
                if left <= right:
                    new_leaves.append(Web3.keccak(left + right))
                else:
                    new_leaves.append(Web3.keccak(right + left))
            leaves = new_leaves

        return leaves[0]

    def generate_merkle_proof(self, leaves, target_leaf):
        """生成Merkle证明"""
        if not leaves or target_leaf not in leaves:
            return []

        proof = []
        index = leaves.index(target_leaf)
        current_leaves = leaves.copy()

        while len(current_leaves) > 1:
            if len(current_leaves) % 2 == 1:
                current_leaves.append(current_leaves[-1])

            if index % 2 == 0:
                sibling_index = index + 1
                if sibling_index < len(current_leaves):
                    proof.append(current_leaves[sibling_index])
            else:
                sibling_index = index - 1
                proof.append(current_leaves[sibling_index])

            # 计算父级
            new_leaves = []
            for i in range(0, len(current_leaves), 2):
                left = current_leaves[i]
                right = current_leaves[i + 1] if i + 1 < len(current_leaves) else current_leaves[i]
                if left <= right:
                    new_leaves.append(Web3.keccak(left + right))
                else:
                    new_leaves.append(Web3.keccak(right + left))

            current_leaves = new_leaves
            index = index // 2

        return proof

    def build_voter_merkle_proof(self, voter_addresses, voter_address):
        """为投票者生成 Merkle 证明（叶子 = keccak(abi.encodePacked(address))，与合约一致）"""
        hashed = [Web3.keccak(encode_abi_packed(['address'], [a])) for a in voter_addresses]
        target = Web3.keccak(encode_abi_packed(['address'], [voter_address]))
        return self.generate_merkle_proof(hashed, target)

    # ==================== 摘要 / 链上哈希 助手（必须与合约逐字节一致） ====================

    def _to_bytes(self, value):
        """hex 字符串或 bytes 归一化为 bytes（不做定长填充）"""
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        s = str(value)
        if s.startswith('0x') or s.startswith('0X'):
            s = s[2:]
        return bytes.fromhex(s)

    def _bytes32(self, value):
        """归一化为 32 字节，等价于 Solidity 的 bytes32 参数"""
        raw = self._to_bytes(value)
        if len(raw) > 32:
            return raw[-32:]
        return raw.rjust(32, b'\x00')

    def _address_bytes(self, address):
        """等价于 abi.encodePacked(address)：20 字节小端序地址"""
        a = str(address)
        if a.startswith('0x') or a.startswith('0X'):
            a = a[2:]
        return bytes.fromhex(a.lower().zfill(40))

    def _pack_uint256(self, value):
        return int(value).to_bytes(32, 'big')

    # ---- 摘要构造统一委托给 utils/protocol.py（spec.md 第 4 节的唯一实现） ----
    def commitment_hash(self, voting_id, voter_address, scores, secret, max_score):
        """等价于合约 calculateCommitmentHash（spec.md 4.2）"""
        return protocol.commitment_hash(voting_id, voter_address, scores, secret, max_score)

    def build_commit_digest(self, voting_id, voter_address, commitment_hash_value):
        """等价于合约 commitDigest"""
        return protocol.commit_digest(voting_id, voter_address, commitment_hash_value)

    def build_reveal_digest(self, voting_id, voter_address, scores, nullifier):
        """等价于合约 revealDigest"""
        return protocol.reveal_digest(voting_id, voter_address, scores, nullifier)

    def _build_and_send(self, contract_fn, gas=800000):
        """由 relayer 私钥构建、签名并发送交易，返回是否成功"""
        transaction = contract_fn.build_transaction({
            'from': self.account.address,
            'nonce': self.w3.eth.get_transaction_count(self.account.address),
            'gas': gas,
            'gasPrice': self.w3.eth.gas_price,
            'chainId': self.w3.eth.chain_id
        })
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_raw_transaction(signed_txn))
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        return receipt.status == 1

    def submit_pedersen_commitment_on_chain(self, voting_id, voter_address, overall_hash,
                                            commitment_points, merkle_proof, signature):
        """在区块链上提交 Pedersen 承诺（relayer 代发，投票者钱包签名授权）

        v3：不再传 keccak(点)，而是把 (x, y) 原值上链 —— 合约要用 EIP-196/197
        预编译重算并校验，链上因此能独立验证承诺的真实性。
        """
        if not self.is_connected():
            logger.warning("区块链未连接，跳过承诺提交")
            return False

        try:
            voter_checksum = Web3.to_checksum_address(voter_address)

            xs, ys = [], []
            for point in commitment_points:
                body = str(point)
                if body.startswith(('0x', '0X')):
                    body = body[2:]
                if len(body) != 128:
                    raise ValueError(f'承诺点格式错误（需 128 位十六进制）: {body[:16]}…')
                xs.append(int(body[:64], 16))
                ys.append(int(body[64:], 16))

            logger.info(
                f"📤 提交 Pedersen 承诺到链: voting_id={voting_id}, voter={voter_checksum}, points={len(xs)}")

            success = self._build_and_send(
                self.contract.functions.submitPedersenCommitment(
                    voting_id,
                    voter_checksum,
                    self._bytes32(overall_hash),
                    xs,
                    ys,
                    merkle_proof,
                    self._to_bytes(signature)
                ),
                gas=900000
            )
            logger.info(f"链上承诺提交{'成功' if success else '失败'}")
            return success

        except Exception as e:
            logger.error(f"❌ 区块链承诺提交失败: {e}")
            return False

    def submit_range_proof_on_chain(self, voting_id, voter_address, commitment, a, b, c, signature):
        """代发范围证明（Groth16），合约验证评委签名与证明后写入 rangeCommitments"""
        if not self.is_connected():
            logger.warning("区块链未连接，跳过范围证明提交")
            return False

        try:
            voter_checksum = Web3.to_checksum_address(voter_address)
            logger.info(f"📤 提交范围证明到链: voting_id={voting_id}, voter={voter_checksum}")

            success = self._build_and_send(
                self.contract.functions.submitRangeProof(
                    voting_id,
                    voter_checksum,
                    to_uint(commitment),
                    [to_uint(a[0]), to_uint(a[1])],
                    [[to_uint(b[0][0]), to_uint(b[0][1])], [to_uint(b[1][0]), to_uint(b[1][1])]],
                    [to_uint(c[0]), to_uint(c[1])],
                    self._to_bytes(signature)
                ),
                gas=650000
            )
            logger.info(f"链上范围证明提交{'成功' if success else '失败'}")
            return success

        except Exception as e:
            logger.error(f"❌ 区块链范围证明提交失败: {e}")
            return False

    def reveal_pedersen_scores_on_chain(self, voting_id, voter_address, scores, secret, salt, nullifier, signature):
        """在区块链上揭示评分（relayer 代发，投票者钱包签名授权）"""
        if not self.is_connected():
            logger.warning("区块链未连接，跳过揭示")
            return False

        try:
            voter_checksum = Web3.to_checksum_address(voter_address)
            score_uint = [int(score) for score in scores]
            logger.info(f"📤 揭示评分到链: voting_id={voting_id}, voter={voter_checksum}")

            success = self._build_and_send(
                self.contract.functions.revealPedersenScores(
                    voting_id,
                    voter_checksum,
                    score_uint,
                    str(secret),
                    int(salt),
                    self._bytes32(nullifier),
                    self._to_bytes(signature)
                ),
                gas=1500000
            )
            if success:
                logger.info("✅ 链上评分揭示成功")
            else:
                logger.error("❌ 链上评分揭示交易失败")
            return success

        except Exception as e:
            logger.error(f"❌ 区块链评分揭示失败: {e}")
            return False

    # ==================== 阶段同步与结果上链 ====================

    def update_voting_phase_on_chain(self, voting_id, phase):
        """把 DB 阶段推送到链（commit->1, scoring->2, completed->3, cancelled->0）"""
        if not self.is_connected():
            logger.warning("区块链未连接，跳过阶段同步")
            return False
        try:
            success = self._build_and_send(
                self.contract.functions.updateVotingPhase(voting_id, int(phase)),
                gas=200000
            )
            logger.info(f"链上阶段同步 {'成功' if success else '失败'}: voting_id={voting_id}, phase={phase}")
            return success
        except Exception as e:
            logger.error(f"链上阶段同步失败: {e}")
            return False

    def calculate_results_on_chain(self, voting_id):
        """触发链上结果结算，成功后返回链上结果数组"""
        if not self.is_connected():
            logger.warning("区块链未连接，跳过结果结算")
            return None
        try:
            success = self._build_and_send(
                self.contract.functions.calculateResults(voting_id),
                gas=1500000
            )
            if not success:
                logger.error("链上结果结算交易失败")
                return None
            return self.get_voting_results_from_chain(voting_id)
        except Exception as e:
            logger.error(f"链上结果结算失败: {e}")
            return None

    def end_voting_on_chain(self, voting_id):
        """链上结束投票（cancelled / 强制收尾）"""
        if not self.is_connected():
            logger.warning("区块链未连接，跳过结束投票")
            return False
        try:
            return self._build_and_send(
                self.contract.functions.endVoting(voting_id),
                gas=200000
            )
        except Exception as e:
            logger.error(f"链上结束投票失败: {e}")
            return False

    def get_voting_info(self, voting_id):
        """获取投票信息"""
        if not self.is_connected():
            return self._get_mock_voting_info(voting_id)

        try:
            # 调用合约获取投票信息
            voting_data = self.contract.functions.votings(voting_id).call()
            candidates = self.contract.functions.getCandidates(voting_id).call()
            voters = self.contract.functions.getVoters(voting_id).call()

            # 获取投票者权重
            voter_weights = {}
            for voter in voters:
                try:
                    weight = self.contract.functions.getVoterWeight(voting_id, voter).call()
                    voter_weights[voter] = weight
                except Exception as e:
                    logger.warning(f"获取投票者 {voter} 权重失败: {e}")
                    voter_weights[voter] = 1

            return {
                'title': voting_data[0],
                'description': voting_data[1],
                'creator': voting_data[2],
                'max_score': voting_data[3],
                'commit_duration': voting_data[4],
                'score_duration': voting_data[5],
                'start_time': voting_data[6],
                'is_active': voting_data[7],
                'phase': voting_data[8],
                'merkle_root': voting_data[9],
                'candidates': candidates,
                'voters': voters,
                'voter_weights': voter_weights,
                'blockchain_id': voting_id
            }
        except Exception as e:
            logger.error(f"获取投票信息失败: {e}")
            return self._get_mock_voting_info(voting_id)

    def _get_mock_voting_info(self, voting_id):
        """获取模拟投票信息"""
        return {
            'title': f'模拟投票{voting_id}',
            'description': '区块链不可用',
            'creator': '0x0000000000000000000000000000000000000000',
            'max_score': 10,
            'phase': 0,
            'candidates': [],
            'voters': []
        }

    def get_voting_count(self):
        """获取投票数量"""
        if not self.is_connected():
            return 0
        try:
            return self.contract.functions.votingCount().call()
        except Exception as e:
            logger.error(f"获取投票数量失败: {e}")
            return 0

    def get_voting_results_from_chain(self, voting_id):
        """从区块链获取投票结果"""
        if not self.is_connected():
            return []
        try:
            return self.contract.functions.getVotingResults(voting_id).call()
        except Exception as e:
            logger.error(f"获取区块链结果失败: {e}")
            return []

    def get_network_info(self):
        """获取网络信息"""
        if not self.is_connected():
            return {
                'connected': False,
                'block_number': 0,
                'account_address': '0x0',
                'contract_address': '0x0',
                'chain_id': 0
            }

        return {
            'connected': True,
            'block_number': self.w3.eth.block_number,
            'account_address': self.account.address,
            'contract_address': self.contract_address,
            'chain_id': self.w3.eth.chain_id
        }

    def get_accounts(self):
        """获取可用账户"""
        if not self.is_connected():
            return []
        try:
            # 返回空列表，不再提供测试账户
            return []
        except:
            return []


# 全局实例
blockchain_service = BlockchainService()