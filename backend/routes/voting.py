# -*- coding: utf-8 -*-
# backend/routes/voting.py - 完整修复版本
import os
import sys
import logging
import json
from datetime import datetime, date
from decimal import Decimal

current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, current_dir)

from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity
from utils.auth import auth_required, role_required, get_current_user
from utils.pedersen import zkp_commitment
from utils import protocol
from services.blockchain import derive_placeholder_address, to_uint
from database import db

try:
    from services.blockchain import blockchain_service

    logger = logging.getLogger(__name__)
except ImportError as e:
    print(f"Blockchain service import failed: {e}")


    class MockBlockchainService:
        def __init__(self):
            self.w3 = None
            self.contract = None
            self.account = None

        def is_connected(self):
            return False

        def create_voting_on_chain(self, voting_data):
            logger.warning("Using mock blockchain service")
            return 0

        def compute_onchain_overall_hash(self, scores, secret, max_score):
            return b'\x00' * 32

        def build_commit_digest(self, voting_id, voter_address, overall_hash):
            return b'\x00' * 32

        def build_reveal_digest(self, voting_id, voter_address, scores, nullifier):
            return b'\x00' * 32

        def submit_pedersen_commitment_on_chain(self, voting_id, voter_address, overall_hash, score_commitments,
                                                merkle_proof, signature):
            logger.warning("Using mock blockchain service")
            return False

        def reveal_pedersen_scores_on_chain(self, voting_id, voter_address, scores, secret, salt, nullifier, signature):
            logger.warning("Using mock blockchain service")
            return False

        def submit_range_proof_on_chain(self, voting_id, voter_address, commitment, a, b, c, signature):
            logger.warning("Using mock blockchain service")
            return False

        def update_voting_phase_on_chain(self, voting_id, phase):
            return False

        def calculate_results_on_chain(self, voting_id):
            return None

        def end_voting_on_chain(self, voting_id):
            return False

        def calculate_merkle_root(self, voters):
            return "0x0000000000000000000000000000000000000000000000000000000000000000"

        def generate_merkle_proof(self, voters, voter):
            return []

        def build_voter_merkle_proof(self, voter_addresses, voter_address):
            return []

        def get_voting_results_from_chain(self, voting_id):
            return []

        def get_voting_info(self, voting_id):
            return {
                'title': 'Mock Voting',
                'description': 'Blockchain unavailable',
                'creator': '0x0000000000000000000000000000000000000000',
                'max_score': 10,
                'phase': 0,
                'candidates': [],
                'voters': []
            }

        def get_network_info(self):
            return {
                'connected': False,
                'block_number': 0,
                'account_address': '0x0000000000000000000000000000000000000000',
                'contract_address': '0x0000000000000000000000000000000000000000',
                'chain_id': 0
            }


    blockchain_service = MockBlockchainService()
    logger = logging.getLogger(__name__)

voting_bp = Blueprint('voting', __name__)


def serialize_value(value):
    if isinstance(value, bytes):
        return value.hex()
    elif isinstance(value, (datetime, date)):
        return value.isoformat()
    elif isinstance(value, Decimal):
        return float(value)
    elif hasattr(value, 'isoformat'):
        return value.isoformat()
    else:
        return value


def serialize_dict(obj):
    if isinstance(obj, dict):
        return {key: serialize_value(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [serialize_dict(item) for item in obj]
    else:
        return serialize_value(obj)


# ==================== 链上签名与阶段同步 助手 ====================

# DB 字符串阶段 -> 合约数字阶段
PHASE_TO_CHAIN = {'commit': 1, 'scoring': 2, 'completed': 3, 'cancelled': 0}


def _numeric_phase(phase):
    return PHASE_TO_CHAIN.get(phase, 0)


def _hex0x(raw):
    h = raw.hex() if hasattr(raw, 'hex') else str(raw)
    return h if h.startswith('0x') else f'0x{h}'


def _get_user_wallet(user):
    wallet = user.get('wallet_address')
    if wallet:
        return wallet
    return f"0x{str(user['username'])[:20].ljust(20, '0')}"


def _voter_addresses(voting):
    """链上 Merkle 白名单的叶子地址集合。

    必须与建活动时上链的地址列表逐字一致，否则 verifyMerkleProof 会失败。
    未绑定钱包的用户用 keccak 派生的占位地址（建活动时用的是同一个函数）。
    """
    return [
        v.get('wallet_address') or derive_placeholder_address(v['username'])
        for v in voting['voters']
    ]


def _prepare_onchain(voting, user, action, scores, secret, commitment_hash=None):
    """返回待签名摘要 {action, voter_address, digest}；链不可用则返回 None

    commitment_hash 必须与承诺阶段写入数据库/链上的值一致（spec.md 4.2）；
    未显式传入时才由 (votingId, voter, scores, secret, maxScore) 重算。
    """
    if voting.get('blockchain_id') is None or not blockchain_service.is_connected():
        return None

    wallet = _get_user_wallet(user)
    chain_id = voting['blockchain_id']

    if action == 'commit':
        if commitment_hash is None:
            commitment_hash = blockchain_service.commitment_hash(
                chain_id, wallet, scores, secret, voting['max_score'])
        digest = blockchain_service.build_commit_digest(chain_id, wallet, commitment_hash)
    else:
        # P5（R-3）：nullifier 由合约按 (votingId, voter) 派生，后端只复算同一值
        nullifier = protocol.derive_nullifier(chain_id, wallet)
        digest = blockchain_service.build_reveal_digest(chain_id, wallet, scores, nullifier)

    return {'action': action, 'voter_address': wallet, 'digest': _hex0x(digest)}


@voting_bp.before_request
def log_voting_requests():
    current_user = get_current_user()
    user_id = current_user['id'] if current_user else 'unauthenticated'
    logger.info(f"Voting request: {request.method} {request.path} - User: {user_id}")


# 投票列表 - GET
@voting_bp.route('/', methods=['GET'])
@auth_required
def get_votings():
    try:
        logger.info("Getting voting list")
        my_only = request.args.get('my', 'false').lower() == 'true'

        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': 'User info failed'
            }), 401

        user_id = current_user['id']
        user_role = current_user['role']

        logger.info(f"UserID: {user_id}, Role: {user_role}, MyOnly: {my_only}")

        if my_only:
            if user_role == 'publisher':
                votings = db.execute_query(
                    """SELECT vs.*, 
                              u.username as creator_name,
                              (SELECT COUNT(*) FROM candidates c WHERE c.voting_id = vs.id) as candidate_count,
                              (SELECT COUNT(*) FROM voting_voters vv WHERE vv.voting_id = vs.id) as voter_count,
                              (SELECT COUNT(*) FROM voting_commitments vc WHERE vc.voting_id = vs.id) as commitment_count,
                              (SELECT COUNT(*) FROM voting_scores vs2 WHERE vs2.voting_id = vs.id) as score_count
                       FROM voting_sessions vs
                       LEFT JOIN users u ON vs.creator_id = u.id
                       WHERE vs.creator_id = ?
                       ORDER BY vs.created_at DESC""",
                    (user_id,)
                )
            else:
                votings = db.execute_query(
                    """SELECT vs.*, 
                              u.username as creator_name,
                              (SELECT COUNT(*) FROM candidates c WHERE c.voting_id = vs.id) as candidate_count,
                              (SELECT COUNT(*) FROM voting_voters vv WHERE vv.voting_id = vs.id) as voter_count,
                              (SELECT COUNT(*) FROM voting_commitments vc WHERE vc.voting_id = vs.id) as commitment_count,
                              (SELECT COUNT(*) FROM voting_scores vs2 WHERE vs2.voting_id = vs.id AND vs2.voter_id = ?) as user_score_count
                       FROM voting_sessions vs
                       JOIN voting_voters vv ON vs.id = vv.voting_id
                       LEFT JOIN users u ON vs.creator_id = u.id
                       WHERE vv.voter_id = ?
                       ORDER BY vs.created_at DESC""",
                    (user_id, user_id)
                )
        else:
            if user_role == 'publisher':
                votings = db.execute_query(
                    """SELECT vs.*, 
                              u.username as creator_name,
                              (SELECT COUNT(*) FROM candidates c WHERE c.voting_id = vs.id) as candidate_count,
                              (SELECT COUNT(*) FROM voting_voters vv WHERE vv.voting_id = vs.id) as voter_count,
                              (SELECT COUNT(*) FROM voting_commitments vc WHERE vc.voting_id = vs.id) as commitment_count,
                              (SELECT COUNT(*) FROM voting_scores vs2 WHERE vs2.voting_id = vs.id) as score_count
                       FROM voting_sessions vs
                       LEFT JOIN users u ON vs.creator_id = u.id
                       ORDER BY vs.created_at DESC"""
                )
            else:
                votings = db.execute_query(
                    """SELECT vs.*, 
                              u.username as creator_name,
                              (SELECT COUNT(*) FROM candidates c WHERE c.voting_id = vs.id) as candidate_count,
                              (SELECT COUNT(*) FROM voting_voters vv WHERE vv.voting_id = vs.id) as voter_count,
                              (SELECT COUNT(*) FROM voting_commitments vc WHERE vc.voting_id = vs.id) as commitment_count,
                              (SELECT COUNT(*) FROM voting_scores vs2 WHERE vs2.voting_id = vs.id AND vs2.voter_id = ?) as user_score_count
                       FROM voting_sessions vs
                       JOIN voting_voters vv ON vs.id = vv.voting_id
                       LEFT JOIN users u ON vs.creator_id = u.id
                       WHERE vv.voter_id = ?
                       ORDER BY vs.created_at DESC""",
                    (user_id, user_id)
                )

        logger.info(f"Found {len(votings) if votings else 0} voting activities")

        blockchain_connected = blockchain_service.is_connected()

        serialized_votings = []
        if votings:
            for voting in votings:
                voting_id = voting['id']
                serialized_voting = serialize_dict(voting)

                serialized_voting['candidates'] = serialize_dict(db.execute_query(
                    "SELECT id, name FROM candidates WHERE voting_id = ? ORDER BY order_index",
                    (voting_id,)
                ))

                serialized_voting['voters'] = serialize_dict(db.execute_query(
                    """SELECT vv.voter_id as id, u.username, u.email, vv.weight, u.wallet_address
                       FROM voting_voters vv 
                       JOIN users u ON vv.voter_id = u.id 
                       WHERE vv.voting_id = ?""",
                    (voting_id,)
                ))

                serialized_voting['commitments'] = serialize_dict(db.execute_query(
                    """SELECT vc.voter_id, u.username, vc.commitment_hash, vc.created_at, vc.commitment_type
                       FROM voting_commitments vc 
                       JOIN users u ON vc.voter_id = u.id 
                       WHERE vc.voting_id = ?""",
                    (voting_id,)
                ))

                serialized_voting['scores'] = serialize_dict(db.execute_query(
                    """SELECT vs.voter_id, vs.candidate_id, vs.score, u.username, vs.weight
                       FROM voting_scores vs 
                       JOIN users u ON vs.voter_id = u.id 
                       WHERE vs.voting_id = ?""",
                    (voting_id,)
                ))

                serialized_voting['blockchain_connected'] = blockchain_connected
                if serialized_voting.get('blockchain_id') is not None:
                    try:
                        blockchain_info = blockchain_service.get_voting_info(serialized_voting['blockchain_id'])
                        serialized_voting['blockchain_info'] = serialize_dict(blockchain_info)
                    except Exception as e:
                        logger.error(f"Get blockchain info failed: {e}")
                        serialized_voting['blockchain_info'] = {'error': str(e)}

                serialized_votings.append(serialized_voting)

        logger.info("Voting list retrieved successfully")
        return jsonify({
            'success': True,
            'data': serialized_votings,
            'blockchain_connected': blockchain_connected,
            'count': len(serialized_votings)
        })

    except Exception as e:
        logger.error(f"Get voting list error: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Get voting activities failed: {str(e)}'
        }), 500


# 创建投票 - POST (关键修复：添加 OPTIONS 方法支持)
@voting_bp.route('/', methods=['POST', 'OPTIONS'])
@auth_required
@role_required(['publisher'])
def create_voting():
    # 处理 OPTIONS 预检请求
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response

    # POST 请求处理
    try:
        logger.info("🎯 进入投票创建路由")
        logger.info(f"📨 请求方法: {request.method}")

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            logger.warning("创建活动请求体不是 JSON 对象")
            return jsonify({
                'success': False,
                'message': '请求体必须是 JSON 对象'
            }), 400

        current_user = get_current_user()
        if not current_user:
            logger.error("❌ 用户信息获取失败")
            return jsonify({
                'success': False,
                'message': 'User info failed'
            }), 401

        logger.info(f"👤 当前用户: {current_user['username']} (ID: {current_user['id']})")

        required_fields = ['title', 'candidates', 'voters']
        for field in required_fields:
            if not data.get(field):
                logger.warning(f"Missing required field: {field}")
                return jsonify({
                    'success': False,
                    'message': f'Please fill {field} field'
                }), 400

        if len(data['candidates']) < 2:
            logger.warning("Insufficient candidates")
            return jsonify({
                'success': False,
                'message': 'At least 2 candidates required'
            }), 400

        if len(data['voters']) < 1:
            logger.warning("Insufficient scorers")
            return jsonify({
                'success': False,
                'message': 'At least 1 scorer required'
            }), 400

        voters_data = data['voters']
        if isinstance(voters_data[0], str):
            processed_voters = []
            for voter in voters_data:
                if isinstance(voter, str):
                    processed_voters.append({
                        'username': voter.strip(),
                        'weight': 1.0
                    })
                else:
                    processed_voters.append(voter)
            data['voters'] = processed_voters

        candidates = data['candidates']
        unique_candidates = []
        seen = set()
        for candidate in candidates:
            candidate_clean = candidate.strip()
            if candidate_clean and candidate_clean not in seen:
                unique_candidates.append(candidate_clean)
                seen.add(candidate_clean)

        voting_data = {
            'title': data['title'],
            'description': data.get('description', ''),
            'creator_id': current_user['id'],
            'max_score': data.get('max_score', 10),
            'weight_type': data.get('weight_type', 'equal'),
            'commit_duration': data.get('commit_duration', 24),
            'score_duration': data.get('score_duration', 48),
            'enable_zk_proof': data.get('enable_zk_proof', True),
            'scoring_rules': data.get('scoring_rules', ''),
            'candidates': unique_candidates,
            'voters': data['voters']
        }

        logger.info(f"Start creating voting: {voting_data['title']}")

        # 导入 Voting 模型
        from models.voting import Voting
        voting = Voting.create_voting(voting_data)

        if not voting:
            logger.error("Voting creation failed, returned None")
            return jsonify({
                'success': False,
                'message': 'Voting creation failed'
            }), 500

        logger.info(f"Database voting created successfully, ID: {voting['id']}")

        blockchain_id = None
        blockchain_success = False
        blockchain_error = None

        if data.get('enable_blockchain', True) and blockchain_service.is_connected():
            try:
                blockchain_voters = []
                blockchain_weights = []

                for voter_info in data['voters']:
                    if isinstance(voter_info, dict):
                        username = voter_info.get('username', '').strip()
                        weight = int(voter_info.get('weight', 1.0) * 100)
                    else:
                        username = str(voter_info).strip()
                        weight = 100

                    if username:
                        user_result = db.execute_query(
                            "SELECT wallet_address, is_test_account FROM users WHERE username = ?", (username,)
                        )
                        if user_result and user_result[0]['wallet_address']:
                            wallet_address = user_result[0]['wallet_address']
                            blockchain_voters.append(wallet_address)
                            blockchain_weights.append(weight)
                        else:
                            # 没有钱包地址的用户：用 keccak 派生的合法占位地址（须与
                            # _voter_addresses 使用同一函数，否则 Merkle 证明会错位）
                            blockchain_voters.append(derive_placeholder_address(username))
                            blockchain_weights.append(weight)

                if not blockchain_voters:
                    blockchain_voters = [blockchain_service.account.address]
                    blockchain_weights = [100]

                # Merkle 根由 BlockchainService 内部按同一份评委地址列表统一计算（单一真源），
                # 路由层不再重复计算，避免两处实现漂移导致 verifyMerkleProof 失败。
                blockchain_data = {
                    'title': data['title'],
                    'description': data.get('description', ''),
                    'max_score': data.get('max_score', 10),
                    'commit_duration': data.get('commit_duration', 24) * 3600,
                    'score_duration': data.get('score_duration', 48) * 3600,
                    'candidates': unique_candidates,
                    'voters': blockchain_voters,
                    'weights': blockchain_weights,
                    'creator': current_user.get('wallet_address')
                }

                logger.info(f"Creating voting on blockchain: {blockchain_data}")
                blockchain_id = blockchain_service.create_voting_on_chain(blockchain_data)

                if blockchain_id is not None:
                    db.execute_query(
                        "UPDATE voting_sessions SET blockchain_id = ? WHERE id = ?",
                        (blockchain_id, voting['id'])
                    )
                    voting['blockchain_id'] = blockchain_id
                    blockchain_success = True
                    logger.info(f"Blockchain voting created successfully, ID: {blockchain_id}")
                else:
                    blockchain_success = False
                    logger.warning("Blockchain voting creation returned None")
                    blockchain_error = "Blockchain voting creation returned None"

            except Exception as blockchain_error_ex:
                blockchain_error = str(blockchain_error_ex)
                logger.error(f"Blockchain creation failed, but database record saved: {blockchain_error}")
                blockchain_success = False

        # 构建响应数据
        response_data = {
            'success': True,
            'message': 'Voting created successfully' if (voting and (not data.get('enable_blockchain',
                                                                                  True) or blockchain_success)) else 'Database voting created but blockchain failed',
            'data': serialize_dict({
                **voting,
                'blockchain_enabled': data.get('enable_blockchain', True),
                'blockchain_success': blockchain_success,
                'blockchain_id': blockchain_id,
                'blockchain_error': blockchain_error
            })
        }

        # 根据区块链状态设置状态码
        status_code = 201 if (not data.get('enable_blockchain', True) or blockchain_success) else 206

        return jsonify(response_data), status_code

    except ValueError as e:
        logger.error(f"Create voting validation error: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Create voting system error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Create voting failed: {str(e)}'
        }), 500


# 获取投票详情
@voting_bp.route('/<int:voting_id>', methods=['GET'])
@auth_required
def get_voting(voting_id):
    try:
        from models.voting import Voting
        if not isinstance(voting_id, int) or voting_id < 1 or voting_id > 2147483647:
            return jsonify({
                'success': False,
                'message': 'Voting ID is invalid'
            }), 400
        voting = Voting.get_voting_by_id(voting_id)

        if not voting:
            return jsonify({
                'success': False,
                'message': 'Voting does not exist'
            }), 404

        serialized_voting = serialize_dict(voting)

        serialized_voting['blockchain_connected'] = blockchain_service.is_connected()
        if serialized_voting.get('blockchain_id') is not None:
            try:
                blockchain_info = blockchain_service.get_voting_info(serialized_voting['blockchain_id'])
                serialized_voting['blockchain_info'] = serialize_dict(blockchain_info)
            except Exception as e:
                logger.error(f"Get blockchain info failed: {e}")
                serialized_voting['blockchain_info'] = {'error': str(e)}

        return jsonify({
            'success': True,
            'data': serialized_voting
        })

    except Exception as e:
        logger.error(f"Get voting error: {e}")
        return jsonify({
            'success': False,
            'message': 'Get voting failed'
        }), 500


# 提交承诺
@voting_bp.route('/<int:voting_id>/commitments', methods=['POST', 'OPTIONS'])
@auth_required
def submit_commitment(voting_id):
    # 处理 OPTIONS 预检请求
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response

    # POST 请求处理
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': 'User info failed'
            }), 401

        logger.info(f"Submit Pedersen commitment request - VotingID: {voting_id}, UserID: {current_user['id']}")

        data = request.get_json()

        # v2 密封契约（spec.md 第 5.2 / 6 节）：
        # 客户端只提交承诺点与承诺哈希，明文分数与 secret 不得离开浏览器。
        required_fields = ['commitments', 'commitment_hash']
        for field in required_fields:
            if field not in data:
                logger.warning(f"Missing required field: {field}")
                return jsonify({
                    'success': False,
                    'message': f'Please provide {field} field'
                }), 400

        if 'scores' in data or 'secret' in data:
            logger.warning(f"拒绝承诺阶段提交明文分数/secret: User{current_user['id']}")
            return jsonify({
                'success': False,
                'message': '承诺阶段不得提交明文分数或 secret，请在浏览器本地生成承诺后仅提交承诺点与承诺哈希'
            }), 400

        from models.voting import Voting
        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            logger.error(f"Voting does not exist: {voting_id}")
            return jsonify({
                'success': False,
                'message': 'Voting does not exist'
            }), 404

        is_voter = any(v['id'] == current_user['id'] for v in voting['voters'])
        if not is_voter:
            logger.warning(f"User无权参与: User{current_user['id']} not in voting{voting_id} voters list")
            return jsonify({
                'success': False,
                'message': 'You are not authorized to participate in this voting'
            }), 403

        if voting['phase'] != 'commit':
            logger.warning(f"Not in commit phase: Current phase{voting['phase']}")
            return jsonify({
                'success': False,
                'message': 'Not in commit phase'
            }), 400

        commitments = data['commitments']
        if isinstance(commitments, str):
            try:
                commitments = json.loads(commitments)
            except json.JSONDecodeError:
                return jsonify({'success': False, 'message': 'Commitments 格式错误'}), 400

        if not isinstance(commitments, list) or len(commitments) != len(voting['candidates']):
            return jsonify({
                'success': False,
                'message': f'承诺数量必须等于候选人数 ({len(voting["candidates"])})'
            }), 400

        # 承诺点必须是 128 hex（x||y，secp256k1 未压缩坐标）
        for point in commitments:
            if not isinstance(point, str) or len(point) != 128:
                return jsonify({
                    'success': False,
                    'message': '承诺点格式错误：应为 128 位十六进制 (x||y)'
                }), 400
            try:
                int(point, 16)
            except ValueError:
                return jsonify({'success': False, 'message': '承诺点含非法字符'}), 400

        commitment_hash_value = str(data['commitment_hash'])
        commitment_data = {
            'voting_id': voting_id,
            'voter_id': current_user['id'],
            'commitment_hash': commitment_hash_value,
            'commitments': json.dumps(commitments),
            'commitment_type': 'pedersen'
        }

        commitment_id = Voting.submit_commitment(commitment_data)

        # 链可用时返回待签名摘要，由前端钱包签名后经 /onchain/relay 代发
        onchain = _prepare_onchain(voting, current_user, 'commit', None, None,
                                   commitment_hash=commitment_hash_value)

        logger.info(f"Pedersen commitment submitted successfully: ID {commitment_id}")
        return jsonify({
            'success': True,
            'message': 'Pedersen commitment submitted successfully',
            'data': {
                'commitment_id': commitment_id,
                'commitment_hash': commitment_hash_value,
                'commitment_type': 'pedersen',
                'type': 'pedersen',
                'onchain': onchain,
                'blockchain_success': False
            }
        }), 201

    except Exception as e:
        logger.error(f"Submit Pedersen commitment error: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'Submit commitment failed: {str(e)}'
        }), 500


# 验证承诺
@voting_bp.route('/<int:voting_id>/commitments/verify', methods=['POST', 'OPTIONS'])
@auth_required
def verify_commitment(voting_id):
    # 处理 OPTIONS 预检请求
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response

    # POST 请求处理
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': 'User info failed'
            }), 401

        logger.info(f"验证 Pedersen 承诺请求 - VotingID: {voting_id}, UserID: {current_user['id']}")

        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'message': '请求数据为空或格式错误'
            }), 400

        required_fields = ['scores', 'secret']
        for field in required_fields:
            if field not in data:
                logger.error(f"缺少必要字段: {field}")
                return jsonify({
                    'success': False,
                    'message': f'请提供{field}字段'
                }), 400

        # 获取用户承诺记录
        from models.voting import Voting
        commitment = Voting.get_user_commitment(voting_id, current_user['id'])
        if not commitment:
            logger.error(f"用户承诺记录未找到 - VotingID: {voting_id}, UserID: {current_user['id']}")
            return jsonify({
                'success': False,
                'message': '承诺记录未找到'
            }), 404

        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            logger.error(f"投票活动不存在 - VotingID: {voting_id}")
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        logger.info(f"开始验证 Pedersen 承诺 - 用户: {current_user['id']}")

        # v2：真椭圆曲线校验 —— 用 (scores, secret) 重算每个 C_i 并与承诺阶段比对
        scores_data = data['scores']
        if isinstance(scores_data, str):
            try:
                scores_data = json.loads(scores_data)
            except json.JSONDecodeError:
                return jsonify({'success': False, 'message': '分数格式错误'}), 400

        if not isinstance(scores_data, list) or len(scores_data) != len(voting['candidates']):
            return jsonify({
                'success': False,
                'message': f'分数数量必须等于候选人数 ({len(voting["candidates"])})'
            }), 400

        stored_commitments = [str(p).lower() for p in json.loads(commitment['commitments'])]

        verification_result = zkp_commitment.verify_commitments(
            scores_data,
            data['secret'],
            stored_commitments,
            voting['max_score']
        )

        # 承诺哈希也必须能被 (scores, secret, maxScore, votingId, voter) 重算出来
        if verification_result.get('is_valid'):
            wallet = _get_user_wallet(current_user)
            voting_ref = voting.get('blockchain_id') if voting.get('blockchain_id') is not None else voting['id']
            expected_hash = protocol.hex0x(protocol.commitment_hash(
                voting_ref, wallet, scores_data, data['secret'], voting['max_score']
            ))
            stored_hash = str(commitment['commitment_hash'] or '').lower()
            if stored_hash != expected_hash.lower():
                logger.warning(
                    f"承诺哈希不一致: User{current_user['id']} 存储={stored_hash[:12]}… 期望={expected_hash[:12]}…")
                verification_result = {
                    'success': False,
                    'is_valid': False,
                    'error': '承诺哈希不一致：分数或密码与承诺阶段不符'
                }

        logger.info(f"用户 {current_user['id']} Pedersen 承诺验证结果: is_valid={verification_result.get('is_valid')}")

        # 链可用时返回揭示阶段的待签名摘要，由前端钱包签名后经 /onchain/relay 代发
        onchain = None
        if verification_result.get('is_valid'):
            onchain = _prepare_onchain(voting, current_user, 'reveal', scores_data, data['secret'])

        if verification_result.get('is_valid'):
            try:
                scores_list = scores_data

                voter_weight = 1.0
                for voter in voting['voters']:
                    if voter['id'] == current_user['id']:
                        voter_weight = voter['weight']
                        break

                existing_scores = db.execute_query(
                    "SELECT id FROM voting_scores WHERE voting_id = ? AND voter_id = ?",
                    (voting_id, current_user['id'])
                )

                submitted_count = 0
                if not existing_scores:
                    for candidate_index, score in enumerate(scores_list):
                        if candidate_index < len(voting['candidates']):
                            score_data = {
                                'voting_id': voting_id,
                                'voter_id': current_user['id'],
                                'candidate_id': voting['candidates'][candidate_index]['id'],
                                'score': score,
                                'weight': voter_weight
                            }
                            try:
                                Voting.submit_score(score_data)
                                submitted_count += 1
                                # 不记录明文分数（spec.md 第 6 节）
                                logger.info(f"成功提交评分: 候选人 {candidate_index}")
                            except Exception as e:
                                logger.error(f"提交评分失败: {e}")

                    logger.info(f"用户 {current_user['id']} Pedersen 承诺验证成功并自动提交了 {submitted_count} 个评分")
                else:
                    logger.info(f"用户 {current_user['id']} 已经提交过评分，跳过自动提交")

                return jsonify({
                    'success': True,
                    'data': {
                        'is_valid': True,
                        'commitment_hash': commitment['commitment_hash'],
                        'auto_submitted': not existing_scores,
                        'submitted_count': submitted_count,
                        'total_candidates': len(voting['candidates']),
                        'onchain': onchain,
                        'commitment_type': 'pedersen'
                    }
                })

            except Exception as e:
                logger.error(f"自动提交评分错误: {e}", exc_info=True)
                return jsonify({
                    'success': False,
                    'message': f'验证成功但评分提交失败: {str(e)}',
                    'data': {
                        'is_valid': True,
                        'commitment_hash': commitment['commitment_hash'],
                        'auto_submitted': False,
                        'onchain': onchain,
                        'commitment_type': 'pedersen'
                    }
                }), 500
        else:
            return jsonify({
                'success': True,
                'data': {
                    'is_valid': False,
                    'commitment_hash': commitment['commitment_hash'],
                    'message': verification_result.get('error',
                                                       'Pedersen 承诺验证失败，请检查密码和分数是否与提交承诺时一致'),
                    'onchain': onchain,
                    'commitment_type': 'pedersen'
                }
            })

    except Exception as e:
        logger.error(f"验证 Pedersen 承诺错误: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'验证承诺失败: {str(e)}'
        }), 500


# 链上代发（relayer）——投票者钱包签名后，由后端把承诺/揭示写入合约
@voting_bp.route('/<int:voting_id>/onchain/relay', methods=['POST', 'OPTIONS'])
@auth_required
def relay_onchain(voting_id):
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response

    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'success': False, 'message': 'User info failed'}), 401

        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({'success': False, 'message': '请求体必须是 JSON 对象'}), 400
        action = data.get('action')
        signature = data.get('signature')

        if action not in ('commit', 'reveal', 'range'):
            return jsonify({'success': False, 'message': 'action 必须是 commit / reveal / range'}), 400
        # P5（R-10）：三种动作都必须由评委钱包签名；范围证明的签名绑定 commitment，
        # relayer 因此不能替换证明，只能拒绝上链（审查属 R-4）。
        if not signature:
            return jsonify({'success': False, 'message': '缺少 signature 字段'}), 400

        from models.voting import Voting
        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            return jsonify({'success': False, 'message': '投票活动不存在'}), 404
        if voting.get('blockchain_id') is None:
            return jsonify({'success': False, 'message': '该投票未在链上创建'}), 400
        if not blockchain_service.is_connected():
            return jsonify({'success': False, 'message': '区块链未连接'}), 503

        commitment = Voting.get_user_commitment(voting_id, current_user['id'])
        if not commitment:
            return jsonify({'success': False, 'message': '未找到承诺记录'}), 404

        wallet = _get_user_wallet(current_user)
        chain_id = voting['blockchain_id']
        client_digest = data.get('digest')

        try:
            stored_points = [str(p).lower() for p in json.loads(commitment.get('commitments') or '[]')]
        except Exception:
            stored_points = []

        if action == 'commit':
            # v2：承诺阶段数据库内只有承诺点与承诺哈希，明文不参与链上代发
            commitment_hash_value = str(commitment.get('commitment_hash') or '')
            if not commitment_hash_value:
                return jsonify({'success': False, 'message': '承诺记录缺少承诺哈希'}), 400
            if len(stored_points) != len(voting['candidates']):
                return jsonify({'success': False, 'message': '承诺点数量与候选人不一致'}), 400

            if client_digest:
                expected = _hex0x(
                    blockchain_service.build_commit_digest(chain_id, wallet, commitment_hash_value)
                )
                if str(client_digest).lower() != expected.lower():
                    return jsonify({'success': False, 'message': '签名摘要与后端计算不一致'}), 400

            # v3：承诺点 (x, y) 原样上链，合约用预编译做 on-curve 与揭晓期重算校验
            merkle_proof = blockchain_service.build_voter_merkle_proof(_voter_addresses(voting), wallet)

            success = blockchain_service.submit_pedersen_commitment_on_chain(
                chain_id, wallet, commitment_hash_value, stored_points, merkle_proof, signature
            )
        elif action == 'range':
            # 范围证明由评委在浏览器本地生成，这里只做代发（合约会 verifyProof）
            commitment_value = data.get('commitment')
            proof = data.get('proof')
            if not isinstance(proof, dict):
                proof = {}
            a, b, c = proof.get('a'), proof.get('b'), proof.get('c')
            if commitment_value is None or not (a and b and c):
                return jsonify({'success': False,
                                'message': '缺范围证明参数：需要 commitment 与 proof.{a,b,c}'}), 400

            commitment_uint = to_uint(commitment_value)
            if client_digest:
                expected = _hex0x(protocol.range_digest(chain_id, wallet, commitment_uint))
                if str(client_digest).lower() != expected.lower():
                    return jsonify({'success': False, 'message': '签名摘要与后端计算不一致'}), 400

            success = blockchain_service.submit_range_proof_on_chain(
                chain_id, wallet, commitment_uint, a, b, c, signature
            )
        else:
            # 揭晓期：明文由评委本人随请求提交（揭晓本就是公开动作），
            # 服务端先用承诺点做椭圆曲线校验，再代发上链。
            scores = data.get('scores')
            secret = data.get('secret')
            salt = data.get('salt')
            if isinstance(scores, str):
                try:
                    scores = json.loads(scores)
                except json.JSONDecodeError:
                    return jsonify({'success': False, 'message': '分数格式错误'}), 400

            if not isinstance(scores, list) or len(scores) != len(voting['candidates']) or not secret:
                return jsonify({
                    'success': False,
                    'message': '揭晓需提供与承诺一致的 scores（数量等于候选人数）与 secret'
                }), 400
            # salt 是范围证明 Poseidon 承诺的盲化因子，揭晓时上链比对 rangeCommitments
            if salt is None or str(salt).strip() == '':
                return jsonify({'success': False, 'message': '缺少 salt（范围证明盲化因子）'}), 400
            try:
                salt = int(salt)
            except (TypeError, ValueError):
                return jsonify({'success': False, 'message': 'salt 必须是整数'}), 400

            verification = zkp_commitment.verify_commitments(
                [int(s) for s in scores], str(secret), stored_points, voting['max_score']
            )
            if not verification.get('is_valid'):
                return jsonify({'success': False, 'message': '承诺校验失败：分数或密码与承诺阶段不符'}), 400

            expected_hash = _hex0x(protocol.commitment_hash(
                chain_id, wallet, scores, str(secret), voting['max_score']
            ))
            if str(commitment.get('commitment_hash') or '').lower() != expected_hash.lower():
                return jsonify({'success': False, 'message': '承诺哈希不一致'}), 400

            nullifier = protocol.derive_nullifier(chain_id, wallet)

            if client_digest:
                expected = _hex0x(
                    blockchain_service.build_reveal_digest(chain_id, wallet, scores, nullifier)
                )
                if str(client_digest).lower() != expected.lower():
                    return jsonify({'success': False, 'message': '签名摘要与后端计算不一致'}), 400

            success = blockchain_service.reveal_pedersen_scores_on_chain(
                chain_id, wallet, scores, secret, salt, nullifier, signature
            )

        return jsonify({
            'success': bool(success),
            'message': '链上代发成功' if success else '链上代发失败',
            'data': {'action': action, 'blockchain_success': bool(success)}
        }), (200 if success else 400)

    except Exception as e:
        logger.error(f"链上代发错误: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'链上代发失败: {str(e)}'
        }), 500


# 获取投票结果
@voting_bp.route('/<int:voting_id>/results', methods=['GET'])
@auth_required
def get_voting_results(voting_id):
    try:
        from models.voting import Voting
        if not isinstance(voting_id, int) or voting_id < 1 or voting_id > 2147483647:
            return jsonify({
                'success': False,
                'message': 'Voting ID is invalid'
            }), 400
        db_results = Voting.get_voting_results(voting_id)

        voting = Voting.get_voting_by_id(voting_id)
        blockchain_results = None

        if voting and voting.get('blockchain_id') is not None and blockchain_service.is_connected():
            try:
                blockchain_results = blockchain_service.get_voting_results_from_chain(voting['blockchain_id'])
                db_results['blockchain_results'] = blockchain_results
                db_results['results_consistent'] = True
            except Exception as e:
                logger.error(f"Get blockchain results failed: {e}")
                db_results['blockchain_error'] = str(e)

        return jsonify({
            'success': True,
            'data': serialize_dict(db_results)
        })

    except Exception as e:
        logger.error(f"Get voting results error: {e}")
        return jsonify({
            'success': False,
            'message': 'Get voting results failed'
        }), 500


# 获取我的承诺
@voting_bp.route('/<int:voting_id>/commitments/my', methods=['GET'])
@auth_required
def get_my_commitment(voting_id):
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': 'User info failed'
            }), 401

        from models.voting import Voting
        commitment = Voting.get_user_commitment(voting_id, current_user['id'])

        if not commitment:
            return jsonify({
                'success': False,
                'message': 'Commitment record not found'
            }), 404

        return jsonify({
            'success': True,
            'data': serialize_dict(commitment)
        })

    except Exception as e:
        logger.error(f"Get user commitment error: {e}")
        return jsonify({
            'success': False,
            'message': 'Get commitment failed'
        }), 500


# 检查参与权限
@voting_bp.route('/<int:voting_id>/can-participate', methods=['GET'])
@auth_required
def can_participate(voting_id):
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': 'User info failed'
            }), 401

        from models.voting import Voting
        can_participate, message = Voting.can_user_participate(voting_id, current_user['id'])

        return jsonify({
            'success': True,
            'data': {
                'can_participate': can_participate,
                'message': message
            }
        })

    except Exception as e:
        logger.error(f"Check participation permission error: {e}")
        return jsonify({
            'success': False,
            'message': 'Check permission failed'
        }), 500


# 更新投票阶段
# routes/voting.py - 修复 update_voting_phase 函数
@voting_bp.route('/<int:voting_id>/phase', methods=['PUT', 'OPTIONS'])
@auth_required
@role_required(['publisher'])
def update_voting_phase(voting_id):
    # 处理 OPTIONS 预检请求
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        response.headers.add('Access-Control-Allow-Methods', 'PUT, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response

    # PUT 请求处理
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                'success': False,
                'message': '请求体必须是 JSON 对象'
            }), 400
        new_phase = data.get('phase')

        if not new_phase:
            return jsonify({
                'success': False,
                'message': '阶段参数不能为空'
            }), 400

        # 使用数据库定义的阶段 - 修复：接受 'scoring' 而不是 'reveal'
        valid_phases = ['commit', 'scoring', 'completed', 'cancelled']
        if new_phase not in valid_phases:
            return jsonify({
                'success': False,
                'message': f'阶段必须是: {", ".join(valid_phases)}'
            }), 400

        from models.voting import Voting
        voting = Voting.get_voting_by_id(voting_id)

        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        if voting['creator_id'] != current_user['id']:
            return jsonify({
                'success': False,
                'message': '只有投票创建者可以更新阶段'
            }), 403

        # 检查阶段转换是否有效
        current_phase = voting['phase']
        valid_transitions = {
            'commit': ['scoring', 'cancelled'],
            'scoring': ['completed', 'cancelled'],
            'completed': [],
            'cancelled': []
        }

        if new_phase not in valid_transitions.get(current_phase, []):
            return jsonify({
                'success': False,
                'message': f'无法从 {current_phase} 阶段转换到 {new_phase} 阶段'
            }), 400

        # 更新阶段
        db.execute_query(
            "UPDATE voting_sessions SET phase = ?, updated_at = GETDATE() WHERE id = ?",
            (new_phase, voting_id)
        )

        # —— DB -> 链 单向同步：阶段推送 + 进入 completed 时触发链上结算 ——
        chain_sync = {'attempted': False, 'success': False}
        if voting.get('blockchain_id') is not None and blockchain_service.is_connected():
            chain_id = voting['blockchain_id']
            chain_sync = {'attempted': True, 'success': False}
            if new_phase == 'completed':
                # 结算须在 scoring 阶段调用，且合约内部会自行把阶段置为 3；
                # 因此不能先推送数字阶段，否则 calculateResults 会因阶段不符而回滚
                results = blockchain_service.calculate_results_on_chain(chain_id)
                chain_sync['results'] = results
                chain_sync['success'] = results is not None
            elif new_phase == 'cancelled':
                chain_sync['ended'] = blockchain_service.end_voting_on_chain(chain_id)
                chain_sync['success'] = bool(chain_sync['ended'])
            else:
                # commit -> scoring：推送数字阶段
                chain_sync['success'] = blockchain_service.update_voting_phase_on_chain(
                    chain_id, _numeric_phase(new_phase)
                )

        # 获取更新后的投票信息
        updated_voting = Voting.get_voting_by_id(voting_id)

        logger.info(f"投票 {voting_id} 阶段已更新: {current_phase} -> {new_phase}")

        return jsonify({
            'success': True,
            'message': f'投票阶段已更新为 {new_phase}',
            'data': {
                'phase': new_phase,
                'chain_sync': chain_sync,
                'voting': serialize_dict(updated_voting)
            }
        })

    except Exception as e:
        logger.error(f"更新投票阶段错误: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'更新阶段失败: {str(e)}'
        }), 500


# 删除投票活动 - 新增DELETE方法
@voting_bp.route('/<int:voting_id>', methods=['DELETE', 'OPTIONS'])
@auth_required
@role_required(['publisher'])
def delete_voting(voting_id):
    """删除投票活动"""
    # 处理 OPTIONS 预检请求
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'preflight'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3001')
        response.headers.add('Access-Control-Allow-Methods', 'DELETE, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response

    # DELETE 请求处理
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        logger.info(f"🗑️ 删除投票请求 - VotingID: {voting_id}, UserID: {current_user['id']}")

        # 首先检查投票是否存在
        from models.voting import Voting
        voting = Voting.get_voting_by_id(voting_id)

        if not voting:
            logger.error(f"投票活动不存在: {voting_id}")
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        # 检查用户是否是创建者
        if voting['creator_id'] != current_user['id']:
            logger.warning(f"用户无权删除: User{current_user['id']} 不是投票{voting_id}的创建者")
            return jsonify({
                'success': False,
                'message': '只有投票的创建者可以删除此活动'
            }), 403

        # 检查投票状态 - 只能删除未开始或已结束的投票
        if voting['phase'] not in ['commit', 'completed', 'cancelled']:
            logger.warning(f"投票状态不允许删除: 当前阶段{voting['phase']}")
            return jsonify({
                'success': False,
                'message': '进行中的投票无法删除，请先结束投票'
            }), 400

        # 执行删除操作 - 使用事务确保数据一致性
        try:
            # 1. 删除承诺记录
            db.execute_query(
                "DELETE FROM voting_commitments WHERE voting_id = ?",
                (voting_id,)
            )
            logger.info(f"删除承诺记录: voting_id={voting_id}")

            # 2. 删除评分记录
            db.execute_query(
                "DELETE FROM voting_scores WHERE voting_id = ?",
                (voting_id,)
            )
            logger.info(f"删除评分记录: voting_id={voting_id}")

            # 3. 删除投票者记录
            db.execute_query(
                "DELETE FROM voting_voters WHERE voting_id = ?",
                (voting_id,)
            )
            logger.info(f"删除投票者记录: voting_id={voting_id}")

            # 4. 删除候选人记录
            db.execute_query(
                "DELETE FROM candidates WHERE voting_id = ?",
                (voting_id,)
            )
            logger.info(f"删除候选人记录: voting_id={voting_id}")

            # 5. 删除投票活动记录
            db.execute_query(
                "DELETE FROM voting_sessions WHERE id = ?",
                (voting_id,)
            )
            logger.info(f"删除投票活动记录: id={voting_id}")

            # 记录删除成功
            logger.info(f"✅ 投票{voting_id}删除成功，所有相关数据已清理")

            return jsonify({
                'success': True,
                'message': '投票活动删除成功',
                'data': {
                    'voting_id': voting_id,
                    'title': voting['title'],
                    'deleted_at': datetime.now().isoformat()
                }
            })

        except Exception as db_error:
            logger.error(f"数据库删除操作失败: {db_error}", exc_info=True)
            return jsonify({
                'success': False,
                'message': f'数据库删除失败: {str(db_error)}'
            }), 500

    except Exception as e:
        logger.error(f"删除投票错误: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'删除投票失败: {str(e)}'
        }), 500