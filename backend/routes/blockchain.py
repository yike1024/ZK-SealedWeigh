# -*- coding: utf-8 -*-
from flask import Blueprint, request, jsonify, g
from utils.auth import auth_required, role_required, get_current_user
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
blockchain_bp = Blueprint('blockchain', __name__)

def get_blockchain_service():
    from services.blockchain import blockchain_service
    return blockchain_service

@blockchain_bp.route('/test-connection', methods=['GET'])
@auth_required
def test_blockchain_connection():
    """测试区块链连接"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        from services.blockchain import blockchain_service

        connected = blockchain_service.is_connected()
        network_info = blockchain_service.get_network_info() if connected else {}

        return jsonify({
            'success': True,
            'data': {
                'connected': connected,
                'network_info': network_info,
                'contract_address': blockchain_service.contract_address if connected else None,
                'account_address': blockchain_service.account.address if connected else None
            }
        })
    except Exception as e:
        logger.error(f"测试区块链连接失败: {e}")
        return jsonify({
            'success': False,
            'message': f'测试区块链连接失败: {str(e)}'
        }), 500


@blockchain_bp.route('/test', methods=['GET'])
@auth_required
def test_connection_simple():
    """简单的区块链连接测试"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        from services.blockchain import blockchain_service

        return jsonify({
            'success': True,
            'data': {
                'connected': blockchain_service.is_connected(),
                'message': '区块链服务正常' if blockchain_service.is_connected() else '区块链未连接'
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'区块链服务异常: {str(e)}'
        }), 500


@blockchain_bp.route('/status', methods=['GET'])
@auth_required
def blockchain_status():
    """区块链状态检查"""
    try:
        blockchain_service = get_blockchain_service()
        return jsonify({
            'success': True,
            'data': {
                'connected': blockchain_service.is_connected(),
                'message': '区块链服务正常' if blockchain_service.is_connected() else '区块链未连接'
            }
        })
    except Exception as e:
        logger.error(f"区块链状态检查失败: {e}")
        return jsonify({
            'success': False,
            'message': f'区块链服务异常: {str(e)}'
        }), 500


@blockchain_bp.route('/voting/<int:voting_id>/status', methods=['GET'])
@auth_required
def get_voting_blockchain_status(voting_id):
    """获取指定投票的区块链状态"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        if not isinstance(voting_id, int) or voting_id < 1 or voting_id > 2147483647:
            return jsonify({
                'success': False,
                'message': '投票活动 ID 不合法'
            }), 400

        from services.blockchain import blockchain_service

        if not blockchain_service.is_connected():
            return jsonify({
                'success': False,
                'message': '区块链未连接'
            }), 500

        # 获取投票信息
        from database import db
        voting = db.execute_query(
            "SELECT blockchain_id FROM voting_sessions WHERE id = ?",
            (voting_id,)
        )

        if not voting or not voting[0].get('blockchain_id'):
            return jsonify({
                'success': False,
                'message': '投票未在区块链上创建'
            }), 404

        blockchain_id = voting[0]['blockchain_id']
        info = blockchain_service.get_voting_info(blockchain_id)

        return jsonify({
            'success': True,
            'data': info
        })
    except Exception as e:
        logger.error(f"获取投票区块链状态失败: {e}")
        return jsonify({
            'success': False,
            'message': f'获取状态失败: {str(e)}'
        }), 500


@blockchain_bp.route('/voting/<int:voting_id>/info', methods=['GET'])
@auth_required
def get_voting_info(voting_id):
    """获取投票信息"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        if not isinstance(voting_id, int) or voting_id < 0 or voting_id > 2147483647:
            return jsonify({
                'success': False,
                'message': '链上活动 ID 不合法'
            }), 400

        from services.blockchain import blockchain_service

        if not blockchain_service.is_connected():
            return jsonify({
                'success': False,
                'message': '区块链未连接'
            }), 500

        info = blockchain_service.get_voting_info(voting_id)

        return jsonify({
            'success': True,
            'data': info
        })
    except Exception as e:
        logger.error(f"获取投票信息失败: {e}")
        return jsonify({
            'success': False,
            'message': f'获取信息失败: {str(e)}'
        }), 500


@blockchain_bp.route('/create-test-voting', methods=['POST'])
@auth_required
@role_required(['publisher'])
def create_test_blockchain_voting():
    """创建测试区块链投票"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        from services.blockchain import blockchain_service

        test_data = {
            'title': '区块链测试投票',
            'description': '测试区块链功能集成',
            'max_score': 10,
            'commit_duration': 3600,
            'score_duration': 7200,
            'candidates': ['区块链候选A', '区块链候选B'],
            'voters': [{'wallet_address': blockchain_service.account.address,
                        'weight': 1.0}] if blockchain_service.is_connected() else [],
        }

        voting_id = blockchain_service.create_voting_on_chain(test_data)

        return jsonify({
            'success': True,
            'data': {
                'blockchain_voting_id': voting_id,
                'test_data': test_data
            }
        })
    except Exception as e:
        logger.error(f"创建测试投票失败: {e}")
        return jsonify({
            'success': False,
            'message': f'创建测试投票失败: {str(e)}'
        }), 500


@blockchain_bp.route('/submit-commitment', methods=['POST'])
@auth_required
def submit_commitment_blockchain():
    """在区块链上提交承诺"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        from services.blockchain import blockchain_service
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                'success': False,
                'message': '请求体必须是 JSON 对象'
            }), 400

        voting_id = data.get('voting_id')
        voter_address = data.get('voter_address')
        overall_hash = data.get('overall_hash') or data.get('commitment_hash')
        score_commitments = data.get('score_commitments', [])
        merkle_proof = data.get('merkle_proof', [])
        signature = data.get('signature')

        if not all([voting_id, voter_address, overall_hash, signature]):
            return jsonify({
                'success': False,
                'message': '缺少必要参数（voting_id / voter_address / overall_hash / signature）'
            }), 400

        success = blockchain_service.submit_pedersen_commitment_on_chain(
            voting_id, voter_address, overall_hash, score_commitments, merkle_proof, signature
        )

        return jsonify({
            'success': success,
            'message': '区块链承诺提交成功' if success else '区块链承诺提交失败'
        })

    except Exception as e:
        logger.error(f"区块链承诺提交失败: {e}")
        return jsonify({
            'success': False,
            'message': f'区块链承诺提交失败: {str(e)}'
        }), 500


@blockchain_bp.route('/reveal-scores', methods=['POST'])
@auth_required
def reveal_scores_blockchain():
    """在区块链上揭示评分"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        from services.blockchain import blockchain_service
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                'success': False,
                'message': '请求体必须是 JSON 对象'
            }), 400

        voting_id = data.get('voting_id')
        voter_address = data.get('voter_address')
        scores = data.get('scores', [])
        secret = data.get('secret', '')
        nullifier = data.get('nullifier', '')
        signature = data.get('signature')

        if not all([voting_id, voter_address, scores, signature]):
            return jsonify({
                'success': False,
                'message': '缺少必要参数（voting_id / voter_address / scores / signature）'
            }), 400

        success = blockchain_service.reveal_pedersen_scores_on_chain(
            voting_id, voter_address, scores, secret, nullifier, signature
        )

        return jsonify({
            'success': success,
            'message': '区块链评分揭示成功' if success else '区块链评分揭示失败'
        })

    except Exception as e:
        logger.error(f"区块链评分揭示失败: {e}")
        return jsonify({
            'success': False,
            'message': f'区块链评分揭示失败: {str(e)}'
        }), 500


@blockchain_bp.route('/network-info', methods=['GET'])
@auth_required
def get_network_info():
    """获取网络信息"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        from services.blockchain import blockchain_service

        network_info = blockchain_service.get_network_info()

        return jsonify({
            'success': True,
            'data': network_info
        })
    except Exception as e:
        logger.error(f"获取网络信息失败: {e}")
        return jsonify({
            'success': False,
            'message': f'获取网络信息失败: {str(e)}'
        }), 500


@blockchain_bp.route('/health', methods=['GET'])
def blockchain_health():
    """区块链健康检查"""
    try:
        from services.blockchain import blockchain_service

        connected = blockchain_service.is_connected()
        status = {
            'blockchain_connected': connected,
            'service': 'blockchain-api',
            'timestamp': datetime.now().isoformat()
        }

        if connected:
            network_info = blockchain_service.get_network_info()
            status.update(network_info)

        return jsonify({
            'success': True,
            'data': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'区块链健康检查失败: {str(e)}'
        }), 500