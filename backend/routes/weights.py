# -*- coding: utf-8 -*-
from flask import Blueprint, request, jsonify, g
from models.voting import Voting
from utils.auth import auth_required, role_required, get_current_user
import logging

logger = logging.getLogger(__name__)

weights_bp = Blueprint('weights', __name__)

# 权重仅在承诺阶段可修改；进入评分阶段后冻结（spec.md R-6）
WEIGHT_EDITABLE_PHASES = ('commit',)


def _weight_frozen_response(voting):
    """权重已冻结时返回统一错误响应"""
    return jsonify({
        'success': False,
        'message': f'权重已冻结：当前阶段为「{voting.get("phase")}」，仅承诺阶段可修改权重'
    }), 409


@weights_bp.route('/voting/<int:voting_id>/weights', methods=['GET'])
@auth_required
def get_voting_weights(voting_id):
    """获取投票活动的权重信息"""
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

        voting = Voting.get_voting_with_weights(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        # 验证权限：只有发布者可以查看详细权重信息
        if current_user['role'] != 'publisher' and voting['creator_id'] != current_user['id']:
            return jsonify({
                'success': False,
                'message': '权限不足'
            }), 403

        return jsonify({
            'success': True,
            'data': voting
        })

    except Exception as e:
        logger.error(f"获取投票权重信息错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取权重信息失败'
        }), 500


@weights_bp.route('/voting/<int:voting_id>/voter/<int:voter_id>', methods=['PUT'])
@auth_required
@role_required(['publisher'])
def update_voter_weight(voting_id, voter_id):
    """更新投票者权重"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        data = request.get_json(silent=True)

        if not isinstance(data, dict) or not data.get('weight'):
            return jsonify({
                'success': False,
                'message': '请提供权重值'
            }), 400

        try:
            weight = float(data['weight'])
        except (TypeError, ValueError):
            return jsonify({
                'success': False,
                'message': '权重值格式错误'
            }), 400

        if weight < 0:
            return jsonify({
                'success': False,
                'message': '权重值不能为负数'
            }), 400

        # 验证投票活动存在且当前用户是创建者
        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        if voting['creator_id'] != current_user['id']:
            return jsonify({
                'success': False,
                'message': '只能修改自己创建的投票活动的权重'
            }), 403

        # 阶段校验：评分阶段开始后权重冻结，否则可用改权重影响已提交的分数
        if voting.get('phase') not in WEIGHT_EDITABLE_PHASES:
            return _weight_frozen_response(voting)

        # 验证投票者存在于此投票中
        is_voter = any(v['id'] == voter_id for v in voting['voters'])
        if not is_voter:
            return jsonify({
                'success': False,
                'message': '投票者不存在于此投票活动中'
            }), 404

        # 更新权重
        success = Voting.update_voter_weight(voting_id, voter_id, weight)

        if success:
            return jsonify({
                'success': True,
                'message': '权重更新成功'
            })
        else:
            return jsonify({
                'success': False,
                'message': '权重更新失败'
            }), 500

    except ValueError as e:
        return jsonify({
            'success': False,
            'message': '权重值格式错误'
        }), 400
    except Exception as e:
        logger.error(f"更新投票者权重错误: {e}")
        return jsonify({
            'success': False,
            'message': '更新权重失败'
        }), 500


@weights_bp.route('/voting/<int:voting_id>/batch-weights', methods=['PUT'])
@auth_required
@role_required(['publisher'])
def update_batch_weights(voting_id):
    """批量更新投票者权重"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        data = request.get_json(silent=True)

        if (not isinstance(data, dict) or not data.get('updates')
                or not isinstance(data['updates'], list)):
            return jsonify({
                'success': False,
                'message': '请提供权重更新列表'
            }), 400

        # 验证投票活动存在且当前用户是创建者
        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        if voting['creator_id'] != current_user['id']:
            return jsonify({
                'success': False,
                'message': '只能修改自己创建的投票活动的权重'
            }), 403

        # 阶段校验：评分阶段开始后权重冻结（同单条更新）
        if voting.get('phase') not in WEIGHT_EDITABLE_PHASES:
            return _weight_frozen_response(voting)

        # 验证所有更新数据
        for update in data['updates']:
            if not isinstance(update, dict):
                return jsonify({
                    'success': False,
                    'message': '权重更新数据格式错误'
                }), 400
            if not update.get('voter_id') or not update.get('weight'):
                return jsonify({
                    'success': False,
                    'message': '权重更新数据格式错误'
                }), 400

            try:
                weight = float(update['weight'])
            except (TypeError, ValueError):
                return jsonify({
                    'success': False,
                    'message': '权重值格式错误'
                }), 400
            if weight < 0:
                return jsonify({
                    'success': False,
                    'message': f'投票者 {update["voter_id"]} 的权重值不能为负数'
                }), 400

            # 验证投票者存在
            voter_id = update['voter_id']
            is_voter = any(v['id'] == voter_id for v in voting['voters'])
            if not is_voter:
                return jsonify({
                    'success': False,
                    'message': f'投票者 {voter_id} 不存在于此投票活动中'
                }), 404

        # 批量更新权重
        success_count = 0
        for update in data['updates']:
            try:
                success = Voting.update_voter_weight(
                    voting_id,
                    update['voter_id'],
                    float(update['weight'])
                )
                if success:
                    success_count += 1
            except Exception as e:
                logger.error(f"更新投票者 {update['voter_id']} 权重失败: {e}")

        return jsonify({
            'success': True,
            'message': f'批量更新完成，成功更新 {success_count}/{len(data["updates"])} 个投票者权重',
            'data': {
                'total': len(data['updates']),
                'success': success_count,
                'failed': len(data['updates']) - success_count
            }
        })

    except ValueError as e:
        return jsonify({
            'success': False,
            'message': '权重值格式错误'
        }), 400
    except Exception as e:
        logger.error(f"批量更新权重错误: {e}")
        return jsonify({
            'success': False,
            'message': '批量更新权重失败'
        }), 500


@weights_bp.route('/voting/<int:voting_id>/weight-stats', methods=['GET'])
@auth_required
def get_weight_statistics(voting_id):
    """获取权重统计信息"""
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

        voting = Voting.get_voting_with_weights(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        # 验证权限：发布者或参与此投票的投票者
        is_creator = voting['creator_id'] == current_user['id']
        is_voter = any(v['id'] == current_user['id'] for v in voting.get('voters', []))

        if not is_creator and not is_voter:
            return jsonify({
                'success': False,
                'message': '权限不足'
            }), 403

        # 计算权重统计
        voters = voting.get('voters', [])
        total_voters = len(voters)
        total_weight = sum(v.get('weight', 1.0) for v in voters)
        avg_weight = total_weight / total_voters if total_voters > 0 else 0
        max_weight = max((v.get('weight', 1.0) for v in voters), default=0)
        min_weight = min((v.get('weight', 1.0) for v in voters), default=0)

        # 获取当前用户的权重
        user_weight = next(
            (v.get('weight', 1.0) for v in voters if v['id'] == current_user['id']),
            1.0
        )

        stats = {
            'total_voters': total_voters,
            'total_weight': total_weight,
            'average_weight': round(avg_weight, 2),
            'max_weight': max_weight,
            'min_weight': min_weight,
            'user_weight': user_weight,
            'weight_type': voting.get('weight_type', 'equal')
        }

        return jsonify({
            'success': True,
            'data': stats
        })

    except Exception as e:
        logger.error(f"获取权重统计错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取权重统计失败'
        }), 500