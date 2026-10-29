# -*- coding: utf-8 -*-
from flask import Blueprint, request, jsonify, g
from models.voting import Voting
from models.user import User
from utils.auth import auth_required, role_required, get_current_user
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

scores_bp = Blueprint('scores', __name__)

@scores_bp.route('/', methods=['POST'])
@auth_required
def submit_score():
    """提交评分"""
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

        required_fields = ['voting_id', 'candidate_id', 'score']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'请提供{field}字段'
                }), 400

        voting_id = data['voting_id']

        # 验证用户是否有权参与此投票
        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        is_voter = any(v['id'] == current_user['id'] for v in voting['voters'])

        if not is_voter:
            return jsonify({
                'success': False,
                'message': '您无权参与此投票活动'
            }), 403

        if voting['phase'] != 'scoring':
            return jsonify({
                'success': False,
                'message': '当前不是评分阶段'
            }), 400

        # 验证用户是否已提交承诺
        has_commitment = any(
            c['voter_id'] == current_user['id'] for c in voting['commitments']
        )

        if not has_commitment:
            return jsonify({
                'success': False,
                'message': '请先提交承诺'
            }), 400

        # 验证分数范围
        score_value = data['score']
        if score_value < 0 or score_value > voting['max_score']:
            return jsonify({
                'success': False,
                'message': f'分数必须在 0-{voting["max_score"]} 之间'
            }), 400

        # 获取用户权重
        voter_weight = 1.0
        for voter in voting['voters']:
            if voter['id'] == current_user['id']:
                voter_weight = voter['weight']
                break

        # 检查是否已经对该候选人评过分
        existing_score = next(
            (s for s in voting['scores']
             if s['voter_id'] == current_user['id'] and s['candidate_id'] == data['candidate_id']),
            None
        )

        if existing_score:
            return jsonify({
                'success': False,
                'message': '您已经对该候选人评过分了'
            }), 400

        score_data = {
            'voting_id': voting_id,
            'voter_id': current_user['id'],
            'candidate_id': data['candidate_id'],
            'score': score_value,
            'weight': voter_weight
        }

        score_id = Voting.submit_score(score_data)

        return jsonify({
            'success': True,
            'message': '评分提交成功',
            'data': {'score_id': score_id}
        }), 201

    except Exception as e:
        logger.error(f"提交评分错误: {e}")
        return jsonify({
            'success': False,
            'message': '提交评分失败'
        }), 500

@scores_bp.route('/batch', methods=['POST'])
@auth_required
def submit_batch_scores():
    """批量提交评分"""
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

        if not data.get('voting_id') or not data.get('scores'):
            return jsonify({
                'success': False,
                'message': '请提供投票ID和分数列表'
            }), 400

        voting_id = data['voting_id']
        scores_list = data['scores']

        if not isinstance(scores_list, list):
            return jsonify({
                'success': False,
                'message': '分数列表必须是数组'
            }), 400

        # 验证用户是否有权参与此投票
        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        is_voter = any(v['id'] == current_user['id'] for v in voting['voters'])

        if not is_voter:
            return jsonify({
                'success': False,
                'message': '您无权参与此投票活动'
            }), 403

        if voting['phase'] != 'scoring':
            return jsonify({
                'success': False,
                'message': '当前不是评分阶段'
            }), 400

        # 验证用户是否已提交承诺
        has_commitment = any(
            c['voter_id'] == current_user['id'] for c in voting['commitments']
        )

        if not has_commitment:
            return jsonify({
                'success': False,
                'message': '请先提交承诺'
            }), 400

        # 获取用户权重
        voter_weight = 1.0
        for voter in voting['voters']:
            if voter['id'] == current_user['id']:
                voter_weight = voter['weight']
                break

        # 验证所有分数
        for score_item in scores_list:
            if not isinstance(score_item, dict):
                return jsonify({
                    'success': False,
                    'message': '分数数据格式错误'
                }), 400
            if not score_item.get('candidate_id') or not score_item.get('score'):
                return jsonify({
                    'success': False,
                    'message': '分数数据格式错误'
                }), 400

            score_value = score_item['score']
            if score_value < 0 or score_value > voting['max_score']:
                return jsonify({
                    'success': False,
                    'message': f'分数必须在 0-{voting["max_score"]} 之间'
                }), 400

        # 提交所有分数
        score_ids = []
        for score_item in scores_list:
            score_data = {
                'voting_id': voting_id,
                'voter_id': current_user['id'],
                'candidate_id': score_item['candidate_id'],
                'score': score_item['score'],
                'weight': voter_weight
            }

            score_id = Voting.submit_score(score_data)
            score_ids.append(score_id)

        return jsonify({
            'success': True,
            'message': '批量评分提交成功',
            'data': {'score_ids': score_ids}
        }), 201

    except Exception as e:
        logger.error(f"批量提交评分错误: {e}")
        return jsonify({
            'success': False,
            'message': '批量提交评分失败'
        }), 500


# v2 起移除「发布者/relayer 代他人揭晓」路径（spec.md G6 / 第 9 节 R-5）。
# 缺失分数只能由该评委本人重新揭晓；阈值托管恢复留待 P3（Shamir k-of-n）。
@scores_bp.route('/recover', methods=['POST'])
@auth_required
@role_required(['publisher'])
def recover_missing_scores():
    """已停用：不存在任何单方可代他人写入分数的接口"""
    return jsonify({
        'success': False,
        'message': '该接口已于协议 v2 停用：缺失评分只能由评委本人重新揭晓，系统不提供代填入口',
        'code': 'RECOVERY_REMOVED'
    }), 410


@scores_bp.route('/voting/<int:voting_id>/voter/<int:voter_id>', methods=['GET'])
@auth_required
def get_voter_scores(voting_id, voter_id):
    """获取指定投票者在指定投票中的评分"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        # 验证权限：只能查看自己的评分或发布者查看所有评分
        if current_user['id'] != voter_id and current_user['role'] != 'publisher':
            return jsonify({
                'success': False,
                'message': '权限不足'
            }), 403

        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        # 获取该投票者的评分
        voter_scores = [
            score for score in voting['scores']
            if score['voter_id'] == voter_id
        ]

        return jsonify({
            'success': True,
            'data': {
                'voting_id': voting_id,
                'voter_id': voter_id,
                'scores': voter_scores
            }
        })

    except Exception as e:
        logger.error(f"获取投票者评分错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取评分失败'
        }), 500

@scores_bp.route('/voting/<int:voting_id>', methods=['GET'])
@auth_required
def get_voting_scores(voting_id):
    """获取指定投票的所有评分"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        # 验证权限：发布者可以查看所有评分，投票者只能查看自己的
        if current_user['role'] != 'publisher':
            # 过滤出当前用户的评分
            user_scores = [
                score for score in voting['scores']
                if score['voter_id'] == current_user['id']
            ]
            scores_data = user_scores
        else:
            scores_data = voting['scores']

        return jsonify({
            'success': True,
            'data': {
                'voting_id': voting_id,
                'scores': scores_data
            }
        })

    except Exception as e:
        logger.error(f"获取投票评分错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取评分失败'
        }), 500

@scores_bp.route('/analysis/<int:voting_id>', methods=['GET'])
@auth_required
def get_score_analysis(voting_id):
    """获取评分分析"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        voting = Voting.get_voting_by_id(voting_id)
        if not voting:
            return jsonify({
                'success': False,
                'message': '投票活动不存在'
            }), 404

        # 计算统计信息
        scores_by_candidate = {}
        for candidate in voting['candidates']:
            candidate_scores = [
                score for score in voting['scores']
                if score['candidate_id'] == candidate['id']
            ]

            if candidate_scores:
                total_score = sum(score['score'] * score['weight'] for score in candidate_scores)
                avg_score = total_score / len(candidate_scores)
                max_score = max(score['score'] for score in candidate_scores)
                min_score = min(score['score'] for score in candidate_scores)
            else:
                total_score = avg_score = max_score = min_score = 0

            scores_by_candidate[candidate['id']] = {
                'candidate_name': candidate['name'],
                'total_score': total_score,
                'average_score': round(avg_score, 2),
                'max_score': max_score,
                'min_score': min_score,
                'vote_count': len(candidate_scores)
            }

        # 计算总体统计
        all_scores = [score['score'] for score in voting['scores']]
        overall_stats = {
            'total_votes': len(voting['scores']),
            'unique_voters': len(set(score['voter_id'] for score in voting['scores'])),
            'average_score': round(sum(all_scores) / len(all_scores), 2) if all_scores else 0,
            'max_score': max(all_scores) if all_scores else 0,
            'min_score': min(all_scores) if all_scores else 0
        }

        return jsonify({
            'success': True,
            'data': {
                'voting_id': voting_id,
                'overall_stats': overall_stats,
                'candidate_stats': scores_by_candidate
            }
        })

    except Exception as e:
        logger.error(f"获取评分分析错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取评分分析失败'
        }), 500