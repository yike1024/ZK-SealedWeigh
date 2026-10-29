# -*- coding: utf-8 -*-
import json
from database import db
import logging

logger = logging.getLogger(__name__)


class Voting:
    @staticmethod
    def create_voting(voting_data):
        """创建投票活动 - 支持自定义权重"""
        try:
            logger.info(f"开始创建投票活动: {voting_data['title']}")

            # 1. 先插入投票活动
            voting_id = db.execute_query(
                """INSERT INTO voting_sessions 
                   (title, description, creator_id, max_score, weight_type, commit_duration, 
                    score_duration, enable_zk_proof, scoring_rules, phase, created_at)
                   OUTPUT INSERTED.id
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'commit', GETDATE())""",
                (
                    voting_data['title'],
                    voting_data['description'],
                    voting_data['creator_id'],
                    voting_data['max_score'],
                    voting_data['weight_type'],
                    voting_data['commit_duration'],
                    voting_data['score_duration'],
                    voting_data['enable_zk_proof'],
                    voting_data['scoring_rules']
                )
            )

            if not voting_id:
                # 如果无法获取ID，尝试查询最后插入的记录
                result = db.execute_query(
                    "SELECT TOP 1 id FROM voting_sessions WHERE creator_id = ? ORDER BY created_at DESC",
                    (voting_data['creator_id'],)
                )
                if result:
                    voting_id = result[0]['id']
                else:
                    raise ValueError("无法获取投票活动ID")

            logger.info(f"投票活动创建成功，ID: {voting_id}")

            # 2. 插入候选人
            candidates = voting_data['candidates']
            logger.info(f"准备插入候选人: {candidates}")

            # 去重并保留顺序
            unique_candidates = []
            seen = set()
            for candidate in candidates:
                candidate_clean = candidate.strip()
                if candidate_clean and candidate_clean not in seen:
                    unique_candidates.append(candidate_clean)
                    seen.add(candidate_clean)

            for index, candidate_name in enumerate(unique_candidates):
                db.execute_query(
                    "INSERT INTO candidates (voting_id, name, order_index, created_at) VALUES (?, ?, ?, GETDATE())",
                    (voting_id, candidate_name, index)
                )

            # 3. 插入投票者并设置权重 - 支持自定义权重
            voters_data = voting_data.get('voters', [])
            logger.info(f"准备插入投票者数据: {voters_data}")

            # 处理投票者数据
            for voter_info in voters_data:
                if isinstance(voter_info, dict):
                    username = voter_info.get('username', '').strip()
                    weight = float(voter_info.get('weight', 1.0))
                else:
                    username = str(voter_info).strip()
                    weight = 1.0

                if not username:
                    continue

                user_result = db.execute_query(
                    "SELECT id FROM users WHERE username = ?", (username,)
                )

                if not user_result:
                    logger.warning(f"用户 {username} 不存在，跳过")
                    continue

                voter_id = user_result[0]['id']

                db.execute_query(
                    """MERGE INTO voting_voters AS target
                       USING (SELECT ? AS voting_id, ? AS voter_id, ? AS weight) AS source
                       ON target.voting_id = source.voting_id AND target.voter_id = source.voter_id
                       WHEN NOT MATCHED THEN
                           INSERT (voting_id, voter_id, weight, created_at)
                           VALUES (source.voting_id, source.voter_id, source.weight, GETDATE())
                       WHEN MATCHED THEN
                           UPDATE SET weight = source.weight, created_at = GETDATE();""",
                    (voting_id, voter_id, weight)
                )
                logger.info(f"成功添加投票者: {username}, 权重: {weight}")

            logger.info("投票活动数据插入完成")
            return Voting.get_voting_by_id(voting_id)

        except Exception as e:
            logger.error(f"创建投票活动错误: {e}", exc_info=True)
            raise

    @staticmethod
    def _calculate_individual_weight(username, weight_type):
        """计算单个投票者的权重 - 简化版本"""
        if weight_type == 'equal':
            return 1.0
        elif weight_type == 'custom':
            # 自定义权重：需要后续手动设置
            return 1.0
        else:
            return 1.0

    @staticmethod
    def update_voter_weight(voting_id, voter_id, new_weight):
        """更新投票者权重"""
        try:
            db.execute_query(
                "UPDATE voting_voters SET weight = ?, updated_at = GETDATE() WHERE voting_id = ? AND voter_id = ?",
                (new_weight, voting_id, voter_id)
            )

            # 更新已提交的评分权重
            db.execute_query(
                "UPDATE voting_scores SET weight = ? WHERE voting_id = ? AND voter_id = ?",
                (new_weight, voting_id, voter_id)
            )

            logger.info(f"更新投票者权重成功: voting_id={voting_id}, voter_id={voter_id}, weight={new_weight}")
            return True

        except Exception as e:
            logger.error(f"更新投票者权重错误: {e}")
            return False

    @staticmethod
    def get_voting_with_weights(voting_id):
        """获取投票活动详情（包含权重信息）"""
        try:
            voting = Voting.get_voting_by_id(voting_id)
            if not voting:
                return None

            # 获取详细的权重统计
            weight_stats = db.execute_query(
                """SELECT 
                      COUNT(*) as total_voters,
                      AVG(weight) as avg_weight,
                      MIN(weight) as min_weight,
                      MAX(weight) as max_weight,
                      SUM(weight) as total_weight
                   FROM voting_voters 
                   WHERE voting_id = ?""",
                (voting_id,)
            )

            voting['weight_statistics'] = weight_stats[0] if weight_stats else {}
            return voting

        except Exception as e:
            logger.error(f"获取投票权重信息错误: {e}")
            return None

    @staticmethod
    def submit_score(score_data):
        """提交评分 - 支持加权计算"""
        try:
            # 检查是否已经评过分
            existing_score = db.execute_query(
                """SELECT id FROM voting_scores 
                   WHERE voting_id = ? AND voter_id = ? AND candidate_id = ?""",
                (score_data['voting_id'], score_data['voter_id'], score_data['candidate_id'])
            )

            # 获取投票者当前权重
            voter_weight_result = db.execute_query(
                "SELECT weight FROM voting_voters WHERE voting_id = ? AND voter_id = ?",
                (score_data['voting_id'], score_data['voter_id'])
            )

            weight = voter_weight_result[0]['weight'] if voter_weight_result else 1.0

            if existing_score:
                # 更新现有评分
                db.execute_query(
                    """UPDATE voting_scores 
                       SET score = ?, weight = ?, created_at = GETDATE()
                       WHERE id = ?""",
                    (score_data['score'], weight, existing_score[0]['id'])
                )
                return existing_score[0]['id']
            else:
                # 插入新评分（包含权重）
                score_id = db.execute_query(
                    """INSERT INTO voting_scores 
                       (voting_id, voter_id, candidate_id, score, weight, created_at)
                       OUTPUT INSERTED.id
                       VALUES (?, ?, ?, ?, ?, GETDATE())""",
                    (
                        score_data['voting_id'],
                        score_data['voter_id'],
                        score_data['candidate_id'],
                        score_data['score'],
                        weight
                    )
                )
                return score_id

        except Exception as e:
            logger.error(f"提交评分错误: {e}")
            raise

    @staticmethod
    def get_weighted_results(voting_id):
        """获取加权评分结果 - 修复版本"""
        try:
            # 获取加权后的候选人得分
            candidate_scores = db.execute_query(
                """SELECT 
                       c.id,
                       c.name,
                       SUM(vs.score * vs.weight) as weighted_total_score,
                       CASE 
                           WHEN SUM(vs.weight) > 0 THEN SUM(vs.score * vs.weight) / SUM(vs.weight)
                           ELSE 0 
                       END as weighted_avg_score,
                       COUNT(vs.id) as vote_count,
                       SUM(vs.weight) as total_weight,
                       AVG(vs.score) as simple_avg_score  -- 简单平均分用于对比
                   FROM candidates c
                   LEFT JOIN voting_scores vs ON c.id = vs.candidate_id
                   WHERE c.voting_id = ?
                   GROUP BY c.id, c.name
                   ORDER BY weighted_avg_score DESC""",
                (voting_id,)
            )

            # 获取详细评分统计
            score_details = db.execute_query(
                """SELECT 
                       c.name as candidate_name,
                       u.username as voter_name,
                       vs.score,
                       vs.weight,
                       vs.score * vs.weight as weighted_score,
                       vs.created_at
                   FROM voting_scores vs
                   JOIN candidates c ON vs.candidate_id = c.id
                   JOIN users u ON vs.voter_id = u.id
                   WHERE vs.voting_id = ?
                   ORDER BY c.name, vs.weight DESC""",
                (voting_id,)
            )

            # 获取投票统计
            stats = db.execute_query(
                """SELECT 
                      COUNT(DISTINCT vv.voter_id) as total_voters,
                      COUNT(DISTINCT vc.voter_id) as committed_voters,
                      COUNT(DISTINCT vs.voter_id) as scored_voters,
                      AVG(vv.weight) as avg_voter_weight,
                      SUM(vv.weight) as total_voter_weight
                   FROM voting_voters vv
                   LEFT JOIN voting_commitments vc ON vv.voting_id = vc.voting_id AND vv.voter_id = vc.voter_id
                   LEFT JOIN voting_scores vs ON vv.voting_id = vs.voting_id AND vv.voter_id = vs.voter_id
                   WHERE vv.voting_id = ?""",
                (voting_id,)
            )

            return {
                'candidates': candidate_scores,
                'score_details': score_details,
                'statistics': stats[0] if stats else {},
                'weight_type': 'weighted'
            }

        except Exception as e:
            logger.error(f"获取加权结果错误: {e}")
            raise

    @staticmethod
    def get_voting_results(voting_id):
        """获取投票结果 - 支持加权和普通两种计算方式"""
        try:
            # 获取投票活动信息
            voting = db.execute_query(
                "SELECT weight_type FROM voting_sessions WHERE id = ?",
                (voting_id,)
            )

            if not voting:
                return None

            weight_type = voting[0]['weight_type']

            if weight_type == 'equal':
                # 等权重计算
                return Voting._get_equal_weight_results(voting_id)
            else:
                # 加权计算
                return Voting.get_weighted_results(voting_id)

        except Exception as e:
            logger.error(f"获取投票结果错误: {e}")
            raise

    @staticmethod
    def _get_equal_weight_results(voting_id):
        """等权重结果计算 - 修复版本"""
        candidate_scores = db.execute_query(
            """SELECT c.id, c.name, 
                      AVG(CAST(vs.score AS FLOAT)) as avg_score,
                      SUM(vs.score) as total_score,
                      COUNT(vs.id) as vote_count
               FROM candidates c
               LEFT JOIN voting_scores vs ON c.id = vs.candidate_id
               WHERE c.voting_id = ?
               GROUP BY c.id, c.name
               ORDER BY avg_score DESC""",
            (voting_id,)
        )

        stats = db.execute_query(
            """SELECT 
                  COUNT(DISTINCT vv.voter_id) as total_voters,
                  COUNT(DISTINCT vc.voter_id) as committed_voters,
                  COUNT(DISTINCT vs.voter_id) as scored_voters
               FROM voting_voters vv
               LEFT JOIN voting_commitments vc ON vv.voting_id = vc.voting_id AND vv.voter_id = vc.voter_id
               LEFT JOIN voting_scores vs ON vv.voting_id = vs.voting_id AND vv.voter_id = vs.voter_id
               WHERE vv.voting_id = ?""",
            (voting_id,)
        )

        return {
            'candidates': candidate_scores,
            'statistics': stats[0] if stats else {},
            'weight_type': 'equal'
        }

    @staticmethod
    def get_voting_by_id(voting_id):
        """根据ID获取投票活动 - 修复序列化问题"""
        try:
            # 获取投票基本信息
            votings = db.execute_query(
                """SELECT vs.*, u.username as creator_name
                   FROM voting_sessions vs
                   LEFT JOIN users u ON vs.creator_id = u.id
                   WHERE vs.id = ?""",
                (voting_id,)
            )

            if not votings:
                return None

            voting = votings[0]

            # 处理 bytes 类型数据
            def convert_bytes(obj):
                if isinstance(obj, dict):
                    return {k: convert_bytes(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_bytes(item) for item in obj]
                elif isinstance(obj, bytes):
                    return obj.hex() if obj else None
                else:
                    return obj

            voting = convert_bytes(voting)

            # 获取候选人
            candidates = db.execute_query(
                "SELECT id, name, order_index FROM candidates WHERE voting_id = ? ORDER BY order_index",
                (voting_id,)
            )
            voting['candidates'] = convert_bytes(candidates)

            # 获取投票者（包含权重与钱包地址：链上 Merkle 白名单按 wallet_address 构造）
            voters = db.execute_query(
                """SELECT u.id, u.username, u.email, u.wallet_address, vv.weight
                   FROM voting_voters vv
                   LEFT JOIN users u ON vv.voter_id = u.id
                   WHERE vv.voting_id = ?""",
                (voting_id,)
            )
            voting['voters'] = convert_bytes(voters)

            # 获取承诺
            commitments = db.execute_query(
                """SELECT vc.*, u.username
                   FROM voting_commitments vc
                   LEFT JOIN users u ON vc.voter_id = u.id
                   WHERE vc.voting_id = ?""",
                (voting_id,)
            )
            voting['commitments'] = convert_bytes(commitments)

            # 获取评分（包含权重信息）
            scores = db.execute_query(
                """SELECT vs.*, u.username, c.name as candidate_name, vs.weight
                   FROM voting_scores vs
                   LEFT JOIN users u ON vs.voter_id = u.id
                   LEFT JOIN candidates c ON vs.candidate_id = c.id
                   WHERE vs.voting_id = ?""",
                (voting_id,)
            )
            voting['scores'] = convert_bytes(scores)

            return voting

        except Exception as e:
            logger.error(f"获取投票活动错误: {e}")
            raise

    @staticmethod
    def get_votings_by_user(user_id, user_role):
        """根据用户ID和角色获取投票活动"""
        try:
            if user_role == 'publisher':
                # 发布者查看自己创建的活动
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
                # 评分者查看自己被邀请的活动
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

            return votings

        except Exception as e:
            logger.error(f"获取用户投票活动错误: {e}")
            raise

    @staticmethod
    def get_all_votings():
        """获取所有投票活动"""
        try:
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
            return votings

        except Exception as e:
            logger.error(f"获取所有投票活动错误: {e}")
            raise

    @staticmethod
    def submit_commitment(commitment_data):
        """提交承诺"""
        try:
            # 检查是否已经提交过承诺
            existing = db.execute_query(
                "SELECT id FROM voting_commitments WHERE voting_id = ? AND voter_id = ?",
                (commitment_data['voting_id'], commitment_data['voter_id'])
            )

            if existing:
                # 更新现有承诺（v2 只持久化承诺点与承诺哈希，不存 scores/secret/blinding_factors）
                db.execute_query(
                    """UPDATE voting_commitments 
                       SET commitment_hash = ?, commitments = ?, commitment_type = 'pedersen', created_at = GETDATE()
                       WHERE id = ?""",
                    (commitment_data['commitment_hash'], commitment_data.get('commitments'),
                     existing[0]['id'])
                )
                return existing[0]['id']
            else:
                # 插入新承诺
                commitment_id = db.execute_query(
                    """INSERT INTO voting_commitments 
                       (voting_id, voter_id, commitment_hash, commitments, commitment_type, created_at)
                       OUTPUT INSERTED.id
                       VALUES (?, ?, ?, ?, 'pedersen', GETDATE())""",
                    (commitment_data['voting_id'], commitment_data['voter_id'],
                     commitment_data['commitment_hash'], commitment_data.get('commitments'))
                )
                return commitment_id

        except Exception as e:
            logger.error(f"提交承诺错误: {e}")
            raise

    @staticmethod
    def update_voting_phase(voting_id, phase):
        """更新投票阶段"""
        try:
            db.execute_query(
                "UPDATE voting_sessions SET phase = ?, updated_at = GETDATE() WHERE id = ?",
                (phase, voting_id)
            )

            # 返回更新后的投票信息
            return Voting.get_voting_by_id(voting_id)

        except Exception as e:
            logger.error(f"更新投票阶段错误: {e}")
            raise

    @staticmethod
    def get_user_commitment(voting_id, voter_id):
        """获取用户的承诺"""
        try:
            commitments = db.execute_query(
                """SELECT vc.*, u.username
                   FROM voting_commitments vc
                   LEFT JOIN users u ON vc.voter_id = u.id
                   WHERE vc.voting_id = ? AND vc.voter_id = ?""",
                (voting_id, voter_id)
            )

            if commitments:
                commitment = commitments[0]
                return commitment
            return None

        except Exception as e:
            logger.error(f"获取用户承诺错误: {e}")
            return None

    # models/voting.py - 修复 can_user_participate 函数
    @staticmethod
    def can_user_participate(voting_id, voter_id):
        """检查用户是否可以参与投票 - 修复SQL Server语法问题"""
        try:
            logger.info(f"检查用户参与权限 - 投票ID: {voting_id}, 用户ID: {voter_id}")

            # 验证参数
            if not voting_id or not voter_id:
                logger.error(f"参数错误: voting_id={voting_id}, voter_id={voter_id}")
                return False, "参数错误"

            # 检查投票是否存在
            voting_result = db.execute_query(
                "SELECT id, phase FROM voting_sessions WHERE id = ?",
                (voting_id,)
            )

            if not voting_result:
                logger.error(f"投票活动不存在: {voting_id}")
                return False, "投票活动不存在"

            # 获取投票阶段
            phase = voting_result[0]['phase']
            logger.info(f"当前投票阶段: {phase}")

            # 检查用户是否是投票者
            voter_result = db.execute_query(
                "SELECT id FROM voting_voters WHERE voting_id = ? AND voter_id = ?",
                (voting_id, voter_id)
            )

            if not voter_result:
                logger.warning(f"用户 {voter_id} 不是投票 {voting_id} 的评分者")
                return False, "您不是此投票的评分者"

            # 定义有效的参与阶段
            valid_phases = ['commit', 'scoring']

            if phase not in valid_phases:
                if phase == 'completed':
                    return False, "投票已结束"
                elif phase == 'cancelled':
                    return False, "投票已取消"
                else:
                    return False, f"投票尚未开始或状态异常: {phase}"

            # 检查是否已经提交过评分 - 修复：使用SQL Server的TOP语法
            if phase == 'scoring':
                score_result = db.execute_query(
                    """SELECT TOP 1 id FROM voting_scores 
                       WHERE voting_id = ? AND voter_id = ?""",
                    (voting_id, voter_id)
                )
                if score_result:
                    logger.info(f"用户 {voter_id} 已经提交过评分")
                    return False, "您已经提交过评分了"

            # 检查是否已经提交过承诺
            commitment_result = db.execute_query(
                "SELECT id FROM voting_commitments WHERE voting_id = ? AND voter_id = ?",
                (voting_id, voter_id)
            )

            if phase == 'commit':
                if commitment_result:
                    logger.info(f"用户 {voter_id} 已经提交过承诺")
                    return False, "您已经提交过承诺了"
                logger.info(f"用户 {voter_id} 可以提交承诺")
                return True, "可以提交承诺"

            elif phase == 'scoring':
                if not commitment_result:
                    logger.warning(f"用户 {voter_id} 还未提交承诺")
                    return False, "您还未提交承诺，无法进行评分"
                logger.info(f"用户 {voter_id} 可以提交评分")
                return True, "可以提交评分"

            else:
                return False, f"当前阶段无法操作: {phase}"

        except Exception as e:
            logger.error(f"检查用户参与权限错误: {e}", exc_info=True)
            # 返回更具体的错误信息
            error_msg = str(e)
            if "LIMIT" in error_msg:
                error_msg = "数据库查询语法错误，请联系管理员"
            elif "42000" in error_msg:
                error_msg = "数据库连接错误，请联系管理员"
            return False, f"检查权限时发生错误: {error_msg}"