# -*- coding: utf-8 -*-
import bcrypt
from database import db
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class User:
    @staticmethod
    def create_user(username, email, password, role, wallet_address=None):
        """创建新用户 - 支持可选的钱包地址"""
        try:
            # 基本验证
            if not username or not email or not password or not role:
                raise ValueError("请填写所有必填字段")

            # 验证角色
            if role not in ['voter', 'publisher']:
                raise ValueError("角色必须是 voter 或 publisher")

            # 验证密码强度
            if len(password) < 6:
                raise ValueError("密码至少需要6个字符")

            # 如果提供了钱包地址，验证格式
            if wallet_address:
                is_valid, wallet_message = User.validate_wallet_address(wallet_address)
                if not is_valid:
                    raise ValueError(wallet_message)

            # 检查用户是否已存在（用户名、邮箱）
            existing_user = db.execute_query(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (username, email)
            )

            if existing_user:
                raise ValueError("用户名或邮箱已存在")

            # 如果提供了钱包地址，检查是否已被使用
            if wallet_address:
                existing_wallet = db.execute_query(
                    "SELECT id FROM users WHERE wallet_address = ?",
                    (wallet_address,)
                )
                if existing_wallet:
                    raise ValueError("钱包地址已被使用")

            # 加密密码
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # 插入用户
            user_id = db.execute_query(
                """INSERT INTO users (username, email, password_hash, role, wallet_address, created_at) 
                   OUTPUT INSERTED.id
                   VALUES (?, ?, ?, ?, ?, GETDATE())""",
                (username, email, hashed_password, role, wallet_address)
            )

            # 获取创建的用户信息
            user = db.execute_query(
                "SELECT id, username, email, role, wallet_address, created_at FROM users WHERE id = ?",
                (user_id,)
            )

            logger.info(f"用户创建成功: {username} ({wallet_address or '无钱包'})")
            return user[0] if user else None

        except Exception as e:
            logger.error(f"创建用户错误: {e}")
            raise

    @staticmethod
    def authenticate_user(username, password):
        """用户认证"""
        try:
            users = db.execute_query(
                """SELECT id, username, email, password_hash, role, wallet_address, created_at 
                   FROM users WHERE username = ? OR email = ?""",
                (username, username)
            )

            if not users:
                raise ValueError("用户不存在")

            user = users[0]

            # 验证密码
            if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                raise ValueError("密码错误")

            # 移除密码哈希
            del user['password_hash']
            return user

        except Exception as e:
            logger.error(f"用户认证错误: {e}")
            raise

    @staticmethod
    def get_user_by_id(user_id):
        """根据ID获取用户"""
        try:
            users = db.execute_query(
                "SELECT id, username, email, role, wallet_address, created_at FROM users WHERE id = ?",
                (user_id,)
            )
            return users[0] if users else None
        except Exception as e:
            logger.error(f"获取用户错误: {e}")
            return None

    @staticmethod
    def get_user_by_username(username):
        """根据用户名获取用户"""
        try:
            users = db.execute_query(
                "SELECT id, username, email, role, wallet_address, created_at FROM users WHERE username = ?",
                (username,)
            )
            return users[0] if users else None
        except Exception as e:
            logger.error(f"获取用户错误: {e}")
            return None

    @staticmethod
    def get_user_by_wallet(wallet_address):
        """根据钱包地址获取用户"""
        try:
            users = db.execute_query(
                "SELECT id, username, email, role, wallet_address, created_at FROM users WHERE wallet_address = ?",
                (wallet_address,)
            )
            return users[0] if users else None
        except Exception as e:
            logger.error(f"根据钱包地址获取用户错误: {e}")
            return None

    @staticmethod
    def get_all_users():
        """获取所有用户（用于管理）"""
        try:
            users = db.execute_query(
                "SELECT id, username, email, role, wallet_address, created_at FROM users ORDER BY created_at DESC"
            )
            return users
        except Exception as e:
            logger.error(f"获取所有用户错误: {e}")
            return []

    @staticmethod
    def update_user_wallet(user_id, wallet_address):
        """更新用户钱包地址"""
        try:
            # 如果提供了钱包地址，验证格式
            if wallet_address:
                is_valid, wallet_message = User.validate_wallet_address(wallet_address)
                if not is_valid:
                    raise ValueError(wallet_message)

            # 检查钱包地址是否已被其他用户使用
            if wallet_address:
                existing_user = db.execute_query(
                    "SELECT id FROM users WHERE wallet_address = ? AND id != ?",
                    (wallet_address, user_id)
                )

                if existing_user:
                    raise ValueError("钱包地址已被其他用户使用")

            db.execute_query(
                "UPDATE users SET wallet_address = ?, updated_at = GETDATE() WHERE id = ?",
                (wallet_address, user_id)
            )

            logger.info(f"用户 {user_id} 钱包地址更新成功: {wallet_address}")
            return True

        except Exception as e:
            logger.error(f"更新用户钱包地址错误: {e}")
            raise

    @staticmethod
    def validate_wallet_address(wallet_address):
        """验证钱包地址格式"""
        if not wallet_address:
            return False, "钱包地址不能为空"

        if not wallet_address.startswith('0x'):
            return False, "钱包地址必须以0x开头"

        if len(wallet_address) != 42:
            return False, "钱包地址必须是42位字符"

        # 验证十六进制字符
        try:
            int(wallet_address[2:], 16)
        except ValueError:
            return False, "钱包地址包含无效的十六进制字符"

        return True, "钱包地址格式正确"

    @staticmethod
    def get_users_by_usernames(usernames):
        """根据用户名列表获取用户"""
        try:
            if not usernames:
                return []

            # 构建IN查询
            placeholders = ','.join(['?'] * len(usernames))
            query = f"""
                SELECT id, username, email, role, wallet_address, created_at 
                FROM users 
                WHERE username IN ({placeholders})
            """

            users = db.execute_query(query, usernames)
            return users
        except Exception as e:
            logger.error(f"根据用户名列表获取用户错误: {e}")
            return []

    @staticmethod
    def get_users_with_wallets():
        """获取所有有钱包地址的用户"""
        try:
            users = db.execute_query(
                "SELECT id, username, email, role, wallet_address, created_at FROM users WHERE wallet_address IS NOT NULL ORDER BY username"
            )
            return users
        except Exception as e:
            logger.error(f"获取有钱包用户错误: {e}")
            return []

    @staticmethod
    def search_users_by_wallet(wallet_query):
        """根据钱包地址搜索用户"""
        try:
            users = db.execute_query(
                "SELECT id, username, email, role, wallet_address, created_at FROM users WHERE wallet_address LIKE ? ORDER BY username",
                (f'%{wallet_query}%',)
            )
            return users
        except Exception as e:
            logger.error(f"搜索钱包用户错误: {e}")
            return []

    @staticmethod
    def connect_wallet(user_id, wallet_address):
        """连接钱包到用户账户"""
        try:
            # 验证钱包地址格式
            is_valid, wallet_message = User.validate_wallet_address(wallet_address)
            if not is_valid:
                raise ValueError(wallet_message)

            # 检查钱包是否已被其他用户使用
            existing_user = db.execute_query(
                "SELECT id, username FROM users WHERE wallet_address = ? AND id != ?",
                (wallet_address, user_id)
            )

            if existing_user:
                raise ValueError(f"钱包地址已被用户 {existing_user[0]['username']} 使用")

            # 更新钱包地址
            db.execute_query(
                "UPDATE users SET wallet_address = ?, updated_at = GETDATE() WHERE id = ?",
                (wallet_address, user_id)
            )

            logger.info(f"用户 {user_id} 成功连接钱包: {wallet_address}")
            return True

        except Exception as e:
            logger.error(f"连接钱包错误: {e}")
            raise

    @staticmethod
    def disconnect_wallet(user_id):
        """断开用户钱包连接"""
        try:
            db.execute_query(
                "UPDATE users SET wallet_address = NULL, updated_at = GETDATE() WHERE id = ?",
                (user_id,)
            )

            logger.info(f"用户 {user_id} 已断开钱包连接")
            return True

        except Exception as e:
            logger.error(f"断开钱包连接错误: {e}")
            raise

    @staticmethod
    def get_user_wallet_stats():
        """获取用户钱包统计信息"""
        try:
            stats = db.execute_query("""
                SELECT 
                    COUNT(*) as total_users,
                    COUNT(wallet_address) as users_with_wallet,
                    COUNT(*) - COUNT(wallet_address) as users_without_wallet,
                    CASE 
                        WHEN COUNT(*) > 0 THEN CAST(COUNT(wallet_address) AS FLOAT) / COUNT(*) * 100 
                        ELSE 0 
                    END as wallet_adoption_rate
                FROM users
            """)

            return stats[0] if stats else {
                'total_users': 0,
                'users_with_wallet': 0,
                'users_without_wallet': 0,
                'wallet_adoption_rate': 0
            }
        except Exception as e:
            logger.error(f"获取钱包统计错误: {e}")
            return {
                'total_users': 0,
                'users_with_wallet': 0,
                'users_without_wallet': 0,
                'wallet_adoption_rate': 0
            }

    @staticmethod
    def get_user_wallet_status(user_id):
        """获取用户钱包状态"""
        try:
            user = User.get_user_by_id(user_id)
            if not user:
                return None

            wallet_address = user.get('wallet_address')

            if not wallet_address:
                return {
                    'has_wallet': False,
                    'wallet_address': None,
                    'status': 'disconnected',
                    'message': '未连接钱包'
                }

            # 检查钱包有效性
            is_valid, message = User.validate_wallet_address(wallet_address)

            return {
                'has_wallet': True,
                'wallet_address': wallet_address,
                'status': 'connected' if is_valid else 'invalid',
                'is_valid': is_valid,
                'message': message
            }

        except Exception as e:
            logger.error(f"获取用户钱包状态错误: {e}")
            return None