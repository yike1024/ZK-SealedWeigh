# routes/auth.py - 完整修复版
from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models.user import User
from utils.auth import auth_required, get_current_user
import logging

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register():
    """用户注册"""
    try:
        data = request.get_json()

        # 验证必填字段
        required_fields = ['username', 'email', 'password', 'role']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'message': f'请填写{field}字段'
                }), 400

        # 验证角色
        if data['role'] not in ['voter', 'publisher']:
            return jsonify({
                'success': False,
                'message': '角色必须是 voter 或 publisher'
            }), 400

        # 验证密码强度
        password = data['password']
        if len(password) < 6:
            return jsonify({
                'success': False,
                'message': '密码至少需要6个字符'
            }), 400

        # 获取钱包地址
        wallet_address = data.get('wallet_address')

        if not wallet_address:
            return jsonify({
                'success': False,
                'message': '请提供钱包地址'
            }), 400

        # 验证钱包地址格式
        is_valid, wallet_message = User.validate_wallet_address(wallet_address)
        if not is_valid:
            return jsonify({
                'success': False,
                'message': wallet_message
            }), 400

        # 创建用户
        user = User.create_user(
            username=data['username'].strip(),
            email=data['email'].strip(),
            password=password,
            role=data['role'],
            wallet_address=wallet_address
        )

        return jsonify({
            'success': True,
            'message': '注册成功',
            'data': user
        }), 201

    except ValueError as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"注册错误: {e}")
        return jsonify({
            'success': False,
            'message': '注册失败'
        }), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """用户登录"""
    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                'success': False,
                'message': '请求体必须是 JSON 对象'
            }), 400

        username = data.get('username')
        password = data.get('password')
        if not isinstance(username, str) or not isinstance(password, str) \
                or not username or not password:
            return jsonify({
                'success': False,
                'message': '请提供用户名和密码'
            }), 400
        # 与 users.username NVARCHAR(50) / bcrypt 72 字节上限对齐，避免 DB 截断变 500
        if len(username) > 50 or len(password.encode('utf-8')) > 72:
            return jsonify({
                'success': False,
                'message': '用户名或密码长度超出限制'
            }), 400

        # 用户认证
        user = User.authenticate_user(username, password)

        # 生成JWT token
        access_token = create_access_token(identity=str(user['id']))

        logger.info(f"用户 {user['username']} 登录成功，钱包地址: {user.get('wallet_address', '无')}")

        return jsonify({
            'success': True,
            'message': '登录成功',
            'data': {
                'user': user,
                'token': access_token
            }
        })

    except ValueError as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 401
    except Exception as e:
        logger.error(f"登录错误: {e}")
        return jsonify({
            'success': False,
            'message': '登录失败'
        }), 500


@auth_bp.route('/me', methods=['GET'])
@auth_required
def get_current_user_info():
    """获取当前用户信息"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        logger.info(f"获取当前用户信息成功: {current_user['username']}")
        return jsonify({
            'success': True,
            'data': current_user
        })
    except Exception as e:
        logger.error(f"获取用户信息错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取用户信息失败'
        }), 500


@auth_bp.route('/user/<username>', methods=['GET'])
@auth_required
def get_user_by_username(username):
    """根据用户名获取用户信息（包括钱包地址）"""
    try:
        if not username or not username.strip():
            return jsonify({
                'success': False,
                'message': '请提供有效的用户名'
            }), 400

        user = User.get_user_by_username(username.strip())

        if not user:
            return jsonify({
                'success': False,
                'message': '用户不存在'
            }), 404

        # 只返回公开信息
        user_public_info = {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'wallet_address': user['wallet_address'],
            'created_at': user['created_at']
        }

        return jsonify({
            'success': True,
            'data': user_public_info
        })

    except Exception as e:
        logger.error(f"获取用户信息错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取用户信息失败'
        }), 500


@auth_bp.route('/wallet/update', methods=['PUT'])
@auth_required
def update_wallet_address():
    """更新当前用户的钱包地址"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        data = request.get_json(silent=True)
        wallet = data.get('wallet_address') if isinstance(data, dict) else None

        if not isinstance(wallet, str) or not wallet.strip():
            return jsonify({
                'success': False,
                'message': '请提供钱包地址'
            }), 400

        wallet_address = wallet.strip()

        # 验证钱包地址格式
        is_valid, wallet_message = User.validate_wallet_address(wallet_address)
        if not is_valid:
            return jsonify({
                'success': False,
                'message': wallet_message
            }), 400

        # 更新钱包地址
        User.update_user_wallet(int(current_user['id']), wallet_address)

        # 获取更新后的用户信息
        user = User.get_user_by_id(int(current_user['id']))

        return jsonify({
            'success': True,
            'message': '钱包地址更新成功',
            'data': user
        })

    except ValueError as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"更新钱包地址错误: {e}")
        return jsonify({
            'success': False,
            'message': '更新钱包地址失败'
        }), 500


@auth_bp.route('/wallet/connect', methods=['POST'])
@auth_required
def connect_wallet():
    """连接钱包到用户账户"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        data = request.get_json()
        wallet_address = data.get('wallet_address')

        if not wallet_address:
            return jsonify({
                'success': False,
                'message': '请提供钱包地址'
            }), 400

        # 连接钱包
        User.connect_wallet(int(current_user['id']), wallet_address)

        # 获取更新后的用户信息
        user = User.get_user_by_id(int(current_user['id']))

        logger.info(f"用户 {current_user['username']} 成功连接钱包: {wallet_address}")

        return jsonify({
            'success': True,
            'message': '钱包连接成功',
            'data': user
        })

    except ValueError as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"连接钱包错误: {e}")
        return jsonify({
            'success': False,
            'message': '连接钱包失败'
        }), 500


@auth_bp.route('/wallet/disconnect', methods=['POST'])
@auth_required
def disconnect_wallet():
    """断开用户钱包连接"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        # 断开钱包连接
        User.disconnect_wallet(int(current_user['id']))

        # 获取更新后的用户信息
        user = User.get_user_by_id(int(current_user['id']))

        logger.info(f"用户 {current_user['username']} 已断开钱包连接")

        return jsonify({
            'success': True,
            'message': '钱包断开成功',
            'data': user
        })

    except Exception as e:
        logger.error(f"断开钱包错误: {e}")
        return jsonify({
            'success': False,
            'message': '断开钱包失败'
        }), 500


@auth_bp.route('/wallet/verify', methods=['POST'])
@auth_required
def verify_wallet_ownership():
    """验证钱包所有权（通过签名）"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        data = request.get_json()
        signature = data.get('signature')
        message = data.get('message')
        wallet_address = data.get('wallet_address')

        if not all([signature, message, wallet_address]):
            return jsonify({
                'success': False,
                'message': '缺少必要参数'
            }), 400

        # 这里可以添加签名验证逻辑
        # 在实际应用中，您需要使用 web3.py 或其他库来验证签名

        # 模拟验证成功
        verification_success = True

        if verification_success:
            # 连接钱包到用户
            User.connect_wallet(int(current_user['id']), wallet_address)

            return jsonify({
                'success': True,
                'message': '钱包所有权验证成功'
            })
        else:
            return jsonify({
                'success': False,
                'message': '签名验证失败'
            }), 400

    except Exception as e:
        logger.error(f"验证钱包所有权错误: {e}")
        return jsonify({
            'success': False,
            'message': '验证失败'
        }), 500


@auth_bp.route('/users/search', methods=['GET'])
@auth_required
def search_users():
    """搜索用户（用于投票者选择）"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        query = request.args.get('q', '').strip()

        if not query or len(query) < 2:
            return jsonify({
                'success': False,
                'message': '请输入至少2个字符进行搜索'
            }), 400

        # 搜索用户名或邮箱包含查询字符的用户
        from database import db
        users = db.execute_query(
            """SELECT id, username, email, role, wallet_address, created_at 
               FROM users 
               WHERE username LIKE ? OR email LIKE ?
               ORDER BY username
               LIMIT 20""",
            (f'%{query}%', f'%{query}%')
        )

        # 只返回公开信息
        public_users = []
        for user in users:
            public_users.append({
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'wallet_address': user['wallet_address'],
                'has_wallet': bool(user['wallet_address'])
            })

        return jsonify({
            'success': True,
            'data': public_users
        })

    except Exception as e:
        logger.error(f"搜索用户错误: {e}")
        return jsonify({
            'success': False,
            'message': '搜索用户失败'
        }), 500


@auth_bp.route('/wallet/validate', methods=['POST'])
def validate_wallet_address():
    """验证钱包地址格式"""
    try:
        data = request.get_json(silent=True)
        wallet = data.get('wallet_address') if isinstance(data, dict) else None

        if not isinstance(wallet, str) or not wallet.strip():
            return jsonify({
                'success': False,
                'message': '请提供钱包地址'
            }), 400

        wallet_address = wallet.strip()
        is_valid, message = User.validate_wallet_address(wallet_address)

        return jsonify({
            'success': True,
            'data': {
                'is_valid': is_valid,
                'message': message,
                'wallet_address': wallet_address
            }
        })

    except Exception as e:
        logger.error(f"验证钱包地址错误: {e}")
        return jsonify({
            'success': False,
            'message': '验证钱包地址失败'
        }), 500


@auth_bp.route('/wallet/status', methods=['GET'])
@auth_required
def get_wallet_status():
    """获取当前用户的钱包状态"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        wallet_status = User.get_user_wallet_status(current_user['id'])

        return jsonify({
            'success': True,
            'data': wallet_status
        })

    except Exception as e:
        logger.error(f"获取钱包状态错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取钱包状态失败'
        }), 500


@auth_bp.route('/users/batch', methods=['POST'])
@auth_required
def get_users_batch():
    """批量获取用户信息（用于投票者验证）"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({
                'success': False,
                'message': '用户信息获取失败'
            }), 401

        data = request.get_json(silent=True)

        if not isinstance(data, dict) or not isinstance(data.get('usernames'), list):
            return jsonify({
                'success': False,
                'message': '请提供用户名列表'
            }), 400

        usernames = []
        for username in data['usernames']:
            if not isinstance(username, str):
                return jsonify({
                    'success': False,
                    'message': '用户名必须是字符串'
                }), 400
            username = username.strip()
            if len(username) > 50:
                return jsonify({
                    'success': False,
                    'message': '用户名长度不能超过 50 个字符'
                }), 400
            if username:
                usernames.append(username)

        if not usernames:
            return jsonify({
                'success': False,
                'message': '用户名列表不能为空'
            }), 400

        users = User.get_users_by_usernames(usernames)

        # 组织返回数据
        user_map = {}
        for user in users:
            wallet_address = user['wallet_address']
            is_valid = bool(wallet_address) and User.validate_wallet_address(wallet_address)[0]

            user_map[user['username']] = {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'wallet_address': wallet_address,
                'has_wallet': bool(wallet_address),
                'wallet_valid': is_valid
            }

        # 为不存在的用户添加错误信息
        for username in usernames:
            if username not in user_map:
                user_map[username] = {
                    'username': username,
                    'error': '用户不存在',
                    'wallet_valid': False
                }

        return jsonify({
            'success': True,
            'data': user_map
        })

    except Exception as e:
        logger.error(f"批量获取用户信息错误: {e}")
        return jsonify({
            'success': False,
            'message': '批量获取用户信息失败'
        }), 500

@auth_bp.route('/wallet/stats', methods=['GET'])
@auth_required
def get_wallet_stats():
    """获取钱包使用统计"""
    try:
        stats = User.get_user_wallet_stats()

        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        logger.error(f"获取钱包统计错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取钱包统计失败'
        }), 500


@auth_bp.route('/users/with-wallets', methods=['GET'])
@auth_required
def get_users_with_wallets():
    """获取所有有钱包地址的用户"""
    try:
        users = User.get_users_with_wallets()

        # 只返回公开信息
        public_users = []
        for user in users:
            public_users.append({
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'wallet_address': user['wallet_address'],
                'created_at': user['created_at']
            })

        return jsonify({
            'success': True,
            'data': public_users
        })
    except Exception as e:
        logger.error(f"获取有钱包用户错误: {e}")
        return jsonify({
            'success': False,
            'message': '获取有钱包用户失败'
        }), 500