# -*- coding: utf-8 -*-
# utils/auth.py - 完整修复版
from functools import wraps
from flask import jsonify, request, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from models.user import User
import logging

logger = logging.getLogger(__name__)


def auth_required(f):
    """JWT认证装饰器 - 修复版本，设置 g.user"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # 验证JWT令牌
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()

            if not current_user_id:
                return jsonify({
                    'success': False,
                    'message': '无效的认证令牌'
                }), 401

            user = User.get_user_by_id(current_user_id)

            if not user:
                return jsonify({
                    'success': False,
                    'message': '用户不存在'
                }), 401

            # 关键修复：将用户信息设置到 Flask 的 g 对象
            g.user = user
            return f(*args, **kwargs)

        except Exception as e:
            logger.error(f"认证错误: {e}")
            return jsonify({
                'success': False,
                'message': '认证失败'
            }), 401

    return decorated_function


def role_required(roles):
    """角色权限装饰器"""

    def decorator(f):
        @wraps(f)
        @auth_required
        def decorated_function(*args, **kwargs):
            # 从 g 对象获取用户信息
            current_user = get_current_user()
            if not current_user:
                return jsonify({
                    'success': False,
                    'message': '用户信息获取失败'
                }), 401

            if current_user['role'] not in roles:
                return jsonify({
                    'success': False,
                    'message': '权限不足'
                }), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def get_current_user():
    """获取当前用户信息"""
    return getattr(g, 'user', None)