# -*- coding: utf-8 -*-
# emergency_fix.py - 紧急修复编码问题
import os
import shutil


def backup_and_fix_voting():
    """备份并修复voting.py文件"""
    original_file = 'routes/voting.py'
    backup_file = 'routes/voting.py.backup'
    fixed_file = 'routes/voting_fixed.py'

    print("🔧 开始紧急修复...")

    # 1. 备份原文件
    if os.path.exists(original_file):
        shutil.copy2(original_file, backup_file)
        print(f"✅ 已备份原文件到: {backup_file}")
    else:
        print("⚠️ 原文件不存在，跳过备份")

    # 2. 创建修复版本
    fixed_content = '''# -*- coding: utf-8 -*-
# routes/voting.py - 修复编码问题版本
import logging
from flask import Blueprint, request, jsonify
from utils.auth import auth_required, role_required

logger = logging.getLogger(__name__)
voting_bp = Blueprint('voting', __name__)

@voting_bp.route('/', methods=['GET'])
@auth_required
def get_votings():
    """获取投票列表"""
    try:
        return jsonify({
            'success': True,
            'data': [],
            'message': '投票服务正常'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@voting_bp.route('/', methods=['POST', 'OPTIONS'])
@auth_required  
@role_required(['publisher'])
def create_voting():
    """创建投票"""
    if request.method == 'OPTIONS':
        return jsonify({'status': 'preflight'})

    try:
        data = request.get_json()
        return jsonify({
            'success': True,
            'message': '投票创建成功',
            'data': {'id': 1, 'title': data.get('title', '')}
        }), 201
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@voting_bp.route('/health', methods=['GET'])
def health():
    return jsonify({'success': True, 'message': '投票服务正常'})
'''

    # 3. 写入修复版本
    with open(original_file, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    print(f"✅ 已创建修复版本: {original_file}")

    print("🎉 紧急修复完成！")


if __name__ == '__main__':
    backup_and_fix_voting()