# -*- coding: utf-8 -*-
# backend/check_imports.py
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)


def check_imports():
    print("🔍 检查导入模块...")

    modules_to_check = [
        ('models.voting', 'Voting'),
        ('utils.auth', 'auth_required'),
        ('services.blockchain', 'blockchain_service'),
        ('database', 'db')
    ]

    for module_path, class_name in modules_to_check:
        try:
            module = __import__(module_path, fromlist=[class_name])
            if hasattr(module, class_name):
                print(f"✅ {module_path}.{class_name} - 导入成功")
            else:
                print(f"❌ {module_path}.{class_name} - 类/函数不存在")
        except Exception as e:
            print(f"❌ {module_path}.{class_name} - 导入失败: {e}")


if __name__ == "__main__":
    check_imports()