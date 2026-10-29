# -*- coding: utf-8 -*-
"""后端 API 契约测试（Flask test client，不占用 5000 端口）。

覆盖的是**契约**而不是业务流程：认证、角色、错误码、后门下线、配置边界。
业务全链路由 tests/e2e_flow.py 覆盖。

运行：
    cd backend
    $env:PYTHONUTF8='1'; python tests\\test_api.py -v

依赖：SQL Server 与 hardhat 链需在线（应用启动时会连接两者）。
本文件只做只读请求与**必然被拒绝**的写请求，不会改动业务数据。
"""
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

# app.py 启动时会把日志写入 cwd/app.log（mode='w'）。切到临时目录再导入，
# 避免截断正在运行的后端日志文件。
_ORIGINAL_CWD = os.getcwd()
_RUNTIME_DIR = tempfile.mkdtemp(prefix='zk_api_test_')
os.chdir(_RUNTIME_DIR)
try:
    import app as app_module                    # noqa: E402
    # app.py 只在 __main__ 分支调用 create_app()；导入时必须显式调用工厂，
    # 否则蓝图不会注册，所有 /api/* 都会 404。
    flask_app = app_module.create_app()
finally:
    os.chdir(_ORIGINAL_CWD)

# 测试输出保持干净：应用把根日志设为 INFO，这里只在失败时看断言
logging.getLogger().setLevel(logging.WARNING)

SEED_VOTING_ID = 1          # database/init.sql 的示例活动
MISSING_VOTING_ID = 999999


class ApiContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = flask_app.test_client()
        cls.admin_token = cls._login('admin')
        cls.voter_token = cls._login('voter1')

    # ---------------- helpers ----------------

    @classmethod
    def _login(cls, username, password='123456'):
        response = cls.client.post('/api/auth/login',
                                   json={'username': username, 'password': password})
        assert response.status_code == 200, response.get_data(as_text=True)
        return response.get_json()['data']['token']

    @staticmethod
    def auth(token):
        return {'Authorization': f'Bearer {token}'}

    def get(self, path, token=None):
        return self.client.get(path, headers=self.auth(token) if token else {})

    def post_json(self, path, payload, token=None):
        return self.client.post(path, json=payload,
                                headers=self.auth(token) if token else {})

    def put_json(self, path, payload, token=None):
        return self.client.put(path, json=payload,
                               headers=self.auth(token) if token else {})

    # ---------------- 健康与认证 ----------------

    def test_health(self):
        response = self.get('/api/health')
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body['status'], 'healthy')
        self.assertEqual(body['dependencies']['database'], 'healthy')

    def test_login_missing_credentials(self):
        response = self.post_json('/api/auth/login', {'username': 'admin'})
        self.assertEqual(response.status_code, 400)

    def test_login_wrong_password(self):
        response = self.post_json('/api/auth/login',
                                  {'username': 'admin', 'password': 'wrong'})
        self.assertEqual(response.status_code, 401)

    def test_login_does_not_leak_password_hash(self):
        response = self.post_json('/api/auth/login',
                                  {'username': 'admin', 'password': '123456'})
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body['success'])
        self.assertIn('token', body['data'])
        self.assertNotIn('password_hash', body['data']['user'])

    def test_me_requires_auth(self):
        self.assertEqual(self.get('/api/auth/me').status_code, 401)

    def test_me_returns_role(self):
        body = self.get('/api/auth/me', self.admin_token).get_json()
        self.assertEqual(body['data']['role'], 'publisher')
        self.assertNotIn('password_hash', body['data'])

    # ---------------- 活动读取 ----------------

    def test_voting_list_requires_auth(self):
        self.assertEqual(self.get('/api/voting/').status_code, 401)

    def test_voting_list(self):
        response = self.get('/api/voting/', self.voter_token)
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body['success'])
        self.assertGreaterEqual(len(body['data']), 1)

    def test_voting_detail(self):
        body = self.get(f'/api/voting/{SEED_VOTING_ID}', self.voter_token).get_json()
        self.assertTrue(body['success'])
        self.assertEqual(len(body['data']['candidates']), 3)
        self.assertEqual(len(body['data']['voters']), 2)
        self.assertEqual(body['data']['max_score'], 10)

    def test_voting_detail_not_found(self):
        response = self.get(f'/api/voting/{MISSING_VOTING_ID}', self.voter_token)
        self.assertEqual(response.status_code, 404)

    def test_can_participate_for_voter(self):
        body = self.get(f'/api/voting/{SEED_VOTING_ID}/can-participate',
                        self.voter_token).get_json()
        self.assertTrue(body['data']['can_participate'])

    def test_can_participate_rejects_non_voter(self):
        body = self.get(f'/api/voting/{SEED_VOTING_ID}/can-participate',
                        self.admin_token).get_json()
        self.assertFalse(body['data']['can_participate'])

    def test_my_commitment_absent(self):
        response = self.get(f'/api/voting/{SEED_VOTING_ID}/commitments/my',
                            self.voter_token)
        self.assertEqual(response.status_code, 404)

    # ---------------- 后门已下线（P0 回归） ----------------

    def test_recovery_backdoor_removed_for_publisher(self):
        response = self.post_json('/api/scores/recover', {}, self.admin_token)
        self.assertEqual(response.status_code, 410)

    def test_recovery_backdoor_rejects_voter(self):
        response = self.post_json('/api/scores/recover', {}, self.voter_token)
        self.assertEqual(response.status_code, 403)

    def test_recovery_backdoor_requires_auth(self):
        self.assertEqual(self.post_json('/api/scores/recover', {}).status_code, 401)

    # ---------------- 角色与参数校验 ----------------

    def test_create_voting_requires_publisher(self):
        response = self.post_json('/api/voting/', {'title': 'x'}, self.voter_token)
        self.assertEqual(response.status_code, 403)

    def test_create_voting_missing_fields(self):
        response = self.post_json('/api/voting/', {'title': 'x'}, self.admin_token)
        self.assertEqual(response.status_code, 400)

    def test_create_voting_too_few_candidates(self):
        response = self.post_json('/api/voting/', {
            'title': 'x', 'candidates': ['only'], 'voters': ['voter1'],
        }, self.admin_token)
        self.assertEqual(response.status_code, 400)

    def test_phase_update_requires_creator(self):
        response = self.put_json(f'/api/voting/{SEED_VOTING_ID}/phase',
                                 {'phase': 'scoring'}, self.voter_token)
        self.assertEqual(response.status_code, 403)

    def test_phase_update_rejects_invalid_phase(self):
        response = self.put_json(f'/api/voting/{SEED_VOTING_ID}/phase',
                                 {'phase': 'bogus'}, self.admin_token)
        self.assertEqual(response.status_code, 400)

    def test_relay_rejects_unknown_action(self):
        response = self.post_json(f'/api/voting/{SEED_VOTING_ID}/onchain/relay',
                                  {'action': 'bogus'}, self.voter_token)
        self.assertEqual(response.status_code, 400)

    def test_relay_rejects_malformed_json(self):
        response = self.client.post(
            f'/api/voting/{SEED_VOTING_ID}/onchain/relay',
            data='{bad json}', content_type='application/json',
            headers=self.auth(self.voter_token))
        self.assertEqual(response.status_code, 400)

    def test_relay_reveal_requires_signature(self):
        response = self.post_json(f'/api/voting/{SEED_VOTING_ID}/onchain/relay',
                                  {'action': 'reveal'}, self.voter_token)
        self.assertEqual(response.status_code, 400)

    # ---------------- 权重 ----------------

    def test_weights_visible_to_publisher(self):
        body = self.get(f'/api/weights/voting/{SEED_VOTING_ID}/weights',
                        self.admin_token).get_json()
        self.assertTrue(body['success'])
        self.assertEqual(len(body['data']['voters']), 2)
        self.assertEqual(body['data']['weight_statistics']['total_voters'], 2)

    def test_weights_forbidden_to_voter(self):
        response = self.get(f'/api/weights/voting/{SEED_VOTING_ID}/weights',
                            self.voter_token)
        self.assertEqual(response.status_code, 403)

    def test_weight_update_unknown_voter(self):
        response = self.put_json(
            f'/api/weights/voting/{SEED_VOTING_ID}/voter/{MISSING_VOTING_ID}',
            {'weight': 1.0}, self.admin_token)
        self.assertEqual(response.status_code, 404)

    # ---------------- 恢复 enrollment 契约（P3.2） ----------------

    def test_recovery_keys_requires_auth(self):
        self.assertEqual(self.post_json('/api/recovery/keys', {}).status_code, 401)

    def test_recovery_keys_requires_voting_id(self):
        self.assertEqual(self.get('/api/recovery/keys', self.voter_token).status_code, 400)

    def test_recovery_keys_rejects_bad_public_key(self):
        response = self.post_json('/api/recovery/keys',
                                  {'publicKey': 'not-base64', 'signature': '0x00'},
                                  self.voter_token)
        self.assertEqual(response.status_code, 400)

    def test_recovery_status_requires_voting_id(self):
        self.assertEqual(self.get('/api/recovery/status', self.voter_token).status_code, 400)

    def test_recovery_enroll_rejects_plaintext(self):
        response = self.post_json('/api/recovery/enroll',
                                  {'votingId': SEED_VOTING_ID, 'scores': [1, 2, 3]},
                                  self.voter_token)
        self.assertEqual(response.status_code, 400)

    def test_recovery_request_requires_auth(self):
        self.assertEqual(self.post_json('/api/recovery/request',
                                        {'votingId': SEED_VOTING_ID}).status_code, 401)

    def test_recovery_request_requires_enrollment(self):
        response = self.post_json('/api/recovery/request',
                                  {'votingId': SEED_VOTING_ID}, self.voter_token)
        self.assertEqual(response.status_code, 400)

    def test_recovery_request_list_requires_voting_id(self):
        self.assertEqual(self.get('/api/recovery/requests', self.voter_token).status_code, 400)

    def test_recovery_sharebox_unknown_request(self):
        response = self.get('/api/recovery/sharebox/999999', self.voter_token)
        self.assertEqual(response.status_code, 404)

    def test_recovery_sharebox_requires_auth(self):
        self.assertEqual(self.get('/api/recovery/sharebox/999999').status_code, 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
