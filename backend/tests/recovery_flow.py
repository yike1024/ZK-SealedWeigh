# -*- coding: utf-8 -*-
"""P3.2/P3.3 门限恢复的端到端验收。

真实链路：
  Node（recovery-crypto.js）生成 P-256 公钥、托管密文、Shamir 份额信封与签名清单
  → Python 用两位评委的 Hardhat 私钥做 EIP-191 签名
  → 调用 /api/recovery/keys、/enroll、/request、/sharebox
  → 校验服务器只存密文、拒绝篡改/越权/明文，并在本地完成 k-of-n 重构

前置：链与后端已启动，种子活动 1 处于 commit 阶段。
运行：
    cd backend
    $env:PYTHONUTF8='1'; python tests\\recovery_flow.py
退出码：0 = 全部通过，1 = 失败（保留现场）。
"""
import datetime
import json
import subprocess
import sys
from pathlib import Path

import requests
from eth_account import Account
from eth_account.messages import encode_defunct

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

from dotenv import load_dotenv                     # noqa: E402

load_dotenv(BACKEND_DIR / '.env')

API = 'http://127.0.0.1:5000/api'
HELPER = PROJECT_DIR / 'frontend' / 'tests' / 'enrollment_payload.js'
ACTIONS = PROJECT_DIR / 'frontend' / 'tests' / 'recovery_actions.js'
VOTING_ID = 1

# Hardhat 本地链的公开测试账户（仅用于本地验收）
VOTERS = [
    {'userId': 2, 'username': 'voter1',
     'wallet': '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
     'key': '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'},
    {'userId': 3, 'username': 'voter2',
     'wallet': '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
     'key': '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'},
]
THRESHOLD = 1          # 2 位评委：份额只能发给 1 位其他评委，因此 k=1
PAYLOAD = {'scores': [7, 9, 0], 'secret': 'correct horse battery staple',
           'salt': '12345678901234567890'}

passed = 0
failed = 0


def check(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  [PASS] {name}')
    else:
        failed += 1
        print(f'  [FAIL] {name} {detail}')


def login(username):
    response = requests.post(f'{API}/auth/login',
                             json={'username': username, 'password': '123456'}, timeout=15)
    response.raise_for_status()
    return response.json()['data']['token']


def auth(token):
    return {'Authorization': f'Bearer {token}'}


def sign_text(private_key, message):
    signed = Account.sign_message(encode_defunct(text=message), private_key=private_key)
    raw = signed.signature.hex()
    return raw if raw.startswith('0x') else '0x' + raw


def build_payload():
    request = {
        'votingId': VOTING_ID,
        'threshold': THRESHOLD,
        'enrollingUserId': VOTERS[0]['userId'],
        'voters': [{'userId': v['userId'], 'wallet': v['wallet']} for v in VOTERS],
        'payload': PAYLOAD,
    }
    process = subprocess.run(
        ['node', str(HELPER)],
        input=json.dumps(request, ensure_ascii=False),
        capture_output=True, text=True, encoding='utf-8', timeout=120)
    if process.returncode != 0:
        raise RuntimeError(f'Node 生成 enrollment 载荷失败: {process.stderr}')
    return json.loads(process.stdout)


def run_action(mode, payload):
    process = subprocess.run(
        ['node', str(ACTIONS), mode],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True, text=True, encoding='utf-8', timeout=120)
    if process.returncode != 0:
        raise RuntimeError(f'Node {mode} 失败: {process.stderr}')
    return json.loads(process.stdout)


def cleanup(publications):
    """清理本次测试写入的数据。

    公钥按 (user_id, public_key) 精确删除，避免误删用户自己通过 UI 发布的公钥。
    """
    from database import db
    db.execute_query(
        """
        DELETE FROM recovery_shares
         WHERE request_id IN (SELECT id FROM recovery_requests WHERE voting_id = ?)
        """,
        (VOTING_ID,)
    )
    db.execute_query('DELETE FROM recovery_requests WHERE voting_id = ?', (VOTING_ID,))
    db.execute_query('DELETE FROM recovery_enrollments WHERE voting_id = ?', (VOTING_ID,))
    for userId, item in publications.items():
        db.execute_query('DELETE FROM recovery_keys WHERE user_id = ? AND public_key = ?',
                         (userId, item['publicKey']))


def main():
    print('\n=== P3.2 enrollment 接口验收 ===\n')
    admin_token = login('admin')
    tokens = {v['userId']: login(v['username']) for v in VOTERS}
    publications = {}

    try:
        print('--- 0. 生成客户端载荷 ---')
        bundle = build_payload()
        publications = {item['userId']: item for item in bundle['keyPublications']}
        enrollment = bundle['enrollment']
        check('Node 生成 2 份公钥', len(publications) == 2)
        check('escrow 与信封都不含明文',
              'correct horse' not in json.dumps(enrollment) and
              'correct horse' not in json.dumps(enrollment['envelopes']))
        check('manifest 只含 1 个信封哈希（排除自己）',
              len(enrollment['manifest']['envelopeHashes']) == 1)
        check('recipients 只包含其他评委',
              enrollment['manifest']['recipients'] == [3])

        print('\n--- 1. 发布公钥 ---')
        for voter in VOTERS:
            item = publications[voter['userId']]
            signature = sign_text(voter['key'], item['message'])
            response = requests.post(f'{API}/recovery/keys', headers=auth(tokens[voter['userId']]),
                                     json={'publicKey': item['publicKey'], 'signature': signature},
                                     timeout=20)
            check(f'{voter["username"]} 公钥发布成功（200）', response.status_code == 200,
                  response.text[:200])

        response = requests.get(f'{API}/recovery/keys?votingId={VOTING_ID}',
                                headers=auth(tokens[2]), timeout=20)
        data = response.json()['data']
        check('公钥列表含 2 位评委', len(data['voters']) == 2)
        check('所有公钥就绪', data['allKeysReady'] is True)

        print('\n--- 2. 登记密文清单 ---')
        manifest_message = enrollment['manifestMessage']
        signature = sign_text(VOTERS[0]['key'], manifest_message)
        body = {
            'votingId': enrollment['votingId'],
            'escrow': enrollment['escrow'],
            'envelopes': enrollment['envelopes'],
            'manifest': enrollment['manifest'],
            'manifestMessage': manifest_message,
            'signature': signature,
        }
        response = requests.post(f'{API}/recovery/enroll', headers=auth(tokens[2]),
                                 json=body, timeout=30)
        result = response.json()
        check('登记成功（201）', response.status_code == 201, result)
        check('返回 threshold=1 / envelopeCount=1',
              result.get('data', {}).get('threshold') == 1 and
              result.get('data', {}).get('envelopeCount') == 1, result)

        response = requests.get(f'{API}/recovery/enrollments/my?votingId={VOTING_ID}',
                                headers=auth(tokens[2]), timeout=20)
        check('本人可读取自己的密文清单（200）', response.status_code == 200, response.text[:200])
        if response.status_code == 200:
            mine = response.json()['data']
            check('escrow 与提交一致', mine['escrow'] == enrollment['escrow'])
            check('信封数量与其他评委数一致', len(mine['envelopes']) == 1)

        status = requests.get(f'{API}/recovery/status?votingId={VOTING_ID}',
                              headers=auth(tokens[3]), timeout=20).json()['data']
        by_user = {v['userId']: v for v in status['voters']}
        check('状态显示 voter1 已登记', by_user[2]['enrolled'] is True)
        check('状态显示 voter2 未登记', by_user[3]['enrolled'] is False)
        check('状态不含任何密文',
              'escrow' not in json.dumps(status) and 'envelope' not in json.dumps(status).lower())

        print('\n--- 3. 拒绝路径 ---')
        tampered = json.loads(json.dumps(body))
        ct = tampered['envelopes'][0]['ct']
        tampered['envelopes'][0]['ct'] = ('A' if ct[0] != 'A' else 'B') + ct[1:]
        response = requests.post(f'{API}/recovery/enroll', headers=auth(tokens[2]),
                                 json=tampered, timeout=20)
        check('篡改信封被拒（400）', response.status_code == 400,
              response.text[:200])

        wrong_signature = sign_text(VOTERS[1]['key'], manifest_message)
        mismatched = dict(body, signature=wrong_signature)
        response = requests.post(f'{API}/recovery/enroll', headers=auth(tokens[2]),
                                 json=mismatched, timeout=20)
        check('他人签名被拒（401）', response.status_code == 401, response.text[:200])

        leaked = dict(body, scores=PAYLOAD['scores'])
        response = requests.post(f'{API}/recovery/enroll', headers=auth(tokens[2]),
                                 json=leaked, timeout=20)
        check('包含明文 scores 被拒（400）', response.status_code == 400, response.text[:200])

        wrong_manifest = json.loads(json.dumps(body))
        wrong_manifest['manifest']['voter'] = VOTERS[1]['wallet']
        wrong_manifest['manifestMessage'] = correct_canonical(wrong_manifest['manifest'])
        response = requests.post(f'{API}/recovery/enroll', headers=auth(tokens[3]),
                                 json=wrong_manifest, timeout=20)
        check('manifest.voter 与登录账号不符被拒（400/401）',
              response.status_code in (400, 401), response.text[:200])

        response = requests.post(f'{API}/recovery/enroll', headers=auth(admin_token),
                                 json=body, timeout=20)
        check('非评委登记被拒（403）', response.status_code == 403, response.text[:200])

        response = requests.get(f'{API}/recovery/enrollments/my?votingId={VOTING_ID}',
                                headers=auth(tokens[3]), timeout=20)
        check('未登记评委读取自己的清单返回 404', response.status_code == 404)

        # ---------------- 4. 恢复请求与份额投递 ----------------
        print('\n--- 4. 恢复请求与份额投递 ---')
        response = requests.post(f'{API}/recovery/request', headers=auth(tokens[2]),
                                 json={'votingId': VOTING_ID}, timeout=20)
        request_data = response.json().get('data') or {}
        request_id = int(request_data.get('requestId') or 0)
        check('丢失方创建恢复请求（201）', response.status_code == 201, response.text[:200])
        check('请求 threshold=1', request_data.get('threshold') == 1, request_data)

        response = requests.post(f'{API}/recovery/request', headers=auth(tokens[2]),
                                 json={'votingId': VOTING_ID}, timeout=20)
        check('重复创建复用同一请求（200）',
              response.status_code == 200 and
              response.json()['data']['requestId'] == request_id, response.text[:200])

        listed = requests.get(f'{API}/recovery/requests?votingId={VOTING_ID}',
                              headers=auth(tokens[3]), timeout=20).json()['data']['requests']
        check('其他评委能看到请求', len(listed) == 1 and listed[0]['requestId'] == request_id)
        check('显示尚未投递', listed[0]['submittedByMe'] is False)

        own_listed = requests.get(f'{API}/recovery/requests?votingId={VOTING_ID}',
                                  headers=auth(tokens[2]), timeout=20).json()['data']['requests']
        check('请求者看不到自己的请求', own_listed == [])

        envelope_result = requests.get(
            f'{API}/recovery/requests/{request_id}/envelopes',
            headers=auth(tokens[3]), timeout=20)
        envelope_data = envelope_result.json().get('data') or {}
        check('其他评委可读取分配给自己的信封',
              envelope_result.status_code == 200 and
              envelope_data.get('recipientIds') == [3] and
              len(envelope_data.get('envelopes', [])) == 1,
              envelope_result.text[:200])
        check('分到的信封与登记时一致',
              envelope_data.get('envelopes', [None])[0] == enrollment['envelopes'][0])

        outsider = requests.get(f'{API}/recovery/requests/{request_id}/envelopes',
                                headers=auth(admin_token), timeout=20)
        check('非评委读取信封被拒（403）', outsider.status_code == 403, outsider.text[:200])

        share_payload = run_action('share', {
            'votingId': VOTING_ID,
            'requestId': request_id,
            'requesterWallet': VOTERS[0]['wallet'],
            'trusteeWallet': VOTERS[1]['wallet'],
            'trusteePrivateJwk': bundle['privateKeys']['3'],
            'enrollmentEnvelope': enrollment['envelopes'][0],
            'requesterPublicKey': publications[2]['publicKey'],
        })
        share_message = share_payload['message']
        envelope = share_payload['envelope']
        share_body = {
            'requestId': request_id,
            'envelope': envelope,
            'message': share_message,
            'signature': sign_text(VOTERS[1]['key'], share_message),
        }

        wrong_signature_body = dict(
            share_body, signature=sign_text(VOTERS[0]['key'], share_message))
        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[3]),
                                 json=wrong_signature_body, timeout=20)
        check('他人签名投递被拒（401）', response.status_code == 401, response.text[:200])

        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[2]),
                                 json=share_body, timeout=20)
        check('请求者给自己投递被拒（403）', response.status_code == 403, response.text[:200])

        response = requests.post(f'{API}/recovery/sharebox', headers=auth(admin_token),
                                 json=share_body, timeout=20)
        check('非评委投递被拒（403）', response.status_code == 403, response.text[:200])

        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[3]),
                                 json=share_body, timeout=30)
        shared = response.json().get('data') or {}
        check('份额投递成功（201）', response.status_code == 201, response.text[:200])
        check('收集数达到门限', shared.get('collected') == 1 and shared.get('ready') is True,
              shared)

        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[3]),
                                 json=share_body, timeout=20)
        check('重复投递被拒（409）', response.status_code == 409, response.text[:200])

        box = requests.get(f'{API}/recovery/sharebox/{request_id}',
                           headers=auth(tokens[2]), timeout=20)
        box_data = box.json().get('data') or {}
        check('请求者可读取份额（200）', box.status_code == 200, box.text[:200])
        check('份额来源正确',
              len(box_data.get('shares', [])) == 1 and
              box_data['shares'][0]['fromWallet'].lower() == VOTERS[1]['wallet'].lower())

        response = requests.get(f'{API}/recovery/sharebox/{request_id}',
                                headers=auth(tokens[3]), timeout=20)
        check('非请求者读取份额被拒（403）', response.status_code == 403, response.text[:200])

        # ---------------- 5. 本地重构 ----------------
        print('\n--- 5. 本地重构 ---')
        recovered = run_action('recover', {
            'votingId': VOTING_ID,
            'requesterWallet': VOTERS[0]['wallet'],
            'requesterPrivateJwk': bundle['privateKeys']['2'],
            'escrow': enrollment['escrow'],
            'shares': [{'fromWallet': item['fromWallet'], 'envelope': item['envelope']}
                       for item in box_data['shares']],
        })['recovered']
        check('重构出的载荷与原始完全一致', recovered == PAYLOAD, recovered)

        tampered_share = json.loads(json.dumps(box_data['shares'][0]))
        ct_text = tampered_share['envelope']['ct']
        tampered_share['envelope']['ct'] = ('A' if ct_text[0] != 'A' else 'B') + ct_text[1:]
        try:
            run_action('recover', {
                'votingId': VOTING_ID,
                'requesterWallet': VOTERS[0]['wallet'],
                'requesterPrivateJwk': bundle['privateKeys']['2'],
                'escrow': enrollment['escrow'],
                'shares': [{'fromWallet': tampered_share['fromWallet'],
                            'envelope': tampered_share['envelope']}],
            })
            check('篡改份额导致本地重构失败', False, '竟然成功了')
        except RuntimeError:
            check('篡改份额导致本地重构失败', True)

        # ---------------- 6. 只读视图：全局待办与恢复历史（P3.10） ----------------
        print('\n--- 6. 全局待办与恢复历史 ---')
        overview = requests.get(f'{API}/recovery/overview',
                                headers=auth(tokens[2]), timeout=20)
        overview_data = overview.json().get('data') or {}
        check('请求者可读取全局恢复待办（200）', overview.status_code == 200,
              overview.text[:200])
        check('请求者已登记 1 个进行中活动',
              overview_data.get('enrolledCount') == 1 and
              overview_data.get('activeVotingCount') == 1, overview_data)
        check('已收集请求不再计入待办',
              overview_data.get('myOpenRequests') == 0 and
              overview_data.get('pendingAssist') == 0, overview_data)

        trustee_overview = requests.get(f'{API}/recovery/overview',
                                         headers=auth(tokens[3]), timeout=20
                                         ).json().get('data') or {}
        check('已投递评委无待协助请求',
              trustee_overview.get('pendingAssist') == 0 and
              trustee_overview.get('enrolledCount') == 0, trustee_overview)

        activities = overview_data.get('activities') or []
        check('全局总览含进行中活动及登记状态',
              len(activities) == 1 and
              activities[0]['votingId'] == VOTING_ID and
              activities[0]['enrolled'] is True and
              activities[0]['myOpenRequests'] == 0 and
              activities[0]['pendingAssist'] == 0, activities)
        trustee_activities = trustee_overview.get('activities') or []
        check('协助者视角活动未登记且无待办',
              len(trustee_activities) == 1 and
              trustee_activities[0]['enrolled'] is False and
              trustee_activities[0]['pendingAssist'] == 0, trustee_activities)

        history = requests.get(f'{API}/recovery/history?votingId={VOTING_ID}',
                               headers=auth(tokens[2]), timeout=20)
        history_data = history.json().get('data') or {}
        check('请求者可读取恢复历史（200）', history.status_code == 200,
              history.text[:200])
        check('历史含 1 条请求且状态为 collected',
              len(history_data.get('requests', [])) == 1 and
              history_data['requests'][0]['status'] == 'collected', history_data)
        check('请求者视角 mine=requester 且投递者正确',
              history_data['requests'][0]['mine'] == 'requester' and
              history_data['requests'][0]['submittedByMe'] is False and
              len(history_data['requests'][0]['shares']) == 1 and
              history_data['requests'][0]['shares'][0]['fromUserId'] == 3,
              history_data['requests'][0])

        trustee_history = requests.get(f'{API}/recovery/history?votingId={VOTING_ID}',
                                       headers=auth(tokens[3]), timeout=20
                                       ).json().get('data') or {}
        check('协助者视角 mine=trustee 且已投递',
              trustee_history['requests'][0]['mine'] == 'trustee' and
              trustee_history['requests'][0]['submittedByMe'] is True,
              trustee_history['requests'][0])
        check('历史不含任何密文',
              'escrow' not in json.dumps(history_data).lower() and
              'envelope' not in json.dumps(history_data).lower())

        outsider_history = requests.get(
            f'{API}/recovery/history?votingId={VOTING_ID}',
            headers=auth(login('voter3')), timeout=20)
        check('非该活动评委读取恢复历史被拒（403）',
              outsider_history.status_code == 403, outsider_history.text[:200])

    finally:
        cleanup(publications)
        print('\n[已清理] 本活动密文清单 + 本次生成的公钥（按 public_key 精确删除）')

    print(f'\n=== 结果：{passed} 通过 / {failed} 失败 ===')
    return 0 if failed == 0 else 1


def correct_canonical(value):
    """与服务器/Python 一致的规范序列化（递归排序键 + 紧凑分隔符）"""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


if __name__ == '__main__':
    raise SystemExit(main())
