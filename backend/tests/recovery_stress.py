# -*- coding: utf-8 -*-
"""P3.6 多评委门限恢复压力测试（3 评委 / k=2）。

与 recovery_flow.py 的区别：那边是 2 位评委只能退化为 k=1（任何单方都能
独立恢复），这里用 3 位评委、n=2、k=2 验证真正的门限语义：

  · 1 份份额无法重构（Shamir 门限不达标必须失败）
  · 2 份份额才能解开托管密文，且逐字段与原始载荷一致
  · 收集到 1 份时请求状态仍为 open，2 份后变为 collected

活动通过 publisher API 创建（enable_blockchain=false），恢复链路本身是
纯链下协议，不依赖链上状态；测试结束后删除活动与全部恢复数据。

前置：后端已启动。
运行：
    cd backend
    $env:PYTHONUTF8='1'; python tests\\recovery_stress.py
退出码：0 = 全部通过，1 = 失败（保留现场）。
"""
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

# Hardhat 本地链的公开测试账户（仅用于本地验收）
VOTERS = [
    {'userId': 2, 'username': 'voter1',
     'wallet': '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
     'key': '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'},
    {'userId': 3, 'username': 'voter2',
     'wallet': '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
     'key': '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'},
    {'userId': 4, 'username': 'voter3',
     'wallet': '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
     'key': '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6'},
]
THRESHOLD = 2          # 3 位评委：份额发给另外 2 位，n=2，取 k=2
PAYLOAD = {'scores': [6, 8, 9], 'secret': 'three trustees threshold two',
           'salt': '09876543210987654321'}

passed = 0
failed = 0
voting_id = None


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


def build_payload(target_voting_id):
    request = {
        'votingId': target_voting_id,
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


def create_voting(admin_token):
    """用 publisher API 创建 3 评委活动（纯 DB，不上链）。"""
    body = {
        'title': '多评委门限恢复压力测试',
        'description': 'P3.6 自动化验收：3 评委 k=2',
        'candidates': ['候选A', '候选B', '候选C'],
        'voters': [{'username': v['username'], 'weight': 1.0} for v in VOTERS],
        'max_score': 10,
        'enable_zk_proof': True,
        'enable_blockchain': False,
    }
    response = requests.post(f'{API}/voting/', headers=auth(admin_token),
                             json=body, timeout=30)
    return response


def cleanup(publications):
    """删除本测试创建的活动及其全部恢复数据。"""
    from database import db
    if voting_id:
        db.execute_query(
            """
            DELETE FROM recovery_shares
             WHERE request_id IN (SELECT id FROM recovery_requests WHERE voting_id = ?)
            """,
            (voting_id,)
        )
        db.execute_query('DELETE FROM recovery_requests WHERE voting_id = ?', (voting_id,))
        db.execute_query('DELETE FROM recovery_enrollments WHERE voting_id = ?', (voting_id,))
    for userId, item in publications.items():
        db.execute_query('DELETE FROM recovery_keys WHERE user_id = ? AND public_key = ?',
                         (userId, item['publicKey']))
    if voting_id:
        # candidates / voting_voters / enrollments / requests 均为 ON DELETE CASCADE
        db.execute_query('DELETE FROM voting_sessions WHERE id = ?', (voting_id,))


def main():
    global voting_id
    print('\n=== P3.6 多评委门限恢复压力测试（3 评委 k=2）===\n')
    admin_token = login('admin')
    tokens = {v['userId']: login(v['username']) for v in VOTERS}
    publications = {}

    try:
        print('--- 0. 创建 3 评委活动 ---')
        response = create_voting(admin_token)
        created = response.json().get('data') or {}
        voting_id = int(created.get('id') or 0)
        check('publisher 创建活动成功（201）', response.status_code == 201, response.text[:200])
        check('活动处于承诺阶段', created.get('phase') == 'commit', created.get('phase'))
        check('活动含 3 位评委', len(created.get('voters') or []) == 3,
              created.get('voters'))
        if not voting_id:
            raise RuntimeError('未取得活动 id，无法继续')

        print('\n--- 1. 生成客户端载荷 ---')
        bundle = build_payload(voting_id)
        publications = {item['userId']: item for item in bundle['keyPublications']}
        enrollment = bundle['enrollment']
        check('Node 生成 3 份公钥', len(publications) == 3)
        check('manifest.recipients 为除自己外的 2 位评委',
              sorted(enrollment['manifest']['recipients']) == [3, 4],
              enrollment['manifest']['recipients'])
        check('manifest 含 2 个信封哈希',
              len(enrollment['manifest']['envelopeHashes']) == 2)
        check('escrow 与信封均不含明文',
              PAYLOAD['secret'] not in json.dumps(enrollment) and
              PAYLOAD['secret'] not in json.dumps(enrollment['envelopes']))

        print('\n--- 2. 三位评委发布公钥并登记 ---')
        for voter in VOTERS:
            item = publications[voter['userId']]
            response = requests.post(
                f'{API}/recovery/keys', headers=auth(tokens[voter['userId']]),
                json={'publicKey': item['publicKey'],
                      'signature': sign_text(voter['key'], item['message'])},
                timeout=20)
            check(f'{voter["username"]} 公钥发布成功（200）', response.status_code == 200,
                  response.text[:200])

        keys_data = requests.get(f'{API}/recovery/keys?votingId={voting_id}',
                                 headers=auth(tokens[2]), timeout=20).json()['data']
        check('公钥列表含 3 位评委', len(keys_data['voters']) == 3)
        check('所有公钥就绪', keys_data['allKeysReady'] is True)

        manifest_message = enrollment['manifestMessage']
        response = requests.post(f'{API}/recovery/enroll', headers=auth(tokens[2]),
                                 json={
                                     'votingId': voting_id,
                                     'escrow': enrollment['escrow'],
                                     'envelopes': enrollment['envelopes'],
                                     'manifest': enrollment['manifest'],
                                     'manifestMessage': manifest_message,
                                     'signature': sign_text(VOTERS[0]['key'], manifest_message),
                                 }, timeout=30)
        enrolled = response.json().get('data') or {}
        check('登记成功（201）', response.status_code == 201, response.text[:200])
        check('返回 threshold=2 / envelopeCount=2',
              enrolled.get('threshold') == 2 and enrolled.get('envelopeCount') == 2, enrolled)

        print('\n--- 3. 恢复请求与双方信封 ---')
        response = requests.post(f'{API}/recovery/request', headers=auth(tokens[2]),
                                 json={'votingId': voting_id}, timeout=20)
        request_data = response.json().get('data') or {}
        request_id = int(request_data.get('requestId') or 0)
        check('丢失方创建恢复请求（201）', response.status_code == 201, response.text[:200])
        check('请求 threshold=2', request_data.get('threshold') == 2, request_data)

        for voter in VOTERS[1:]:
            listed = requests.get(f'{API}/recovery/requests?votingId={voting_id}',
                                  headers=auth(tokens[voter['userId']]), timeout=20
                                  ).json()['data']['requests']
            mine = [item for item in listed if item['requestId'] == request_id]
            check(f'{voter["username"]} 能看到请求且未投递',
                  len(mine) == 1 and mine[0]['submittedByMe'] is False, listed)

        envelope_data = requests.get(
            f'{API}/recovery/requests/{request_id}/envelopes',
            headers=auth(tokens[3]), timeout=20).json().get('data') or {}
        check('信封接收者包含两位评委',
              sorted(envelope_data.get('recipientIds') or []) == [3, 4],
              envelope_data.get('recipientIds'))
        check('信封数量为 2 且与登记一致',
              envelope_data.get('envelopes') == enrollment['envelopes'])

        print('\n--- 4. 第 1 份份额：门限不达标 ---')
        shares = {}
        for index, voter in enumerate(VOTERS[1:]):
            shares[voter['userId']] = run_action('share', {
                'votingId': voting_id,
                'requestId': request_id,
                'requesterWallet': VOTERS[0]['wallet'],
                'trusteeWallet': voter['wallet'],
                'trusteePrivateJwk': bundle['privateKeys'][str(voter['userId'])],
                'enrollmentEnvelope': enrollment['envelopes'][index],
                'requesterPublicKey': publications[2]['publicKey'],
            })

        first = shares[3]
        first_body = {
            'requestId': request_id,
            'envelope': first['envelope'],
            'message': first['message'],
            'signature': sign_text(VOTERS[1]['key'], first['message']),
        }

        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[2]),
                                 json=first_body, timeout=20)
        check('请求者给自己投递被拒（403）', response.status_code == 403, response.text[:200])

        wrong_signer = dict(first_body, signature=sign_text(VOTERS[2]['key'], first['message']))
        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[3]),
                                 json=wrong_signer, timeout=20)
        check('他人签名投递被拒（401）', response.status_code == 401, response.text[:200])

        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[3]),
                                 json=first_body, timeout=30)
        first_result = response.json().get('data') or {}
        check('voter2 份额投递成功（201）', response.status_code == 201, response.text[:200])
        check('收集 1/2，尚未达到门限',
              first_result.get('collected') == 1 and first_result.get('ready') is False,
              first_result)

        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[3]),
                                 json=first_body, timeout=20)
        check('重复投递被拒（409）', response.status_code == 409, response.text[:200])

        box = requests.get(f'{API}/recovery/sharebox/{request_id}',
                           headers=auth(tokens[2]), timeout=20).json().get('data') or {}
        check('请求者读到 1 份份额', len(box.get('shares', [])) == 1, box)
        check('份额来源为 voter2',
              box['shares'][0]['fromWallet'].lower() == VOTERS[1]['wallet'].lower())
        check('份额箱不含任何明文',
              PAYLOAD['secret'] not in json.dumps(box) and
              'scores' not in json.dumps(box).lower())

        try:
            run_action('recover', {
                'votingId': voting_id,
                'requesterWallet': VOTERS[0]['wallet'],
                'requesterPrivateJwk': bundle['privateKeys']['2'],
                'escrow': enrollment['escrow'],
                'shares': [{'fromWallet': item['fromWallet'], 'envelope': item['envelope']}
                           for item in box['shares']],
            })
            check('仅 1 份份额无法重构（门限生效）', False, '竟然恢复成功')
        except RuntimeError as exc:
            check('仅 1 份份额无法重构（门限生效）', True,
                  str(exc).splitlines()[0][:120])

        request_listed = requests.get(f'{API}/recovery/requests?votingId={voting_id}',
                                      headers=auth(tokens[2]), timeout=20
                                      ).json()['data']['requests']
        check('请求者看不到自己的请求', request_listed == [])

        print('\n--- 5. 第 2 份份额：达到门限 ---')
        second = shares[4]
        second_body = {
            'requestId': request_id,
            'envelope': second['envelope'],
            'message': second['message'],
            'signature': sign_text(VOTERS[2]['key'], second['message']),
        }
        response = requests.post(f'{API}/recovery/sharebox', headers=auth(tokens[4]),
                                 json=second_body, timeout=30)
        second_result = response.json().get('data') or {}
        check('voter3 份额投递成功（201）', response.status_code == 201, response.text[:200])
        check('收集 2/2，达到门限',
              second_result.get('collected') == 2 and second_result.get('ready') is True,
              second_result)

        box = requests.get(f'{API}/recovery/sharebox/{request_id}',
                           headers=auth(tokens[2]), timeout=20).json().get('data') or {}
        check('请求者读到 2 份份额', len(box.get('shares', [])) == 2, box)

        recovered = run_action('recover', {
            'votingId': voting_id,
            'requesterWallet': VOTERS[0]['wallet'],
            'requesterPrivateJwk': bundle['privateKeys']['2'],
            'escrow': enrollment['escrow'],
            'shares': [{'fromWallet': item['fromWallet'], 'envelope': item['envelope']}
                       for item in box['shares']],
        })['recovered']
        check('2 份份额重构出的载荷与原始完全一致', recovered == PAYLOAD, recovered)

        tampered = json.loads(json.dumps(box['shares'][0]))
        ct_text = tampered['envelope']['ct']
        tampered['envelope']['ct'] = ('A' if ct_text[0] != 'A' else 'B') + ct_text[1:]
        try:
            run_action('recover', {
                'votingId': voting_id,
                'requesterWallet': VOTERS[0]['wallet'],
                'requesterPrivateJwk': bundle['privateKeys']['2'],
                'escrow': enrollment['escrow'],
                'shares': [{'fromWallet': item['fromWallet'], 'envelope': item['envelope']}
                           for item in box['shares'][:1]] +
                          [{'fromWallet': tampered['fromWallet'],
                            'envelope': tampered['envelope']}],
            })
            check('篡改任意一份份额导致重构失败', False, '竟然成功了')
        except RuntimeError:
            check('篡改任意一份份额导致重构失败', True)

        from database import db
        row = db.execute_query(
            'SELECT status FROM recovery_requests WHERE id = ?', (request_id,))[0]
        check('达到门限后请求状态为 collected', row['status'] == 'collected', row['status'])

    finally:
        cleanup(publications)
        print('\n[已清理] 测试活动 + 全部恢复数据 + 本次生成的公钥')

    print(f'\n=== 结果：{passed} 通过 / {failed} 失败 ===')
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
