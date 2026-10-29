# -*- coding: utf-8 -*-
"""端到端验收：新建活动 → 承诺 → 范围证明 → 揭晓 → 结算 → 审计 → 审计包。

与 test_protocol.py 的区别：本脚本是**集成验收**，需要三件东西同时在线：
  1. Hardhat 本地链（127.0.0.1:8545，合约已部署）
  2. Flask 后端（127.0.0.1:5000）
  3. SQL Server（backend/.env 配置）

每次运行都会**新建一个活动**（唯一标题），因此可重复执行且不污染种子活动。
默认成功后清理该活动的数据库记录（链上记录不可删，保留作证据）；加 --keep 可保留。

运行：
    cd backend
    $env:PYTHONUTF8='1'; python tests\\e2e_flow.py
    $env:PYTHONUTF8='1'; python tests\\e2e_flow.py --keep

退出码：0 = 全部通过；1 = 存在失败（会保留现场并打印活动 id）。
"""
import argparse
import datetime
import json
import sys
import tempfile
from pathlib import Path

import requests
from eth_account import Account
from eth_account.messages import encode_defunct

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_DIR / 'scripts'))

from dotenv import load_dotenv                     # noqa: E402

load_dotenv(BACKEND_DIR / '.env')

from utils import protocol                         # noqa: E402
from utils.pedersen import zkp_commitment          # noqa: E402

API = 'http://127.0.0.1:5000/api'
FIXTURE = PROJECT_DIR / 'circuits' / 'build' / 'proof_fixture.json'

SCORES = [7, 9, 0]
SECRET = 'correct horse battery staple'
MAX_SCORE = 10

# Hardhat 本地链的公开测试账户 #1（voter1），私钥仅用于本地验收
VOTER_ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'
VOTER_KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'

passed = 0
failed = 0
created_voting_id = None
created_chain_id = None


def check(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  [PASS] {name}')
    else:
        failed += 1
        print(f'  [FAIL] {name} {detail}')


def header(text):
    print(f'\n--- {text} ---')


def login(username):
    response = requests.post(f'{API}/auth/login',
                             json={'username': username, 'password': '123456'}, timeout=15)
    response.raise_for_status()
    return response.json()['data']['token']


def auth(token):
    return {'Authorization': f'Bearer {token}'}


def sign_voter(digest):
    return Account.sign_message(encode_defunct(hexstr=digest),
                                private_key=VOTER_KEY).signature.hex()


def main(keep=False):
    header('0. 环境前置检查')
    try:
        health = requests.get(f'{API}/health', timeout=10).json()
    except Exception as exc:
        print(f'  [FAIL] 后端不可达：{exc}')
        return 1
    check('后端健康', health.get('status') == 'healthy', health.get('status'))
    check('数据库连接', health['dependencies'].get('database') == 'healthy',
          health['dependencies'].get('database'))
    check('区块链连接', health['dependencies'].get('blockchain') == 'connected',
          health['dependencies'].get('blockchain'))
    contract = health['dependencies'].get('blockchain_info', {}).get('contract_address', '')
    check('合约地址与 .env 一致',
          contract.lower() == __import__('os').getenv('CONTRACT_ADDRESS', '').lower(),
          f'{contract} vs {__import__("os").getenv("CONTRACT_ADDRESS")}')
    check('范围证明样本存在', FIXTURE.exists(), str(FIXTURE))
    if failed:
        print('\n前置条件不满足，终止。')
        return 1

    fixture = json.loads(FIXTURE.read_text(encoding='utf-8'))
    check('样本与本次评分/评委一致',
          fixture['scores'] == SCORES and fixture['voter'].lower() == VOTER_ADDRESS.lower(),
          fixture.get('voter'))

    admin = login('admin')
    voter = login('voter1')

    # ---------- 1. 新建活动 ----------
    header('1. 新建活动（发布者链路）')
    title = f'P2.8 验收 {datetime.datetime.now():%Y-%m-%d %H:%M:%S}'
    payload = {
        'title': title,
        'description': '端到端验收自动创建，可安全删除',
        'candidates': ['验收候选 A', '验收候选 B', '验收候选 C'],
        'voters': [{'username': 'voter1', 'weight': 1.0},
                   {'username': 'voter2', 'weight': 1.0}],
        'max_score': MAX_SCORE,
        'commit_duration': 24,
        'score_duration': 48,
        'enable_blockchain': True,
    }
    response = requests.post(f'{API}/voting/', headers=auth(admin), json=payload, timeout=60)
    body = response.json()
    global created_voting_id, created_chain_id
    created_voting_id = (body.get('data') or {}).get('id')
    created_chain_id = (body.get('data') or {}).get('blockchain_id')
    check('活动创建成功（201）', response.status_code == 201, response.status_code)
    check('活动已上链', created_chain_id is not None, body.get('data', {}).get('blockchain_id'))
    if not created_voting_id or created_chain_id is None:
        print('\n创建失败，终止。')
        return 1

    detail = requests.get(f'{API}/voting/{created_voting_id}', headers=auth(voter), timeout=15).json()
    check('候选人数 = 3', len(detail['data']['candidates']) == 3,
          len(detail['data']['candidates']))
    check('满分 = 10', detail['data']['max_score'] == MAX_SCORE, detail['data']['max_score'])

    # ---------- 2. 承诺 ----------
    header('2. Pedersen 承诺上链')
    generated = zkp_commitment.generate_score_commitments(SCORES, SECRET, MAX_SCORE)
    commits = generated['commitments']
    commitment_hash = protocol.hex0x(
        protocol.commitment_hash(created_chain_id, VOTER_ADDRESS, SCORES, SECRET, MAX_SCORE))

    body = requests.post(f'{API}/voting/{created_voting_id}/commitments', headers=auth(voter),
                         json={'commitments': commits, 'commitment_hash': commitment_hash},
                         timeout=30).json()
    check('承诺写入数据库', body.get('success') is True, body)
    onchain = (body.get('data') or {}).get('onchain') or {}
    check('返回承诺签名摘要', bool(onchain.get('digest')), onchain)
    if not onchain.get('digest'):
        print('\n承诺接口未返回摘要，终止。')
        return 1

    body = requests.post(f'{API}/voting/{created_voting_id}/onchain/relay', headers=auth(voter),
                         json={'action': 'commit', 'digest': onchain['digest'],
                               'signature': sign_voter(onchain['digest'])}, timeout=60).json()
    check('承诺交易上链', body.get('success') is True, body)

    # ---------- 3. 范围证明 ----------
    header('3. Groth16 范围证明上链')
    body = requests.post(f'{API}/voting/{created_voting_id}/onchain/relay', headers=auth(voter),
                         json={'action': 'range'}, timeout=30).json()
    check('缺评委签名被拒', body.get('success') is False and 'signature' in (body.get('message') or ''),
          body)

    body = requests.post(f'{API}/voting/{created_voting_id}/onchain/relay', headers=auth(voter),
                         json={'action': 'range', 'signature': '0x' + '00' * 65}, timeout=30).json()
    check('缺参数被拒', body.get('success') is False and '范围证明参数' in (body.get('message') or ''),
          body)

    a, b, c = fixture['calldata'][:3]
    # P5（R-10）：范围证明必须由评委签名，签名绑定 commitment
    range_digest = protocol.hex0x(protocol.range_digest(
        created_chain_id, VOTER_ADDRESS, int(fixture['commitment'])))
    body = requests.post(f'{API}/voting/{created_voting_id}/onchain/relay', headers=auth(voter),
                         json={'action': 'range', 'commitment': fixture['commitment'],
                               'proof': {'a': a, 'b': b, 'c': c},
                               'digest': range_digest,
                               'signature': sign_voter(range_digest)}, timeout=90).json()
    check('范围证明上链', body.get('success') is True, body)

    # ---------- 4. 阶段推进与权重冻结 ----------
    header('4. 阶段推进与权重冻结')
    body = requests.put(f'{API}/voting/{created_voting_id}/phase', headers=auth(admin),
                        json={'phase': 'scoring'}, timeout=60).json()
    check('推进到评分阶段', body.get('success') is True, body)

    freeze = requests.put(f'{API}/weights/voting/{created_voting_id}/voter/2',
                          headers=auth(admin), json={'weight': 2.0}, timeout=20)
    check('评分阶段权重冻结（409）', freeze.status_code == 409, freeze.status_code)

    # ---------- 5. 揭晓 ----------
    header('5. 揭晓（带 salt 与范围绑定）')
    body = requests.post(f'{API}/voting/{created_voting_id}/commitments/verify',
                         headers=auth(voter),
                         json={'scores': SCORES, 'secret': 'wrong-secret',
                               'salt': fixture['salt']}, timeout=30).json()
    check('错误密码被拒', (body.get('data') or {}).get('is_valid') is False, body)

    body = requests.post(f'{API}/voting/{created_voting_id}/commitments/verify',
                         headers=auth(voter),
                         json={'scores': SCORES, 'secret': SECRET, 'salt': fixture['salt']},
                         timeout=30).json()
    check('链下 Pedersen 校验通过', (body.get('data') or {}).get('is_valid') is True, body)
    reveal = (body.get('data') or {}).get('onchain') or {}
    check('返回揭晓签名摘要', bool(reveal.get('digest')), reveal)
    if not reveal.get('digest'):
        print('\n揭晓接口未返回摘要，终止。')
        return 1

    body = requests.post(f'{API}/voting/{created_voting_id}/onchain/relay', headers=auth(voter),
                         json={'action': 'reveal', 'digest': reveal['digest'],
                               'signature': sign_voter(reveal['digest']),
                               'scores': SCORES, 'secret': SECRET}, timeout=30).json()
    check('缺 salt 被拒', body.get('success') is False and 'salt' in (body.get('message') or ''),
          body)

    body = requests.post(f'{API}/voting/{created_voting_id}/onchain/relay', headers=auth(voter),
                         json={'action': 'reveal', 'digest': reveal['digest'],
                               'signature': sign_voter(reveal['digest']),
                               'scores': SCORES, 'secret': SECRET, 'salt': '0'}, timeout=60).json()
    check('错误 salt 被链上拒绝', body.get('success') is False, body)

    body = requests.post(f'{API}/voting/{created_voting_id}/onchain/relay', headers=auth(voter),
                         json={'action': 'reveal', 'digest': reveal['digest'],
                               'signature': sign_voter(reveal['digest']),
                               'scores': SCORES, 'secret': SECRET,
                               'salt': fixture['salt']}, timeout=90).json()
    check('揭晓上链', body.get('success') is True, body)

    # ---------- 6. 结算与独立审计 ----------
    header('6. 结算与独立审计')
    body = requests.put(f'{API}/voting/{created_voting_id}/phase', headers=auth(admin),
                        json={'phase': 'completed'}, timeout=90).json()
    check('结算触发成功', body.get('success') is True, body)

    from audit_voting import audit
    report = audit(created_chain_id)
    check('链下审计 PASS', report['verdict'] == 'PASS', report['findings'])
    check('链上结果 = [700, 900, 0]', report['results']['on_chain'] == [700, 900, 0],
          report['results']['on_chain'])

    # ---------- 7. 签名审计包 ----------
    header('7. 签名审计包导出与独立验证')
    import audit_bundle
    bundle_path = Path(tempfile.gettempdir()) / f'zk_e2e_bundle_{created_chain_id}.json'
    try:
        export_rc = audit_bundle.export(created_chain_id, str(bundle_path))
        check('审计包导出 PASS', export_rc == 0, export_rc)
        verify_rc = audit_bundle.verify(str(bundle_path))
        check('审计包独立验证 PASS', verify_rc == 0, verify_rc)

        raw = bundle_path.read_text(encoding='utf-8-sig')
        check('审计包不含 secret 明文', '"secret"' not in raw)
        bundle = json.loads(raw)
        check('审计包含范围证明绑定记录',
              all(r.get('range_binding_ok') for r in bundle['payload']['facts']['reveals']),
              bundle['payload']['facts']['reveals'])
    finally:
        bundle_path.unlink(missing_ok=True)

    # ---------- 8. 清理 ----------
    if keep:
        print(f'\n[保留现场] 数据库活动 id={created_voting_id}，链上 id={created_chain_id}')
    else:
        cleanup(created_voting_id)
        print(f'\n[已清理] 数据库活动 id={created_voting_id}；链上 id={created_chain_id} 保留')

    print(f'\n=== 结果：{passed} 通过 / {failed} 失败 ===')
    if failed:
        print(f'（现场保留：数据库活动 id={created_voting_id}，链上 id={created_chain_id}）')
    return 0 if failed == 0 else 1


def cleanup(voting_id):
    from database import db
    for sql in (
        'DELETE FROM voting_scores WHERE voting_id = ?',
        'DELETE FROM voting_commitments WHERE voting_id = ?',
        'DELETE FROM voting_voters WHERE voting_id = ?',
        'DELETE FROM candidates WHERE voting_id = ?',
        'DELETE FROM voting_sessions WHERE id = ?',
    ):
        db.execute_query(sql, (voting_id,))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P2.8 端到端验收')
    parser.add_argument('--keep', action='store_true', help='成功后保留数据库记录以便人工查看')
    args = parser.parse_args()
    raise SystemExit(main(keep=args.keep))
