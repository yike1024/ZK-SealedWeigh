# -*- coding: utf-8 -*-
"""签名审计包：把一次评审的链上事实打包成可签名、可独立复验的 JSON。

为什么需要它
------------
`audit_voting.py` 是"审计者自己跑一遍"的工具，结论只存在于审计者的终端里。
评审报告/答辩需要的是一个**可交付物**：任何人拿到 bundle.json，就能：
  1. 校验它由谁签发（EIP-191 签名，防篡改）；
  2. 重新连链，把包里的每一条事实与链上状态逐项比对；
  3. 复算加权结果、检查承诺点、检查范围证明绑定。

签名只证明"这份包由该地址签发且未被修改"，**正确性来自重算**，不来自对签发者的信任。
因此签发者用 relayer 私钥即可，不需要引入新的信任根。

包里绝不含 `secret`（评委密码）。`salt` 会包含——它在揭晓交易的 calldata 里本来就公开，
且是复验 `rangeHash` 绑定所必需。

用法
----
    # 导出（需要 RPC + 合约 ABI + .env 中的 DEPLOYER_PRIVATE_KEY）
    python scripts/audit_bundle.py --chain-id 0 --export bundle.json

    # 独立验证（第三方只需 bundle.json + RPC）
    python scripts/audit_bundle.py --verify bundle.json

    # 仅校验签名与包内自洽（无链环境时）
    python scripts/audit_bundle.py --verify bundle.json --offline
"""
import os
import sys
import json
import argparse
import datetime
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_DIR / 'scripts'))

from dotenv import load_dotenv                       # noqa: E402
from web3 import Web3                                # noqa: E402
from eth_account import Account                      # noqa: E402
from eth_account.messages import encode_defunct      # noqa: E402

from audit_voting import ARTIFACT, RPC_URL, CONTRACT_ADDRESS  # noqa: E402

load_dotenv(BACKEND_DIR / '.env')

SCHEMA = 'ZK-SealedWeigh.audit-bundle.v1'
DOMAIN = b'ZK-SealedWeigh.audit.v1'


# ==================== 基础 ====================

def connect():
    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={'timeout': 20}))
    if not w3.is_connected():
        raise SystemExit(f'[x] 连不上 RPC: {RPC_URL}')
    return w3


def load_contract(w3):
    if not ARTIFACT.exists():
        raise SystemExit(f'[x] 找不到合约 ABI: {ARTIFACT}（先执行 npx hardhat compile）')
    abi = json.loads(ARTIFACT.read_text(encoding='utf-8'))['abi']
    return w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)


def _hex(value):
    if isinstance(value, (bytes, bytearray)):
        return '0x' + bytes(value).hex()
    return str(value)


# ==================== 链上事实 ====================

def collect_facts(w3, zk, chain_id):
    """只从链上读取事实；不接触后端数据库。"""
    (title, description, creator, max_score, commit_duration, score_duration,
     start_time, is_active, phase, merkle_root) = zk.functions.votings(chain_id).call()

    candidates = list(zk.functions.getCandidates(chain_id).call())
    voters = list(zk.functions.getVoters(chain_id).call())

    total_voters, committed_voters, revealed_voters, total_scores = \
        zk.functions.getVotingStats(chain_id).call()

    voter_rows = []
    commitments = []
    for address in voters:
        weight = zk.functions.getVoterWeight(chain_id, address).call()
        commitment_hash = zk.functions.pedersenCommitments(chain_id, address).call()[0]
        xs, ys = zk.functions.getCommitmentPoints(chain_id, address).call()
        range_commitment = zk.functions.rangeCommitments(chain_id, address).call()

        voter_rows.append({'address': address, 'weight': str(weight)})
        commitments.append({
            'voter': address,
            'committed': commitment_hash != b'\x00' * 32,
            'commitment_hash': _hex(commitment_hash),
            'points': [[str(x), str(y)] for x, y in zip(xs, ys)],
            'range_commitment': str(range_commitment),
        })

    scores_rows = []
    for i in range(total_scores):
        voter, candidate_id, score, ts, weight = zk.functions.scores(chain_id, i).call()
        scores_rows.append({
            'voter': voter,
            'candidate_id': str(candidate_id),
            'score': str(score),
            'weight': str(weight),
            'timestamp': str(ts),
        })

    # 揭晓交易里的 salt / nullifier：salt 是复验 rangeHash 的必需材料，secret 绝不导出
    reveals = []
    reveal_events_ok = True
    try:
        logs = zk.events.PedersenScoreRevealed().get_logs(
            fromBlock=0, argument_filters={'votingId': chain_id})
    except Exception as exc:                              # 事件不可用时显式降级
        logs = []
        reveal_events_ok = False
        reveal_error = str(exc)

    for log in logs:
        voter = log['args']['voter']
        tx_hash = _hex(log['transactionHash'])
        salt = None
        nullifier = None
        scores_in_tx = None
        try:
            tx = w3.eth.get_transaction(log['transactionHash'])
            fn, params = zk.decode_function_input(tx['input'])
            if fn.fn_name == 'revealPedersenScores':
                salt = str(params['_salt']) if params.get('_salt') is not None else None
                nullifier = _hex(params['_nullifier']) if params.get('_nullifier') is not None else None
                scores_in_tx = [str(s) for s in params.get('_scores', [])]
        except Exception:
            pass

        range_hash_ok = False
        if salt is not None and scores_in_tx is not None:
            try:
                recomputed = zk.functions.rangeHash(
                    [int(s) for s in scores_in_tx], int(salt), voter).call()
                stored = zk.functions.rangeCommitments(chain_id, voter).call()
                range_hash_ok = int(recomputed) == int(stored) != 0
            except Exception:
                range_hash_ok = False

        reveals.append({
            'voter': voter,
            'scores': scores_in_tx if scores_in_tx is not None else [str(s) for s in log['args']['scores']],
            'weight': str(log['args']['weight']),
            'tx_hash': tx_hash,
            'salt': salt,
            'nullifier': nullifier,
            'range_binding_ok': range_hash_ok,
        })

    on_chain_results = [str(x) for x in zk.functions.getVotingResults(chain_id).call()]
    recomputed = [0] * len(candidates)
    for row in scores_rows:
        idx = int(row['candidate_id'])
        if 0 <= idx < len(recomputed):
            recomputed[idx] += int(row['score']) * int(row['weight'])

    return {
        'voting': {
            'chain_voting_id': str(chain_id),
            'title': title,
            'description': description,
            'creator': creator,
            'max_score': str(max_score),
            'commit_duration': str(commit_duration),
            'score_duration': str(score_duration),
            'start_time': str(start_time),
            'is_active': bool(is_active),
            'phase': str(phase),
            'merkle_root': _hex(merkle_root),
            'candidates': [{'id': str(i), 'name': name} for i, name in enumerate(candidates)],
            'voters': voter_rows,
        },
        'counters': {
            'total_voters': str(total_voters),
            'committed_voters': str(committed_voters),
            'revealed_voters': str(revealed_voters),
            'total_scores': str(total_scores),
            'reveal_events': str(len(logs)) if reveal_events_ok else None,
        },
        'commitments': commitments,
        'reveals': reveals,
        'scores': scores_rows,
        'tally': {
            'on_chain': on_chain_results,
            'recomputed': [str(x) for x in recomputed],
            'match': on_chain_results == [str(x) for x in recomputed],
        },
        'checks': {
            'all_points_on_curve': all(
                zk.functions.isOnCurve(int(x), int(y)).call()
                for c in commitments for x, y in c['points']
            ),
            'weights_consistent': all(
                row['weight'] == next(v['weight'] for v in voter_rows if v['address'] == row['voter'])
                for row in scores_rows
            ),
            'range_bindings_ok': all(r['range_binding_ok'] for r in reveals) if reveals else True,
            'reveal_events_readable': reveal_events_ok,
        },
    }


def build_payload(w3, zk, chain_id):
    facts = collect_facts(w3, zk, chain_id)
    block = w3.eth.get_block(w3.eth.block_number)

    findings = []
    if not facts['tally']['match']:
        findings.append('链上结果与原始 Score 复算不一致')
    if not facts['checks']['all_points_on_curve']:
        findings.append('存在不在 alt_bn128 曲线上的承诺点')
    if not facts['checks']['weights_consistent']:
        findings.append('Score 权重与 voterWeights 不一致')
    if not facts['checks']['range_bindings_ok']:
        findings.append('存在无法通过 rangeHash 复验的揭晓记录')
    if not facts['checks']['reveal_events_readable']:
        findings.append('无法读取揭晓事件，范围证明绑定未验证')
    expected_scores = int(facts['counters']['revealed_voters']) * len(facts['voting']['candidates'])
    if int(facts['counters']['total_scores']) != expected_scores:
        findings.append(
            f"Score 条数 {facts['counters']['total_scores']} != "
            f"已揭晓人数 {facts['counters']['revealed_voters']} × 候选数 "
            f"{len(facts['voting']['candidates'])}")

    return {
        'schema': SCHEMA,
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'network': {
            'chain_id': str(w3.eth.chain_id),
            'contract': CONTRACT_ADDRESS,
        },
        'snapshot': {
            'block_number': str(block['number']),
            'block_hash': _hex(block['hash']),
        },
        'facts': facts,
        'findings': findings,
        'verdict': 'PASS' if not findings else 'FAIL',
    }


# ==================== 签名 ====================

def canonical_bytes(payload):
    """稳定序列化：排序键 + 紧凑分隔符 + UTF-8，禁止浮点。"""
    return json.dumps(payload, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


def bundle_digest(payload):
    return Web3.keccak(DOMAIN + canonical_bytes(payload))


def sign_payload(payload, private_key):
    digest = bundle_digest(payload)
    signed = Account.sign_message(encode_defunct(primitive=digest), private_key=private_key)
    return {
        'scheme': 'EIP-191(32-byte digest)',
        'domain': DOMAIN.decode(),
        'signer': Account.from_key(private_key).address,
        'digest': _hex(digest),
        'signature': _hex(signed.signature),
    }


def verify_signature(payload, attestation):
    digest = bundle_digest(payload)
    if _hex(digest).lower() != str(attestation.get('digest', '')).lower():
        return False, 'digest 与 payload 不匹配（包已被修改）'
    try:
        recovered = Account.recover_message(
            encode_defunct(primitive=digest), signature=attestation['signature'])
    except Exception as exc:
        return False, f'签名无法恢复：{exc}'
    if recovered.lower() != str(attestation.get('signer', '')).lower():
        return False, f'签名者不符：恢复 {recovered} vs 声明 {attestation.get("signer")}'
    return True, recovered


# ==================== 导出 / 验证 ====================

def export(chain_id, out_path):
    w3 = connect()
    zk = load_contract(w3)
    payload = build_payload(w3, zk, chain_id)

    private_key = os.getenv('DEPLOYER_PRIVATE_KEY')
    if not private_key:
        raise SystemExit('[x] .env 缺少 DEPLOYER_PRIVATE_KEY，无法签发审计包')
    attestation = sign_payload(payload, private_key)

    bundle = {'payload': payload, 'attestation': attestation}
    Path(out_path).write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding='utf-8')

    facts = payload['facts']
    print('=' * 62)
    print(f"审计包导出 · 活动 #{chain_id} 《{facts['voting']['title']}》")
    print('=' * 62)
    print(f"签名者     {attestation['signer']}")
    print(f"摘要       {attestation['digest']}")
    print(f"区块快照   #{payload['snapshot']['block_number']} "
          f"{payload['snapshot']['block_hash'][:18]}…")
    print(f"评委 {facts['counters']['total_voters']} / 已承诺 {facts['counters']['committed_voters']}"
          f" / 已揭晓 {facts['counters']['revealed_voters']}"
          f" / Score 条数 {facts['counters']['total_scores']}")
    print(f"链上结果   {facts['tally']['on_chain']}")
    print(f"独立复算   {facts['tally']['recomputed']}")
    print(f"范围绑定   {'通过' if facts['checks']['range_bindings_ok'] else '未通过'}")
    print(f"结论       {payload['verdict']}")
    if payload['findings']:
        print('\n发现的问题：')
        for item in payload['findings']:
            print(f'  - {item}')
    print(f"\n已写入 {out_path}")
    return 0 if payload['verdict'] == 'PASS' else 1


def verify(bundle_path, offline=False):
    # utf-8-sig：Windows 下用记事本/PowerShell 另存过的 JSON 常带 BOM，直接 utf-8 会解析失败
    bundle = json.loads(Path(bundle_path).read_text(encoding='utf-8-sig'))
    payload = bundle.get('payload') or {}
    attestation = bundle.get('attestation') or {}

    print('=' * 62)
    print(f'审计包验证 · {bundle_path}')
    print('=' * 62)

    sig_ok, signer_or_reason = verify_signature(payload, attestation)
    print(f"schema      {payload.get('schema')}")
    print(f"签名校验    {'通过' if sig_ok else '失败'} ({signer_or_reason})")
    if not sig_ok:
        print('\n结论：FAIL（签名无效，后续无需再验）')
        return 1

    if payload.get('schema') != SCHEMA:
        print(f'\n结论：FAIL（schema 不支持：{payload.get("schema")}）')
        return 1

    if offline:
        local_ok = (payload.get('verdict') == 'PASS'
                    and payload['facts']['tally']['match'] is True)
        print(f"包内自洽    {'通过' if local_ok else '失败'}（离线模式不做链上比对）")
        print(f"\n结论：{'PASS' if local_ok else 'FAIL'}")
        return 0 if local_ok else 1

    # —— 链上重算：第三方不需要信任签发者，也不需要我们的数据库 ——
    chain_id = int(payload['facts']['voting']['chain_voting_id'])
    w3 = connect()
    zk = load_contract(w3)

    if Web3.to_checksum_address(CONTRACT_ADDRESS) != Web3.to_checksum_address(
            payload['network']['contract']):
        print(f"合约地址不符：当前 {CONTRACT_ADDRESS} vs 包内 {payload['network']['contract']}")
        print('\n结论：FAIL（请用包内记录的网络/合约复验）')
        return 1

    live = collect_facts(w3, zk, chain_id)
    mismatches = []
    for key in ('voting', 'counters', 'commitments', 'reveals', 'scores', 'tally', 'checks'):
        if live[key] != payload['facts'][key]:
            mismatches.append(key)

    if mismatches:
        print(f"链上比对    不一致（{', '.join(mismatches)}）")
        for key in mismatches:
            print(f'  - {key}: 包内与当前链状态不同')
        print('\n结论：FAIL（链状态已变化或包内容被篡改）')
        return 1

    print('链上比对    一致（voting / counters / commitments / reveals / scores / tally / checks）')
    ok = live['tally']['match'] and live['checks']['range_bindings_ok'] and \
        live['checks']['all_points_on_curve'] and live['checks']['weights_consistent']
    print(f"范围绑定    {'通过' if live['checks']['range_bindings_ok'] else '未通过'}")
    print(f"承诺点      {'全部在曲线上' if live['checks']['all_points_on_curve'] else '存在非法点'}")
    print(f"结果复算    {'一致' if live['tally']['match'] else '不一致'}")
    print(f"\n结论：{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description='签名审计包导出 / 独立验证')
    parser.add_argument('--chain-id', type=int, help='链上活动 id（导出时必需）')
    parser.add_argument('--export', metavar='PATH', help='导出签名审计包到指定文件')
    parser.add_argument('--verify', metavar='PATH', help='验证一个审计包')
    parser.add_argument('--offline', action='store_true', help='验证时不做链上比对（仅签名与包内自洽）')
    args = parser.parse_args()

    if args.export:
        if args.chain_id is None:
            raise SystemExit('[x] --export 需要同时指定 --chain-id')
        return export(args.chain_id, args.export)
    if args.verify:
        return verify(args.verify, offline=args.offline)
    raise SystemExit('[x] 请指定 --export PATH --chain-id N 或 --verify PATH')


if __name__ == '__main__':
    raise SystemExit(main())
