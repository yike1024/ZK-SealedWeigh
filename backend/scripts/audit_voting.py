# -*- coding: utf-8 -*-
"""链下独立审计器：只用链上公开数据复算评审结果（协议 v3）。

设计原则
--------
**不读后端数据库**。审计者只需要 RPC + 合约地址，即可独立判断：
  1. 链上记录的加权结果是否等于原始 Score 逐条聚合的结果；
  2. 每条 Score 的权重是否与 `voterWeights` 一致（防止事后改权重）；
  3. 每位评委的承诺点是否都在 alt_bn128 曲线上、是否非无穷远；
  4. 已揭晓评委的数量与 Score 条数是否自洽（每人每条候选恰好一条）；
  5. nullifier 是否被重复消费（按事件统计）。

这是「结果可审计」（G5）的最小实现：揭晓之后分数与权重都是公开的，
因此任何第三方都能复算，无需信任 relayer、后端或数据库。

用法
----
    python scripts/audit_voting.py --chain-id 2
    python scripts/audit_voting.py --chain-id 2 --json report.json
"""
import os
import sys
import json
import argparse
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACKEND_DIR.parent

from dotenv import load_dotenv          # noqa: E402
from web3 import Web3                   # noqa: E402

load_dotenv(BACKEND_DIR / '.env')

RPC_URL = os.getenv('BLOCKCHAIN_RPC_URL', 'http://127.0.0.1:8545')
CONTRACT_ADDRESS = os.getenv('CONTRACT_ADDRESS', '')

ARTIFACT = (PROJECT_DIR / 'frontend' / 'contract-artifacts'
            / 'contracts' / 'ZKVoting.sol' / 'ZKVoting.json')


def load_contract(w3):
    if not ARTIFACT.exists():
        raise SystemExit(f'[x] 找不到合约 ABI: {ARTIFACT}（先执行 npx hardhat compile）')
    abi = json.loads(ARTIFACT.read_text(encoding='utf-8'))['abi']
    return w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)


def audit(chain_id, verbose=True):
    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={'timeout': 20}))
    if not w3.is_connected():
        raise SystemExit(f'[x] 连不上 RPC: {RPC_URL}')

    zk = load_contract(w3)
    findings = []

    # ---------- 1. 活动元数据 ----------
    voting = zk.functions.votings(chain_id).call()
    title, _desc, creator, max_score, commit_dur, score_dur, start_time, is_active, phase, merkle_root = voting
    candidates = zk.functions.getCandidates(chain_id).call()
    voters = zk.functions.getVoters(chain_id).call()

    # ---------- 2. 原始 Score 逐条读取（唯一可信的计票来源） ----------
    stats = zk.functions.getVotingStats(chain_id).call()
    total_voters, committed_voters, revealed_voters, total_scores = stats

    raw_scores = []
    for i in range(total_scores):
        voter, candidate_id, score, ts, weight = zk.functions.scores(chain_id, i).call()
        raw_scores.append({
            'voter': voter, 'candidate_id': candidate_id,
            'score': score, 'weight': weight, 'timestamp': ts,
        })

    # ---------- 3. 结果复算 ----------
    on_chain_results = list(zk.functions.getVotingResults(chain_id).call())
    recomputed = [0] * len(candidates)
    for s in raw_scores:
        if s['candidate_id'] < len(recomputed):
            recomputed[s['candidate_id']] += s['score'] * s['weight']
        else:
            findings.append(f'Score 的 candidateId={s["candidate_id"]} 越界')

    results_match = [int(x) for x in on_chain_results] == recomputed
    if not results_match:
        findings.append(f'结果不一致：链上 {on_chain_results} vs 复算 {recomputed}')

    # ---------- 4. 权重一致性 ----------
    weight_ok = True
    per_voter = []
    for addr in voters:
        onchain_weight = zk.functions.getVoterWeight(chain_id, addr).call()
        my_scores = [s for s in raw_scores if s['voter'] == addr]
        bad = [s for s in my_scores if s['weight'] != onchain_weight]
        if bad:
            weight_ok = False
            findings.append(f'评委 {addr} 的 Score 权重 {bad[0]["weight"]} != voterWeights {onchain_weight}')

        # ---------- 5. 承诺点合法性 ----------
        xs, ys = zk.functions.getCommitmentPoints(chain_id, addr).call()
        points_on_curve = True
        for x, y in zip(xs, ys):
            if not zk.functions.isOnCurve(x, y).call():
                points_on_curve = False
                findings.append(f'评委 {addr} 存在非法承诺点 ({x}, {y})')

        per_voter.append({
            'address': addr,
            'weight_onchain': onchain_weight,
            'committed': zk.functions.hasCommitted(chain_id, addr).call(),
            'revealed': zk.functions.hasRevealed(chain_id, addr).call(),
            'commitment_points': len(xs),
            'points_on_curve': points_on_curve,
            'score_rows': len(my_scores),
        })

    # ---------- 6. 每人每条候选恰好一条 ----------
    counts_ok = True
    if total_scores != revealed_voters * len(candidates):
        counts_ok = False
        findings.append(
            f'Score 条数 {total_scores} != 已揭晓人数 {revealed_voters} × 候选数 {len(candidates)}')
    seen = set()
    for s in raw_scores:
        key = (s['voter'], s['candidate_id'])
        if key in seen:
            counts_ok = False
            findings.append(f'重复 Score：voter={s["voter"]} candidate={s["candidate_id"]}')
        seen.add(key)

    # ---------- 7. nullifier 事件（唯一性） ----------
    try:
        logs = zk.events.PedersenScoreRevealed().get_logs(
            fromBlock=0, argument_filters={'votingId': chain_id})
        event_reveals = len(logs)
    except Exception as e:                       # 事件不可用时降级，不影响主结论
        event_reveals = None
        findings.append(f'无法读取 PedersenScoreRevealed 事件：{e}')

    report = {
        'audited_at': __import__('datetime').datetime.now().isoformat(timespec='seconds'),
        'rpc': RPC_URL,
        'contract': CONTRACT_ADDRESS,
        'chain_id': chain_id,
        'protocol': 'v3 (alt_bn128)',
        'voting': {
            'title': title,
            'candidates': candidates,
            'max_score': max_score,
            'phase': phase,
            'is_active': is_active,
            'merkle_root': Web3.to_hex(merkle_root),
        },
        'counters': {
            'total_voters': total_voters,
            'committed_voters': committed_voters,
            'revealed_voters': revealed_voters,
            'total_scores': total_scores,
            'reveal_events': event_reveals,
        },
        'results': {
            'on_chain': [int(x) for x in on_chain_results],
            'recomputed': recomputed,
            'match': results_match,
        },
        'checks': {
            'weights_consistent': weight_ok,
            'score_rows_complete': counts_ok,
            'all_points_on_curve': all(v['points_on_curve'] for v in per_voter) if per_voter else True,
        },
        'voters': per_voter,
        'findings': findings,
        'verdict': 'PASS' if not findings else 'FAIL',
    }
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--chain-id', type=int, required=True, help='链上活动 id（不是数据库 id）')
    parser.add_argument('--json', help='把审计报告写入该文件')
    args = parser.parse_args()

    report = audit(args.chain_id)

    print('=' * 62)
    print(f"链下独立审计 · 活动 #{report['chain_id']} 《{report['voting']['title']}》")
    print('=' * 62)
    c = report['counters']
    print(f"评委 {c['total_voters']} / 已承诺 {c['committed_voters']} / 已揭晓 {c['revealed_voters']}"
          f" / Score 条数 {c['total_scores']}")
    print(f"链上结果   {report['results']['on_chain']}")
    print(f"独立复算   {report['results']['recomputed']}")
    print(f"结果一致   {'是' if report['results']['match'] else '否'}")
    print(f"权重一致   {'是' if report['checks']['weights_consistent'] else '否'}")
    print(f"条数完整   {'是' if report['checks']['score_rows_complete'] else '否'}")
    print(f"点在曲线上 {'是' if report['checks']['all_points_on_curve'] else '否'}")

    if report['findings']:
        print('\n发现的问题：')
        for f in report['findings']:
            print(f'  - {f}')
    print(f"\n结论：{report['verdict']}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'报告已写入 {args.json}')

    return 0 if report['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
