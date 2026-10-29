# -*- coding: utf-8 -*-
"""把数据库中 blockchain_id 为 NULL 的活动补建到链上（幂等）。

为什么需要它：
    `database/init.sql` 直接 INSERT 的种子活动没有链上记录，导致
    `blockchain_id IS NULL` —— 该活动的承诺 / 揭晓会被 `_prepare_onchain`
    直接跳过链上路径，界面上看起来"正常"，但链上什么都没有。

本脚本按数据库里的真实配置（候选、评委地址、权重、时长、创建者）重建链上活动，
并把返回的链上 id 写回 `voting_sessions.blockchain_id`。

用法（无需启动 Flask，但 hardhat node 必须在运行）：
    python scripts/repair_onchain_votings.py
    python scripts/repair_onchain_votings.py --dry-run
"""
import sys
import argparse
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from database import db                                    # noqa: E402
from services.blockchain import blockchain_service, derive_placeholder_address  # noqa: E402


def build_payload(voting):
    """从 DB 还原 create_voting_on_chain 需要的参数"""
    voting_id = voting['id']

    candidates = [r['name'] for r in db.execute_query(
        "SELECT name FROM candidates WHERE voting_id = ? ORDER BY order_index", (voting_id,))]

    voter_rows = db.execute_query(
        """SELECT vv.voter_id, vv.weight, u.wallet_address, u.username
           FROM voting_voters vv
           JOIN users u ON vv.voter_id = u.id
           WHERE vv.voting_id = ?
           ORDER BY vv.id""", (voting_id,))

    voters, weights = [], []
    for row in voter_rows:
        address = row['wallet_address'] or derive_placeholder_address(row['username'])
        voters.append(address)
        # DB 权重是浮点（1.0 = 等权），链上用整数放大 100 倍
        weights.append(int(round(float(row['weight']) * 100)))

    creator_rows = db.execute_query(
        "SELECT wallet_address FROM users WHERE id = ?", (voting['creator_id'],))
    creator = creator_rows[0]['wallet_address'] if creator_rows else None

    return {
        'title': voting['title'],
        'description': voting['description'] or '',
        'max_score': int(voting['max_score']),
        # DB 里存的是"小时"，链上参数是"秒"
        'commit_duration': int(voting['commit_duration']) * 3600,
        'score_duration': int(voting['score_duration']) * 3600,
        'candidates': candidates,
        'voters': voters,
        'weights': weights,
        'creator': creator,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true', help='只打印，不写链/不改库')
    args = parser.parse_args()

    if not blockchain_service.is_connected():
        print('[x] 区块链未连接，请先启动 hardhat node (127.0.0.1:8545)')
        return 1

    pending = db.execute_query(
        "SELECT * FROM voting_sessions WHERE blockchain_id IS NULL ORDER BY id")
    if not pending:
        print('[i] 没有 blockchain_id 为 NULL 的活动，无需处理')
        return 0

    print(f'[i] 待补建 {len(pending)} 个活动')
    ok = 0
    for voting in pending:
        payload = build_payload(voting)
        print(f"\n  → id={voting['id']} 《{voting['title']}》")
        print(f"    候选 {len(payload['candidates'])} 个 / 评委 {len(payload['voters'])} 人 "
              f"/ 权重 {payload['weights']}")
        print(f"    承诺阶段 {payload['commit_duration']}s，评分阶段 {payload['score_duration']}s")

        if len(payload['candidates']) < 2 or not payload['voters']:
            print('    [skip] 候选人或评委不足，合约会拒绝创建')
            continue
        if args.dry_run:
            print('    [dry-run] 跳过实际写链')
            continue

        chain_id = blockchain_service.create_voting_on_chain(payload)
        if chain_id is None:
            print('    [x] 上链失败，跳过')
            continue

        db.execute_query(
            "UPDATE voting_sessions SET blockchain_id = ?, updated_at = GETDATE() WHERE id = ?",
            (chain_id, voting['id']))
        print(f'    [✓] 已上链，blockchain_id = {chain_id}')
        ok += 1

    print(f'\n完成：成功 {ok} / 待处理 {len(pending)}')
    return 0 if ok or args.dry_run else 2


if __name__ == '__main__':
    raise SystemExit(main())
