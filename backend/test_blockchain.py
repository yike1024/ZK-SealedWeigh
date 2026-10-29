# -*- coding: utf-8 -*-
import asyncio
import sys
import os

# 添加当前目录到路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.blockchain import blockchain_service


def test_blockchain_integration():
    """测试区块链集成功能"""
    print("🧪 开始区块链集成测试...")

    # 1. 测试连接
    print("1. 测试区块链连接...")
    if blockchain_service.is_connected():
        print("   ✅ 区块链连接成功")
        print(f"   📄 合约地址: {blockchain_service.contract_address}")
        print(f"   👤 账户地址: {blockchain_service.account.address}")
        print(f"   🔗 网络ID: {blockchain_service.w3.eth.chain_id}")
    else:
        print("   ❌ 区块链连接失败")
        return

    # 2. 测试创建投票
    print("2. 测试创建投票...")
    try:
        test_voting_data = {
            'title': '集成测试投票',
            'description': '测试区块链集成功能',
            'max_score': 10,
            'commit_duration': 3600,  # 1小时
            'score_duration': 7200,  # 2小时
            'candidates': ['候选A', '候选B', '候选C'],
            'voters': [blockchain_service.account.address],
            'weights': [100]  # 权重为1.0 * 100
        }

        voting_id = blockchain_service.create_voting_on_chain(test_voting_data)
        print(f"   ✅ 投票创建成功，ID: {voting_id}")

        # 3. 测试获取投票信息
        print("3. 测试获取投票信息...")
        voting_info = blockchain_service.get_voting_info(voting_id)
        print(f"   📋 投票标题: {voting_info['title']}")
        print(f"   🎯 候选人: {voting_info['candidates']}")
        print(f"   👥 投票者: {voting_info['voters']}")

        # 4. 测试提交承诺（投票者钱包签名 -> relayer 代发）
        print("4. 测试提交 Pedersen 承诺（含 EIP-191 签名）...")
        from eth_account import Account
        from eth_account.messages import encode_defunct

        scores = [8, 7, 9]
        secret = "test_secret_123"
        max_score = test_voting_data['max_score']
        voter = blockchain_service.account.address

        overall_hash = blockchain_service.compute_onchain_overall_hash(scores, secret, max_score)
        digest = blockchain_service.build_commit_digest(voting_id, voter, overall_hash)
        signed = Account.sign_message(encode_defunct(primitive=digest), private_key=blockchain_service.private_key)

        # 承诺数量必须与候选人数一致
        score_commitments = [b"\x00" * 32 for _ in test_voting_data['candidates']]
        merkle_proof = []  # 单投票者 Merkle 树，proof 为空

        success = blockchain_service.submit_pedersen_commitment_on_chain(
            voting_id,
            voter,
            overall_hash,
            score_commitments,
            merkle_proof,
            signed.signature
        )
        print(f"   {'✅' if success else '❌'} 承诺提交{'成功' if success else '失败'}")

        # 5. 测试投票数量
        voting_count = blockchain_service.get_voting_count()
        print(f"5. 当前投票总数: {voting_count}")

    except Exception as e:
        print(f"   ❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_blockchain_integration()