// scripts/deploy-simple.ts
import { ethers } from "hardhat";

async function main() {
  console.log("🚀 开始部署 ZKVoting 合约...");

  const [deployer] = await ethers.getSigners();
  console.log("📝 部署者地址:", deployer.address);

  const ZKVoting = await ethers.getContractFactory("ZKVoting");
  const zkVoting = await ZKVoting.deploy(
    "测试投票活动",
    "这是一个测试投票活动",
    10,
    86400, // 24小时
    172800, // 48小时
    ["候选人A", "候选人B"],
    [deployer.address],
    [100],
    "0x0000000000000000000000000000000000000000000000000000000000000001"
  );

  await zkVoting.waitForDeployment();
  const address = await zkVoting.getAddress();
  
  console.log("✅ ZKVoting合约部署成功!");
  console.log("📝 合约地址:", address);
}

main().catch(console.error);