// scripts/deploy.ts
import { ethers } from "hardhat";

async function main() {
  console.log("🚀 开始部署 ZKVoting 合约...");

  // 获取部署者
  const [deployer] = await ethers.getSigners();
  console.log(`📝 部署者地址: ${deployer.address}`);

  try {
    // 使用 ethers v5 语法获取余额
    const balance = await deployer.getBalance();
    console.log(`💰 部署者余额: ${ethers.utils.formatEther(balance)} ETH`);

    // 检查是否有足够的余额
    if (balance.isZero()) {
      console.log("❌ 错误: 部署者账户没有余额");
      console.log("💡 请确保已经运行: npx hardhat node");
      return;
    }

    // PoseidonT6 是 public 库：函数被外部调用，必须单独部署后再链接进 ZKVoting
    console.log("📦 正在部署 PoseidonT6 库...");
    const PoseidonT6 = await ethers.getContractFactory("PoseidonT6");
    const poseidonT6 = await PoseidonT6.deploy();
    await poseidonT6.deployed();
    console.log(`📄 PoseidonT6 地址: ${poseidonT6.address}`);
    console.log(`POSEIDON_T6_ADDRESS=${poseidonT6.address}`);

    // 部署合约
    console.log("📦 正在编译合约...");
    const ZKVoting = await ethers.getContractFactory("ZKVoting", {
      libraries: { PoseidonT6: poseidonT6.address },
    });
    
    console.log("🚀 正在部署合约...");
    const zkVoting = await ZKVoting.deploy();
    
    console.log("⏳ 等待合约部署确认...");
    await zkVoting.deployed();

    console.log("✅ ZKVoting 合约部署成功!");
    console.log(`📄 合约地址: ${zkVoting.address}`);
    console.log(`👤 部署者: ${deployer.address}`);
    // 机器可读输出：供 start-all.ps1 解析，避免依赖中文字符串匹配
    console.log(`CONTRACT_ADDRESS=${zkVoting.address}`);
    
    // 等待交易被打包。本地 Hardhat 链是 automine：每笔交易只产生 1 个区块，
    // 若等待 2 个确认会永远等不到第 2 个区块而卡死，因此只等 1 个确认。
    const deploymentTx = zkVoting.deployTransaction;
    console.log(`📦 部署交易哈希: ${deploymentTx.hash}`);
    console.log("⏳ 等待交易打包...");
    await deploymentTx.wait();
    console.log("✅ 交易已打包!");

  } catch (error) {
    console.error("❌ 部署失败:", error);
    process.exitCode = 1;
  }
}

// 执行部署
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});