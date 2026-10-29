// hardhat-project/hardhat.config.ts
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    // 本地开发网络
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337
    },
    // 兼容Ganache（如果需要）
    ganache: {
      url: "http://127.0.0.1:7545",
      chainId: 1337
    }
  },
  paths: {
    artifacts: "../frontend/contract-artifacts",
    cache: "./cache",
    sources: "./contracts",
    tests: "./test"
  },
  // 修正 TypeChain 配置 - 使用 ethers-v5
  typechain: {
    outDir: "../frontend/typechain-types",
    target: "ethers-v5"  // 改为 ethers-v5
  }
};

export default config;