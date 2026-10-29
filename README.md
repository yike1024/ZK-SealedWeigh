# 零知识密封加权评审系统（ZK-SealedWeigh）

基于 **Pedersen 承诺** 与 **区块链 commit–reveal** 的密封加权评审系统：评委在「承诺阶段」提交分数的密码学承诺，在「揭晓阶段」才公开，系统按权重加权汇总，全过程与结果可链上审计。

> 一句话：**把评审的"打分"做成先密封、后揭晓、可验证的链上流程。**

---

## 核心特性

| 特性 | 说明 |
|---|---|
| 密封评审（commit–reveal） | 分数先承诺后揭晓，抑制从众、串通与中途翻盘 |
| 本地生成承诺 | 承诺点 `C = v·G + r·H` 在**浏览器本地**计算，明文分数与 `secret` 不上传、不入库 |
| 链上可验证承诺 | alt_bn128 + EIP-196/197 预编译，合约**自己重算** `C_i`，relayer 无法替换承诺点 |
| **零知识范围证明** | Groth16（circom/snarkjs）在**评委浏览器本地**生成，证明「所有分数 ∈ [0, maxScore]」且不泄露分数；合约用 `Groth16Verifier` 验证，揭晓时 `Poseidon(scores,salt,voter)` 与承诺比对 |
| 加权汇总 | 结果 = Σ(分数 × 权重)，支持等权 / 自定义权重 |
| 评委白名单 | Merkle 树限定合法评委，由合约校验（`verifyMerkleProof`） |
| 重复提交防护 | nullifier 在合约内去重（`usedNullifiers`） |
| 钱包签名授权 | 评委用 **EIP-191** 签名，后端仅作 relayer 代发，无法伪造他人承诺 |
| 阶段与状态同步 | 发布者推进阶段，DB 状态单向同步到链；进入终态触发链上结算 |
| 角色权限 | `publisher`（建活动 / 管权重 / 推进阶段）与 `voter`（提交承诺与揭晓） |

---

## 系统架构

| 层 | 位置 | 技术 |
|---|---|---|
| 前端 | `frontend/` | 原生 HTML + JavaScript，MetaMask 钱包，`zk-utils.js` 统一封装 API 与签名 |
| 后端 | `backend/` | Flask 2.3 + Flask-JWT-Extended + SQLAlchemy |
| 数据 | `database/init.sql` | SQL Server（6 张业务表） |
| 链 | `hardhat-project/` | Solidity 0.8.20 + Hardhat + OpenZeppelin 4.9 |

**评审协议（三条关键链路）**

1. **建活动**：`publisher` 提交候选、评委、权重 → 后端写库并 `createVoting` 上链，同时写入评委地址的 Merkle 根与发布者 `creator`。
2. **承诺（commit）**：评委在浏览器本地计算 Pedersen 承诺 `C = v·G + r·H`（**alt_bn128**）+ 随机 `salt` + **Groth16 范围证明** → 后端返回待签名摘要 → 评委钱包 `personal_sign` → 后端 relayer 代发 `submitPedersenCommitment`，合约校验每个点是否在曲线上、验签、校验 Merkle 白名单；随后评委对 `rangeDigest` 签名，relayer 代发 `submitRangeProof`，合约验签并验证证明后记录 `rangeCommitments`。
3. **揭晓（reveal）**：评委提交 `(分数, 密码, salt)` → 后端先做链下椭圆曲线校验 → 自动落分 → relayer 代发 `revealPedersenScores`，**合约派生并校验 nullifier、用 EIP-196/197 预编译重算 `C_i` 并逐点比对**，再用 `Poseidon` 校验揭晓分数正是被范围证明过的那一组，最后重算承诺哈希、按权重写入链上分数。

**签名摘要（合约 / 后端 / 前端三方逐字节一致，详见 [`spec.md`](spec.md)）**

```
commitmentHash   = keccak256(abi.encode(TAG_COMMITMENT, votingId, voter, scores, secret, maxScore))
commitDigest     = keccak256(abi.encode(TAG_COMMIT_SIG,  votingId, voter, commitmentHash))
revealDigest     = keccak256(abi.encode(TAG_REVEAL_SIG, votingId, voter, scores, nullifier))
deriveNullifier  = keccak256(abi.encode(TAG_NULLIFIER, votingId, voter))
rangeDigest      = keccak256(abi.encode(TAG_RANGE_SIG,  votingId, voter, commitment))
ethHash          = keccak256("\x19Ethereum Signed Message:\n32" || digest)   // EIP-191
ECDSA.recover(ethHash, signature) == voter
```

- 五个域分隔标签前缀 `ZK-SealedWeigh.*.v3`，杜绝跨用途摘要重放。
- 编码一律 `abi.encode`（动态类型带 offset/length），禁止 `abi.encodePacked` 拼接动态类型。
- `commitmentHash` 绑定 `votingId` 与 `voter`，不同活动/评委之间不可移植。

**链上可验证承诺（v3 的核心增量）**

v2 的链上只存 `keccak(承诺点)` + 承诺哈希，而**哈希并不包含承诺点**——持有评委签名的 relayer 可以把点替换成任意值，链上无从发现。
v3 把曲线迁到 EVM 唯一带预编译的 **alt_bn128（BN254）**，将 `(x, y)` 原值上链，揭晓时由合约自己验算：

```
r_i      = sha256("secret:i:n") mod n            // 链上 sha256 预编译
(gx,gy)  = ecMul(G, v_i)     // 0x07
(hx,hy)  = ecMul(H, r_i)     // 0x07
(cx,cy)  = ecAdd((gx,gy),(hx,hy))  // 0x06
require(cx == storedX[i] && cy == storedY[i], "Pedersen point mismatch")
```

单点约 `2×6000 + 2×150 ≈ 12.3k gas`。合约测试中包含"relayer 替换承诺点 → 揭晓必定 revert"的攻击用例。

**零知识范围证明（P2.6 接入）**

Pedersen 承诺钉住"分数没被改"，但钉不住"分数在合法区间"。区间性由 Groth16 证明承担：

```
承诺阶段（评委浏览器本地）
  salt          ← crypto.getRandomValues(31B)
  commitment    = Poseidon([scores…], salt, uint160(voter))     // 电路公开信号
  proof         = groth16.fullProve(...)                        // vendor/zk/*.wasm + *.zkey
  → 只上传 commitment 与 proof，salt 留在 localStorage

链上
  submitRangeProof(votingId, voter, commitment, a, b, c, signature)
    ← 评委对 rangeDigest 签名：relayer 不能替换 commitment（R-10）
    ← 合约以 pubSignals = [commitment, maxScore] 调 Groth16Verifier

揭晓
  require(rangeHash(scores, salt, voter) == rangeCommitments[voter])
```

电路按 **3 个候选人**编译（369 约束）；不足 3 个补 0，多于 3 个链上直接 revert。
可信设置为本地单方 `pot12` 仪式，**仅开发/演示用途**，生产须多方 MPC 或公开 ptau。

---

## 快速开始

### 前置依赖

| 依赖 | 版本要求 | 说明 |
|---|---|---|
| Python | **3.9**（推荐） | `requirements.txt` 为固定旧版本，3.13/3.14 无预编译 wheel；**且须开启 UTF-8 模式（`PYTHONUTF8=1`）** |
| Node.js | **18 / 20 LTS** | Hardhat 不支持 22+ / 25（会有告警） |
| SQL Server | 任意 | 需 `ODBC Driver 17 for SQL Server` |
| MetaMask | — | 需添加本地网络 RPC `http://127.0.0.1:8545`，chainId `31337` |

### 一键启动（推荐）

```powershell
cd d:\国赛\voting-system\voting-system
powershell -ExecutionPolicy Bypass -File .\start-all.ps1
```

脚本会依次：起本地链 → 编译并部署合约 → 自动把新合约地址写入 `backend/.env` → 起后端 → 起前端。
（已部署过、不想重新部署时加 `-SkipDeploy`。）

### 手动启动

```powershell
# 1) 依赖（首次）
py -3.9 -m venv C:\Users\<你>\.venvs\zkvoting
C:\Users\<你>\.venvs\zkvoting\Scripts\Activate.ps1
cd backend; pip install -r requirements.txt

# 2) 本地链（保持运行）
cd ..\hardhat-project; npx hardhat node

# 3) 部署（另开终端）
npx hardhat run scripts/deploy.ts --network localhost   # 记下打印的合约地址

# 4) 配置
#   复制 backend/.env.example 为 backend/.env，填 CONTRACT_ADDRESS / DEPLOYER_PRIVATE_KEY 等

# 5) 起服务（先启用 UTF-8 模式，否则中文 Windows 下 web3 读数据文件会报错）
cd ..\backend; $env:PYTHONUTF8='1'; python app.py        # http://127.0.0.1:5000
cd ..\frontend; python server.py                         # http://127.0.0.1:3001
```

### 一条命令验收（P2.8）

链与后端启动后，在项目根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\verify-all.ps1
```

脚本依次跑完 12 个环节，任一失败返回非零：

| 环节 | 内容 | 规模 |
|---|---|---|
| 1 | `npx hardhat test test/digest.test.ts test/rangeProof.test.ts`（摘要/派生值 + 范围证明链上验证与替换攻击回归） | 19 项 |
| 2 | `circuits/scripts/prove.js`（证明生成 + 负向用例） | 9 项 |
| 3 | `backend/tests/test_protocol.py`（协议向量、曲线、承诺原语、nullifier/range 派生） | 25 项 |
| 4 | `backend/tests/test_api.py`（认证、角色、错误码、后门与恢复接口回归） | 37 项 |
| 5 | `backend/tests/e2e_flow.py`（新建活动 → 承诺 → 范围证明签名 → 揭晓 → 结算 → 审计包） | 31 项 |
| 6 | `frontend/tests/recovery.test.js`（Shamir / AES-GCM / ECDH，含完整恢复流程） | 41 项 |
| 7 | `backend/tests/recovery_flow.py`（公钥、托管、请求、份额投递、本地重构、全局待办/活动总览/恢复历史、拒绝路径） | 54 项 |
| 8 | `backend/tests/recovery_stress.py`（3 评委 k=2：单份不可恢复、两份重构一致、收集中状态迁移） | 36 项 |
| 9 | `frontend/tests/recovery-key-store.test.js`（IndexedDB 存储、v1 迁移、密钥轮换、元信息、换账号/篡改拒绝） | 40 项 |
| 10 | `backend/tests/model_check.py`（P4 有界模型检验：阶段单调性等 7 条安全不变量 + 缺陷模型反例） | 7 项 |
| 11 | `hardhat-project/test/fuzz.test.ts`（P4 合约状态机模糊测试：随机阶段序列 + 完整生命周期 + 签名/白名单篡改） | 3 项 |
| 12 | `backend/tests/test_fuzz_api.py` + `frontend/tests/recovery-fuzz.test.js`（P4 接口畸形输入 111 例 + 恢复密码学 40 轮随机测试） | 391 项 |

合计 693 项断言。

前置条件：8545（链）与 5000（后端）在线、合约已部署、证明构件齐全。脚本只验证，不启动或重启服务。
`-FailFast` 可让首个失败立即停止；`-Python` 可指定解释器（默认项目 venv）。

> 没有 MetaMask 时做本地 UI 走查：在页面 URL 加 `?devwallet=0x…`（仅 `localhost` / `127.0.0.1` 生效），
> `frontend/dev-wallet.js` 会把 Hardhat 已解锁账户包装成 `window.ethereum`；私钥始终留在本地节点。
> 这是开发工具，生产演示仍应使用真实钱包。

> `e2e_flow.py` 每次新建一个活动并在成功后清理数据库记录；链上记录不可删，保留作为证据。

---

## 配置（`backend/.env`）

| 变量 | 必填 | 说明 |
|---|---|---|
| `DB_SERVER` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` / `DB_PORT` / `DB_DRIVER` | ✅ | SQL Server 连接信息 |
| `JWT_SECRET_KEY` | ✅ | JWT 签名密钥，**请改为随机强密钥** |
| `JWT_ACCESS_TOKEN_EXPIRES` | | 令牌有效期（秒），默认 86400 |
| `HOST` / `PORT` | | 后端监听地址/端口，默认 `127.0.0.1:5000` |
| `CORS_ORIGINS` | | 允许的前端来源 |
| `BLOCKCHAIN_RPC_URL` | | 链 RPC，默认 `http://127.0.0.1:8545`（勿用 `localhost`，Windows 会先走 IPv6 导致每次连接多等约 2s） |
| `CONTRACT_ADDRESS` | ✅（链功能） | 部署脚本打印的合约地址 |
| `DEPLOYER_PRIVATE_KEY` | ✅（链功能） | relayer 私钥；**仅本地开发使用，严禁提交仓库** |
| `CHAIN_ID` | | 默认 `31337` |

> 敏感项均无硬编码默认值：缺失时后端会在启动阶段**明确报错**（见 `backend/config.py`）。

---

## 目录结构

```
voting-system/
├─ backend/                   Flask 后端
│  ├─ app.py                  应用入口、路由与错误处理、蓝图注册
│  ├─ config.py               集中配置（无硬编码密钥）
│  ├─ database.py             SQL Server 连接封装
│  ├─ models/                 users / voting_sessions / candidates / ... 数据访问
│  ├─ routes/                 auth / voting / scores / weights / blockchain 蓝图
│  ├─ services/blockchain.py  链交互：ABI、摘要构造、Merkle、阶段同步
│  └─ utils/                  auth（JWT/角色）、pedersen（承诺）
├─ frontend/                  9 个页面 + zk-utils.js / zk-wallet.js + server.py
├─ hardhat-project/           ZKVoting.sol、部署脚本、Hardhat 配置
└─ database/init.sql          建库建表 + 种子数据
```

---

## 已知限制与路线图

协议 v3（见 [`spec.md`](spec.md)）已完成的安全加固：

| # | 早期现状 | 当前状态 |
|---|---|---|
| 1 | 链上**不校验承诺点**，只比 `commitmentHash`；哈希不含点，relayer 可替换 | **v3 已修复**：曲线迁至 alt_bn128，`(x,y)` 原值上链，合约用 `ecAdd/ecMul` 重算并逐点比对 |
| 2 | 保密性仅来自 Pedersen 承诺，范围证明等"零知识"部分未实现 | **P2.6 已实现**：Groth16 范围证明在浏览器本地生成，链上 `Groth16Verifier` 验证；残留限制是单方可信设置与 3 候选上限 |
| 3 | DB 用 `sha256/JSON`、链上用 `keccak`，**两套摘要并存** | **已修复**：三方统一到 `abi.encode` + 域分隔的单一套摘要（`utils/protocol.py` 为唯一实现） |
| 4 | 发布者可 `recoverPedersenScores` 代他人揭晓 | **已移除**：合约函数、`/scores/recover`（返回 410）、admin 入口全部下线 |
| 5 | `voting_commitments.secret` 明文入库 | **已修复**：承诺在浏览器本地生成，DB 仅存承诺点与承诺哈希 |
| 6 | 投票进行中权重可被修改并回写历史分数 | **已修复**：`scoring` 及之后阶段改权重返回 409 |
| 7 | relayer 中心化（可延迟/审查） | 待解决：多签或门限中继 |

后续计划：多方可信设置仪式、支持更多候选的电路、门限恢复的去中心化中继。
门限恢复已通过 **3 评委 k=2 压力测试（P3.6）**，并完成 **交互式三步向导（P3.7）**：
步骤条、门禁校验、份额进度自动轮询、URL 断点续做，见 [`spec.md`](spec.md) 第 11 节与 `frontend/recovery.html`。

> **升级提示（v3.1 → v3.2，P5 / R-3 + R-10）**：`nullifier` 改为合约内
> `deriveNullifier(votingId, voter)` 派生；`submitRangeProof` 新增 `bytes signature`。
> 旧 ABI 与旧 nullifier **不兼容**，必须重新部署合约并重建数据库（步骤同下）。

> **升级提示（v2 → v3）**：曲线由 secp256k1 改为 **alt_bn128**，域分隔标签升至 `.v3`，
> 合约承诺存储由 `bytes32[]`（点的哈希）改为 `uint256[] commitmentX/Y`（点的原值）。
> 旧数据全部失效，必须重新部署合约并重建数据库：
>
> ```powershell
> # 1) 重建数据库（会删除全部旧数据）
> sqlcmd -S "tcp:localhost,1433" -U sa -P <口令> -Q "ALTER DATABASE ZKVotingSystem SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE ZKVotingSystem"
> sqlcmd -S "tcp:localhost,1433" -U sa -P <口令> -f 65001 -i database\init.sql
> # 2) 重新部署合约（hardhat node 需已启动）
> cd hardhat-project; npx hardhat run scripts/deploy.ts --network localhost
> # 3) 重启后端（编译产物 ABI 会自动加载，无需手工同步）
> ```
>
> 浏览器端旧 `localStorage` 中的 `zkc:commit:*`（secp256k1 承诺）已失效，需重新提交承诺。

> **升级提示（v1 → v2）**：`voting_commitments` 表已移除 `scores` / `secret` / `blinding_factors` 三列，
> 且签名摘要格式变更为域分隔版本。旧库与旧合约**不兼容**，必须重建数据库并重新部署合约：
>
> ```powershell
> # 1) 重建数据库（会删除全部旧数据）
> sqlcmd -S "tcp:localhost,1433" -U sa -P <口令> -Q "DROP DATABASE IF EXISTS ZKVotingSystem"
> sqlcmd -S "tcp:localhost,1433" -U sa -P <口令> -f 65001 -i database\init.sql
> # 2) 重新部署合约（hardhat node 需已启动）
> cd hardhat-project; npx hardhat run scripts/deploy.ts --network localhost
> # 3) 重启后端，使 .env 中的合约地址生效
> ```

---

## 运维与审计脚本

`backend/scripts/` 下三个脚本都可以独立运行（仅需 hardhat node 与 `.env`）：

**1. 把未上链的活动补建到链上（幂等）**

```powershell
cd backend
$env:PYTHONUTF8='1'; python scripts\repair_onchain_votings.py --dry-run   # 先看要处理哪些
$env:PYTHONUTF8='1'; python scripts\repair_onchain_votings.py
```

`database/init.sql` 直接插入的种子活动没有链上记录（`blockchain_id IS NULL`），
建库后跑一次即可把它补齐；否则该活动的承诺/揭晓会**静默跳过链上路径**。

**2. 链下独立审计（只读链上数据）**

```powershell
cd backend
python scripts\audit_voting.py --chain-id 2 --json audit.json
```

审计器**不连接数据库**，只用 RPC + 合约地址复算：

| 检查项 | 判据 |
|---|---|
| 结果一致 | `Σ(score × weight)` 逐条聚合 == `getVotingResults()` |
| 权重一致 | 每条 `Score.weight` == `voterWeights` |
| 条数完整 | `totalScores == revealedVoters × candidateCount`，无重复 `(voter, candidate)` |
| 点合法 | 每个承诺点 `isOnCurve(x, y) == true` |

退出码 0 = PASS，1 = FAIL。

> **已知边界**：揭晓时只公开 `(scores, weight)`，未公开盲化因子 `r_i`，
> 因此审计器目前**不能**独立验算"承诺点是否对应某分数"。下一步是在揭晓交易中公开 `r_i`
> （而非 `secret`，避免跨活动可链接性）。

**3. 导出 / 验证签名审计包（P2.7）**

```powershell
cd backend
# 导出（用 relayer 私钥做 EIP-191 签名）
$env:PYTHONUTF8='1'; python scripts\audit_bundle.py --chain-id 0 --export audit-bundle.json

# 第三方验证：重新连链、逐节比对、复算结果与范围证明绑定
$env:PYTHONUTF8='1'; python scripts\audit_bundle.py --verify audit-bundle.json

# 无链环境时：只校验签名与包内自洽
$env:PYTHONUTF8='1'; python scripts\audit_bundle.py --verify audit-bundle.json --offline
```

审计包是一个约 5 KB 的 JSON，包含链上活动配置、承诺点、揭晓记录、逐条 Score、
计票结果与检查项；`attestation` 段给出签名者、摘要与签名。

| 特性 | 说明 |
|---|---|
| 签名域 | `keccak256("ZK-SealedWeigh.audit.v1" ‖ canonical_json(payload))`，EIP-191 |
| 规范序列化 | 排序键 + 紧凑分隔符 + UTF-8，数值一律字符串（禁止浮点） |
| 隐私边界 | **不含 `secret`**；`salt` 来自揭晓交易 calldata，用于复验范围证明绑定 |
| 正确性来源 | 不信任签名者：验证方重新连链、重算 `Σ(score×weight)` 与 `rangeHash` |
| 快照锚点 | `block_number` + `block_hash` |

签名只解决"来源与完整性"，**正确性来自重算**。链状态在导出后继续变化会导致在线验证失败——
这正说明包记录的是某一时刻的事实。

---

## 范围证明（`circuits/`）

证明「每位候选人的分数 ∈ [0, maxScore]」而不泄露分数，Groth16 / alt_bn128。

**工具链**：`circom 2.0.8`（WASM 版 `circom2`）+ `circomlib 2.0.5` + `snarkjs 0.7.5`

**电路**（`circuits/range_proof.circom`）：369 个非线性约束，2 个公开输出，6 个私有输入
- `Num2Bits(8)` + `LessEqThan(8)` 断言 `0 ≤ scores[i] ≤ maxScore`；
- `Poseidon(scores, salt, voter)` 作为公开承诺，把"已验证范围的分数向量"钉住并绑定评委；
- `maxScore` 透传为公开输出，防止证明跨活动复用。

**复现**：

```powershell
cd circuits
npm install                                   # circom2 / circomlib / circomlibjs

# 1) 编译
npx circom2 range_proof.circom --r1cs --wasm --sym -l node_modules -o build

# 2) 可信设置（本地 dev 仪式）
$S = "..\backend\node_modules\snarkjs\build\cli.cjs"
node $S powersoftau new bn128 12 pot12_0000.ptau
node $S powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name=dev -e="seed"
node $S powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau
node $S groth16 setup build\range_proof.r1cs pot12_final.ptau range_proof_0000.zkey
node $S zkey contribute range_proof_0000.zkey range_proof.zkey --name=dev -e="seed2"
node $S zkey export verificationkey range_proof.zkey verification_key.json
node $S zkey export solidityverifier range_proof.zkey ..\hardhat-project\contracts\Groth16RangeVerifier.sol

# 3) 生成 + 验证证明（产物：build/proof_fixture.json）
node scripts\prove.js

# 4) 链上验证
cd ..\hardhat-project; npx hardhat test test\rangeProof.test.ts

# 5) 同步浏览器端证明构件
copy ..\circuits\build\range_proof_js\range_proof.wasm ..\frontend\vendor\zk\
copy ..\circuits\range_proof.zkey ..\frontend\vendor\zk\
```

**结果**

| 项 | 数值 |
|---|---|
| 电路约束 | 369 |
| 链下证明 + 验证 | 9/9 通过 |
| 链上 `verifyProof` gas | 221,437 |
| 承诺 / 范围证明 / 揭晓 gas | 280,738 / 261,618 / 678,757 |
| 负向用例 | 超范围（11）、负数（`p-1`）均无法生成证明；篡改公开承诺或 `maxScore`、换评委地址后验证失败 |

> ⚠️ **两条必须说明的边界**
> 1. **可信设置是单方本地生成的**（`pot12` 只有一个 contributor），toxic waste 可被重建，
>    理论上可伪造证明。仅用于开发/演示；生产必须用公开 ptau 或多方 MPC 仪式。
> 2. 电路只编译到 **3 个候选人**；更多候选的活动链上会 `revert("Range proof supports at most 3 candidates")`，
>    需要重新编译电路并重做 setup。

---

## 常见问题

**Q：重启了 `npx hardhat node`，链上提交/揭晓失败？**
A：链状态已被重置，`votingCount` 归零，而 DB 旧记录的 `blockchain_id` 仍指向消失的编号。请**重建数据库**（`database/init.sql`）或**重新创建评审活动**。

**Q：创建活动成功，但 `blockchain_id` 一直是 `null`（永远不上链）？**
A：先看后端日志里有没有 `BlockchainService object has no attribute ...` 或 `non-hexadecimal number found in fromhex()`。
前者是历史 Bug（路由层把模块级函数当实例方法调用），后者是用户没绑钱包时用用户名拼出的假地址——
用户名不是十六进制，`keccak256(abi.encodePacked(address))` 会直接抛错。v2 已修复：占位地址改为
`keccak256(utf8(username))` 派生，且建活动与 Merkle 证明共用同一函数（`derive_placeholder_address`）。

**Q：所有接口都慢约 2 秒（`/api/voting/`、`/api/health` 尤其明显）？**
A：`.env` 的 `BLOCKCHAIN_RPC_URL` 写成了 `localhost`。Windows 会先解析到 IPv6 `::1`，而 Hardhat 只监听 IPv4，
每次连接都要空等约 2s 才回退（实测 2091ms vs 24ms）。改成 `http://127.0.0.1:8545` 即可，接口降到几十毫秒。

**Q：relayer 发交易报 `'SignedTransaction' object has no attribute 'raw_transaction'`？**
A：eth-account 0.9.x 用驼峰 `rawTransaction`，0.10+ 才改成 `raw_transaction`。代码已用
`services/blockchain.py::signed_raw_transaction()` 兼容两种命名；若自行升级依赖后仍报错，检查该函数是否被绕过。

**Q：浏览器 Network 里看到 `net::ERR_ABORTED /api/voting/`，但页面数据又正常显示？**
A：多为页面在请求返回前发生跳转（登录后重定向、手动切页）导致请求被浏览器取消，属正常现象。
若确实伴随 2s 级延迟，按上一条排查 RPC 地址。

**Q：后端启动报 `No module named 'flask_sqlalchemy'`？**
A：用错了解释器。请始终用装好依赖的那个（如 venv 内的 `python`），不要用系统默认 `python`。

**Q：`npx hardhat node` 出现 Node 版本告警？**
A：用 Node 18/20 LTS 可消除；告警本身通常不影响运行。

**Q：评委钱包必须用哪个账户？**
A：必须与建活动时登记的 `wallet_address` 一致（Merkle 白名单由该地址构成）。本地演示请导入 Hardhat 打印的账户私钥。

**Q：种子账号的密码是什么？**
A：`admin` / `voter1` / `voter2` / `voter3` 口令**均为 `123456`**，其钱包地址分别对应 Hardhat 账户 #0 / #1 / #2 / #3（`voter3` 用于 3 评委门限恢复压力测试）。

**Q：启动报 `UnicodeDecodeError: 'gbk' codec can't decode byte 0x88`？**
A：中文 Windows 下 Python 默认按 GBK 解码文件，`web3` / `eth_utils` 读取自带的 UTF-8 JSON 会失败。启动前设 `$env:PYTHONUTF8='1'`，或永久执行 `setx PYTHONUTF8 1`（需重开终端）。

**Q：注册/登录时报数据库连接失败（`10061` / “目标计算机积极拒绝”）？**
A：SQL Server 服务未启动。以**管理员**身份运行 `net start MSSQLSERVER`，再用 `Get-NetTCPConnection -LocalPort 1433` 确认 1433 已在监听。

**Q：页面上的中文变成乱码（如 `绀轰緥璇勫…`）？**
A：用 `sqlcmd` 执行 `init.sql` 时未加 `-f 65001`，UTF-8 脚本被按 GBK 读入并写进了库。删库后带该参数重建：
`sqlcmd -S "tcp:localhost,1433" -U sa -P <口令> -f 65001 -i database\init.sql`。

---

## 许可

仅供学习与竞赛使用。
