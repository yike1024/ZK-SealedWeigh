# ZK-SealedWeigh 协议规约（Spec v3）

> 本文件是**规范性文件**：链上合约（Solidity）、后端（Python）、前端（JavaScript）三方的摘要构造、
> 字段编码与校验顺序都必须与本文件逐字节一致。任何一方偏离即为协议不一致，必须同步修改并更新
> 本文第 7 节的测试向量。
>
> 版本：**v3**（2026-10）。v2 与 v3 **不兼容**（曲线由 secp256k1 迁移到 alt_bn128），
> 需重新部署合约并重建数据库，见第 8 节。

---

## 1. 参与方与信任假设

| 参与方 | 能力 | 本轮信任假设 |
|---|---|---|
| **发布者 (publisher)** | 创建活动、配置候选/评委/权重、推进阶段 | **不可信**（v2 起不得代他人揭晓） |
| **评委 (voter)** | 提交承诺、揭晓分数；持有钱包私钥 | 诚实但可能被胁迫；私钥不泄露 |
| **relayer（后端）** | 代发链上交易（评委不直接付 gas）、托管数据库 | **半可信**：可能延迟/审查，但无法伪造评委签名 |
| **链上合约** | 状态机、白名单校验、承诺一致性校验、按权重结算 | 可信（代码即规则） |
| **第三方验证者** | 仅凭链上公开数据复算 | 不可信 |

**关键边界**：relayer 在**承诺阶段不得接触明文分数与 secret**（v2 的核心目标，见第 6 节）。

---

## 2. 威胁模型

**敌手能力（in scope）**
- A1 读取数据库全部内容（含 relayer 凭据）。
- A2 控制发布者账户与 relayer 账户，可任意构造/重放/延迟交易。
- A3 控制至多 `n-1` 个评委（无多数共谋）。
- A4 可观测链上全部交易与事件。

**安全目标**
- G1 承诺阶段：任何未持有 `(v, r)` 的一方（含 relayer、发布者、其他评委）无法恢复 `v`。
- G2 绑定性：评委在揭晓期无法改变已承诺的分数向量。
- G3 不可伪冒：relayer 无法以他人名义提交承诺或揭晓（EIP-191 评委签名）。
- G4 白名单：非白名单地址无法参与（Merkle 根）。
- G5 结算可复算：第三方仅凭链上事件可复算加权总分并与合约结算结果比对一致。
- G6 无单方后门：不存在任何一方可**代替评委**写入分数的路径。

**明确不可达（out of scope，写清以免误期许）**
- 抗报名期胁迫与「最后一名揭晓者可跟随」的从众攻击（需要更复杂的协议，如 MPC 揭晓）。
- 抗链上流量分析（评委↔分数的可关联性对 A4 可见）。
- 常量时间实现与侧信道防护。
- relayer 的审查/延迟可用性攻击（G3 只保完整性，不保活性）。

---

## 3. 密码学原语与参数

**群**：**alt_bn128（BN254）**，曲线 `y² = x³ + 3`，参数见 `backend/utils/pedersen.py`。

```
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
n = 21888242871839275222246405745257275088548364400416034343698204186575808495617
G = (1, 2)                      // 标准生成元；2² = 1³ + 3
```

> **v3 为何换曲线**：EVM 只对 alt_bn128 提供 `0x06 ecAdd` / `0x07 ecMul` 预编译（EIP-196/197）。
> secp256k1 没有预编译，纯 Solidity 实现一次点乘需数十万 gas，链上校验不可行。
> 换曲线的代价是：所有承诺点、盲化因子、测试向量全部重算（见第 8 节迁移）。

**第二生成元 `H`（NUMS，nothing-up-my-sleeves）**：由公开种子与公开算法派生，
任何第三方可复算：

```
H = hash_to_point( SHA256("ZK-SealedWeigh.Pedersen.H.v3" || uint32_be(counter)) )
// counter 从 0 递增，取第一个 x³+3 为二次剩余的值；本协议命中 counter = 2
// 结果规范化：取偶数 y（(x,y) 与 (x,-p+y) 都在曲线上，必须约定其一）
Hx = 0x23ae7e827609887ff1721f43efed23e0d3941cef3a524e28576a8c165b0b23c1
Hy = 0x09485bce1c81e4f60d2852f4ab22f9a79997cc8a19f87afbfcee998cc818b5f6
```

安全前提是**无人知晓 `dlog_H(G)`**。该前提为**计算性假设**（无已知攻击），不是可证明事实；
在报告中必须如此表述，不得写成"已证明"。三端启动/加载时都会复算 `H` 并自检。

**承诺**：`C_i = v_i · G + r_i · H`（`v_i` 为该评委给第 i 个候选人的分数）。
- 隐藏性：信息论隐藏（对任何计算能力敌手）。**前提是 `r_i` 保密且均匀**。
- 绑定性：离散对数假设下计算绑定。

**盲化因子派生（确定性，便于揭晓期重算，无需入库）**：

```
r_i = int_be(SHA256(secret_bytes || 0x3A || ASCII(i) || 0x3A || ASCII(n))) mod n
```

即 `sha256(f"{secret}:{i}:{n}")`。链上用 `sha256` 预编译 + `Strings.toString` 复现同一字符串。

**链上校验（v3 的核心增量）**：

```
提交阶段：对每个 C_i 调用 ecAdd(C_i, G) 做 on-curve 检查（预编译对非法点直接失败）
揭晓阶段：对每个 i 计算
    (gx, gy) = ecMul(G, v_i)
    (hx, hy) = ecMul(H, r_i)
    (cx, cy) = ecAdd((gx,gy), (hx,hy))
    要求 cx == 存储的 x_i 且 cy == 存储的 y_i
```

单点校验 gas ≈ `2 × 6000 (ecMul) + 2 × 150 (ecAdd) ≈ 12.3k`，与候选人数线性相关。

**范围证明（Groth16 / circom 2.0.8，P2.6 起生效）**

Pedersen 承诺只保证"分数没被改"，不保证"分数在合法区间"。区间性由第二重承诺承担：

```
commitment = Poseidon(scores[0..2], salt, uint160(voter))      // 电路输出，公开
maxScoreOut = maxScore                                          // 电路输出，公开
```

电路 `circuits/range_proof.circom`（`ScoreRangeProof(3)`，369 约束）对每个分量：
1. `Num2Bits(8)` 强制分量是 8 bit 无符号整数（先将域元素 `p-1` 这类"负数"排除）；
2. `LessEqThan(8)` 断言 `score_i <= maxScore`；
3. `Poseidon` 汇总为公开承诺。

`voter` 与 `maxScore` 进入公开承诺/公开信号，使证明**不可跨评委、跨活动重放**。
链上 `rangeHash(scores, salt, voter)` 用 `PoseidonT6` 库复算同一承诺；候选不足 3 个时补 0，
多于 3 个则 `revert("Range proof supports at most 3 candidates")`。

- 可信设置：本地单方 `pot12` 仪式，仅开发/演示用途；生产必须多方 MPC 或公开 ptau。
- 证明**必须在评委浏览器内生成**（`vendor/zk/range_proof.wasm` + `.zkey` + snarkjs）。
  服务端生成证明必然读取明文分数，会推翻第 6 节的密封边界。

---

## 4. 编码规范（规范性）

| 编号 | 规则 |
|---|---|
| **R1** | 摘要输入**一律使用 `abi.encode`**（类型化、对动态类型带 offset/length），**禁止**使用 `abi.encodePacked` 组合动态类型。 |
| **R2** | 每个摘要的**首个字段必须是 32 字节域分隔标签**（见 4.1），不得复用标签。 |
| **R3** | **禁止**任何 JSON 序列化参与摘要计算——Python `json.dumps(..., sort_keys=True)` 与 JavaScript `JSON.stringify` 的空白/转义规则不同，无法保证逐字节一致。 |
| **R4** | 承诺哈希必须**绑定 `votingId` 与 `voter`**，防止跨活动/跨评委复用同一摘要。 |
| **R5** | 变长字段（`string`）以 UTF-8 编码后作为 `string` 类型参与 `abi.encode`；调用方不得自行拼接长度前缀。 |

### 4.1 域分隔标签

```
TAG_COMMITMENT = keccak256("ZK-SealedWeigh.commitment.v3")
TAG_COMMIT_SIG = keccak256("ZK-SealedWeigh.sig.commit.v3")
TAG_REVEAL_SIG = keccak256("ZK-SealedWeigh.sig.reveal.v3")
```

（具体十六进制值见第 7 节。）

### 4.2 摘要与派生值的精确布局

| 名称 | 类型序列 | 取值序列 |
|---|---|---|
| `commitmentHash` | `(bytes32, uint256, address, uint256[], string, uint256)` | `(TAG_COMMITMENT, votingId, voter, scores, secret, maxScore)` |
| `commitDigest` | `(bytes32, uint256, address, bytes32)` | `(TAG_COMMIT_SIG, votingId, voter, commitmentHash)` |
| `revealDigest` | `(bytes32, uint256, address, uint256[], bytes32)` | `(TAG_REVEAL_SIG, votingId, voter, scores, nullifier)` |
| `deriveNullifier` | `(bytes32, uint256, address)` | `(TAG_NULLIFIER, votingId, voter)` |
| `rangeDigest` | `(bytes32, uint256, address, uint256)` | `(TAG_RANGE_SIG, votingId, voter, commitment)` |
| 链上存储值 | — | `commitDigest` 经 EIP-191 包裹后由评委签名 |

EIP-191 包裹（v1 一致，保持不变）：

```
ethHash(d) = keccak256(0x19 || "Ethereum Signed Message:\n32" || d)
signer     = ECDSA.recover(ethHash(d), signature)   必须 == voter
```

**`nullifier`（P5 / R-3 已修复）**：由合约在链上派生
`keccak256(abi.encode(TAG_NULLIFIER, votingId, voter))`，客户端只能提交该派生值，
任何自定义 nullifier 都会 revert `Invalid nullifier`。v1 的
`sha256(secret:scores:userId)` 不再使用。

---

## 5. 协议流程与校验顺序

### 5.1 建活动
relayer 调 `createVoting(...)`，参数含候选列表、评委地址与权重、`merkleRoot`（评委地址白名单）、`creator`。
合约要求 `msg.sender == relayer`、`voters.length == weights.length`、`candidates.length >= 2`。

### 5.2 承诺阶段（commit）
1. **客户端（评委浏览器）本地**计算：`r_i`、`C_i = v_i·G + r_i·H`、`commitmentHash`（第 4.2 节）。
2. 客户端向 relayer 提交：`{ commitments: [C_1..C_n], commitmentHash }`。
   **不得**提交 `scores`、`secret`、`r_i`（第 6 节）。
3. relayer 校验 `len(commitments) == candidateCount`，构造 `commitDigest` 并返回给客户端。
4. 客户端用评委钱包对 `commitDigest` 做 `personal_sign`（EIP-191）。
5. relayer 代发 `submitPedersenCommitment(votingId, voter, commitmentHash, X[], Y[], merkleProof, sig)`。
6. 合约依次校验：relayer 身份 → 阶段为 commit 且未超时 → 未重复承诺 → `len(X)==len(Y)==候选数`
   → **每个点都在 alt_bn128 上且非无穷远**（`ecAdd(C_i, G)` 预编译调用是否成功）
   → EIP-191 签名归属 `voter` → Merkle 白名单 → 存储 `(X, Y)` 与 `commitmentHash`。
7. **范围证明（P2.6 / P5）**：客户端本地随机生成 `salt`，用 `snarkjs.groth16.fullProve` 得到
   `{ commitment, proof:{a,b,c} }`，`salt` 与证明只存浏览器 localStorage。
   客户端对 `rangeDigest(votingId, voter, commitment)` 做 EIP-191 签名，经 relayer 调
   `submitRangeProof(votingId, voter, commitment, a, b, c, signature)`；
   合约先验签（R-10：relayer 不能替换 commitment），再用 `Groth16Verifier` 以
   `pubSignals = [commitment, voting.maxScore]` 验证后写入 `rangeCommitments`。

### 5.3 揭晓阶段（reveal）
1. 评委提交 `{ scores, secret, salt }`——`salt` 是范围证明的盲化因子，缺失时 relayer 直接拒绝。
2. relayer 先做链下预检：①逐项 `C_i == v_i·G + r_i·H`（真实椭圆曲线校验）；
   ②点是否在曲线上；③重算 `commitmentHash` 并与承诺阶段落库值比对。
3. 两项均通过后构造 `revealDigest`，评委签名，relayer 代发 `revealPedersenScores(...)`。
4. 合约依次校验：relayer → 阶段为 scoring 且未超时 → 是白名单评委
   → **`nullifier == deriveNullifier(votingId, voter)`** → 未揭晓 → nullifier 未用过
   → `scores.length == 候选数` → EIP-191 签名
   → **链上重算**：对每个 i，`r_i = sha256(secret:i:n) mod n`，
     用 `0x07 ecMul` 算 `v_i·G` 与 `r_i·H`、`0x06 ecAdd` 相加，要求等于存储点
   → **范围证明绑定**：`rangeCommitments[voter] != 0` 且
     `rangeHash(scores, salt, voter) == rangeCommitments[voter]`，否则 `Range proof missing` /
     `Range commitment mismatch`
   → `commitmentHash` 重算一致 → 消费 nullifier → 按评委权重写入链上分数。

> **v3 的关键安全属性**：`commitmentHash` **不包含**承诺点（只含 scores/secret/maxScore），
> 因此拿到评委签名的 relayer 理论上可以替换成任意合法点。v2 链上只比哈希，无法发现；
> v3 由合约自己重算 `C_i` 并逐点比对，替换必定 revert `Pedersen point mismatch`。
> 这是本次升级最实质的安全收益，已由合约测试覆盖。

### 5.4 结算
`calculateResults(votingId)` 由 creator 或 relayer 调用，要求评分阶段已超时；按 `Σ(score·weight)` 汇总并
置 `phase = 3`。链下由 relayer 做 SQL 聚合用于展示，第三方可仅凭事件复算（G5，P2 交付验证器）。

---

## 6. 数据模型与公开/私有边界

| 数据 | 承诺阶段 | 揭晓阶段 | 存放位置 |
|---|---|---|---|
| `scores`（明文分数） | **仅存于评委浏览器内存** | 广播给 relayer 并入链 | **不得入库**（v2 起移除该列） |
| `secret` | **仅存于评委浏览器内存** | 揭晓时提交 | **不得入库**（v2 起移除该列） |
| `r_i`（盲化因子） | 由 `secret` 确定性派生 | 由 `secret` 重算 | **不得入库**（v2 起移除该列） |
| `salt`（范围证明盲化因子） | 浏览器 `crypto.getRandomValues` 生成 | 随揭晓提交 | **不得入库**，仅存 localStorage |
| `rangeCommitment`（Poseidon 承诺） | 由证明的公开信号给出 | 公开 | 链上 `rangeCommitments` |
| `C_i`（承诺点） | 公开 | 公开 | 入库 + 上链 |
| `commitmentHash` | 公开 | 公开 | 入库 + 上链 |
| 权重、候选、阶段 | 公开 | 公开 | 入库 + 上链 |

> v1 曾把 `scores`、`secret`、`blinding_factors` 明文入库，使 A1 敌手可绕过承诺直接读分，
> 保密性仅对"其他评委"成立。v2 移除此三列。

---

## 7. 测试向量

固定夹具（**三方实现跑此向量必须逐字节一致**）：

```
votingId  = 1
voter     = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
scores    = [7, 9, 0]
secret    = "correct horse battery staple"
maxScore  = 10
nullifier = 0xc1da3c3588b03fbe83be605534c6a9f58ceba3081c58c041a0a9ae0a9111a8fc
            （仅用于 revealDigest 向量；实际揭晓用合约派生值）
```

| 量 | 期望值（hex, 无 0x 前缀） |
|---|---|
| `TAG_COMMITMENT` | `f989c362dc9cceb77b838df72487e54a41bd549faa230a87932d4fb9b04f08b7` |
| `TAG_COMMIT_SIG` | `735f961bc7874a87e44d11e265946ea355f478906fb5489ec1b8739bcc00c6ab` |
| `TAG_REVEAL_SIG` | `67d980de8ae16cf5ab80b48362d15dcd4c2d9d207672346e98847066da301db6` |
| `TAG_RANGE_SIG` | `1693686b05e4d5b7a1091a1e4260ff5886009af024017cf6b75fd91772dd8404` |
| `TAG_NULLIFIER` | `07eee5bbe23d4225614099ecb14510f5168bf7c194bc0ffb673ae42164adcfe2` |
| `derivedNullifier(1, voter)` | `e5f5161b4b98890d723fa3d596954ba85525c9b44b319e6e53c772142d932eb7` |
| `rangeDigest(1, voter, rangeCommitment)` | `c100ac7c9d3bef526ff22abb1d71e675ddc8bc7245eff729b7cefa7b30ddd835` |
| `commitmentHash` | `3bb8f63ff26c8f455588b1f6b55363f628b71f5eaef4673ab5cee01de282be0c` |
| `commitDigest` | `2cd580910aa9acbee0e0956def252fbae3468764ba7b60cad9946d3f34a9f609` |
| `revealDigest` | `7e5db8ac0976c7e409c94b3a0f236919362c5a396f871d79228fbd7b43e1e4fb` |
| `ethHash(commitDigest)` | `7ef3526c709c8032a11bf5acb0cd3143fd3b496301691f36614ce7c697dc320e` |
| `ethHash(revealDigest)` | `2aeaafac315557ce362323195cc003aa5d304fe532249320d30b8d6dedec7a73` |
| `abi.encode` 长度 | `384` 字节 |

**承诺点与盲化因子向量（alt_bn128，同一夹具）**：

```
r_0 = 11331531710196327524856561149319088737098671986330248307203685176617335942994
r_1 = 2800419421753264120076415202257965566892541408650663719876681182483906309872
r_2 = 4804764372245660068797630501824517595943658061948539868936512225051414332963

C_0 = 0x06ae23dbd2b2c323dd377f3ebcd6ddab72d8ae7f5634bd39bdbfecd92ef9b3fc0ef6987c64195d008237f32797de0433c236225a13cd6b0873ea09d68258d4fb
C_1 = 0x25ab8fba6599243fb05c1c8c6532d9ade3a1fa51109f91b189dc06e09ea5a90e0d2bc03efdd457045885e6c2dde903bcee50494b28315fcfddf24da1ee7d38f3
C_2 = 0x14b081aec82aa9c3e4c4a2444b566eaaba63a4083a2d67d8594a18fdd7932bff244f9fad0994da303dd67ac4b6da94d1d17ad4a3a923e71713fa329755721510
```

**范围证明向量（同一夹具，P2.6）**：

```
salt            = 12345678901234567890
rangeCommitment = 2187125169807282827423416889253800045206127458618452263738622424698383698062
                = 0x04d5de75525c887d03ba3dde9c9eed37c766743112f11883d57c8d2c3f3f088e
maxScoreOut     = 10
```

`rangeCommitment = Poseidon([7, 9, 0], salt, uint160(voter))`，由 `circuits/scripts/prove.js`
产出并写入 `circuits/build/proof_fixture.json`；合约侧 `rangeHash` 必须复算出同一值（测试已断言）。

**一致性验证矩阵**：

| | Python | JavaScript | Solidity |
|---|---|---|---|
| `commitmentHash` | 断言（`self_check`） | 断言（node 交叉验证） | 合约 `calculateCommitmentHash` |
| `commitDigest` | 断言 | —（只做签名） | 合约 `commitDigest` |
| `revealDigest` | 断言 | 断言（node 交叉验证） | 合约 `revealDigest` |
| `deriveNullifier` | 断言 | — | 合约 `deriveNullifier` |
| `rangeDigest` | 断言 | `zk-crypto.js` | 合约 `rangeDigest` |
| `C_i = v_i·G + r_i·H` | 断言 | 断言（本地生成） | **合约用预编译重算校验**（v3） |
| `r_i` 派生 | 断言 | 断言 | 合约 `deriveBlinding`（sha256 预编译） |
| `rangeCommitment` | — | 浏览器 `fullProve` 公开信号 | 合约 `rangeHash` + Groth16 校验 |

---

## 8. 版本与迁移

**v1 → v2**：① `abi.encodePacked` → `abi.encode`；② 新增域分隔标签与 `votingId/voter` 绑定；
③ 移除 `recoverPedersenScores` 与 `/scores/recover`。

**v2 → v3**：① 曲线 secp256k1 → **alt_bn128**（`y²=x³+3`，`G=(1,2)`）；
② 第二生成元改为 NUMS 派生（种子 `ZK-SealedWeigh.Pedersen.H.v3`，counter=2）；
③ 域分隔标签升到 `.v3`；
④ 合约存储由 `bytes32[] scoreCommitments`（点的 keccak）改为 `uint256[] commitmentX/Y`，
并用 EIP-196/197 预编译在**揭晓期重算校验**；
⑤ `submitPedersenCommitment` 参数由 `bytes32[]` 改为两个 `uint256[]`。

**v3.1（P2.6，向后兼容）**：新增 `submitRangeProof` / `rangeHash` / `rangeCommitments`；
`revealPedersenScores` **新增 `uint256 _salt` 参数**（位于 `_secret` 之后）。
调用方必须同步更新；链下流程只在原有承诺之后追加一次范围证明提交，失败时该评委无法揭晓。

**v3.2（P5 / R-3 + R-10，签名与派生规则变更）**：
① `nullifier` 由客户端提供改为合约派生 `keccak256(abi.encode(TAG_NULLIFIER, votingId, voter))`；
② `submitRangeProof` **新增 `bytes signature`**，评委对
   `rangeDigest(votingId, voter, commitment)` 签名；
③ 新增纯函数 `deriveNullifier` / `rangeDigest`，供三端复算。
旧 ABI 与旧 nullifier 均不兼容，必须重新部署合约。

**迁移步骤**（数据不可保留）：
1. 重新部署合约（**先部署 `PoseidonT6` 库并链接**），更新 `backend/.env` 的 `CONTRACT_ADDRESS`；
2. 删库重建：`sqlcmd -S "tcp:localhost,1433" -U sa -P <口令> -f 65001 -i database\init.sql`；
   若不删库，至少把 `voting_sessions.blockchain_id` 置 `NULL` 后运行
   `backend/scripts/repair_onchain_votings.py` 重建链上记录；
3. 重新创建评审活动（链上 `votingCount` 已归零，旧 `blockchain_id` 失效）；
4. 浏览器端旧 `localStorage` 的 `zkc:commit:*` **失效**（旧记录没有 `salt`），需重新提交承诺；
5. 报告中的截图需重拍（界面与流程均已变更）。

---

## 9. 已知残留风险

| 编号 | 风险 | 状态 |
|---|---|---|
| R-1 | ~~链上不校验承诺点~~ | **v3 已修复**：合约用 `ecAdd`/`ecMul` 重算 `C_i = v_i·G + r_i·H` 并逐点比对；单点 ≈ 12.3k gas |
| R-2 | ~~范围合法性只是后端 `require`~~ | **P2.6 已修复**：Groth16 范围证明在浏览器生成、链上 `Groth16Verifier` 验证，揭晓时 `rangeHash` 绑定；可信设置仍为单方（见 R-9） |
| R-3 | ~~`nullifier` 由客户端提供且依赖 `secret`，重放防护实际由 `hasRevealed` 承担~~ | **P5 已修复**：合约派生 `deriveNullifier(votingId, voter)`，不匹配即 revert |
| R-4 | relayer 中心化：可延迟/审查，且 `.env` 私钥即 relayer 身份 | 待做：门限中继 |
| R-5 | ~~缺失分数只能由**评委本人**重新揭晓；无门限托管恢复~~ | **P3 已修复**：GF(256) Shamir(k, n) 分片 + AES-GCM 托管 + ECDH 信封，见第 11 节 |
| R-6 | ~~权重可在 scoring 阶段被修改~~ | **P0 已修复**，见 `routes/weights.py` 阶段校验 |
| R-7 | 评委仍可能主动泄露 `(scores, secret)` 给第三方（协议无法阻止自愿披露） | 设计边界，如实声明 |
| R-8 | 承诺点与分数一一对应，若候选人数极少且 `secret` 熵低，可能被字典攻击反推 | 强制 `secret` 长度 ≥ 6；后续可加盐或 PBKDF |
| R-9 | 范围证明的可信设置是**单方本地仪式**，toxic waste 可重建，理论上可伪造证明 | 仅开发/演示；生产须多方 MPC 或公开 ptau |
| R-10 | ~~relayer 可以**替换或省略**某评委的范围证明，使其无法揭晓（DoS，不能伪造分数）~~ | **P5 已修复替换**：范围证明要求评委 `rangeDigest` 签名；省略仍属 R-4 审查风险 |
| R-11 | 电路按 3 个候选人编译，更多候选的活动不支持 | 按最大候选数重编电路并重做 setup |

---

## 10. 可验证审计包（P2.7，已实现）

**目的**：把一次评审的链上事实导出为**可签名、可独立复验**的 JSON，第三方不需要信任后端、
不需要访问数据库，只需 `bundle.json` + RPC 即可判断结果是否可信。

**包结构**

```json
{
  "payload": {
    "schema": "ZK-SealedWeigh.audit-bundle.v1",
    "generated_at": "…",
    "network": { "chain_id": "31337", "contract": "0x…" },
    "snapshot": { "block_number": "8", "block_hash": "0x…" },
    "facts": {
      "voting": { "title", "candidates", "voters", "max_score", "phase", "merkle_root", … },
      "counters": { "total_voters", "committed_voters", "revealed_voters", "total_scores" },
      "commitments": [ { "voter", "commitment_hash", "points", "range_commitment" } ],
      "reveals": [ { "voter", "scores", "salt", "nullifier", "tx_hash", "range_binding_ok" } ],
      "scores": [ … 逐条 Score（voter/candidate/score/weight）… ],
      "tally": { "on_chain", "recomputed", "match" },
      "checks": { "all_points_on_curve", "weights_consistent", "range_bindings_ok", … }
    },
    "findings": [],
    "verdict": "PASS"
  },
  "attestation": {
    "scheme": "EIP-191(32-byte digest)",
    "domain": "ZK-SealedWeigh.audit.v1",
    "signer": "0x…",
    "digest": "0x…",
    "signature": "0x…"
  }
}
```

**签名与规范序列化**

```
digest = keccak256("ZK-SealedWeigh.audit.v1" || canonical_json(payload))
canonical_json = JSON.sort_keys + separators(',', ':') + UTF-8     // 禁止浮点，数值一律字符串
signature = EIP-191(digest)
```

**验证流程**（`scripts/audit_bundle.py --verify`）
1. 重算 `digest` 并 `ECDSA.recover` → 必须等于 `attestation.signer`；
2. 重新连链，按 `chain_id` 重建 `facts`，与包内逐节比对
   （`voting / counters / commitments / reveals / scores / tally / checks`）；
3. 复算加权结果、逐点 `isOnCurve`、逐个揭晓记录重算
   `rangeHash(scores, salt, voter) == rangeCommitments[voter]`；
4. 任一不符 → FAIL。

**边界（必须如实说明）**
- 签名只证明"包由该地址签发且未被修改"，**正确性来自重算**，不来自对签发者的信任；
- 第三方必须能访问同一 RPC/链；链状态在导出后继续变化会导致比对失败（这是特性，不是缺陷）；
- 包里**绝不含 `secret`**。`salt` 会包含——它在揭晓交易的 calldata 里本来就公开，
  且是复验 `rangeHash` 绑定所必需；未揭晓评委的 `salt` 永远不会出现。

---

## 11. 门限恢复（Shamir k-of-n）—— 全链路已实现

> 状态：**P3.1–P3.11 全部落地**。密码学核心（P3.1）、enrollment 与密文存储（P3.2）、
> 请求/份额/本地重构（P3.3）、私钥持久化（P3.4）、恢复页面（P3.5）、
> 3 评委 k=2 压力测试（P3.6）、交互式三步向导（P3.7）、私钥存储层升级（P3.8）、
> 恢复 UI 收口（P3.9）、全局联动/恢复记录（P3.10）与全局恢复中心（P3.11）
> 均已完成并通过验收。
> 本节回答"评委丢了浏览器数据怎么办"，同时明确**不重新引入单方代揭晓后门**。

### 11.1 目标与非目标

**目标**
- 评委 i 丢失本地 `(scores, secret, salt)` 后，可由 **k 位评委协作**恢复，且恢复结果能通过链上全部校验；
- 服务器全程**不接触**明文、主密钥或可用分片，只保存密文；
- 不新增任何"服务器替谁揭晓"的接口。

**非目标**
- 不防止 **k 个评委合谋**恢复某人的分数——这是门限托管的固有代价，必须写进报告与 UI；
- 不在投票窗口关闭后恢复（链上 `Scoring phase ended` 不可绕过）；
- 不绕过 `hasRevealed`：已揭晓者不能借恢复二次揭晓。

### 11.2 威胁模型与信任假设

| 角色 | 假设 |
|---|---|
| 服务器 | 诚实但好奇；可能在 setup 后被攻破。只允许看到密文与公开参数 |
| 评委浏览器 | setup 与恢复时可信；恢复后的本地校验必做 |
| k-1 个评委 + 服务器 | 合谋仍不足 k 份 → 无法恢复 |
| k 个评委 | 可以恢复（显式声明的隐私边界） |
| 恶意份额 | 由 AES-GCM 认证失败检出，恢复中止 |

### 11.3 数据对象

```
P_i        = { votingId, voter, scores[], secret, salt }      // 仅存在于评委 i 的浏览器
K_i        = 32 字节随机主密钥（评委 i 在承诺阶段生成）
K_esc_i    = HKDF-SHA256(K_i, "ZK-SealedWeigh.recovery.escrow.v1")
CE_i       = AES-256-GCM(K_esc_i, P_i)                        // 服务器只存这个密文
S_{i,j}    = Shamir(k, n) 把 K_i 拆成 n 份，交给评委 j 的那一份（j 只取**其他**评委，不含自己）
K^pub_j    = 评委 j 的 ECDH P-256 公钥（setup 时生成并公开）
E_{i,j}    = AES-256-GCM(ECDH(K^priv_j, K^pub_i 协商键), S_{i,j})   // 只有 j 能解
M_i        = 规范 JSON { schema, votingId, voter, sha256(CE_i), E_{i,*} } + 评委 i 的 EIP-191 签名
```

服务器保存：`CE_i`、`E_{i,j}`、`M_i`、各评委的 `K^pub_j`。
服务器**永远不保存**：`P_i`、`K_i`、`S_{i,j}` 明文、任何解密后的份额。

### 11.4 流程

**A. 承诺阶段（enrollment）**
1. 浏览器已算出 `P_i`；生成 `K_i`、`CE_i`，用 Shamir(k, n) 拆成 n 份（**n = 其他评委数**，不含自己）；
2. 从 `/api/recovery/keys?votingId=` 取各评委的 P-256 公钥（公开信息）；
3. 逐份 `E_{i,j}` 加密；组装 `M_i` 并用评委钱包签名；
4. 上传 `{ CE_i, E_{i,*}, M_i }`。服务器校验签名与 `votingId/voter` 绑定后存储。

**B. 恢复阶段（k-of-n）**
1. 丢失方 r 打开恢复页，发布恢复请求（附 `K^pub_r`，该公钥在 setup 时已公开）；
2. k 位评委 j 各自：用 `K^priv_j` 解开 `E_{r,j}` 得到 `S_{r,j}`，再按 r 的公钥重新加密为
   `E'_{r,j}`，投入 sharebox（服务器只转发密文）；
3. r 收齐 k 份，本地解密并重构 `K_r` → 解 `CE_r` 得 `P_r`；
4. **本地自检**：用 `P_r` 重算每个 `C_i`、`rangeHash(scores,salt,voter)`，与链上比对，全部通过才允许使用；
5. 走正常揭晓流程（`revealDigest` 签名 → relayer 代发）。链上仍会独立校验承诺点、范围绑定与承诺哈希，
   **恢复机制本身无法伪造分数**。

**C. 失败路径**
- 不足 k 份 → 不恢复（fail closed），UI 明确显示还缺几份；
- 任一份被篡改 → GCM 认证失败 → 中止并标出提供者；
- 服务器不返回 `CE_i` 或 envelope → 只能造成 DoS；评委可线下交换 envelope 绕过服务器。

**D. 清单与签名（规范性，P3.2 已实现）**

```json
{
  "schema": "ZK-SealedWeigh.recovery.manifest.v1",
  "votingId": 1,
  "voter": "0x…",                       // 登记人的钱包地址
  "threshold": 2,
  "escrowHash": "sha256(canonical_json(escrow))",
  "recipients": [2, 3],                 // 与 envelopes 顺序一一对应
  "envelopeHashes": ["sha256(canonical_json(envelopes[0]))", "…"]
}
```

```
canonical_json = 递归排序键 + 紧凑分隔符(',', ':') + UTF-8
manifestMessage = canonical_json(manifest)
signature       = EIP-191(text = manifestMessage)

公钥发布消息 = "ZK-SealedWeigh.recovery.key.v1|userId|publicKey"   // 同样 EIP-191
```

服务端必须校验：
1. `canonical_json(manifest) == manifestMessage`（防止规范序列化漂移）；
2. `escrowHash` 与 `envelopeHashes` 与实际密文逐字节一致；
3. `recipients` 覆盖该活动全部评委、数量与 envelopes 相同、`1 ≤ threshold ≤ n`；
4. 签名者等于登记人的绑定钱包；
5. 请求体中不存在 `scores` / `secret` / `salt` / 明文类字段；
6. 登记只能在 `commit` 阶段，且所有评委都已发布公钥（否则拒绝半套材料）。

**E. 私钥持久化（P3.4 / P3.8，已实现）**

评委的 ECDH P-256 私钥必须能跨页面重开恢复，但不能以明文落盘。采用钱包派生密钥：

```
walletMessage = "ZK-SealedWeigh.recovery.walletkey.v1|" + lowercase(address)
signature     = personal_sign( hex(utf8(walletMessage)) )     // 65 字节
K_wrap        = HKDF-SHA256(signature, salt="…walletkey.v1.salt",
                             info="…walletkey.v1|address")
envelope(v2)  = AES-256-GCM(K_wrap, JSON(privateJwk),
                            AAD="…walletkey.v1|aad|address")
envelope      = { v:2, alg, address, epoch, iv, ct }
```

**存储层（P3.8）**：

```
主存储   IndexedDB  ZK-SealedWeigh.recovery / walletKeys   key = "v2:" + lowercase(address)
回退     主存储打开失败或运行时报错 → localStorage 同名键
记录     { schema:"ZK-SealedWeigh.recovery.keyrecord.v1", version:2,
          address, createdAt, updatedAt, envelope }
迁移     P3.4 的 localStorage["zkr:key:{address}"]（v1）在首次读取时
         解密 → 重新加密为 v2 → 写入主存储 → 删除旧键
轮换     epoch + 1；签名消息 = "…|rotate|{epoch}|{address}"，
         HKDF info 同步带 epoch；旧 epoch 的签名无法解开新密文
```

安全前提与边界：
- 依赖钱包签名的**确定性**（MetaMask / RFC6979）。若钱包引入随机性，重新派生会失败，
  必须显式报错而不是静默清空；
- **钱包是根信任**：能重放这条签名的人就能解出私钥；
- 签名消息与 AAD 都绑定地址，换账号得到不同的密钥、旧密文无法解开；
- IndexedDB / localStorage 中只有密文，不含 `d`/`x`/`y` 等私钥材料；
- IndexedDB 不可用时静默回退 localStorage，不阻断恢复流程，但容量与隔离性较弱。

### 11.5 密码学参数与域分隔

| 组件 | 选择 |
|---|---|
| 秘密共享 | Shamir over **GF(256)**，k-1 次多项式，32 字节秘密 = 32 条独立多项式 |
| 对称加密 | AES-256-GCM，96-bit 随机 nonce，AAD 绑定 `domain || votingId || voter || purpose` |
| 密钥派生 | HKDF-SHA256 |
| 份额加密 | ECDH **P-256**（WebCrypto 兼容性优于 X25519）+ HKDF |
| 域分隔 | `.recovery.escrow.v1` / `.recovery.share.v1` / `.recovery.manifest.v1` |

选择 GF(256) 而非大素数域：份额小（32 字节）、浏览器实现简单、可与 AES 密钥长度直接对齐。
错误份额无需 Feldman VSS：k 份重构后 GCM 认证失败即可检出并中止。

### 11.6 安全分析

| 攻击 | 结果 |
|---|---|
| 服务器单独读取 DB | 只有 `CE_i` / `E_{i,j}`，无密钥，无法解密 |
| 服务器 + k-1 评委 | 仍缺 1 份，无法重构 `K_i` |
| k 个评委合谋 | **可以**恢复（声明边界），应通过选择 k 与受托人控制 |
| 恶意评委提交错误份额 | GCM 失败，恢复中止；envelope 带签名可追责 |
| 丢失方伪造恢复请求 | 只能恢复自己的 `CE_r`，拿不到别人的密文 |
| 恢复后二次揭晓 | 合约 `hasRevealed` / `usedNullifiers` 拒绝 |

### 11.7 与 P0"后门移除"的关系（必须能答辩）

- P0 删除的是**服务器持有秘密、可替评委揭晓**的能力；本设计把重构放在**评委浏览器**，
  服务器只存密文，且**不新增任何接受明文的接口**；
- `/api/scores/recover` 继续返回 410；
- 恢复产出的揭晓仍必须通过链上椭圆曲线与范围证明校验，服务端没有任何"跳过校验"的分支。

### 11.8 接口（P3.2/P3.3 已实现全部流程接口，UI 见 P3.5）

```
POST /api/recovery/keys             ✅ 发布评委 P-256 公钥（需登录 + 钱包签名）
GET  /api/recovery/keys?votingId=   ✅ 读取公开公钥（活动参与者）
POST /api/recovery/enroll           ✅ 上传 CE_i + E_{i,*} + 签名清单（仅密文）
GET  /api/recovery/enrollments/my   ✅ 读取自己的密文清单
GET  /api/recovery/status           ✅ 活动维度准备状态（不含密文）
POST /api/recovery/request          ✅ 丢失方创建/复用恢复请求
GET  /api/recovery/requests         ✅ 其他评委查看可协助的请求（不含密文）
GET  /api/recovery/requests/<id>/envelopes ✅ 评委读取请求者发给自己的密文信封
POST /api/recovery/sharebox         ✅ 评委投递重新加密给请求者的份额
GET  /api/recovery/sharebox/<rid>   ✅ 请求者读取已收集的份额（仅本人）
GET  /api/recovery/overview         ✅ 当前用户的恢复待办与进行中活动总览（仅元数据）
GET  /api/recovery/history?votingId= ✅ 活动内恢复请求与投递记录（仅参与人、时间、状态）
```

以上接口**一律只收发密文**，不接受 `scores` / `secret` / `salt`，也不返回任何明文。

### 11.9 验收标准

1. `k-1` 份无法重构 `K`；`k` 份重构结果逐字节一致；
2. 篡改任意一份 → GCM 认证失败；
3. 服务器数据库中检索不到 `scores` / `secret` / `salt` 明文；
4. 恢复产出的揭晓能通过链上全部校验（Pedersen 点、范围绑定、承诺哈希）；
5. 已揭晓者再次恢复揭晓 → 合约拒绝。

### 11.10 实施拆分

| 阶段 | 内容 | 状态 |
|---|---|---|
| P3.1 | GF(256) Shamir + AES-GCM + ECDH 的纯前端密码学核心与测试向量（不接服务器） | ✅ `frontend/recovery-crypto.js`，41 项向量通过 |
| P3.2 | enrollment 接口与服务器密文存储 | ✅ 完成（21 项接口验收；界面由 P3.5 提供） |
| P3.3 | 恢复请求、份额投递、本地重构 | ✅ 完成（`recovery_flow.py` 42 项；界面由 P3.5 提供） |
| P3.4 | 钱包派生私钥持久化 | ✅ 完成（P3.8 扩展至 40 项向量） |
| P3.5 | 恢复页面与 enrollment UI | ✅ 完成（`recovery.html`，浏览器实测通过） |
| P3.6 | 多评委压力测试（3 评委、n=2、k=2） | ✅ 完成（`recovery_stress.py` 36 项：单份不可恢复、两份逐字段一致、状态迁移） |
| P3.7 | 恢复流程交互式三步向导 | ✅ 完成（步骤条 + 门禁 + 8s 进度轮询 + URL 断点续做，浏览器实测通过） |
| P3.8 | 私钥存储层升级 | ✅ 完成（IndexedDB 主存储 + v2 版本化记录 + v1 自动迁移 + 密钥轮换，40 项向量） |
| P3.9 | 恢复 UI 收口 | ✅ 完成（开发钱包全流程、密钥管理卡、评分页入口、键盘/移动端；实测修复 escrow 取值 bug） |
| P3.10 | 全局联动与恢复记录 | ✅ 完成（导航待办徽标、仪表盘恢复卡片、历史时间线、无障碍与移动端；54 项恢复流程断言） |
| P3.11 | 全局恢复中心 | ✅ 完成（跨活动总览、记录详情时间线、JSON/CSV 导出、15s 待办轮询） |

**P3.6 的协议意义**：2 位评委时份额只能发给唯一的另一位评委，`n=1` 使 `k` 只能取 1，
任何单方都能独立恢复，门限退化为单点。3 位评委时 `n=2`，取 `k=2` 后
「服务器 + 任一评委」仍不掌握全部门限份额，才真正验证了 11.2 中
"k-1 个评委 + 服务器无法恢复"的威胁模型。

**P3.7 的交互约束**（与 11.9 的验收标准对应）：
- 第 2 步在未登记时**不隐藏**，而是显示门禁提示并给出返回第 1 步的按钮；
- 轮询只在「第 2 步 + 页面可见 + 未达门限」三个条件同时成立时开启（8s），
  恢复成功或达标后立即停止，页面隐藏时跳过请求；
- 当前步骤写入 `#stepN`，刷新后优先按 hash 恢复，否则按是否已登记自动落位；
- 界面的「已完成」只由真实接口状态驱动（登记成功 / 重构成功 / 已投递），不做预估。

**P3.9 UI 收口**：
- 新增仅限 `localhost` 的 `dev-wallet.js`（`?devwallet=0x…`），把 Hardhat 已解锁账户包装成
  EIP-1193 provider，用于没有 MetaMask 时的本地全流程走查；私钥始终留在节点。
- 评分页在缺少本地明文时显示恢复入口（`recovery.html?id=…`），不再只弹一条 toast。
- 钱包管理页新增「恢复密钥」卡片：展示 IndexedDB/localStorage、记录版本、epoch 与时间，
  支持轮换与删除；轮换只改本地加密派生密钥，不改 ECDH 私钥。
- 向导补齐方向键切换、`aria-controls`/`aria-selected`、`aria-live` 状态区、按钮忙碌态与移动端布局。
- **实测修复**：`collectAndRecover` 把已经解包过的 `myEnrollment` 又当成接口响应取了 `.data`，
  导致 `Cannot read properties of undefined (reading 'escrow')`；现已改为直接读 `enrollment.escrow`。

**P3.10 全局联动与恢复记录**：
- `GET /api/recovery/overview`：返回当前用户在进行中活动里的待协助数、待恢复请求数、
  已登记活动数与最多若干条待办；只含活动标题、发起人、门限、进度与状态。
- `GET /api/recovery/history?votingId=`：返回活动内全部恢复请求与投递记录
  （发起人、协助者、时间、状态），**不含 `escrow` / `envelope` / 任何密文**；仅该活动评委可读。
- 侧边导航「恢复中心」显示待协助请求数徽标；仪表盘新增「恢复与协作」卡片；
  评分承诺提交成功后引导登记恢复材料。
- 恢复页新增「恢复记录」时间线表格；窄屏可横向滚动，触控设备按钮最小高度 44px。
- 无障碍：步骤条 `aria-current` / `aria-selected` / `aria-controls`，步骤提示与记录区 `aria-live`。

**P3.11 全局恢复中心与记录审计**：
- 不带 `?id=` 打开 `recovery.html` 时展示跨活动总览：每个进行中活动的登记状态、门限、
  待协助数、我的待恢复请求数，并可直接进入对应活动；
  数据来自 `overview.activities`，字段只有 `enrolled / threshold / pendingAssist / myOpenRequests`。
- 恢复记录支持「详情」展开：按时间顺序展示请求创建、每次份额投递与达到门限的事件；
- 支持导出 `JSON` / `CSV`（`schema=ZK-SealedWeigh.recovery.history.v1`），
  导出内容与历史接口一致，**不含任何密文**；页面就地显示导出文件名或失败原因。
- 导航徽标每 15 秒轮询一次（页面隐藏时跳过）；待协助数量增加时提示一次，首次加载不提示。

> **报告写作提示**：不要把"门限恢复"写成"解决了一切丢失问题"。正确表述是
> "在 k-of-n 假设下恢复可用，代价是 k 个受托人合谋可读取该评委的分数"。

---

## 12. 形式化验证与模糊测试（P4，已实现）

> 状态：**P4 全部落地**，并接入 `verify-all.ps1` 的第 10–12 环节。

### 12.1 有界模型检验（`backend/tests/model_check.py`）

把合约阶段机抽象为显式状态 `(phase, commits, reveals, settled)`，用 BFS 枚举：

```
2 评委 / 2 候选 / 分数域 {0,1} / 最大深度 6
344 个可达状态 / 604 条迁移
```

检查的不变量：

| 不变量 | 含义 |
|---|---|
| `reveal_without_commit` | 未承诺不可揭晓 |
| `wrong_score_length` | 揭晓分数个数必须等于候选数 |
| `score_out_of_range` | 分数必须在 `0..maxScore` |
| `results_mismatch` | 结算结果必须等于已揭晓分数之和 |
| `settled_not_completed` | 结算后阶段必须为 completed |
| `inactive_not_completed` | 活动结束后不可再改阶段 |
| `reveal_in_commit_phase` | 承诺阶段不可揭晓 |
| `phase_regression` | 阶段只能单调前进 |

另建**缺陷模型**（故意允许阶段回退）作为检验器的阴性对照，必须能给出反例：
`update_phase(2) -> update_phase(1)`。

### 12.2 四类模糊测试

| 层 | 文件 | 规模 | 断言重点 |
|---|---|---|---|
| 合约状态机 | `hardhat-project/test/fuzz.test.ts` | 24 轮 × 5 步 + 完整生命周期 + 签名/白名单篡改 | 阶段只增不减、结束后不可改、越权/伪点/重复/错误密码/提前结算全部拒绝，签名与 Merkle 证明篡改必败 |
| 接口 | `backend/tests/test_fuzz_api.py` | 111 例 | 畸形 JSON、类型混淆、超长字符串、SQL INT 溢出、畸形认证头；**不得出现 500**，不得泄露堆栈/驱动名/明文 |
| 恢复密码学 | `frontend/tests/recovery-fuzz.test.js` | 40 轮 × 7 类 = 280 断言 | Shamir、少于门限、AES-GCM 往返、ECDH 信封、AAD 错配、密文篡改 |

### 12.3 由 P4 发现并修复的缺陷

1. **合约阶段可回退**（`phase_regression`）：`updateVotingPhase` 原先只校验 `_phase <= 3`，
   允许 2 → 1，使已完成评分的活动重新接受承诺。修复：

```solidity
require(voting.isActive, "Voting is not active");
require(_phase <= 3, "Invalid phase");
require(_phase >= voting.phase, "Phase cannot move backwards");
```

2. **接口 500**：登录畸形 JSON / 空体 / 数组体 / 超长字段、`votingId=10^30` 溢出 SQL INT、
   建活动畸形 JSON。修复为 `request.get_json(silent=True)` + dict/字符串/长度校验 +
   `_parse_id` 限界 `1..2147483647`。
3. **第二轮接口扩展又发现 14 个 500**：钱包校验与批量用户的数组体/非字符串、
   旧评分与批量评分的数组体、权重单个/批量的数组体与对象权重、阶段更新数组体、
   结果/链上状态超大 ID、链上提交与揭晓数组体。根因统一为
   「假设请求体一定是 dict + `float(dict)` + 大整数直接进 SQL」，均已收口。

### 12.4 一个必须说明的密码学语义

`combineShares` 只做 Lagrange 插值，**不知道门限 k**，因此少于 k 份时不会抛错，
而是静默算出一个错误密钥。安全属性应由系统层断言：

- 重构结果 ≠ 原主密钥；
- 用该错误密钥调用 `decryptEscrow` 必须因 AES-GCM 认证失败而中止。

模糊测试据此使用 `under-threshold-key-differs` 与 `under-threshold-decrypt-rejected` 双断言。

### 12.5 验收

```
有界模型检验       7/7，344 状态 / 604 迁移 / 深度 6
合约模糊测试       3/3
接口模糊测试       111/111（200×1 / 400×92 / 401×7 / 404×8 / 405×1 / 410×2，无 500）
恢复密码学模糊测试 280/280
一键验收           12/12 环节，693 项断言
```
