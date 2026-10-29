// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "poseidon-solidity/PoseidonT6.sol";
import "./Groth16RangeVerifier.sol";

/**
 * @title ZKVoting —— 链上可验证的密封加权评审（协议 v3）
 *
 * v2 的链上只存 `keccak(commitmentPoint)` 与承诺哈希，合约**无法验证**承诺点是否
 * 真的对应 (分数, 密码)。这意味着 relayer 可以在保持 commitmentHash 不变的前提下
 * 替换承诺点（哈希不含点），链上无从发现。
 *
 * v3 改为：
 *   · 曲线换成 alt_bn128(BN254) —— EVM 唯一有预编译的曲线；
 *   · 承诺点以 (x, y) 原样上链，提交时校验点在曲线上；
 *   · 揭晓时用 0x06(ecAdd) / 0x07(ecMul) 现场重算 C'_i = v_i·G + r_i·H 并逐点比对。
 *
 * 单点校验 gas ≈ 2×6000(ecMul) + 2×150(ecAdd) ≈ 12.3k，与候选人数线性相关。
 */
contract ZKVoting {
    using ECDSA for bytes32;
    using Strings for uint256;

    // —— 签名授权：后端作为 relayer 代发交易，投票者用钱包做 EIP-191 签名 ——
    // 域分隔标签（见 spec.md 第 4.1 节），禁止复用
    bytes32 private constant TAG_COMMITMENT_SIG = keccak256("ZK-SealedWeigh.sig.commit.v3");
    bytes32 private constant TAG_REVEAL_SIG = keccak256("ZK-SealedWeigh.sig.reveal.v3");
    bytes32 private constant TAG_RANGE_SIG = keccak256("ZK-SealedWeigh.sig.range.v3");
    bytes32 private constant TAG_NULLIFIER = keccak256("ZK-SealedWeigh.nullifier.v3");
    bytes32 private constant TAG_COMMITMENT = keccak256("ZK-SealedWeigh.commitment.v3");
    string private constant SIG_PREFIX = "\x19Ethereum Signed Message:\n32";
    address public relayer;

    // —— alt_bn128 (BN254) 域参数：y² = x³ + 3 ——
    // 与 backend/utils/pedersen.py、frontend/zk-crypto.js 逐字节一致（spec.md 第 3 节）
    uint256 private constant P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 private constant N = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant GX = 1;
    uint256 private constant GY = 2;
    // H = hash_to_point(sha256("ZK-SealedWeigh.Pedersen.H.v3" || counter))，counter=2
    uint256 private constant HX = 0x23AE7E827609887FF1721F43EFED23E0D3941CEF3A524E28576A8C165B0B23C1;
    uint256 private constant HY = 0x09485BCE1C81E4F60D2852F4AB22F9A79997CC8A19F87AFBFCEE998CC818B5F6;

    struct Voting {
        string title;
        string description;
        address creator;
        uint256 maxScore;
        uint256 commitDuration;
        uint256 scoreDuration;
        uint256 startTime;
        bool isActive;
        uint8 phase;
        bytes32 merkleRoot;
    }

    struct PedersenCommitment {
        bytes32 commitmentHash;
        uint256[] commitmentX;   // 承诺点 x 坐标（原样上链，供链上验算）
        uint256[] commitmentY;   // 承诺点 y 坐标
        bool hasRevealed;
        uint256 timestamp;
    }

    struct Score {
        address voter;
        uint256 candidateId;
        uint256 score;
        uint256 timestamp;
        uint256 weight;
    }

    mapping(uint256 => Voting) public votings;
    mapping(uint256 => address[]) public votingVoters;
    mapping(uint256 => string[]) public votingCandidates;
    mapping(uint256 => mapping(address => PedersenCommitment)) public pedersenCommitments;
    mapping(uint256 => Score[]) public scores;
    mapping(uint256 => mapping(address => uint256)) public voterWeights;
    mapping(uint256 => mapping(bytes32 => bool)) public usedNullifiers;

    mapping(uint256 => mapping(address => uint256)) public rangeCommitments;

    uint256 public votingCount;

    /// @notice 范围证明的 Groth16 验证器（构造时部署，避免额外的地址配置）
    Groth16Verifier public immutable rangeVerifier;

    constructor() {
        relayer = msg.sender;
        rangeVerifier = new Groth16Verifier();
    }

    event VotingCreated(uint256 indexed votingId, address creator, string title, bytes32 merkleRoot);
    event PhaseChanged(uint256 indexed votingId, uint8 newPhase);
    event PedersenCommitmentSubmitted(
        uint256 indexed votingId,
        address voter,
        bytes32 commitmentHash,
        uint256[] commitmentX,
        uint256[] commitmentY
    );
    event PedersenScoreRevealed(uint256 indexed votingId, address voter, uint256[] scores, uint256 weight);
    event RangeProofSubmitted(uint256 indexed votingId, address voter, uint256 commitment);
    event VoterAdded(uint256 indexed votingId, address voter, uint256 weight);
    event ResultsCalculated(uint256 indexed votingId, uint256[] results);

    // ==================== 曲线运算（EIP-196 / EIP-197 预编译）====================

    /// @dev 0x06 ecAdd：输入 128 字节 (x1,y1,x2,y2)，输出 64 字节
    function _ecAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        internal
        view
        returns (bool ok, uint256 x3, uint256 y3)
    {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory out;
        assembly {
            ok := staticcall(gas(), 0x06, input, 0x80, out, 0x40)
        }
        return (ok, out[0], out[1]);
    }

    /// @dev 0x07 ecMul：输入 96 字节 (x,y,scalar)，输出 64 字节
    function _ecMul(uint256 x, uint256 y, uint256 scalar)
        internal
        view
        returns (bool ok, uint256 x3, uint256 y3)
    {
        uint256[3] memory input = [x, y, scalar];
        uint256[2] memory out;
        assembly {
            ok := staticcall(gas(), 0x07, input, 0x60, out, 0x40)
        }
        return (ok, out[0], out[1]);
    }

    /**
     * @dev 点是否在曲线上。
     * 直接借 ecAdd 做校验：EIP-196 规定输入非曲线点时必须失败，
     * 因此 staticcall 返回 false 即代表点非法。比对 y²==x³+3 省去大数模运算。
     * 同时拒绝 (0,0)（无穷远点不能作为承诺）。
     */
    function isOnCurve(uint256 x, uint256 y) public view returns (bool) {
        if (x == 0 && y == 0) return false;
        if (x >= P || y >= P) return false;
        (bool ok, , ) = _ecAdd(x, y, GX, GY);
        return ok;
    }

    /// @dev 盲化因子派生：r_i = sha256("secret:i:count") mod n —— 与 Python/JS 完全一致
    function deriveBlinding(string memory _secret, uint256 _index, uint256 _count)
        public
        pure
        returns (uint256)
    {
        bytes memory material = bytes(string.concat(_secret, ":", _index.toString(), ":", _count.toString()));
        return uint256(sha256(material)) % N;
    }

    /**
     * @dev 校验 C == value·G + blinding·H。
     * 这是 v3 的核心：链上不再信任 relayer 提交的点，而是自己重算。
     */
    function verifyCommitmentPoint(uint256 value, uint256 blinding, uint256 cx, uint256 cy)
        public
        view
        returns (bool)
    {
        (bool okG, uint256 gx, uint256 gy) = _ecMul(GX, GY, value % N);
        if (!okG) return false;
        (bool okH, uint256 hx, uint256 hy) = _ecMul(HX, HY, blinding % N);
        if (!okH) return false;
        (bool okA, uint256 ax, uint256 ay) = _ecAdd(gx, gy, hx, hy);
        if (!okA) return false;
        return ax == cx && ay == cy;
    }

    // ==================== Merkle 白名单 ====================

    function verifyMerkleProof(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) public pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash == root;
    }

    // ==================== 生命周期 ====================

    function createVoting(
        string memory _title,
        string memory _description,
        uint256 _maxScore,
        uint256 _commitDuration,
        uint256 _scoreDuration,
        string[] memory _candidates,
        address[] memory _voters,
        uint256[] memory _weights,
        bytes32 _merkleRoot,
        address _creator
    ) public returns (uint256) {
        require(msg.sender == relayer, "Only relayer");
        require(_creator != address(0), "Invalid creator");
        require(_voters.length == _weights.length, "Voters and weights length mismatch");
        require(_candidates.length >= 2, "At least 2 candidates required");
        require(_commitDuration > 0, "Commit duration must be positive");
        require(_scoreDuration > 0, "Score duration must be positive");

        uint256 votingId = votingCount++;

        votings[votingId] = Voting({
            title: _title,
            description: _description,
            creator: _creator,
            maxScore: _maxScore,
            commitDuration: _commitDuration,
            scoreDuration: _scoreDuration,
            startTime: block.timestamp,
            isActive: true,
            phase: 1,
            merkleRoot: _merkleRoot
        });

        for (uint256 i = 0; i < _candidates.length; i++) {
            votingCandidates[votingId].push(_candidates[i]);
        }

        for (uint256 i = 0; i < _voters.length; i++) {
            require(_voters[i] != address(0), "Invalid voter address");
            require(_weights[i] > 0, "Weight must be positive");

            votingVoters[votingId].push(_voters[i]);
            voterWeights[votingId][_voters[i]] = _weights[i];
            emit VoterAdded(votingId, _voters[i], _weights[i]);
        }

        emit VotingCreated(votingId, msg.sender, _title, _merkleRoot);
        return votingId;
    }

    /**
     * @dev 提交承诺点。v3 与 v2 的接口差异：不再传 keccak(点)，而是传 (x, y) 原值。
     */
    function submitPedersenCommitment(
        uint256 _votingId,
        address _voter,
        bytes32 _commitmentHash,
        uint256[] memory _commitmentX,
        uint256[] memory _commitmentY,
        bytes32[] memory _merkleProof,
        bytes memory _signature
    ) public {
        require(msg.sender == relayer, "Only relayer");
        Voting storage voting = votings[_votingId];
        require(voting.isActive, "Voting is not active");
        require(voting.phase == 1, "Not in commit phase");
        require(block.timestamp <= voting.startTime + voting.commitDuration, "Commit phase ended");
        require(pedersenCommitments[_votingId][_voter].commitmentHash == bytes32(0), "Already committed");

        uint256 n = votingCandidates[_votingId].length;
        require(_commitmentX.length == n && _commitmentY.length == n, "Invalid commitments count");

        // 逐点校验：必须在 alt_bn128 上且非无穷远点
        for (uint256 i = 0; i < n; i++) {
            require(isOnCurve(_commitmentX[i], _commitmentY[i]), "Commitment point not on curve");
        }

        // 投票者本人签名授权（后端代发，无法伪造他人承诺）
        _verifyVoterSig(commitDigest(_votingId, _voter, _commitmentHash), _signature, _voter);

        bytes32 leaf = keccak256(abi.encodePacked(_voter));
        require(verifyMerkleProof(_merkleProof, voting.merkleRoot, leaf), "Not authorized voter");

        PedersenCommitment storage pc = pedersenCommitments[_votingId][_voter];
        pc.commitmentHash = _commitmentHash;
        pc.commitmentX = _commitmentX;
        pc.commitmentY = _commitmentY;
        pc.hasRevealed = false;
        pc.timestamp = block.timestamp;

        emit PedersenCommitmentSubmitted(_votingId, _voter, _commitmentHash, _commitmentX, _commitmentY);
    }

    /**
     * @dev 范围证明的公开承诺：Poseidon(scores 补齐到 3 位, salt, voter)
     * 电路按 n=3 编译；不足 3 个候选人时补 0（补的 0 必然在范围内）。
     */
    function rangeHash(uint256[] memory _scores, uint256 _salt, address _voter) public pure returns (uint256) {
        require(_scores.length <= 3, "Range proof supports at most 3 candidates");
        uint256[5] memory input;
        input[0] = _scores.length > 0 ? _scores[0] : 0;
        input[1] = _scores.length > 1 ? _scores[1] : 0;
        input[2] = _scores.length > 2 ? _scores[2] : 0;
        input[3] = _salt;
        input[4] = uint256(uint160(_voter));
        return PoseidonT6.hash(input);
    }

    /**
     * @notice 提交范围证明（证明「分数都在 [0, maxScore]」且承诺绑定评委本人）
     *
     * P5（R-10）：要求评委对 `rangeDigest(votingId, voter, commitment)` 签名。
     * 证明的公开承诺本来已绑定 voter，但 relayer 仍可替换/省略；加签名后
     * relayer 只能拒绝上链（审查，属 R-4），不能替换成别的 commitment。
     */
    function submitRangeProof(
        uint256 _votingId,
        address _voter,
        uint256 _commitment,
        uint256[2] memory _a,
        uint256[2][2] memory _b,
        uint256[2] memory _c,
        bytes memory _signature
    ) public {
        require(msg.sender == relayer, "Only relayer");
        Voting storage voting = votings[_votingId];
        require(voting.isActive, "Voting is not active");
        require(voting.phase == 1, "Not in commit phase");
        require(pedersenCommitments[_votingId][_voter].commitmentHash != bytes32(0), "Commit Pedersen first");

        // P5（R-10）：范围证明必须由评委本人授权。relayer 仍可拒绝上链（审查），
        // 但不能再替换成别人的证明或替换 commitment。
        _verifyVoterSig(rangeDigest(_votingId, _voter, _commitment), _signature, _voter);

        // 公开信号 = [commitment, maxScore]：maxScore 绑定到本活动的满分，
        // 防止把一个满分 100 的证明复用到满分 10 的活动。
        uint256[2] memory pubSignals;
        pubSignals[0] = _commitment;
        pubSignals[1] = voting.maxScore;
        require(rangeVerifier.verifyProof(_a, _b, _c, pubSignals), "Invalid range proof");

        rangeCommitments[_votingId][_voter] = _commitment;
        emit RangeProofSubmitted(_votingId, _voter, _commitment);
    }

    function revealPedersenScores(
        uint256 _votingId,
        address _voter,
        uint256[] memory _scores,
        string memory _secret,
        uint256 _salt,
        bytes32 _nullifier,
        bytes memory _signature
    ) public {
        require(msg.sender == relayer, "Only relayer");
        Voting storage voting = votings[_votingId];
        require(voting.isActive, "Voting is not active");
        require(voting.phase == 2, "Not in scoring phase");
        require(block.timestamp <= voting.startTime + voting.commitDuration + voting.scoreDuration, "Scoring phase ended");
        require(isVoter(_votingId, _voter), "Not a voter in this voting");
        // P5（R-3）：nullifier 由合约按 (votingId, voter) 派生，客户端只能提交
        // 这个派生值；任何自定义 nullifier 都会在这里被拒绝。
        require(_nullifier == deriveNullifier(_votingId, _voter), "Invalid nullifier");
        require(!pedersenCommitments[_votingId][_voter].hasRevealed, "Already revealed");
        require(!usedNullifiers[_votingId][_nullifier], "Nullifier already used");
        require(_scores.length == votingCandidates[_votingId].length, "Scores count mismatch");

        PedersenCommitment storage pc = pedersenCommitments[_votingId][_voter];
        require(pc.commitmentX.length == _scores.length, "No commitment stored");

        // 投票者本人签名授权
        _verifyVoterSig(revealDigest(_votingId, _voter, _scores, _nullifier), _signature, _voter);

        // —— v3 核心：链上用预编译重算每个承诺点并比对 ——
        for (uint256 i = 0; i < _scores.length; i++) {
            uint256 blinding = deriveBlinding(_secret, i, _scores.length);
            require(
                verifyCommitmentPoint(_scores[i], blinding, pc.commitmentX[i], pc.commitmentY[i]),
                "Pedersen point mismatch"
            );
        }

        // —— 范围证明绑定：承诺阶段已通过 Groth16 验证的 poseidon 承诺必须与揭晓值一致 ——
        // 由此可断言：揭开的这组分数，就是当初被证明"每个分量都在 [0, maxScore]"的那组。
        uint256 rc = rangeCommitments[_votingId][_voter];
        require(rc != 0, "Range proof missing");
        require(rangeHash(_scores, _salt, _voter) == rc, "Range commitment mismatch");

        // 仍保留承诺哈希校验：它把 votingId / voter / 明文一起绑定，防跨活动、跨评委重放
        bytes32 calculatedHash = calculateCommitmentHash(_votingId, _voter, _scores, _secret, voting.maxScore);
        require(pc.commitmentHash == calculatedHash, "Commitment hash mismatch");

        usedNullifiers[_votingId][_nullifier] = true;

        uint256 weight = voterWeights[_votingId][_voter];
        for (uint256 i = 0; i < _scores.length; i++) {
            require(_scores[i] <= voting.maxScore, "Score exceeds max score");
            scores[_votingId].push(Score({
                voter: _voter,
                candidateId: i,
                score: _scores[i],
                timestamp: block.timestamp,
                weight: weight
            }));
        }

        pc.hasRevealed = true;
        emit PedersenScoreRevealed(_votingId, _voter, _scores, weight);
    }

    // ==================== 摘要 ====================

    /// @notice 承诺哈希（spec.md 4.2）：绑定 votingId 与 voter，禁止跨活动/跨评委复用
    function calculateCommitmentHash(
        uint256 _votingId,
        address _voter,
        uint256[] memory _scores,
        string memory _secret,
        uint256 _maxScore
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(TAG_COMMITMENT, _votingId, _voter, _scores, _secret, _maxScore));
    }

    /// @notice 提交阶段待签名摘要（EIP-191 前置）——后端与投票者钱包必须一致地构造
    function commitDigest(uint256 _votingId, address _voter, bytes32 _commitmentHash) public pure returns (bytes32) {
        return keccak256(abi.encode(TAG_COMMITMENT_SIG, _votingId, _voter, _commitmentHash));
    }

    /// @notice 揭示阶段待签名摘要（EIP-191 前置）
    function revealDigest(
        uint256 _votingId,
        address _voter,
        uint256[] memory _scores,
        bytes32 _nullifier
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(TAG_REVEAL_SIG, _votingId, _voter, _scores, _nullifier));
    }

    /// @notice 活动内唯一的揭晓标识：keccak256(abi.encode(TAG_NULLIFIER, votingId, voter))
    function deriveNullifier(uint256 _votingId, address _voter) public pure returns (bytes32) {
        return keccak256(abi.encode(TAG_NULLIFIER, _votingId, _voter));
    }

    /// @notice 范围证明待签名摘要：keccak256(abi.encode(TAG_RANGE_SIG, votingId, voter, commitment))
    function rangeDigest(uint256 _votingId, address _voter, uint256 _commitment) public pure returns (bytes32) {
        return keccak256(abi.encode(TAG_RANGE_SIG, _votingId, _voter, _commitment));
    }

    function _verifyVoterSig(bytes32 digest, bytes memory signature, address voter) internal pure {
        require(voter != address(0), "Invalid voter");
        require(signature.length == 65, "Invalid signature length");
        bytes32 ethHash = keccak256(abi.encodePacked(SIG_PREFIX, digest));
        require(ECDSA.recover(ethHash, signature) == voter, "Invalid signature");
    }

    // ==================== 结算与查询 ====================

    function calculateResults(uint256 _votingId) public returns (uint256[] memory) {
        Voting storage voting = votings[_votingId];
        require(voting.isActive, "Voting is not active");
        require(voting.phase == 2, "Not in scoring phase");
        require(msg.sender == voting.creator || msg.sender == relayer, "Only creator or relayer can calculate results");
        require(block.timestamp > voting.startTime + voting.commitDuration + voting.scoreDuration, "Scoring phase not ended");

        uint256 candidateCount = votingCandidates[_votingId].length;
        uint256[] memory results = new uint256[](candidateCount);

        for (uint256 i = 0; i < scores[_votingId].length; i++) {
            Score memory s = scores[_votingId][i];
            results[s.candidateId] += s.score * s.weight;
        }

        voting.phase = 3;
        emit ResultsCalculated(_votingId, results);

        return results;
    }

    function isVoter(uint256 _votingId, address _voter) public view returns (bool) {
        address[] memory voters = votingVoters[_votingId];
        for (uint256 i = 0; i < voters.length; i++) {
            if (voters[i] == _voter) {
                return true;
            }
        }
        return false;
    }

    function getVotingResults(uint256 _votingId) public view returns (uint256[] memory) {
        uint256 candidateCount = votingCandidates[_votingId].length;
        uint256[] memory results = new uint256[](candidateCount);

        for (uint256 i = 0; i < scores[_votingId].length; i++) {
            Score memory s = scores[_votingId][i];
            results[s.candidateId] += s.score * s.weight;
        }

        return results;
    }

    function getCandidates(uint256 _votingId) public view returns (string[] memory) {
        return votingCandidates[_votingId];
    }

    function getVoters(uint256 _votingId) public view returns (address[] memory) {
        return votingVoters[_votingId];
    }

    function getVoterWeight(uint256 _votingId, address _voter) public view returns (uint256) {
        return voterWeights[_votingId][_voter];
    }

    /// @notice 返回链上存储的承诺点，便于第三方独立复算
    function getCommitmentPoints(uint256 _votingId, address _voter)
        public
        view
        returns (uint256[] memory xs, uint256[] memory ys)
    {
        PedersenCommitment storage pc = pedersenCommitments[_votingId][_voter];
        return (pc.commitmentX, pc.commitmentY);
    }

    function hasCommitted(uint256 _votingId, address _voter) public view returns (bool) {
        return pedersenCommitments[_votingId][_voter].commitmentHash != bytes32(0);
    }

    function hasRevealed(uint256 _votingId, address _voter) public view returns (bool) {
        return pedersenCommitments[_votingId][_voter].hasRevealed;
    }

    function updateVotingPhase(uint256 _votingId, uint8 _phase) public {
        Voting storage voting = votings[_votingId];
        require(msg.sender == voting.creator || msg.sender == relayer, "Only creator or relayer can update phase");
        require(voting.isActive, "Voting is not active");
        require(_phase <= 3, "Invalid phase");
        // P4 模型检验发现：原实现允许 2→1 回退，会让"已评分"活动重新接受承诺。
        // 阶段必须单调前进；取消/结束请使用 endVoting()。
        require(_phase >= voting.phase, "Phase cannot move backwards");

        voting.phase = _phase;
        emit PhaseChanged(_votingId, _phase);
    }

    function endVoting(uint256 _votingId) public {
        Voting storage voting = votings[_votingId];
        require(msg.sender == voting.creator || msg.sender == relayer, "Only creator or relayer can end voting");
        require(voting.isActive, "Voting already ended");

        voting.isActive = false;
        voting.phase = 3;
    }

    function getVotingStats(uint256 _votingId) public view returns (
        uint256 totalVoters,
        uint256 committedVoters,
        uint256 revealedVoters,
        uint256 totalScores
    ) {
        address[] memory voters = votingVoters[_votingId];
        totalVoters = voters.length;

        for (uint256 i = 0; i < voters.length; i++) {
            if (hasCommitted(_votingId, voters[i])) {
                committedVoters++;
            }
            if (hasRevealed(_votingId, voters[i])) {
                revealedVoters++;
            }
        }

        totalScores = scores[_votingId].length;

        return (totalVoters, committedVoters, revealedVoters, totalScores);
    }

    function getVotingPhaseStatus(uint256 _votingId) public view returns (
        uint8 phase,
        bool isActive,
        uint256 timeRemaining
    ) {
        Voting storage voting = votings[_votingId];
        phase = voting.phase;
        isActive = voting.isActive;

        if (phase == 1) {
            if (block.timestamp > voting.startTime + voting.commitDuration) {
                timeRemaining = 0;
            } else {
                timeRemaining = voting.startTime + voting.commitDuration - block.timestamp;
            }
        } else if (phase == 2) {
            if (block.timestamp > voting.startTime + voting.commitDuration + voting.scoreDuration) {
                timeRemaining = 0;
            } else {
                timeRemaining = voting.startTime + voting.commitDuration + voting.scoreDuration - block.timestamp;
            }
        } else {
            timeRemaining = 0;
        }

        return (phase, isActive, timeRemaining);
    }
}
