/**
 * spec.md 第 7 节测试向量 —— Solidity 侧一致性断言（协议 v3 / alt_bn128）
 *
 * 与 backend/utils/protocol.py 的 self_check() 及 frontend/zk-crypto.js 使用同一组夹具，
 * 三方必须逐字节一致。运行：npx hardhat test
 */
import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const RANGE_FIXTURE_PATH = path.join(__dirname, "..", "..", "circuits", "build", "proof_fixture.json");
const RANGE_SALT = "12345678901234567890";

// spec.md 第 7 节夹具
const FIXTURE = {
    votingId: 1,
    voter: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    scores: [7, 9, 0],
    secret: "correct horse battery staple",
    maxScore: 10,
    nullifier: "0xc1da3c3588b03fbe83be605534c6a9f58ceba3081c58c041a0a9ae0a9111a8fc",
};

const EXPECTED = {
    TAG_COMMITMENT: "0xf989c362dc9cceb77b838df72487e54a41bd549faa230a87932d4fb9b04f08b7",
    TAG_COMMIT_SIG: "0x735f961bc7874a87e44d11e265946ea355f478906fb5489ec1b8739bcc00c6ab",
    TAG_REVEAL_SIG: "0x67d980de8ae16cf5ab80b48362d15dcd4c2d9d207672346e98847066da301db6",
    TAG_RANGE_SIG: "0x1693686b05e4d5b7a1091a1e4260ff5886009af024017cf6b75fd91772dd8404",
    TAG_NULLIFIER: "0x07eee5bbe23d4225614099ecb14510f5168bf7c194bc0ffb673ae42164adcfe2",
    commitmentHash: "0x3bb8f63ff26c8f455588b1f6b55363f628b71f5eaef4673ab5cee01de282be0c",
    commitDigest: "0x2cd580910aa9acbee0e0956def252fbae3468764ba7b60cad9946d3f34a9f609",
    revealDigest: "0x7e5db8ac0976c7e409c94b3a0f236919362c5a396f871d79228fbd7b43e1e4fb",
    derivedNullifier: "0xe5f5161b4b98890d723fa3d596954ba85525c9b44b319e6e53c772142d932eb7",
    rangeDigest: "0xc100ac7c9d3bef526ff22abb1d71e675ddc8bc7245eff729b7cefa7b30ddd835",
};

// 三个承诺点与盲化因子（Python 生成，JS 已验证逐字节一致）
const POINTS = [
    "0x06ae23dbd2b2c323dd377f3ebcd6ddab72d8ae7f5634bd39bdbfecd92ef9b3fc0ef6987c64195d008237f32797de0433c236225a13cd6b0873ea09d68258d4fb",
    "0x25ab8fba6599243fb05c1c8c6532d9ade3a1fa51109f91b189dc06e09ea5a90e0d2bc03efdd457045885e6c2dde903bcee50494b28315fcfddf24da1ee7d38f3",
    "0x14b081aec82aa9c3e4c4a2444b566eaaba63a4083a2d67d8594a18fdd7932bff244f9fad0994da303dd67ac4b6da94d1d17ad4a3a923e71713fa329755721510",
];
const BLINDINGS = [
    "11331531710196327524856561149319088737098671986330248307203685176617335942994",
    "2800419421753264120076415202257965566892541408650663719876681182483906309872",
    "4804764372245660068797630501824517595943658061948539868936512225051414332963",
];

function splitPoint(hex: string): [string, string] {
    const body = hex.startsWith("0x") ? hex.slice(2) : hex;
    return ["0x" + body.slice(0, 64), "0x" + body.slice(64)];
}

function leafOf(address: string): string {
    // 合约用 keccak256(abi.encodePacked(address))，即 20 字节紧凑编码
    return ethers.utils.solidityKeccak256(["address"], [address]);
}

describe("spec.md 第 7 节测试向量：Solidity 侧（v3 / alt_bn128）", function () {
    let zk: any;
    let rangeFixture: any;

    before(async function () {
        rangeFixture = JSON.parse(fs.readFileSync(RANGE_FIXTURE_PATH, "utf8"));

        // PoseidonT6 是 public 库，需要链接后才能部署 ZKVoting
        const PoseidonT6 = await ethers.getContractFactory("PoseidonT6");
        const poseidonT6 = await PoseidonT6.deploy();
        await poseidonT6.deployed();

        const ZKVoting = await ethers.getContractFactory("ZKVoting", {
            libraries: { PoseidonT6: poseidonT6.address },
        });
        zk = await ZKVoting.deploy();
        await zk.deployed();
    });

    /** 提交 Pedersen 承诺 + 范围证明（复用 circuits 生成的证明样本） */
    async function commitWithRangeProof(votingId: any, voter: any, xs: string[], ys: string[], commitmentHash: string) {
        const cDigest = await zk.commitDigest(votingId, voter.address, commitmentHash);
        const cSig = await voter.signMessage(ethers.utils.arrayify(cDigest));
        await (await zk.submitPedersenCommitment(
            votingId, voter.address, commitmentHash, xs, ys, [], cSig
        )).wait();

        const [a, b, c] = rangeFixture.calldata;
        const rDigest = await zk.rangeDigest(votingId, voter.address, rangeFixture.commitment);
        const rSig = await voter.signMessage(ethers.utils.arrayify(rDigest));
        await (await zk.submitRangeProof(
            votingId, voter.address, rangeFixture.commitment, a, b, c, rSig
        )).wait();
    }

    // ---------------- 摘要一致性 ----------------

    it("commitmentHash 与 spec 一致", async function () {
        const hash = await zk.calculateCommitmentHash(
            FIXTURE.votingId, FIXTURE.voter, FIXTURE.scores, FIXTURE.secret, FIXTURE.maxScore
        );
        expect(hash).to.equal(EXPECTED.commitmentHash);
    });

    it("commitDigest 与 spec 一致", async function () {
        const digest = await zk.commitDigest(FIXTURE.votingId, FIXTURE.voter, EXPECTED.commitmentHash);
        expect(digest).to.equal(EXPECTED.commitDigest);
    });

    it("revealDigest 与 spec 一致", async function () {
        const digest = await zk.revealDigest(FIXTURE.votingId, FIXTURE.voter, FIXTURE.scores, FIXTURE.nullifier);
        expect(digest).to.equal(EXPECTED.revealDigest);
    });

    it("deriveNullifier 与 spec 一致（R-3）", async function () {
        const derived = await zk.deriveNullifier(FIXTURE.votingId, FIXTURE.voter);
        expect(derived).to.equal(EXPECTED.derivedNullifier);
        // 绑定 votingId 与 voter：换任一维度都必须不同
        expect(await zk.deriveNullifier(2, FIXTURE.voter)).to.not.equal(derived);
        expect(await zk.deriveNullifier(FIXTURE.votingId, ethers.constants.AddressZero))
            .to.not.equal(derived);
    });

    it("rangeDigest 与 spec 一致（R-10）", async function () {
        const digest = await zk.rangeDigest(
            FIXTURE.votingId, FIXTURE.voter, rangeFixture.commitment);
        expect(digest).to.equal(EXPECTED.rangeDigest);
        expect(await zk.rangeDigest(2, FIXTURE.voter, rangeFixture.commitment))
            .to.not.equal(digest);
    });

    it("commitmentHash 确实绑定了 votingId 与 voter（R4）", async function () {
        const base = await zk.calculateCommitmentHash(
            FIXTURE.votingId, FIXTURE.voter, FIXTURE.scores, FIXTURE.secret, FIXTURE.maxScore
        );
        const otherVoting = await zk.calculateCommitmentHash(
            2, FIXTURE.voter, FIXTURE.scores, FIXTURE.secret, FIXTURE.maxScore
        );
        const otherVoter = await zk.calculateCommitmentHash(
            FIXTURE.votingId, ethers.constants.AddressZero, FIXTURE.scores, FIXTURE.secret, FIXTURE.maxScore
        );
        expect(base).to.not.equal(otherVoting);
        expect(base).to.not.equal(otherVoter);
    });

    it("不再存在任何单方代揭晓入口（G6）", async function () {
        expect(zk.recoverPedersenScores).to.equal(undefined);
        expect(zk.calculatePedersenHash).to.equal(undefined);
    });

    // ---------------- v3 新增：曲线层 ----------------

    it("deriveBlinding 与 Python/JS 一致（sha256 派生）", async function () {
        for (let i = 0; i < BLINDINGS.length; i++) {
            const got = await zk.deriveBlinding(FIXTURE.secret, i, BLINDINGS.length);
            expect(got.toString()).to.equal(BLINDINGS[i]);
        }
    });

    it("isOnCurve 接受 G 与合法承诺点，拒绝伪造点", async function () {
        expect(await zk.isOnCurve(1, 2)).to.equal(true);       // G
        for (const p of POINTS) {
            const [x, y] = splitPoint(p);
            expect(await zk.isOnCurve(x, y)).to.equal(true);
        }
        expect(await zk.isOnCurve(1, 3)).to.equal(false);
        expect(await zk.isOnCurve(0, 0)).to.equal(false);      // 无穷远点
    });

    it("verifyCommitmentPoint 对正确 (分数, 盲化) 为 true，篡改为 false", async function () {
        for (let i = 0; i < POINTS.length; i++) {
            const [x, y] = splitPoint(POINTS[i]);
            expect(await zk.verifyCommitmentPoint(FIXTURE.scores[i], BLINDINGS[i], x, y)).to.equal(true);
            expect(await zk.verifyCommitmentPoint(FIXTURE.scores[i] + 1, BLINDINGS[i], x, y)).to.equal(false);
            expect(await zk.verifyCommitmentPoint(FIXTURE.scores[i], BLINDINGS[i], x, "0x01")).to.equal(false);
        }
    });

    // ---------------- 全链路 ----------------

    it("完整链路：提交承诺点 → 揭晓 → 链上验算并记账（含 gas）", async function () {
        const signers = await ethers.getSigners();
        const deployer = signers[0];
        const voter = signers[1];

        const candidates = ["A", "B", "C"];
        const merkleRoot = leafOf(voter.address);

        await (await zk.createVoting(
            "v3 测试", "链上验算", 10, 3600, 7200, candidates,
            [voter.address], [100], merkleRoot, deployer.address
        )).wait();

        const votingId = (await zk.votingCount()).sub(1);
        const commitmentHash = await zk.calculateCommitmentHash(
            votingId, voter.address, FIXTURE.scores, FIXTURE.secret, 10
        );

        const xs = POINTS.map((p) => splitPoint(p)[0]);
        const ys = POINTS.map((p) => splitPoint(p)[1]);

        const commitDigest = await zk.commitDigest(votingId, voter.address, commitmentHash);
        const commitSig = await voter.signMessage(ethers.utils.arrayify(commitDigest));

        const commitReceipt = await (
            await zk.submitPedersenCommitment(votingId, voter.address, commitmentHash, xs, ys, [], commitSig)
        ).wait();
        console.log(`      提交承诺（3 次 on-curve 校验）gas = ${commitReceipt.gasUsed.toString()}`);

        // 范围证明：链上 verifyProof，并把 Poseidon 承诺写入 rangeCommitments
        const [ra, rb, rcA] = rangeFixture.calldata;
        const rangeDigest = await zk.rangeDigest(
            votingId, voter.address, rangeFixture.commitment);
        const rangeSig = await voter.signMessage(ethers.utils.arrayify(rangeDigest));
        const rangeReceipt = await (
            await zk.submitRangeProof(
                votingId, voter.address, rangeFixture.commitment, ra, rb, rcA, rangeSig)
        ).wait();
        console.log(`      提交范围证明（Groth16 verify）gas = ${rangeReceipt.gasUsed.toString()}`);
        expect(await zk.rangeCommitments(votingId, voter.address)).to.equal(rangeFixture.commitment);

        await (await zk.updateVotingPhase(votingId, 2)).wait();

        // R-3：nullifier 现在由合约派生
        const nullifier = await zk.deriveNullifier(votingId, voter.address);
        const revealDigest = await zk.revealDigest(votingId, voter.address, FIXTURE.scores, nullifier);
        const revealSig = await voter.signMessage(ethers.utils.arrayify(revealDigest));

        const revealReceipt = await (
            await zk.revealPedersenScores(
                votingId, voter.address, FIXTURE.scores, FIXTURE.secret,
                RANGE_SALT, nullifier, revealSig
            )
        ).wait();
        console.log(`      揭晓（3 点椭圆曲线验算）gas = ${revealReceipt.gasUsed.toString()}`);

        expect(await zk.hasRevealed(votingId, voter.address)).to.equal(true);

        const stats = await zk.getVotingStats(votingId);
        expect(stats.totalScores.toString()).to.equal("3");

        const results = await zk.getVotingResults(votingId);
        expect(results[0].toString()).to.equal("700");
        expect(results[1].toString()).to.equal("900");
        expect(results[2].toString()).to.equal("0");
    });

    it("relayer 替换承诺点后揭晓必定失败（v3 修复的核心漏洞）", async function () {
        const signers = await ethers.getSigners();
        const deployer = signers[0];
        const voter = signers[1];

        const candidates = ["A", "B"];
        const merkleRoot = leafOf(voter.address);

        await (await zk.createVoting(
            "替换攻击", "", 10, 3600, 7200, candidates,
            [voter.address], [100], merkleRoot, deployer.address
        )).wait();
        const votingId = (await zk.votingCount()).sub(1);

        const scores = [7, 9];
        const secret = FIXTURE.secret;
        const commitmentHash = await zk.calculateCommitmentHash(
            votingId, voter.address, scores, secret, 10
        );

        // 攻击场景：评委只对 commitmentHash 签名（哈希不含点），
        // relayer 因此可以自行选择任意合法点上链。这里故意把第 2 点换成 P2
        // （P2 对应分数 0，而不是 9）。
        const xs = [splitPoint(POINTS[0])[0], splitPoint(POINTS[2])[0]];
        const ys = [splitPoint(POINTS[0])[1], splitPoint(POINTS[2])[1]];

        // 两个点都是合法曲线点，on-curve 检查会通过
        expect(await zk.isOnCurve(xs[1], ys[1])).to.equal(true);

        const commitDigest = await zk.commitDigest(votingId, voter.address, commitmentHash);
        const commitSig = await voter.signMessage(ethers.utils.arrayify(commitDigest));
        await (await zk.submitPedersenCommitment(
            votingId, voter.address, commitmentHash, xs, ys, [], commitSig
        )).wait();

        // 攻击者仍然可以提交一个**合法**范围证明（[7,9] 补齐为 [7,9,0]，与证明样本一致）
        const [ra, rb, rcA] = rangeFixture.calldata;
        const rangeDigest = await zk.rangeDigest(
            votingId, voter.address, rangeFixture.commitment);
        const rangeSig = await voter.signMessage(ethers.utils.arrayify(rangeDigest));
        await (await zk.submitRangeProof(
            votingId, voter.address, rangeFixture.commitment, ra, rb, rcA, rangeSig
        )).wait();

        await (await zk.updateVotingPhase(votingId, 2)).wait();

        const nullifier = await zk.deriveNullifier(votingId, voter.address);
        const revealDigest = await zk.revealDigest(votingId, voter.address, scores, nullifier);
        const revealSig = await voter.signMessage(ethers.utils.arrayify(revealDigest));

        // v3：链上重算 C'_i 并比对 → 第 2 点不匹配，必须 revert
        await expect(
            zk.revealPedersenScores(
                votingId, voter.address, scores, secret, RANGE_SALT, nullifier, revealSig
            )
        ).to.be.revertedWith("Pedersen point mismatch");
    });

    it("缺少范围证明时揭晓被拒", async function () {
        const signers = await ethers.getSigners();
        const deployer = signers[0];
        const voter = signers[1];
        const candidates = ["A", "B", "C"];
        const merkleRoot = leafOf(voter.address);

        await (await zk.createVoting(
            "缺证明", "", 10, 3600, 7200, candidates,
            [voter.address], [100], merkleRoot, deployer.address
        )).wait();
        const votingId = (await zk.votingCount()).sub(1);

        const commitmentHash = await zk.calculateCommitmentHash(
            votingId, voter.address, FIXTURE.scores, FIXTURE.secret, 10
        );
        const xs = POINTS.map((p) => splitPoint(p)[0]);
        const ys = POINTS.map((p) => splitPoint(p)[1]);
        const cDigest = await zk.commitDigest(votingId, voter.address, commitmentHash);
        const cSig = await voter.signMessage(ethers.utils.arrayify(cDigest));
        await (await zk.submitPedersenCommitment(
            votingId, voter.address, commitmentHash, xs, ys, [], cSig
        )).wait();

        await (await zk.updateVotingPhase(votingId, 2)).wait();
        const nullifier = await zk.deriveNullifier(votingId, voter.address);
        const rDigest = await zk.revealDigest(votingId, voter.address, FIXTURE.scores, nullifier);
        const rSig = await voter.signMessage(ethers.utils.arrayify(rDigest));

        await expect(
            zk.revealPedersenScores(
                votingId, voter.address, FIXTURE.scores, FIXTURE.secret,
                RANGE_SALT, nullifier, rSig
            )
        ).to.be.revertedWith("Range proof missing");
    });

    it("链上 rangeHash 与电路公开信号一致", async function () {
        const voter = (await ethers.getSigners())[1];
        const onchain = await zk.rangeHash(FIXTURE.scores, RANGE_SALT, voter.address);
        expect(onchain.toString()).to.equal(rangeFixture.commitment);
    });
});
