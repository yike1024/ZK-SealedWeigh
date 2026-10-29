/**
 * P4 合约状态机模糊测试（确定性种子，无外部依赖）
 *
 * 1. 相位模糊：随机生成 updateVotingPhase 序列，断言阶段永不回退、
 *    结束后的状态不可再修改；
 * 2. 生命周期：用固定夹具覆盖"重复提交 / 越权 / 曲线伪点 / 错误揭晓 /
 *    重复揭晓 / 提前结算 / 阶段回退"等探针，并核对统计与结果。
 *
 * 运行：npx hardhat test test/fuzz.test.ts
 */
import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const FIXTURE_PATH = path.join(__dirname, "..", "..", "circuits", "build", "proof_fixture.json");
const SALT = "12345678901234567890";
const SCORES = [7, 9, 0];
const SECRET = "correct horse battery staple";

const COMMITMENT_HASH = "0x3bb8f63ff26c8f455588b1f6b55363f628b71f5eaef4673ab5cee01de282be0c";
const POINTS = [
    "0x06ae23dbd2b2c323dd377f3ebcd6ddab72d8ae7f5634bd39bdbfecd92ef9b3fc0ef6987c64195d008237f32797de0433c236225a13cd6b0873ea09d68258d4fb",
    "0x25ab8fba6599243fb05c1c8c6532d9ade3a1fa51109f91b189dc06e09ea5a90e0d2bc03efdd457045885e6c2dde903bcee50494b28315fcfddf24da1ee7d38f3",
    "0x14b081aec82aa9c3e4c4a2444b566eaaba63a4083a2d67d8594a18fdd7932bff244f9fad0994da303dd67ac4b6da94d1d17ad4a3a923e71713fa329755721510",
];

function splitPoint(hex: string): [string, string] {
    const body = hex.startsWith("0x") ? hex.slice(2) : hex;
    return ["0x" + body.slice(0, 64), "0x" + body.slice(64)];
}

const XS = POINTS.map((point) => splitPoint(point)[0]);
const YS = POINTS.map((point) => splitPoint(point)[1]);

function leafOf(address: string): string {
    return ethers.utils.solidityKeccak256(["address"], [address]);
}

/** 确定性 PRNG，保证失败可复现 */
function mulberry32(seed: number) {
    return function () {
        seed |= 0;
        seed = (seed + 0x6D2B79F5) | 0;
        let value = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
        return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
    };
}

describe("P4 合约状态机模糊测试", function () {
    let zk: any;
    let relayer: any;
    let fixtureVoter: any;
    let outsider: any;
    let rangeFixture: any;

    before(async function () {
        rangeFixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
        const signers = await ethers.getSigners();
        relayer = signers[0];
        fixtureVoter = signers[1];
        outsider = signers[2];

        const PoseidonT6 = await ethers.getContractFactory("PoseidonT6");
        const poseidonT6 = await PoseidonT6.deploy();
        await poseidonT6.deployed();

        const ZKVoting = await ethers.getContractFactory("ZKVoting", {
            libraries: { PoseidonT6: poseidonT6.address },
        });
        zk = await ZKVoting.deploy();
        await zk.deployed();

        // id=0 占位；id=1 与夹具 commitmentHash 的 votingId 对齐
        await (await zk.createVoting(
            "dummy", "", 10, 3600, 3600,
            ["A", "B"], [], [], ethers.constants.HashZero, relayer.address
        )).wait();

        await (await zk.createVoting(
            "fixture", "", 10, 3600, 3600,
            ["A", "B", "C"], [fixtureVoter.address], [1],
            leafOf(fixtureVoter.address), relayer.address
        )).wait();
    });

    it("随机相位序列中阶段只增不减，结束后不可再改", async function () {
        const random = mulberry32(0x5eed1234);

        for (let round = 0; round < 24; round++) {
            const id = await zk.votingCount();
            await (await zk.createVoting(
                "fuzz-" + round, "", 10, 3600, 3600,
                ["A", "B"], [], [], ethers.constants.HashZero, relayer.address
            )).wait();

            let phase = 1;
            for (let step = 0; step < 5; step++) {
                const target = Math.floor(random() * 4); // 0..3
                if (target < phase) {
                    await expect(zk.updateVotingPhase(id, target))
                        .to.be.revertedWith("Phase cannot move backwards");
                } else {
                    await (await zk.updateVotingPhase(id, target)).wait();
                    phase = target;
                }
                const status = await zk.getVotingPhaseStatus(id);
                expect(Number(status.phase)).to.be.gte(phase);
                expect(status.isActive).to.equal(true);
            }

            await (await zk.endVoting(id)).wait();
            const ended = await zk.getVotingPhaseStatus(id);
            expect(Number(ended.phase)).to.equal(3);
            expect(ended.isActive).to.equal(false);

            await expect(zk.updateVotingPhase(id, 3))
                .to.be.revertedWith("Voting is not active");
            await expect(zk.endVoting(id))
                .to.be.revertedWith("Voting already ended");
        }
    });

    it("完整生命周期：错误路径全部拒绝，正确路径结果一致", async function () {
        const votingId = 1;
        const scores = SCORES;
        // R-3：nullifier 由合约派生，不再由客户端自由选择
        const nullifier = await zk.deriveNullifier(votingId, fixtureVoter.address);

        const commitDigest = await zk.commitDigest(votingId, fixtureVoter.address, COMMITMENT_HASH);
        const commitSig = await fixtureVoter.signMessage(ethers.utils.arrayify(commitDigest));

        // 承诺阶段：不能揭晓
        const revealDigest = await zk.revealDigest(votingId, fixtureVoter.address, scores, nullifier);
        const revealSig = await fixtureVoter.signMessage(ethers.utils.arrayify(revealDigest));
        await expect(zk.revealPedersenScores(
            votingId, fixtureVoter.address, scores, SECRET, SALT, nullifier, revealSig
        )).to.be.revertedWith("Not in scoring phase");

        // 越权评委：签名有效但不在 Merkle 白名单
        const outsiderDigest = await zk.commitDigest(votingId, outsider.address, COMMITMENT_HASH);
        const outsiderSig = await outsider.signMessage(ethers.utils.arrayify(outsiderDigest));
        await expect(zk.submitPedersenCommitment(
            votingId, outsider.address, COMMITMENT_HASH, XS, YS, [], outsiderSig
        )).to.be.revertedWith("Not authorized voter");

        // 曲线外伪点
        await expect(zk.submitPedersenCommitment(
            votingId, fixtureVoter.address, COMMITMENT_HASH,
            ["0", "0", "0"], ["0", "0", "0"], [], commitSig
        )).to.be.revertedWith("Commitment point not on curve");

        // 正确承诺 + 范围证明（R-10：必须由评委签名）
        await (await zk.submitPedersenCommitment(
            votingId, fixtureVoter.address, COMMITMENT_HASH, XS, YS, [], commitSig
        )).wait();
        const [a, b, c] = rangeFixture.calldata;
        const rangeDigest = await zk.rangeDigest(
            votingId, fixtureVoter.address, rangeFixture.commitment);
        const rangeSig = await fixtureVoter.signMessage(ethers.utils.arrayify(rangeDigest));

        // relayer 拿别人的签名替换证明 → 拒绝
        const outsiderRangeSig = await outsider.signMessage(
            ethers.utils.arrayify(rangeDigest));
        await expect(zk.submitRangeProof(
            votingId, fixtureVoter.address, rangeFixture.commitment, a, b, c, outsiderRangeSig
        )).to.be.revertedWith("Invalid signature");

        // 空签名 → 拒绝
        await expect(zk.submitRangeProof(
            votingId, fixtureVoter.address, rangeFixture.commitment, a, b, c, "0x"
        )).to.be.revertedWith("Invalid signature length");

        await (await zk.submitRangeProof(
            votingId, fixtureVoter.address, rangeFixture.commitment, a, b, c, rangeSig
        )).wait();

        // 重复承诺
        await expect(zk.submitPedersenCommitment(
            votingId, fixtureVoter.address, COMMITMENT_HASH, XS, YS, [], commitSig
        )).to.be.revertedWith("Already committed");

        // 阶段前进 + 回退拒绝
        await (await zk.updateVotingPhase(votingId, 2)).wait();
        await expect(zk.updateVotingPhase(votingId, 1))
            .to.be.revertedWith("Phase cannot move backwards");

        // R-3：客户端自选 nullifier → 拒绝
        const forgedNullifier = ethers.utils.keccak256(
            ethers.utils.toUtf8Bytes("forged-nullifier"));
        const forgedDigest = await zk.revealDigest(
            votingId, fixtureVoter.address, scores, forgedNullifier);
        const forgedSig = await fixtureVoter.signMessage(
            ethers.utils.arrayify(forgedDigest));
        await expect(zk.revealPedersenScores(
            votingId, fixtureVoter.address, scores, SECRET, SALT, forgedNullifier, forgedSig
        )).to.be.revertedWith("Invalid nullifier");

        // 错误分数 / 错误密码
        const wrongScores = [0, 0, 0];
        const wrongScoreDigest = await zk.revealDigest(
            votingId, fixtureVoter.address, wrongScores, nullifier);
        const wrongScoreSig = await fixtureVoter.signMessage(ethers.utils.arrayify(wrongScoreDigest));
        await expect(zk.revealPedersenScores(
            votingId, fixtureVoter.address, wrongScores, SECRET, SALT, nullifier, wrongScoreSig
        )).to.be.revertedWith("Pedersen point mismatch");

        await expect(zk.revealPedersenScores(
            votingId, fixtureVoter.address, scores, "wrong secret", SALT, nullifier, revealSig
        )).to.be.revertedWith("Pedersen point mismatch");

        // 正确揭晓 + 重复揭晓拒绝
        await (await zk.revealPedersenScores(
            votingId, fixtureVoter.address, scores, SECRET, SALT, nullifier, revealSig
        )).wait();
        expect(await zk.hasRevealed(votingId, fixtureVoter.address)).to.equal(true);
        await expect(zk.revealPedersenScores(
            votingId, fixtureVoter.address, scores, SECRET, SALT, nullifier, revealSig
        )).to.be.revertedWith("Already revealed");

        // 提前结算拒绝
        await expect(zk.calculateResults(votingId))
            .to.be.revertedWith("Scoring phase not ended");

        // 时间推进后结算
        await ethers.provider.send("evm_increaseTime", [7201]);
        await ethers.provider.send("evm_mine", []);
        await (await zk.calculateResults(votingId)).wait();

        const results = await zk.getVotingResults(votingId);
        expect(results.map((value: any) => Number(value))).to.deep.equal(scores.slice());

        const stats = await zk.getVotingStats(votingId);
        expect(Number(stats.totalVoters)).to.equal(1);
        expect(Number(stats.committedVoters)).to.equal(1);
        expect(Number(stats.revealedVoters)).to.equal(1);
        expect(Number(stats.totalScores)).to.equal(3);

        // 已完成后仍拒绝回退与再结算
        await expect(zk.updateVotingPhase(votingId, 1))
            .to.be.revertedWith("Phase cannot move backwards");
        await expect(zk.calculateResults(votingId))
            .to.be.revertedWith("Not in scoring phase");

        await (await zk.endVoting(votingId)).wait();
        await expect(zk.updateVotingPhase(votingId, 3))
            .to.be.revertedWith("Voting is not active");
    });

    it("签名与 Merkle 白名单模糊测试：任意篡改都被拒绝", async function () {
        const votingId = await zk.votingCount();
        await (await zk.createVoting(
            "auth-fuzz", "", 10, 3600, 3600,
            ["A", "B", "C"], [fixtureVoter.address], [1],
            leafOf(fixtureVoter.address), relayer.address
        )).wait();

        const submit = (
            sig: string,
            voter: string = fixtureVoter.address,
            commitmentHash: string = COMMITMENT_HASH,
            proof: string[] = []
        ) => zk.submitPedersenCommitment(
            votingId, voter, commitmentHash, XS, YS, proof, sig
        );

        const digest = await zk.commitDigest(votingId, fixtureVoter.address, COMMITMENT_HASH);
        const goodSig = await fixtureVoter.signMessage(ethers.utils.arrayify(digest));

        // 1) 错误签名者：他人用自己的私钥签同一摘要
        const outsiderSig = await outsider.signMessage(ethers.utils.arrayify(digest));
        await expect(submit(outsiderSig)).to.be.revertedWith("Invalid signature");

        // 2) 签名长度异常（0 / 64 / 66 字节）
        for (const malformed of ["0x", "0x" + "11".repeat(64), "0x" + "22".repeat(66)]) {
            await expect(submit(malformed)).to.be.revertedWith("Invalid signature length");
        }

        // 3) 摘要与提交的 commitmentHash 不匹配
        const otherHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("tampered"));
        const otherDigest = await zk.commitDigest(votingId, fixtureVoter.address, otherHash);
        const sigForOther = await fixtureVoter.signMessage(ethers.utils.arrayify(otherDigest));
        await expect(submit(sigForOther)).to.be.revertedWith("Invalid signature");

        // 4) 随机比特级篡改签名
        const random = mulberry32(0xA11CE);
        const hexChars = goodSig.slice(2).split("");
        for (let round = 0; round < 12; round++) {
            const chars = hexChars.slice();
            const flips = 1 + Math.floor(random() * 3);
            for (let i = 0; i < flips; i++) {
                const position = Math.floor(random() * chars.length);
                chars[position] = "0123456789abcdef"[Math.floor(random() * 16)];
            }
            const mutated = "0x" + chars.join("");
            if (mutated === goodSig) continue;
            await expect(submit(mutated)).to.be.reverted;
        }

        // 5) Merkle 证明被篡改
        const fakeProof = [ethers.utils.keccak256(ethers.utils.toUtf8Bytes("fake"))];
        await expect(submit(goodSig, fixtureVoter.address, COMMITMENT_HASH, fakeProof))
            .to.be.revertedWith("Not authorized voter");

        // 6) 非白名单地址，即使签名完全正确
        const outsiderDigest = await zk.commitDigest(
            votingId, outsider.address, COMMITMENT_HASH);
        const outsiderOwnSig = await outsider.signMessage(
            ethers.utils.arrayify(outsiderDigest));
        await expect(submit(outsiderOwnSig, outsider.address))
            .to.be.revertedWith("Not authorized voter");

        // 7) 零地址评委
        await expect(submit(goodSig, ethers.constants.AddressZero))
            .to.be.revertedWith("Invalid voter");

        // 8) 正确路径作对照：同一签名仍可成功提交
        await (await submit(goodSig)).wait();
        expect(await zk.hasCommitted(votingId, fixtureVoter.address)).to.equal(true);
        await expect(submit(goodSig)).to.be.revertedWith("Already committed");
    });
});
