/**
 * 链上验证范围证明（Groth16 / alt_bn128）
 *
 * 证据来源：circuits/scripts/prove.js 生成的 build/proof_fixture.json
 * 运行：npx hardhat test test/rangeProof.test.ts
 */
import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const FIXTURE_PATH = path.join(__dirname, "..", "..", "circuits", "build", "proof_fixture.json");

describe("范围证明：链上验证（Groth16 / alt_bn128）", function () {
    let verifier: any;
    let fixture: any;

    before(async function () {
        fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
        const V = await ethers.getContractFactory("Groth16Verifier");
        verifier = await V.deploy();
        await verifier.deployed();
    });

    it("合法证明在链上验证通过", async function () {
        const [a, b, c, pub] = fixture.calldata;
        expect(await verifier.verifyProof(a, b, c, pub)).to.equal(true);
    });

    it("篡改公开承诺后链上验证失败", async function () {
        const [a, b, c, pub] = fixture.calldata;
        // 公开信号 = [commitment, maxScore]
        const tampered = [BigInt(pub[0]) + 1n, pub[1]];
        expect(await verifier.verifyProof(a, b, c, tampered)).to.equal(false);
    });

    it("替换 maxScore 后链上验证失败", async function () {
        const [a, b, c, pub] = fixture.calldata;
        expect(await verifier.verifyProof(a, b, c, [pub[0], "9"])).to.equal(false);
    });

    it("公开信号确实等于 Poseidon(scores, salt)（由脚本交叉验证）", async function () {
        // 脚本已用 circomlibjs 独立算出期望值并与电路输出比对
        expect(fixture.commitment).to.equal(fixture.publicSignals[0]);
    });

    it("测量链上验证 gas", async function () {
        const [a, b, c, pub] = fixture.calldata;
        const gas = await verifier.estimateGas.verifyProof(a, b, c, pub);
        console.log(`      链上 verifyProof 预估 gas = ${gas.toString()}`);
        expect(gas.toNumber()).to.be.greaterThan(0);
    });
});
