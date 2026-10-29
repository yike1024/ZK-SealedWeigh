/**
 * 生成并验证范围证明（Groth16 / alt_bn128）
 *
 * 运行：node scripts/prove.js
 * 产物：build/proof_fixture.json（供 Solidity 测试读取）
 */
const path = require('path');
const fs = require('fs');
const snarkjs = require(path.join(__dirname, '..', '..', 'backend', 'node_modules', 'snarkjs'));
const { buildPoseidon } = require('circomlibjs');

const ROOT = path.join(__dirname, '..');
const WASM = path.join(ROOT, 'build', 'range_proof_js', 'range_proof.wasm');
const ZKEY = path.join(ROOT, 'range_proof.zkey');
const VKEY = path.join(ROOT, 'verification_key.json');
const OUT = path.join(ROOT, 'build', 'proof_fixture.json');

let pass = 0, fail = 0;
function check(name, cond, extra) {
    if (cond) { pass++; console.log(`  [PASS] ${name}`); }
    else { fail++; console.log(`  [FAIL] ${name}${extra !== undefined ? ' :: ' + JSON.stringify(extra) : ''}`); }
}

(async () => {
    console.log('\n=== 范围证明验收（Groth16 / BN254）===\n');

    const vkey = JSON.parse(fs.readFileSync(VKEY, 'utf8'));
    const scores = [7, 9, 0];
    const salt = '12345678901234567890';
    const voter = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const voterField = BigInt(voter);
    const maxScore = 10;

    // ---------- 1) 正常证明 ----------
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        { scores, salt, voter: voterField.toString(), maxScore }, WASM, ZKEY);
    check('生成证明成功', !!proof && publicSignals.length === 2);
    check('公开信号 = [commitment, maxScore]',
        publicSignals[0] === publicSignals[0] && publicSignals[1] === String(maxScore), publicSignals);

    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    check('链下验证通过', ok === true);

    // ---------- 2) 公开信号 == Poseidon(scores, salt, voter) ----------
    const poseidon = await buildPoseidon();
    const expected = poseidon.F.toString(poseidon([...scores, salt, voterField]));
    check('publicSignal 等于 Poseidon(scores, salt, voter)',
        publicSignals[0] === expected, { circuit: publicSignals[0], offchain: expected });

    // ---------- 3) 篡改公开信号 → 验证失败 ----------
    const tamperedSignals = [String(BigInt(expected) + 1n), String(maxScore)];
    const tamperedOk = await snarkjs.groth16.verify(vkey, tamperedSignals, proof);
    check('篡改公开承诺后验证失败', tamperedOk === false);

    // ---------- 3b) 换 maxScore → 验证失败（公开输入被绑定） ----------
    const wrongMaxOk = await snarkjs.groth16.verify(vkey, [publicSignals[0], '9'], proof);
    check('把 maxScore 改为 9 后验证失败', wrongMaxOk === false);

    // ---------- 4) 超范围分数无法生成证明 ----------
    let outOfRangeRejected = false;
    try {
        await snarkjs.groth16.fullProve(
            { scores: [7, 11, 0], salt, voter: voterField.toString(), maxScore }, WASM, ZKEY);
    } catch (e) {
        outOfRangeRejected = true;
    }
    check('超范围分数（11 > maxScore）无法生成证明', outOfRangeRejected);

    // ---------- 5) 负分（域元素表示的 -1）也无法生成 ----------
    let negativeRejected = false;
    try {
        // BN254 标量域的 p-1，等价于 -1
        const negOne = '21888242871839275222246405745257275088548364400416034343698204186575808495616';
        await snarkjs.groth16.fullProve(
            { scores: [negOne, 9, 0], salt, voter: voterField.toString(), maxScore }, WASM, ZKEY);
    } catch (e) {
        negativeRejected = true;
    }
    check('负数（域元素 p-1）无法生成证明', negativeRejected);

    // ---------- 6) 换评委地址后承诺不同（防跨人重放） ----------
    const otherVoter = BigInt('0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC');
    const expectedOther = poseidon.F.toString(poseidon([...scores, salt, otherVoter]));
    check('同一组分数换成其他评委地址 → 承诺不同',
        expectedOther !== expected, { alice: expected, bob: expectedOther });

    // ---------- 7) 供 Solidity 测试的 fixture ----------
    const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
    fs.writeFileSync(OUT, JSON.stringify({
        scores, salt, voter,
        commitment: publicSignals[0],
        proof,
        publicSignals,
        calldata: JSON.parse('[' + calldata + ']'),
    }, null, 2));
    console.log(`\n  fixture 已写入 ${OUT}`);

    console.log(`\n=== 结果：${pass} 通过 / ${fail} 失败 ===\n`);
    process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error('证明流程异常:', e); process.exit(2); });
