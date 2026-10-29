/**
 * P3.1 恢复密码学核心的验收向量（Node 19+，使用 WebCrypto）
 *
 * 运行：node frontend/tests/recovery.test.js
 *
 * 覆盖：
 *   · GF(256) 已知值（AES 域）与逆元性质
 *   · Shamir(k,n) 任意 k 份重构、k-1 份失败、重复 x 拒绝
 *   · AES-256-GCM 的密钥 / 上下文 / 密文三项绑定
 *   · ECDH 份额信封的接收者绑定与篡改检测
 *   · 完整恢复流程：托管 → 拆分 → 两位评委转交 → 重构 → 解密
 */
const RC = require('../recovery-crypto.js');

let passed = 0;
let failed = 0;

function check(name, condition, detail) {
    if (condition) {
        passed++;
        console.log(`  [PASS] ${name}`);
    } else {
        failed++;
        console.log(`  [FAIL] ${name}${detail !== undefined ? ' :: ' + JSON.stringify(detail) : ''}`);
    }
}

async function expectThrow(name, action) {
    try {
        await action();
        check(name, false, '未抛出异常');
    } catch (error) {
        check(name, true);
    }
}

function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function deterministicSecret() {
    const secret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) secret[i] = i;
    return secret;
}

function fixedRandom(length) {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = 0x10 + i;
    return out;
}

async function main() {
    console.log('\n=== P3.1 恢复密码学核心验收 ===\n');

    // ---------- 1. GF(256) ----------
    console.log('--- GF(256) ---');
    check('0x53 × 0xCA = 0x01（AES 域互逆对）', RC.gfMul(0x53, 0xca) === 0x01);
    check('0x02 × 0x80 = 0x1b（xtime）', RC.gfMul(0x02, 0x80) === 0x1b);
    check('0x53 ÷ 0x01 = 0x53', RC.gfDiv(0x53, 0x01) === 0x53);
    check('0x01 ÷ 0x53 = 0xCA（即逆元）', RC.gfDiv(0x01, 0x53) === 0xca);
    check('inv(0x53) = 0xCA', RC.gfInv(0x53) === 0xca);
    let inverseOk = true;
    for (let a = 1; a <= 255; a++) {
        if (RC.gfMul(a, RC.gfInv(a)) !== 1) inverseOk = false;
    }
    check('所有 255 个非零元都有逆元', inverseOk);
    let divisionOk = true;
    for (let a = 1; a <= 255; a++) {
        for (let b = 1; b <= 255; b++) {
            if (RC.gfMul(RC.gfDiv(a, b), b) !== a) divisionOk = false;
        }
    }
    check('除法与乘法互逆（255 × 255 组合）', divisionOk);

    // ---------- 2. Shamir ----------
    console.log('\n--- Shamir(k, n) ---');
    const secret = deterministicSecret();
    for (const [k, n] of [[2, 3], [3, 5], [5, 7]]) {
        const shares = RC.splitSecret(secret, k, n);
        check(`(${k},${n}) 生成 ${n} 份且 x 连续`, shares.length === n &&
            shares.every((s, i) => s.x === i + 1));
        check(`(${k},${n}) 前 k 份可重构`, equalBytes(RC.combineShares(shares.slice(0, k)), secret));
        check(`(${k},${n}) 全部 n 份可重构`, equalBytes(RC.combineShares(shares), secret));
        const fewer = shares.slice(0, k - 1);
        check(`(${k},${n}) k-1 份不能重构`, !equalBytes(RC.combineShares(fewer), secret));
    }

    const fixed1 = RC.splitSecret(secret, 2, 3, fixedRandom);
    const fixed2 = RC.splitSecret(secret, 2, 3, fixedRandom);
    check('相同随机源产生相同份额（确定性）',
        fixed1.every((s, i) => equalBytes(s.y, fixed2[i].y)));
    check('份额编码/解码往返一致',
        equalBytes(RC.decodeShare(RC.encodeShare(fixed1[0])).y, fixed1[0].y));

    await expectThrow('重复 x 的份额被拒', async () => {
        RC.combineShares([fixed1[0], { x: fixed1[0].x, y: fixed1[1].y }]);
    });
    await expectThrow('k > n 被拒', async () => RC.splitSecret(secret, 4, 3));
    await expectThrow('k = 0 被拒', async () => RC.splitSecret(secret, 0, 3));
    await expectThrow('非 32 字节主密钥被拒', async () => RC.splitSecret(new Uint8Array(16), 2, 3));

    // ---------- 3. 恢复载荷 ----------
    console.log('\n--- AES-256-GCM 恢复载荷 ---');
    const context = { votingId: 7, voter: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' };
    const payload = { scores: [7, 9, 0], secret: 'correct horse battery staple', salt: '12345678901234567890' };

    const escrow = await RC.encryptEscrow(payload, secret, context);
    const decrypted = await RC.decryptEscrow(escrow, secret, context);
    check('加密/解密往返一致', JSON.stringify(decrypted) === JSON.stringify(payload));
    check('载荷密文不含明文', !JSON.stringify(escrow).includes('correct horse'));

    const otherKey = new Uint8Array(32);
    otherKey[0] = 0xff;
    await expectThrow('错误主密钥无法解密', async () => RC.decryptEscrow(escrow, otherKey, context));
    await expectThrow('错误上下文（换评委）无法解密', async () =>
        RC.decryptEscrow(escrow, secret, { votingId: 7, voter: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC' }));
    const tamperedEscrow = JSON.parse(JSON.stringify(escrow));
    const ct = RC.b64ToBytes(tamperedEscrow.ct);
    ct[0] ^= 0xff;
    tamperedEscrow.ct = RC.bytesToB64(ct);
    await expectThrow('篡改载荷密文被检出', async () => RC.decryptEscrow(tamperedEscrow, secret, context));

    // ---------- 4. 份额信封 ----------
    console.log('\n--- ECDH P-256 份额信封 ---');
    const alice = await RC.generateKeyPair();
    const bob = await RC.generateKeyPair();
    const carol = await RC.generateKeyPair();
    const alicePub = await RC.exportPublicKey(alice.publicKey);
    const bobPub = await RC.exportPublicKey(bob.publicKey);
    const carolPub = await RC.exportPublicKey(carol.publicKey);

    const shareCtx = { votingId: 7, from: '0xAl', to: '0xBo' };
    const envelope = await RC.wrapShareFor(fixed1[0], bobPub, shareCtx);

    const bobGot = await RC.unwrapShare(envelope, bob.privateKey, shareCtx);
    check('接收者能解开自己的份额', equalBytes(bobGot.y, fixed1[0].y) && bobGot.x === fixed1[0].x);
    await expectThrow('非接收者无法解开', async () => RC.unwrapShare(envelope, carol.privateKey, shareCtx));
    await expectThrow('错误 AAD 上下文无法解开', async () =>
        RC.unwrapShare(envelope, bob.privateKey, { votingId: 7, from: '0xAl', to: '0xXx' }));

    const tamperedEnvelope = JSON.parse(JSON.stringify(envelope));
    const eCt = RC.b64ToBytes(tamperedEnvelope.ct);
    eCt[0] ^= 0xff;
    tamperedEnvelope.ct = RC.bytesToB64(eCt);
    await expectThrow('篡改信封被检出', async () => RC.unwrapShare(tamperedEnvelope, bob.privateKey, shareCtx));

    // ---------- 5. 完整恢复流程（k=2, n=3） ----------
    console.log('\n--- 完整恢复流程（spec.md 11.4） ---');
    const recovering = await RC.generateKeyPair();
    const recoveringPub = await RC.exportPublicKey(recovering.publicKey);
    const trustees = [alice, bob, carol];
    const trusteePubs = [alicePub, bobPub, carolPub];
    const judgeAddress = '0xJudgeR';
    const trusteeNames = ['0xAl', '0xBo', '0xCa'];

    // A. 丢失方在承诺阶段：生成主密钥、托管载荷、拆分并逐个加密给 3 位评委
    const shares = RC.splitSecret(secret, 2, 3);
    const envelopes = [];
    for (let i = 0; i < 3; i++) {
        envelopes.push(await RC.wrapShareFor(shares[i], trusteePubs[i], {
            votingId: 7, from: judgeAddress, to: trusteeNames[i]
        }));
    }

    // B. 恢复阶段：A、B 各自解开自己那份，再加密给丢失方
    const relays = [];
    for (let i = 0; i < 2; i++) {
        const mine = await RC.unwrapShare(envelopes[i], trustees[i].privateKey, {
            votingId: 7, from: judgeAddress, to: trusteeNames[i]
        });
        relays.push(await RC.wrapShareFor(mine, recoveringPub, {
            votingId: 7, from: trusteeNames[i], to: judgeAddress
        }));
    }

    // C. 丢失方收齐 2 份，本地重构并解密
    const collected = [];
    for (let i = 0; i < 2; i++) {
        collected.push(await RC.unwrapShare(relays[i], recovering.privateKey, {
            votingId: 7, from: trusteeNames[i], to: judgeAddress
        }));
    }
    const rebuiltKey = RC.combineShares(collected);
    check('两位评委协作可重构主密钥', equalBytes(rebuiltKey, secret));
    const recovered = await RC.decryptEscrow(escrow, rebuiltKey, context);
    check('恢复出的载荷与原始一致', JSON.stringify(recovered) === JSON.stringify(payload));

    // D. 只有 1 份：重构出的密钥错误，托管解密必须失败
    const oneShareKey = RC.combineShares(collected.slice(0, 1));
    check('单份份额得不到正确主密钥', !equalBytes(oneShareKey, secret));
    await expectThrow('单份份额无法解密托管载荷', async () =>
        RC.decryptEscrow(escrow, oneShareKey, context));

    // E. 转交的密文被篡改：必须停在 GCM 认证
    const tamperedRelay = JSON.parse(JSON.stringify(relays[0]));
    const rCt = RC.b64ToBytes(tamperedRelay.ct);
    rCt[1] ^= 0xff;
    tamperedRelay.ct = RC.bytesToB64(rCt);
    await expectThrow('被篡改的转交份额被检出', async () =>
        RC.unwrapShare(tamperedRelay, recovering.privateKey,
            { votingId: 7, from: trusteeNames[0], to: judgeAddress }));

    // ---------- 6. 序列化 ----------
    console.log('\n--- 序列化 ---');
    const serialized = RC.encodeShare(shares[2]);
    const restored = RC.decodeShare(serialized);
    check('份额 base64 往返一致', restored.x === shares[2].x && equalBytes(restored.y, shares[2].y));
    await expectThrow('非法长度份额字符串被拒', async () => RC.decodeShare(RC.bytesToB64(new Uint8Array(5))));

    console.log(`\n=== ${passed} 通过 / ${failed} 失败 ===\n`);
    return failed === 0 ? 0 : 1;
}

main()
    .then((code) => process.exit(code))
    .catch((error) => {
        console.error('测试异常:', error);
        process.exit(2);
    });
