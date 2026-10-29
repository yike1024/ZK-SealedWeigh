/**
 * P4 恢复密码学模糊测试（确定性种子）
 *
 * 随机化 k/n、主密钥、载荷与地址，验证：
 *   · Shamir 任意 k-of-n 重构一致；
 *   · 少于 k 份必须失败；
 *   · AES-GCM 托管密文往返一致，篡改必失败；
 *   · ECDH 信封往返一致，AAD 不匹配 / 篡改必失败。
 *
 * 运行：node frontend/tests/recovery-fuzz.test.js
 */
const RC = require('../recovery-crypto.js');

const SEED = 0x5eed2026;
const ROUNDS = 40;

let passed = 0;
let failed = 0;

function check(name, condition, detail) {
    if (condition) {
        passed++;
    } else {
        failed++;
        console.log(`  [FAIL] ${name}${detail !== undefined ? ' :: ' + JSON.stringify(detail) : ''}`);
    }
}

function mulberry32(seed) {
    return function () {
        seed |= 0;
        seed = (seed + 0x6D2B79F5) | 0;
        let value = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
        return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
    };
}

function randomAddress(rng) {
    let text = '0x';
    for (let i = 0; i < 40; i++) {
        text += '0123456789abcdef'[Math.floor(rng() * 16)];
    }
    return text;
}

function randomText(rng, length) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789 中文';
    let text = '';
    for (let i = 0; i < length; i++) {
        text += alphabet[Math.floor(rng() * alphabet.length)];
    }
    return text;
}

function tamperBase64(text) {
    const bytes = Buffer.from(text, 'base64');
    bytes[0] ^= 0xff;
    return bytes.toString('base64');
}

async function main() {
    console.log('\n=== P4 恢复密码学模糊测试（40 轮，固定种子）===\n');
    const rng = mulberry32(SEED);

    let shamirOk = 0;
    let underThresholdOk = 0;
    let escrowOk = 0;
    let envelopeOk = 0;
    let aadRejectOk = 0;
    let tamperRejectOk = 0;

    for (let round = 0; round < ROUNDS; round++) {
        const n = 1 + Math.floor(rng() * 5);
        const k = 1 + Math.floor(rng() * n);
        const votingId = 1 + Math.floor(rng() * 1000);
        const voter = randomAddress(rng);
        const trustee = randomAddress(rng);

        // 1. Shamir
        const masterKey = RC.randomBytes(RC.MASTER_KEY_BYTES);
        const shares = RC.splitSecret(masterKey, k, n);
        const rebuilt = RC.combineShares(shares.slice(0, k));
        check('shamir', Buffer.from(rebuilt).equals(Buffer.from(masterKey)),
            { round, n, k });
        if (Buffer.from(rebuilt).equals(Buffer.from(masterKey))) shamirOk++;

        // 少于门限：combineShares 只做插值、不知道 k，因此不保证抛错；
        // 真正的安全属性是“重构不出原密钥，且错误密钥解不开托管密文”。
        const underThresholdShares = shares.slice(0, k - 1);
        let underThresholdHeld = false;
        let wrongKey = null;
        try {
            wrongKey = RC.combineShares(underThresholdShares);
            underThresholdHeld = !Buffer.from(wrongKey).equals(Buffer.from(masterKey));
        } catch (error) {
            // 0 份或格式非法时直接抛错，同样满足属性
            underThresholdHeld = true;
        }
        check('under-threshold-key-differs', underThresholdHeld, { round, n, k });
        if (underThresholdHeld) underThresholdOk++;

        // 2. 托管密文
        const payload = {
            scores: Array.from({ length: 1 + Math.floor(rng() * 5) },
                () => Math.floor(rng() * 11)),
            secret: randomText(rng, 1 + Math.floor(rng() * 30)),
            salt: randomText(rng, 1 + Math.floor(rng() * 20))
        };
        const escrow = await RC.encryptEscrow(payload, masterKey, {
            votingId, voter
        });
        const decrypted = await RC.decryptEscrow(escrow, masterKey, {
            votingId, voter
        });
        const escrowEqual = JSON.stringify(decrypted) === JSON.stringify(payload);
        check('escrow-roundtrip', escrowEqual, { round });
        if (escrowEqual) escrowOk++;

        // 少于门限推出的错误密钥必须解不开托管密文（AES-GCM 认证失败）
        let wrongKeyRejected = false;
        try {
            const leaked = await RC.decryptEscrow(escrow, wrongKey, { votingId, voter });
            wrongKeyRejected = JSON.stringify(leaked) !== JSON.stringify(payload);
        } catch (error) {
            wrongKeyRejected = true;
        }
        check('under-threshold-decrypt-rejected', wrongKeyRejected, { round, n, k });
        if (wrongKeyRejected) underThresholdOk++;

        // 3. ECDH 信封
        const trusteePair = await RC.generateKeyPair();
        const trusteePublic = await RC.exportPublicKey(trusteePair.publicKey);
        const trusteePrivate = trusteePair.privateKey;

        const share = shares[0];
        const envelope = await RC.wrapShareFor(share, trusteePublic, {
            votingId, from: voter, to: trustee
        });
        const unwrapped = await RC.unwrapShare(envelope, trusteePrivate, {
            votingId, from: voter, to: trustee
        });
        const envelopeEqual = unwrapped.x === share.x &&
            Buffer.from(unwrapped.y).equals(Buffer.from(share.y));
        check('envelope-roundtrip', envelopeEqual, { round });
        if (envelopeEqual) envelopeOk++;

        // 4. AAD 不匹配必须失败
        let aadRejected = false;
        try {
            await RC.unwrapShare(envelope, trusteePrivate, {
                votingId: votingId + 1, from: voter, to: trustee
            });
        } catch (error) {
            aadRejected = true;
        }
        check('aad-mismatch', aadRejected, { round });
        if (aadRejected) aadRejectOk++;

        // 5. 篡改密文必须失败（信封与托管各一次）
        let tamperRejected = 0;
        const badEnvelope = Object.assign({}, envelope, {
            ct: tamperBase64(envelope.ct)
        });
        try {
            await RC.unwrapShare(badEnvelope, trusteePrivate, {
                votingId, from: voter, to: trustee
            });
        } catch (error) {
            tamperRejected++;
        }
        const badEscrow = Object.assign({}, escrow, {
            ct: tamperBase64(escrow.ct)
        });
        try {
            await RC.decryptEscrow(badEscrow, masterKey, { votingId, voter });
        } catch (error) {
            tamperRejected++;
        }
        check('tamper-reject', tamperRejected === 2, { round });
        if (tamperRejected === 2) tamperRejectOk++;
    }

    console.log(`  [${shamirOk === ROUNDS ? 'PASS' : 'FAIL'}] Shamir k-of-n 重构一致 ${shamirOk}/${ROUNDS}`);
    console.log(`  [${underThresholdOk === ROUNDS * 2 ? 'PASS' : 'FAIL'}] 少于门限无法解出明文 ${underThresholdOk}/${ROUNDS * 2}`);
    console.log(`  [${escrowOk === ROUNDS ? 'PASS' : 'FAIL'}] 托管密文往返一致 ${escrowOk}/${ROUNDS}`);
    console.log(`  [${envelopeOk === ROUNDS ? 'PASS' : 'FAIL'}] ECDH 信封往返一致 ${envelopeOk}/${ROUNDS}`);
    console.log(`  [${aadRejectOk === ROUNDS ? 'PASS' : 'FAIL'}] AAD 不匹配被拒 ${aadRejectOk}/${ROUNDS}`);
    console.log(`  [${tamperRejectOk === ROUNDS ? 'PASS' : 'FAIL'}] 篡改密文被拒 ${tamperRejectOk}/${ROUNDS}`);

    console.log(`\n=== 结果：${passed} 通过 / ${failed} 失败 ===`);
    return failed === 0 ? 0 : 1;
}

main()
    .then((code) => process.exit(code))
    .catch((error) => {
        console.error('测试异常:', error);
        process.exit(2);
    });
