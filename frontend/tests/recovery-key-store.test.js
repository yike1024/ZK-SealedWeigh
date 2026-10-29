/**
 * P3.4 / P3.8 钱包派生私钥持久化的验收向量（Node 19+）
 *
 * 运行：node frontend/tests/recovery-key-store.test.js
 *
 * 覆盖：
 *   · 签名消息格式（含 epoch 轮换）与 personal_sign 的十六进制编码
 *   · 保存 / 读取往返一致，本地密文不含私钥材料
 *   · v2 记录结构（schema / version / createdAt / envelope.epoch）
 *   · P3.4 v1 localStorage 记录自动迁移并删除旧键
 *   · 密钥轮换：epoch 递增、旧签名无法解开新密文
 *   · 可注入后端（模拟 IndexedDB 主存储路径）
 *   · 换签名、换地址、篡改密文都会失败
 *   · 钱包账户不一致时拒绝签名
 */
globalThis.localStorage = {
    _data: {},
    getItem(key) {
        return Object.prototype.hasOwnProperty.call(this._data, key) ? this._data[key] : null;
    },
    setItem(key, value) { this._data[key] = String(value); },
    removeItem(key) { delete this._data[key]; }
};

const Store = require('../recovery-key-store.js');

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

const ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const OTHER = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const LEGACY = '0x90F79bf6EB2c4f870365E785982E1f101E93b906';
const SIGNATURE_A = '0x' + 'a1'.repeat(65);
const SIGNATURE_B = '0x' + 'b2'.repeat(65);
const SIGNATURE_C = '0x' + 'c3'.repeat(65);
const PRIVATE_JWK = {
    kty: 'EC', crv: 'P-256',
    x: 'AAAA', y: 'BBBB', d: 'SECRET_SCALAR_abcdef'
};
const TEXT = new TextEncoder();

function signerFor(signature, expectedAddress) {
    return async (message) => {
        if (message !== Store.messageFor(expectedAddress)) {
            throw new Error('消息格式不符: ' + message);
        }
        return signature;
    };
}

/** 轮换签名器：epoch 0 用 A，epoch 1 用 B，验证消息确实带 epoch */
function rotatingSigner() {
    return async (message) => {
        if (message === Store.messageFor(ADDRESS)) return SIGNATURE_A;
        if (message === Store.messageForEpoch(ADDRESS, 1)) return SIGNATURE_B;
        throw new Error('未预期的签名消息: ' + message);
    };
}

function signatureBytes(signatureHex) {
    return Uint8Array.from(Buffer.from(signatureHex.slice(2), 'hex'));
}

/** 构造 P3.4 的 v1 旧记录（用于迁移测试） */
async function buildLegacyBlob(jwk, signatureHex, address) {
    const key = await Store.deriveWrappingKey(signatureBytes(signatureHex), address, 0);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await globalThis.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            additionalData: TEXT.encode(Store.DOMAIN + '|aad|' + address.toLowerCase())
        },
        key,
        TEXT.encode(JSON.stringify(jwk))
    );
    return {
        v: 1,
        alg: 'AES-256-GCM+HKDF-SHA256',
        address: address.toLowerCase(),
        iv: Buffer.from(iv).toString('base64'),
        ct: Buffer.from(ciphertext).toString('base64')
    };
}

function readRecord(address) {
    const raw = localStorage.getItem(Store.RECORD_PREFIX + address.toLowerCase());
    return raw ? JSON.parse(raw) : null;
}

async function main() {
    console.log('\n=== P3.4 / P3.8 钱包派生私钥持久化验收 ===\n');

    console.log('--- 消息与编码 ---');
    check('消息绑定并规范化地址',
        Store.messageFor('0xAbC') === 'ZK-SealedWeigh.recovery.walletkey.v1|0xabc',
        Store.messageFor('0xAbC'));
    check('轮换消息绑定 epoch',
        Store.messageForEpoch('0xAbC', 1) ===
        'ZK-SealedWeigh.recovery.walletkey.v1|rotate|1|0xabc',
        Store.messageForEpoch('0xAbC', 1));
    check('UTF-8 消息转个人签名十六进制',
        Store.messageToHex('A') === '0x41', Store.messageToHex('A'));
    check('中文消息按 UTF-8 编码',
        Store.messageToHex('中') === '0xe4b8ad', Store.messageToHex('中'));

    console.log('\n--- 保存与读取（localStorage 回退路径） ---');
    const signA = signerFor(SIGNATURE_A, ADDRESS);
    await Store.clear(ADDRESS);
    check('初始无记录', (await Store.hasStoredKey(ADDRESS)) === false);
    const initialInfo = await Store.getKeyInfo(ADDRESS);
    check('初始元信息为不存在',
        initialInfo.exists === false && initialInfo.backend === 'localstorage', initialInfo);

    const blob = await Store.savePrivateKey(PRIVATE_JWK, { address: ADDRESS, sign: signA });
    check('保存后存在记录', (await Store.hasStoredKey(ADDRESS)) === true);
    check('返回的密文为 v2 / epoch 0',
        blob.v === 2 && blob.epoch === 0, blob);

    const record = readRecord(ADDRESS);
    check('记录带 schema 与 version',
        record.schema === Store.RECORD_SCHEMA && record.version === 2, record && record.schema);
    check('记录带 createdAt / updatedAt',
        typeof record.createdAt === 'string' && typeof record.updatedAt === 'string');
    check('记录内信封为 v2 / epoch 0',
        record.envelope.v === 2 && record.envelope.epoch === 0, record.envelope);
    check('密文不含私钥标量', !JSON.stringify(record).includes('SECRET_SCALAR'));
    check('本地存储同样不含私钥标量',
        !localStorage.getItem(Store.RECORD_PREFIX + ADDRESS.toLowerCase())
            .includes('SECRET_SCALAR'));

    const loaded = await Store.loadPrivateKey({ address: ADDRESS, sign: signA });
    check('读取结果与原始 JWK 一致', JSON.stringify(loaded) === JSON.stringify(PRIVATE_JWK), loaded);

    const info = await Store.getKeyInfo(ADDRESS);
    check('元信息为 v2 / epoch 0 / 带创建时间',
        info.exists === true && info.version === 2 && info.epoch === 0 &&
        typeof info.createdAt === 'string', info);

    console.log('\n--- P3.4 v1 记录迁移 ---');
    await Store.clear(LEGACY);
    const legacyBlob = await buildLegacyBlob(PRIVATE_JWK, SIGNATURE_A, LEGACY);
    localStorage.setItem(Store.STORAGE_PREFIX + LEGACY.toLowerCase(), JSON.stringify(legacyBlob));
    check('旧记录可被识别为已存在', (await Store.hasStoredKey(LEGACY)) === true);
    check('迁移前没有 v2 记录', readRecord(LEGACY) === null);

    const migrated = await Store.loadPrivateKey({
        address: LEGACY, sign: signerFor(SIGNATURE_A, LEGACY)
    });
    check('迁移后仍能解出原私钥', JSON.stringify(migrated) === JSON.stringify(PRIVATE_JWK));
    check('迁移后生成 v2 记录',
        readRecord(LEGACY) !== null && readRecord(LEGACY).envelope.v === 2);
    check('迁移后旧 v1 键被删除',
        localStorage.getItem(Store.STORAGE_PREFIX + LEGACY.toLowerCase()) === null);

    console.log('\n--- 密钥轮换 ---');
    const beforeRotate = readRecord(ADDRESS).envelope.ct;
    const rotated = await Store.rotatePrivateKey({ address: ADDRESS, sign: rotatingSigner() });
    check('轮换返回 epoch=1', rotated.epoch === 1, rotated);
    check('记录中的 epoch 已递增', readRecord(ADDRESS).envelope.epoch === 1);
    check('轮换后密文发生变化', readRecord(ADDRESS).envelope.ct !== beforeRotate);
    const rotatedInfo = await Store.getKeyInfo(ADDRESS);
    check('元信息反映 epoch 1 与轮换时间',
        rotatedInfo.epoch === 1 && typeof rotatedInfo.rotatedAt === 'string', rotatedInfo);
    check('轮换后仍能解出原私钥',
        JSON.stringify(await Store.loadPrivateKey({
            address: ADDRESS, sign: rotatingSigner()
        })) === JSON.stringify(PRIVATE_JWK));
    await expectThrow('旧 epoch 的签名无法解开新密文', async () =>
        Store.decryptPrivateKey(readRecord(ADDRESS).envelope,
            signatureBytes(SIGNATURE_A), ADDRESS, 0));

    console.log('\n--- 可注入后端（模拟 IndexedDB 主存储） ---');
    const memory = new Map();
    Store.__setBackend({
        name: 'memory',
        get: async (key) => memory.has(key) ? JSON.parse(JSON.stringify(memory.get(key))) : null,
        set: async (key, value) => { memory.set(key, JSON.parse(JSON.stringify(value))); },
        remove: async (key) => { memory.delete(key); }
    });
    const injectedAddress = OTHER;
    check('注入后端初始无记录', (await Store.hasStoredKey(injectedAddress)) === false);
    await Store.savePrivateKey(PRIVATE_JWK, {
        address: injectedAddress, sign: signerFor(SIGNATURE_A, injectedAddress)
    });
    check('注入后端保存后可读回',
        JSON.stringify(await Store.loadPrivateKey({
            address: injectedAddress, sign: signerFor(SIGNATURE_A, injectedAddress)
        })) === JSON.stringify(PRIVATE_JWK));
    check('注入后端不写 localStorage 记录',
        localStorage.getItem(Store.RECORD_PREFIX + injectedAddress.toLowerCase()) === null);
    await Store.clear(injectedAddress);
    check('注入后端清除后无记录',
        (await Store.hasStoredKey(injectedAddress)) === false);
    Store.__setBackend(null);

    console.log('\n--- 拒绝路径 ---');
    const sigBytes = signatureBytes(SIGNATURE_A);
    const directBlob = await Store.encryptPrivateKey(PRIVATE_JWK, sigBytes, ADDRESS, 0);
    const directLoaded = await Store.decryptPrivateKey(directBlob, sigBytes, ADDRESS, 0);
    check('直接加解密往返一致',
        JSON.stringify(directLoaded) === JSON.stringify(PRIVATE_JWK));
    await expectThrow('换一个地址无法解密（AAD/HKDF 绑定）', async () =>
        Store.decryptPrivateKey(directBlob, sigBytes, OTHER, 0));

    await expectThrow('换一个签名无法解密', async () =>
        Store.loadPrivateKey({ address: ADDRESS, sign: async () => SIGNATURE_C }));

    check('其他地址没有本地记录', (await Store.hasStoredKey(OTHER)) === false);

    const tampered = JSON.parse(JSON.stringify(readRecord(ADDRESS)));
    const ctBytes = Buffer.from(tampered.envelope.ct, 'base64');
    ctBytes[0] ^= 0xff;
    tampered.envelope.ct = ctBytes.toString('base64');
    localStorage.setItem(Store.RECORD_PREFIX + ADDRESS.toLowerCase(), JSON.stringify(tampered));
    await expectThrow('篡改本地密文被检出', async () =>
        Store.loadPrivateKey({ address: ADDRESS, sign: rotatingSigner() }));

    await Store.clear(ADDRESS);
    check('清除后无记录', (await Store.hasStoredKey(ADDRESS)) === false);

    console.log('\n--- 钱包交互 ---');
    const provider = {
        calls: [],
        async request(args) {
            this.calls.push(args);
            if (args.method === 'eth_accounts') return [ADDRESS];
            return SIGNATURE_A;
        }
    };
    const signature = await Store.personalSign(Store.messageFor(ADDRESS), provider, ADDRESS);
    check('personal_sign 返回签名', signature === SIGNATURE_A);
    check('personal_sign 参数为十六进制消息',
        provider.calls.some((call) => call.method === 'personal_sign' &&
            call.params[0] === Store.messageToHex(Store.messageFor(ADDRESS))));

    const wrongProvider = {
        async request(args) {
            if (args.method === 'eth_accounts') return [OTHER];
            return SIGNATURE_B;
        }
    };
    await expectThrow('钱包账户与登录账号不一致被拒', async () =>
        Store.personalSign(Store.messageFor(ADDRESS), wrongProvider, ADDRESS));

    const emptyProvider = {
        async request() { return []; }
    };
    await expectThrow('钱包未连接被拒', async () =>
        Store.personalSign(Store.messageFor(ADDRESS), emptyProvider, ADDRESS));

    console.log(`\n=== ${passed} 通过 / ${failed} 失败 ===\n`);
    return failed === 0 ? 0 : 1;
}

main()
    .then((code) => process.exit(code))
    .catch((error) => {
        console.error('测试异常:', error);
        process.exit(2);
    });
