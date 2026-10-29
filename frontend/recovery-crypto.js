/* =============================================================================
   recovery-crypto.js —— 门限恢复的浏览器端密码学核心（P3.1）

   规范见 spec.md 第 11 节。本文件只做密码学，不含服务器与 UI：
     · Shamir(k, n) over GF(256)：把一个 32 字节主密钥拆成 n 份
     · AES-256-GCM：加密评委的本地载荷（scores/secret/salt）
     · ECDH P-256 + HKDF-SHA256：把份额只加密给指定接收者

   安全边界（必须遵守）：
     1. 主密钥、份额明文、恢复载荷永远不离开浏览器；
     2. 服务器只允许接收本文件产出的密文；
     3. 私钥必须由上层用钱包派生的密钥加密后再持久化。

   兼容：浏览器（window.RecoveryCrypto）与 Node（module.exports），
   依赖 WebCrypto（Chrome 89+ / Node 19+）。
   ========================================================================== */
(function (global) {
    'use strict';

    var DOMAIN = {
        ESCROW: 'ZK-SealedWeigh.recovery.escrow.v1',
        SHARE: 'ZK-SealedWeigh.recovery.share.v1',
        MANIFEST: 'ZK-SealedWeigh.recovery.manifest.v1'
    };

    var MASTER_KEY_BYTES = 32;
    var GCM_IV_BYTES = 12;
    var TEXT = new TextEncoder();

    function utf8(text) { return TEXT.encode(String(text)); }
    function fail(message) { throw new Error('RecoveryCrypto: ' + message); }

    function randomBytes(length) {
        var out = new Uint8Array(length);
        global.crypto.getRandomValues(out);
        return out;
    }

    // ---------------- base64（浏览器与 Node 通用） ----------------
    function bytesToB64(bytes) {
        var chunk = 0x8000, out = '';
        for (var i = 0; i < bytes.length; i += chunk) {
            out += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
        }
        return global.btoa(out);
    }

    function b64ToBytes(text) {
        var raw = global.atob(String(text));
        var out = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out;
    }

    // ---------------- GF(256)（AES 域，不可约多项式 0x11b） ----------------
    // 生成元取 3：x ← x·3 = x ⊕ xtime(x)，遍历 255 个非零元。
    var EXP = new Uint8Array(512);
    var LOG = new Uint8Array(256);
    (function initTables() {
        var x = 1;
        for (var i = 0; i < 255; i++) {
            EXP[i] = x;
            LOG[x] = i;
            var xtime = ((x << 1) & 0xff) ^ ((x & 0x80) ? 0x1b : 0x00);
            x = xtime ^ x;
        }
        for (var j = 255; j < 512; j++) EXP[j] = EXP[j - 255];
    })();

    function gfMul(a, b) {
        if (a === 0 || b === 0) return 0;
        return EXP[LOG[a] + LOG[b]];
    }

    function gfDiv(a, b) {
        if (b === 0) fail('GF(256) 除数为零');
        if (a === 0) return 0;
        return EXP[(LOG[a] - LOG[b] + 255) % 255];
    }

    function gfInv(a) {
        if (a === 0) fail('GF(256) 零元没有逆元');
        return EXP[255 - LOG[a]];
    }

    // ---------------- Shamir 秘密共享 ----------------
    function evalPolynomial(coefficients, x) {
        var result = 0;
        for (var i = coefficients.length - 1; i >= 0; i--) {
            result = gfMul(result, x) ^ coefficients[i];
        }
        return result;
    }

    /**
     * 把 32 字节主密钥拆成 n 份，任意 k 份可重构。
     * @param {Uint8Array} secret 必须是 32 字节
     * @param {number} k 门限
     * @param {number} n 份额总数
     * @param {Function} [randomSource] 仅测试使用：返回指定长度随机字节的函数
     * @returns {Array<{x:number, y:Uint8Array}>}
     */
    function splitSecret(secret, k, n, randomSource) {
        if (!(secret instanceof Uint8Array) || secret.length !== MASTER_KEY_BYTES) {
            fail('主密钥必须是 ' + MASTER_KEY_BYTES + ' 字节的 Uint8Array');
        }
        if (!Number.isInteger(k) || !Number.isInteger(n) || k < 1 || n < k || n > 255) {
            fail('需要满足 1 ≤ k ≤ n ≤ 255');
        }
        var rng = typeof randomSource === 'function' ? randomSource : randomBytes;

        var shares = [];
        for (var index = 1; index <= n; index++) {
            shares.push({ x: index, y: new Uint8Array(MASTER_KEY_BYTES) });
        }

        for (var byteIndex = 0; byteIndex < MASTER_KEY_BYTES; byteIndex++) {
            var coefficients = new Uint8Array(k);
            coefficients[0] = secret[byteIndex];
            if (k > 1) {
                var random = rng(k - 1);
                if (!(random instanceof Uint8Array) || random.length !== k - 1) {
                    fail('randomSource 返回长度不正确');
                }
                coefficients.set(random, 1);
            }
            for (var s = 0; s < shares.length; s++) {
                shares[s].y[byteIndex] = evalPolynomial(coefficients, shares[s].x);
            }
        }
        return shares;
    }

    /** 用任意 ≥k 份重构主密钥（x=0 处的 Lagrange 插值） */
    function combineShares(shares) {
        if (!Array.isArray(shares) || shares.length === 0) fail('份额不能为空');

        var seen = {};
        var length = null;
        shares.forEach(function (share) {
            if (!share || !Number.isInteger(share.x) || share.x < 1 || share.x > 255) {
                fail('份额的 x 必须是 1..255 的整数');
            }
            if (seen[share.x]) fail('份额 x 重复：' + share.x);
            seen[share.x] = true;
            if (!(share.y instanceof Uint8Array)) fail('份额的 y 必须是 Uint8Array');
            if (length === null) length = share.y.length;
            if (share.y.length !== length) fail('份额长度不一致');
        });

        var secret = new Uint8Array(length);
        for (var byteIndex = 0; byteIndex < length; byteIndex++) {
            var value = 0;
            for (var i = 0; i < shares.length; i++) {
                var numerator = 1;
                var denominator = 1;
                for (var j = 0; j < shares.length; j++) {
                    if (i === j) continue;
                    numerator = gfMul(numerator, shares[j].x);
                    denominator = gfMul(denominator, shares[j].x ^ shares[i].x);
                }
                value ^= gfMul(shares[i].y[byteIndex], gfDiv(numerator, denominator));
            }
            secret[byteIndex] = value;
        }
        return secret;
    }

    /** 份额传输格式：1 字节 x + 32 字节 y */
    function shareToBytes(share) {
        var out = new Uint8Array(1 + share.y.length);
        out[0] = share.x;
        out.set(share.y, 1);
        return out;
    }

    function bytesToShare(raw) {
        if (!(raw instanceof Uint8Array) || raw.length !== 1 + MASTER_KEY_BYTES) {
            fail('份额字节长度不正确');
        }
        return { x: raw[0], y: raw.subarray(1) };
    }

    function encodeShare(share) {
        return bytesToB64(shareToBytes(share));
    }

    function decodeShare(text) {
        return bytesToShare(b64ToBytes(text));
    }

    // ---------------- AES-256-GCM / HKDF-SHA256 ----------------
    async function deriveAesKey(ikm, salt, info) {
        var baseKey = await global.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
        return global.crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: salt, info: utf8(info) },
            baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    }

    function escrowAad(context) {
        return [DOMAIN.ESCROW, context.votingId, context.voter].join('|');
    }

    function shareAad(context) {
        return [DOMAIN.SHARE, context.votingId, context.from, context.to].join('|');
    }

    async function deriveEscrowKey(masterKey, context) {
        if (masterKey.length !== MASTER_KEY_BYTES) fail('主密钥长度必须是 32 字节');
        return deriveAesKey(masterKey, utf8(DOMAIN.ESCROW + '.salt'), escrowAad(context));
    }

    /**
     * 加密评委本地载荷（scores / secret / salt）。服务器只应保存该密文。
     * @param {Object} payload 可 JSON 序列化的对象
     * @param {Uint8Array} masterKey 32 字节
     * @param {{votingId:string|number, voter:string}} context
     */
    async function encryptEscrow(payload, masterKey, context) {
        var plaintext = utf8(JSON.stringify(payload));
        var key = await deriveEscrowKey(masterKey, context);
        var iv = randomBytes(GCM_IV_BYTES);
        var ciphertext = await global.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, additionalData: utf8(escrowAad(context)) },
            key, plaintext);
        return {
            v: 1,
            alg: 'AES-256-GCM+HKDF-SHA256',
            context: { votingId: String(context.votingId), voter: String(context.voter) },
            iv: bytesToB64(iv),
            ct: bytesToB64(new Uint8Array(ciphertext))
        };
    }

    async function decryptEscrow(blob, masterKey, context) {
        try {
            var key = await deriveEscrowKey(masterKey, context);
            var plaintext = await global.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: b64ToBytes(blob.iv), additionalData: utf8(escrowAad(context)) },
                key, b64ToBytes(blob.ct));
            return JSON.parse(new TextDecoder().decode(plaintext));
        } catch (error) {
            fail('恢复载荷解密失败（主密钥错误、上下文不符或密文被篡改）');
        }
    }

    // ---------------- ECDH P-256 ----------------
    async function generateKeyPair() {
        return global.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    }

    async function exportPublicKey(publicKey) {
        var spki = await global.crypto.subtle.exportKey('spki', publicKey);
        return bytesToB64(new Uint8Array(spki));
    }

    async function importPublicKey(base64Spki) {
        return global.crypto.subtle.importKey(
            'spki', b64ToBytes(base64Spki),
            { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    }

    /** 私钥只应在上层用钱包派生的密钥加密后持久化；本函数不做保护 */
    async function exportPrivateKey(privateKey) {
        return global.crypto.subtle.exportKey('jwk', privateKey);
    }

    async function importPrivateKey(jwk) {
        return global.crypto.subtle.importKey(
            'jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    }

    async function deriveShareKey(privateKey, publicKey) {
        var shared = await global.crypto.subtle.deriveBits(
            { name: 'ECDH', public: publicKey }, privateKey, 256);
        return deriveAesKey(new Uint8Array(shared), utf8(DOMAIN.SHARE + '.salt'), DOMAIN.SHARE + '|hkdf');
    }

    /**
     * 把份额加密给指定接收者（每次使用临时密钥对，信封自带临时公钥）。
     * @param {{x:number,y:Uint8Array}} share
     * @param {string} recipientPublicKeyB64 接收者的 P-256 SPKI（base64）
     * @param {{votingId:string|number, from:string, to:string}} context
     */
    async function wrapShareFor(share, recipientPublicKeyB64, context) {
        var ephemeral = await generateKeyPair();
        var recipient = await importPublicKey(recipientPublicKeyB64);
        var key = await deriveShareKey(ephemeral.privateKey, recipient);
        var iv = randomBytes(GCM_IV_BYTES);
        var ciphertext = await global.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, additionalData: utf8(shareAad(context)) },
            key, shareToBytes(share));
        return {
            v: 1,
            alg: 'ECDH-P256+HKDF-SHA256+AES-256-GCM',
            epk: await exportPublicKey(ephemeral.publicKey),
            iv: bytesToB64(iv),
            ct: bytesToB64(new Uint8Array(ciphertext))
        };
    }

    async function unwrapShare(envelope, privateKey, context) {
        try {
            var ephemeral = await importPublicKey(envelope.epk);
            var key = await deriveShareKey(privateKey, ephemeral);
            var plaintext = await global.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: b64ToBytes(envelope.iv), additionalData: utf8(shareAad(context)) },
                key, b64ToBytes(envelope.ct));
            return decodeShare(bytesToB64(new Uint8Array(plaintext)));
        } catch (error) {
            fail('份额解密失败（接收者不符、上下文不符或信封被篡改）');
        }
    }

    // ---------------- 对外 API ----------------
    var RecoveryCrypto = {
        VERSION: 1,
        DOMAIN: DOMAIN,
        MASTER_KEY_BYTES: MASTER_KEY_BYTES,

        // GF(256)
        gfMul: gfMul,
        gfDiv: gfDiv,
        gfInv: gfInv,

        // Shamir
        splitSecret: splitSecret,
        combineShares: combineShares,
        encodeShare: encodeShare,
        decodeShare: decodeShare,

        // 恢复载荷
        deriveEscrowKey: deriveEscrowKey,
        encryptEscrow: encryptEscrow,
        decryptEscrow: decryptEscrow,

        // 份额信封
        generateKeyPair: generateKeyPair,
        exportPublicKey: exportPublicKey,
        importPublicKey: importPublicKey,
        exportPrivateKey: exportPrivateKey,
        importPrivateKey: importPrivateKey,
        wrapShareFor: wrapShareFor,
        unwrapShare: unwrapShare,

        // 工具
        randomBytes: randomBytes,
        bytesToB64: bytesToB64,
        b64ToBytes: b64ToBytes
    };

    global.RecoveryCrypto = RecoveryCrypto;
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = RecoveryCrypto;
    }
})(typeof window !== 'undefined' ? window : globalThis);
