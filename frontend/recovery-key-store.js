/* =============================================================================
   recovery-key-store.js —— 用钱包派生密钥加密保存 P-256 私钥（P3.4 / P3.8）

   问题：门限恢复要解开份额，必须有评委自己的 ECDH P-256 私钥。
        把 JWK 明文放进 localStorage 等于把恢复权限交给任何能读存储的人。
   做法：让钱包对一条固定消息做 personal_sign（MetaMask 等使用 RFC6979，
        同一账号 + 同一消息的签名是确定的），用签名字节经 HKDF-SHA256
        派生 AES-256-GCM 密钥，再加密私钥 JWK 后写入本地。

   P3.8 存储层升级：
     · 主存储改为 IndexedDB（容量更大、不阻塞主线程），不可用时回退 localStorage；
     · 信封升级为 v2，记录带 schema / version / 时间戳 / epoch；
     · P3.4 写入的 v1 localStorage 记录在首次读取时自动迁移并删除旧键；
     · 支持密钥轮换：epoch 递增后换用新的派生消息重新加密，旧密文被覆盖。

   安全边界（必须如实说明）：
     · 钱包是根信任：能重放这条签名的人就能解出私钥；
     · 依赖钱包签名确定性；若某钱包引入随机性，重开页面会解不开 → 必须显式报错；
     · 签名消息绑定地址与 epoch，换账号得到的密钥不同；
     · 本模块不接触链上交易，也不上传任何东西。
   ========================================================================== */
(function (global) {
    'use strict';

    var DOMAIN = 'ZK-SealedWeigh.recovery.walletkey.v1';
    var RECORD_SCHEMA = 'ZK-SealedWeigh.recovery.keyrecord.v1';
    var STORAGE_PREFIX = 'zkr:key:';          // P3.4 旧键前缀，仅用于迁移
    var RECORD_PREFIX = 'v2:';                // P3.8 新记录键前缀
    var DB_NAME = 'ZK-SealedWeigh.recovery';
    var DB_VERSION = 1;
    var STORE_NAME = 'walletKeys';
    var GCM_IV_BYTES = 12;
    var TEXT = new TextEncoder();

    var dbPromise = null;
    var backendOverride = null;

    function utf8(text) { return TEXT.encode(String(text)); }
    function fail(message) { throw new Error('RecoveryKeyStore: ' + message); }

    function normalizeAddress(address) {
        return String(address || '').toLowerCase();
    }

    function randomBytes(length) {
        var out = new Uint8Array(length);
        global.crypto.getRandomValues(out);
        return out;
    }

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

    function bytesToHex(bytes) {
        var out = '';
        for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
        return out;
    }

    function hexToBytes(text) {
        var s = String(text);
        if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2);
        if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) fail('签名不是合法的十六进制串');
        var out = new Uint8Array(s.length / 2);
        for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
        return out;
    }

    /** 钱包要签的消息：绑定地址，换账号得到不同的派生密钥 */
    function messageFor(address) {
        return DOMAIN + '|' + normalizeAddress(address);
    }

    /** 轮换后绑定 epoch，避免新旧记录共用同一派生密钥 */
    function messageForEpoch(address, epoch) {
        var index = Number(epoch) || 0;
        if (index <= 0) return messageFor(address);
        return DOMAIN + '|rotate|' + index + '|' + normalizeAddress(address);
    }

    /** personal_sign 需要十六进制数据，这里把 UTF-8 消息转成 0x… */
    function messageToHex(message) {
        return '0x' + bytesToHex(utf8(message));
    }

    function aadFor(address) {
        return DOMAIN + '|aad|' + normalizeAddress(address);
    }

    function storage() {
        if (!global.localStorage) fail('当前环境没有 localStorage');
        return global.localStorage;
    }

    function legacyKey(address) {
        return STORAGE_PREFIX + normalizeAddress(address);
    }

    function recordKey(address) {
        return RECORD_PREFIX + normalizeAddress(address);
    }

    // ---------------- 钱包派生密钥 ----------------

    function wrappingInfo(address, epoch) {
        var index = Number(epoch) || 0;
        return index <= 0
            ? DOMAIN + '|' + normalizeAddress(address)
            : DOMAIN + '|rotate|' + index + '|' + normalizeAddress(address);
    }

    async function deriveWrappingKey(signatureBytes, address, epoch) {
        if (!(signatureBytes instanceof Uint8Array) || signatureBytes.length < 64) {
            fail('钱包签名长度不足（需要 65 字节）');
        }
        var baseKey = await global.crypto.subtle.importKey(
            'raw', signatureBytes, 'HKDF', false, ['deriveKey']);
        return global.crypto.subtle.deriveKey(
            {
                name: 'HKDF', hash: 'SHA-256',
                salt: utf8(DOMAIN + '.salt'),
                info: utf8(wrappingInfo(address, epoch))
            },
            baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    }

    async function encryptPrivateKey(privateJwk, signatureBytes, address, epoch) {
        if (!privateJwk || typeof privateJwk !== 'object') fail('缺少私钥 JWK');
        var index = Number(epoch) || 0;
        var key = await deriveWrappingKey(signatureBytes, address, index);
        var iv = randomBytes(GCM_IV_BYTES);
        var ciphertext = await global.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, additionalData: utf8(aadFor(address)) },
            key, utf8(JSON.stringify(privateJwk)));
        return {
            v: 2,
            alg: 'AES-256-GCM+HKDF-SHA256',
            address: normalizeAddress(address),
            epoch: index,
            iv: bytesToB64(iv),
            ct: bytesToB64(new Uint8Array(ciphertext))
        };
    }

    async function decryptPrivateKey(blob, signatureBytes, address, epoch) {
        try {
            var index = epoch === undefined ? Number(blob.epoch) || 0 : Number(epoch) || 0;
            var key = await deriveWrappingKey(signatureBytes, address, index);
            var plaintext = await global.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: b64ToBytes(blob.iv),
                    additionalData: utf8(aadFor(address))
                },
                key, b64ToBytes(blob.ct));
            return JSON.parse(new TextDecoder().decode(plaintext));
        } catch (error) {
            fail('私钥解密失败：钱包账号不符、签名不确定或本地数据被篡改');
        }
    }

    // ---------------- IndexedDB 适配 ----------------

    function hasIndexedDB() {
        return typeof global.indexedDB !== 'undefined' && global.indexedDB &&
            typeof global.indexedDB.open === 'function';
    }

    function openDb() {
        if (dbPromise) return dbPromise;
        dbPromise = new Promise(function (resolve, reject) {
            var request;
            try {
                request = global.indexedDB.open(DB_NAME, DB_VERSION);
            } catch (error) {
                reject(error);
                return;
            }
            request.onupgradeneeded = function () {
                var database = request.result;
                if (!database.objectStoreNames.contains(STORE_NAME)) {
                    database.createObjectStore(STORE_NAME);
                }
            };
            request.onsuccess = function () { resolve(request.result); };
            request.onerror = function () {
                reject(request.error || new Error('IndexedDB 打开失败'));
            };
        }).catch(function (error) {
            dbPromise = null;
            throw error;
        });
        return dbPromise;
    }

    function idbRun(mode, action) {
        return openDb().then(function (database) {
            return new Promise(function (resolve, reject) {
                var transaction = database.transaction(STORE_NAME, mode);
                var store = transaction.objectStore(STORE_NAME);
                var request = action(store);
                transaction.oncomplete = function () {
                    resolve(request ? request.result : undefined);
                };
                transaction.onerror = function () {
                    reject(transaction.error || (request && request.error));
                };
                transaction.onabort = function () {
                    reject(transaction.error || new Error('IndexedDB 事务中止'));
                };
            });
        });
    }

    function indexedDbBackend() {
        return {
            name: 'indexeddb',
            get: function (key) { return idbRun('readonly', function (s) { return s.get(key); }); },
            set: function (key, value) { return idbRun('readwrite', function (s) { return s.put(value, key); }); },
            remove: function (key) { return idbRun('readwrite', function (s) { return s.delete(key); }); }
        };
    }

    function localStorageBackend() {
        return {
            name: 'localstorage',
            get: function (key) {
                var raw = storage().getItem(key);
                return Promise.resolve(raw ? JSON.parse(raw) : null);
            },
            set: function (key, value) {
                storage().setItem(key, JSON.stringify(value));
                return Promise.resolve();
            },
            remove: function (key) {
                storage().removeItem(key);
                return Promise.resolve();
            }
        };
    }

    function activeBackend() {
        if (backendOverride) return backendOverride;
        return hasIndexedDB() ? indexedDbBackend() : localStorageBackend();
    }

    /* IndexedDB 运行时失败（隐私模式、配额等）时回退到 localStorage，避免整页不可用 */
    function backendOp(name, args) {
        var backend = activeBackend();
        return backend[name].apply(backend, args).catch(function (error) {
            if (backendOverride || backend.name !== 'indexeddb') throw error;
            var fallback = localStorageBackend();
            return fallback[name].apply(fallback, args);
        });
    }

    function backendGet(key) { return backendOp('get', [key]); }
    function backendSet(key, value) { return backendOp('set', [key, value]); }
    function backendRemove(key) { return backendOp('remove', [key]); }

    function currentBackendName() {
        if (backendOverride) return backendOverride.name || 'custom';
        return hasIndexedDB() ? 'indexeddb' : 'localstorage';
    }

    // ---------------- v1 旧记录迁移 ----------------

    function readLegacy(address) {
        try {
            var raw = storage().getItem(legacyKey(address));
            return raw ? JSON.parse(raw) : null;
        } catch (error) {
            return null;
        }
    }

    function removeLegacy(address) {
        try {
            storage().removeItem(legacyKey(address));
        } catch (error) { /* 无 localStorage 时忽略 */ }
    }

    function makeRecord(address, envelope, createdAt) {
        var now = new Date().toISOString();
        return {
            schema: RECORD_SCHEMA,
            version: 2,
            address: normalizeAddress(address),
            createdAt: createdAt || now,
            updatedAt: now,
            envelope: envelope
        };
    }

    async function migrateLegacy(address, signer) {
        var legacy = readLegacy(address);
        if (!legacy) return null;

        var signature = await signer(messageFor(address));
        var jwk = await decryptPrivateKey(legacy, hexToBytes(signature), address, 0);
        var envelope = await encryptPrivateKey(jwk, hexToBytes(signature), address, 0);
        var record = makeRecord(address, envelope);
        await backendSet(recordKey(address), record);
        removeLegacy(address);
        return { record: record, jwk: jwk, migrated: true };
    }

    async function loadRecord(address, signer) {
        var record = await backendGet(recordKey(address));
        if (record) {
            var envelope = record.envelope || record;
            var epoch = Number(envelope.epoch) || 0;
            var signature = await signer(messageForEpoch(address, epoch));
            var jwk = await decryptPrivateKey(envelope, hexToBytes(signature), address, epoch);
            return {
                record: record.envelope ? record : makeRecord(address, envelope),
                jwk: jwk,
                migrated: false
            };
        }
        return migrateLegacy(address, signer);
    }

    // ---------------- 浏览器钱包交互 ----------------

    /**
     * 用注入的 EIP-1193 provider 对消息做 personal_sign。
     * @param {string} message
     * @param {Object} provider window.ethereum
     * @param {string} expectedAddress 必须与当前账户一致，避免签错账号
     * @returns {Promise<string>} 0x 开头的 65 字节签名
     */
    async function personalSign(message, provider, expectedAddress) {
        if (!provider || typeof provider.request !== 'function') {
            fail('未检测到以太坊钱包');
        }
        var accounts = await provider.request({ method: 'eth_accounts' });
        if (!accounts || accounts.length === 0) fail('钱包未连接');
        var account = accounts[0];
        if (expectedAddress && account.toLowerCase() !== normalizeAddress(expectedAddress)) {
            fail('当前钱包账户与登录账号不一致：' + account);
        }
        return provider.request({
            method: 'personal_sign',
            params: [messageToHex(message), account]
        });
    }

    // ---------------- 对外 API ----------------

    var RecoveryKeyStore = {
        VERSION: 2,
        DOMAIN: DOMAIN,
        RECORD_SCHEMA: RECORD_SCHEMA,
        STORAGE_PREFIX: STORAGE_PREFIX,
        RECORD_PREFIX: RECORD_PREFIX,
        DB_NAME: DB_NAME,
        STORE_NAME: STORE_NAME,

        messageFor: messageFor,
        messageForEpoch: messageForEpoch,
        messageToHex: messageToHex,
        deriveWrappingKey: deriveWrappingKey,
        encryptPrivateKey: encryptPrivateKey,
        decryptPrivateKey: decryptPrivateKey,
        personalSign: personalSign,

        /** 加密并写入主存储（覆盖旧值），成功后删除 v1 旧键 */
        async savePrivateKey(privateJwk, options) {
            var address = options.address;
            var signature = await options.sign(messageFor(address));
            var envelope = await encryptPrivateKey(privateJwk, hexToBytes(signature), address, 0);
            var record = makeRecord(address, envelope);
            await backendSet(recordKey(address), record);
            removeLegacy(address);
            return envelope;
        },

        /** 读取并解密；没有记录时返回 null；遇到 v1 记录会顺带迁移 */
        async loadPrivateKey(options) {
            var loaded = await loadRecord(options.address, options.sign);
            return loaded ? loaded.jwk : null;
        },

        /** 是否存在可用记录（含尚未迁移的 v1 旧记录） */
        async hasStoredKey(address) {
            var record = await backendGet(recordKey(address));
            if (record) return true;
            return !!readLegacy(address);
        },

        /** 只读取元信息，不解密、不要求钱包签名（供管理页展示） */
        async getKeyInfo(address) {
            var record = await backendGet(recordKey(address));
            var legacy = record ? null : readLegacy(address);
            if (!record && !legacy) {
                return { exists: false, backend: currentBackendName() };
            }
            var envelope = record ? (record.envelope || record) : legacy;
            return {
                exists: true,
                backend: currentBackendName(),
                version: record ? record.version : 1,
                epoch: Number(envelope.epoch) || 0,
                createdAt: record ? record.createdAt : null,
                updatedAt: record ? record.updatedAt : null,
                rotatedAt: record ? record.rotatedAt : null,
                pendingMigration: !record && !!legacy
            };
        },

        /**
         * 密钥轮换：epoch + 1，用新派生消息重新加密同一份私钥。
         * 旧密文被覆盖，旧 epoch 的签名不再能解开新记录。
         */
        async rotatePrivateKey(options) {
            var address = options.address;
            var loaded = await loadRecord(address, options.sign);
            if (!loaded) fail('没有可轮换的恢复私钥');

            var nextEpoch = (Number(loaded.record.envelope.epoch) || 0) + 1;
            var signature = await options.sign(messageForEpoch(address, nextEpoch));
            var envelope = await encryptPrivateKey(
                loaded.jwk, hexToBytes(signature), address, nextEpoch);
            var record = makeRecord(address, envelope, loaded.record.createdAt);
            record.rotatedAt = record.updatedAt;
            await backendSet(recordKey(address), record);
            return { epoch: nextEpoch, rotatedAt: record.rotatedAt };
        },

        /** 清除主存储与 v1 旧键 */
        async clear(address) {
            await backendRemove(recordKey(address));
            removeLegacy(address);
        },

        /** 仅供测试：注入内存后端；传 null 恢复默认选择逻辑 */
        __setBackend(backend) {
            backendOverride = backend || null;
        }
    };

    global.RecoveryKeyStore = RecoveryKeyStore;
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = RecoveryKeyStore;
    }
})(typeof window !== 'undefined' ? window : globalThis);
