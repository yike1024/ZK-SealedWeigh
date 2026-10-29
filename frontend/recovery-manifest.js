/* =============================================================================
   recovery-manifest.js —— 规范 JSON 与 SHA-256（浏览器 / Node 共用）

   服务端 Python 的规范序列化是
     json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False)
   本文件的 canonicalJson 必须与之逐字节一致，否则签名校验会失败。
   ========================================================================== */
(function (global) {
    'use strict';

    var TEXT = new TextEncoder();

    function canonicalJson(value) {
        if (Array.isArray(value)) {
            return '[' + value.map(canonicalJson).join(',') + ']';
        }
        if (value && typeof value === 'object') {
            var keys = Object.keys(value).sort();
            return '{' + keys.map(function (key) {
                return JSON.stringify(key) + ':' + canonicalJson(value[key]);
            }).join(',') + '}';
        }
        return JSON.stringify(value);
    }

    async function sha256Hex(text) {
        var digest = await global.crypto.subtle.digest('SHA-256', TEXT.encode(String(text)));
        var bytes = new Uint8Array(digest);
        var out = '';
        for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
        return out;
    }

    var RecoveryManifest = { canonicalJson: canonicalJson, sha256Hex: sha256Hex };

    global.RecoveryManifest = RecoveryManifest;
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = RecoveryManifest;
    }
})(typeof window !== 'undefined' ? window : globalThis);
