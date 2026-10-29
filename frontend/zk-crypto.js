/* =============================================================================
   zk-crypto.js —— 浏览器端密码学原语（承诺本地生成，服务端零知识）
   规范见 spec.md 第 3、4 节；本文件与 backend/utils/protocol.py 必须逐字节一致。

   依赖：vendor/sha3.min.js（js-sha3 0.8.0, MIT, 提供全局 keccak256）
   不引入任何 CDN；曲线运算用 BigInt 手写，便于审计。
   ========================================================================== */
(function (global) {
    'use strict';

    // ---------------- alt_bn128（BN254）域参数 ----------------
    // 选 BN254 而非 secp256k1：只有它在 EVM 有预编译（0x06 ecAdd / 0x07 ecMul），
    // 链上才能做真正的椭圆曲线校验。曲线：y² = x³ + 3。
    var P = BigInt('21888242871839275222246405745257275088696311157297823662689037894645226208583');
    var N = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
    var GX = 1n;
    var GY = 2n;

    // 第二生成元 H（NUMS）：hash_to_point(SHA256("ZK-SealedWeigh.Pedersen.H.v3" || counter))。
    // 无人知晓 dlog_H(G)；否则绑定性可被构造碰撞破坏（见 spec.md 第 3 节）。
    var HX = BigInt('0x23ae7e827609887ff1721f43efed23e0d3941cef3a524e28576a8c165b0b23c1');
    var HY = BigInt('0x09485bce1c81e4f60d2852f4ab22f9a79997cc8a19f87afbfcee998cc818b5f6');

    var G = { x: GX, y: GY };
    var H = { x: HX, y: HY };

    // ---------------- 模运算与椭圆曲线 ----------------
    function mod(a, m) {
        var r = a % m;
        return r >= 0n ? r : r + m;
    }

    function modInv(a, m) {
        var lm = 1n, hm = 0n, low = mod(a, m), high = m;
        while (low > 1n) {
            var r = high / low;
            var nm = hm - lm * r;
            var nw = high - low * r;
            hm = lm; lm = nm;
            high = low; low = nw;
        }
        return mod(lm, m);
    }

    function pointAdd(p1, p2) {
        if (!p1) return p2;
        if (!p2) return p1;
        if (p1.x === p2.x) {
            if (mod(p1.y + p2.y, P) === 0n) return null; // 互为逆元
            return pointDouble(p1);
        }
        var s = mod((p2.y - p1.y) * modInv(p2.x - p1.x, P), P);
        var x = mod(s * s - p1.x - p2.x, P);
        var y = mod(s * (p1.x - x) - p1.y, P);
        return { x: x, y: y };
    }

    function pointDouble(p) {
        if (!p || p.y === 0n) return null;
        var s = mod(3n * p.x * p.x * modInv(2n * p.y, P), P);
        var x = mod(s * s - 2n * p.x, P);
        var y = mod(s * (p.x - x) - p.y, P);
        return { x: x, y: y };
    }

    function pointMul(point, scalar) {
        scalar = mod(scalar, N);
        var result = null, addend = point;
        while (scalar > 0n) {
            if (scalar & 1n) result = pointAdd(result, addend);
            addend = pointDouble(addend);
            scalar >>= 1n;
        }
        return result;
    }

    // ---------------- 编解码 ----------------
    function bytesToHex(bytes) {
        var out = '';
        for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
        return out;
    }

    function hexToBytes(hex) {
        var s = String(hex);
        if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2);
        if (s.length % 2) s = '0' + s;
        var out = new Uint8Array(s.length / 2);
        for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
        return out;
    }

    function utf8(str) { return new TextEncoder().encode(String(str)); }

    function concatBytes() {
        var total = 0, i;
        for (i = 0; i < arguments.length; i++) total += arguments[i].length;
        var out = new Uint8Array(total), off = 0;
        for (i = 0; i < arguments.length; i++) { out.set(arguments[i], off); off += arguments[i].length; }
        return out;
    }

    function uint256Bytes(value) {
        var v = BigInt(value);
        if (v < 0n) throw new Error('uint256 不能为负');
        var out = new Uint8Array(32);
        for (var i = 31; i >= 0; i--) { out[i] = Number(v & 0xFFn); v >>= 8n; }
        return out;
    }

    /** abi.encode 中的 address 槽：左填充到 32 字节（注意不是 20 字节！） */
    function addressWord(address) {
        var s = String(address).toLowerCase();
        if (s.startsWith('0x')) s = s.slice(2);
        s = s.padStart(64, '0');
        return hexToBytes(s.slice(-64));
    }

    /** abi.encode 中的 bytes32 槽 */
    function bytes32Word(value) {
        var s = String(value);
        if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2);
        s = s.padStart(64, '0');
        return hexToBytes(s.slice(-64));
    }

    function bigIntToHex32(v) { return BigInt(v).toString(16).padStart(64, '0'); }

    function keccak(bytes) {
        if (typeof global.keccak256 !== 'function') {
            throw new Error('缺少 vendor/sha3.min.js，无法计算 keccak256');
        }
        return hexToBytes(global.keccak256(bytes));
    }

    function keccakText(text) { return keccak(utf8(text)); }

    // ---------------- SHA-256（用于派生盲化因子） ----------------
    function sha256(bytes) {
        return global.crypto.subtle.digest('SHA-256', bytes).then(function (buf) {
            return new Uint8Array(buf);
        });
    }

    // ---------------- Pedersen 承诺 ----------------
    /** r_i = SHA256(secret || ':' || i || ':' || n) mod N —— 与 Python 侧一致 */
    function deriveBlinding(secret, index, count) {
        var material = utf8(String(secret) + ':' + index + ':' + count);
        return sha256(material).then(function (digest) {
            return mod(BigInt('0x' + bytesToHex(digest)), N);
        });
    }

    function commitPoint(value, blinding) {
        var c = pointAdd(pointMul(G, BigInt(value)), pointMul(H, blinding));
        if (!c) throw new Error('承诺点无穷远');
        return c;
    }

    function serializePoint(point) {
        return bigIntToHex32(point.x) + bigIntToHex32(point.y);
    }

    function deserializePoint(hex) {
        var s = String(hex);
        if (s.length !== 128) return null;
        return { x: BigInt('0x' + s.slice(0, 64)), y: BigInt('0x' + s.slice(64)) };
    }

    /** 点是否落在 y² = x³ + 3 上（用于拒绝伪造/畸形承诺点） */
    function isOnCurve(point) {
        if (!point) return false;
        if (point.x < 0n || point.x >= P || point.y < 0n || point.y >= P) return false;
        return mod(point.y * point.y - (point.x * point.x * point.x + 3n), P) === 0n;
    }

    // ---------------- ABI 编码（spec.md R1/R5） ----------------
    /**
     * keccak256(abi.encode(TAG_COMMITMENT, votingId, voter, scores, secret, maxScore))
     * 手工编码，避免依赖 ethers/web3，保证与 Python eth_abi.encode 一致。
     */
    function commitmentHash(votingId, voter, scores, secret, maxScore) {
        var TAG = keccakText('ZK-SealedWeigh.commitment.v3');
        var count = scores.length;
        var scoresTail = count * 32;

        var offsetScores = 6 * 32;                       // 头部 6 槽
        var offsetSecret = offsetScores + 32 + scoresTail;

        var head = concatBytes(
            TAG,
            uint256Bytes(votingId),
            addressWord(voter),                          // address 左填充到 32 字节
            uint256Bytes(offsetScores),
            uint256Bytes(offsetSecret),
            uint256Bytes(maxScore)
        );

        var scoresEncoded = concatBytes(uint256Bytes(count));
        for (var i = 0; i < count; i++) scoresEncoded = concatBytes(scoresEncoded, uint256Bytes(scores[i]));

        var secretBytes = utf8(secret);
        var padded = new Uint8Array(Math.ceil(secretBytes.length / 32) * 32);
        padded.set(secretBytes);
        var secretEncoded = concatBytes(uint256Bytes(secretBytes.length), padded);

        return keccak(concatBytes(head, scoresEncoded, secretEncoded));
    }

    /** keccak256(abi.encode(TAG_REVEAL_SIG, votingId, voter, scores, nullifier)) */
    function revealDigest(votingId, voter, scores, nullifier) {
        var TAG = keccakText('ZK-SealedWeigh.sig.reveal.v3');
        var count = scores.length;

        var head = concatBytes(
            TAG,
            uint256Bytes(votingId),
            addressWord(voter),
            uint256Bytes(5 * 32),                        // scores 偏移：5 个头部槽（含 bytes32 nullifier）
            bytes32Word(nullifier)                       // 静态项全部在头部
        );

        var body = concatBytes(uint256Bytes(count));
        for (var i = 0; i < count; i++) body = concatBytes(body, uint256Bytes(scores[i]));
        return keccak(concatBytes(head, body));
    }

    /** keccak256(abi.encode(TAG_RANGE_SIG, votingId, voter, commitment)) */
    function rangeDigest(votingId, voter, commitment) {
        var TAG = keccakText('ZK-SealedWeigh.sig.range.v3');
        return keccak(concatBytes(
            TAG,
            uint256Bytes(votingId),
            addressWord(voter),
            uint256Bytes(commitment)
        ));
    }

    // ---------------- Groth16 范围证明（在浏览器本地生成） ----------------
    // 证明构件由 circuits 目录产出后拷贝到 vendor/zk；服务端永远看不到明文分数。
    var RANGE_PROOF_WASM = 'vendor/zk/range_proof.wasm';
    var RANGE_PROOF_ZKEY = 'vendor/zk/range_proof.zkey';
    var RANGE_PROOF_SIZE = 3;   // 电路按 3 个候选人编译，少于 3 个用 0 补齐（与合约 rangeHash 一致）

    /** 31 字节随机数 ⇒ BN254 标量域元素，作为 Poseidon 承诺的盲化因子 */
    function randomSalt() {
        var buf = new Uint8Array(31);
        global.crypto.getRandomValues(buf);
        return mod(BigInt('0x' + bytesToHex(buf)), N).toString();
    }

    function paddedScores(scores) {
        var out = [];
        for (var i = 0; i < RANGE_PROOF_SIZE; i++) {
            out.push(i < scores.length ? Number(scores[i]) : 0);
        }
        return out;
    }

    /**
     * 生成 { commitment, maxScore, proof:{a,b,c} }
     * commitment = Poseidon(scores‖0…, salt, voter)，与合约 rangeHash 完全一致。
     */
    function generateRangeProof(opts) {
        if (!global.snarkjs || !global.snarkjs.groth16) {
            return Promise.reject(new Error('范围证明库未加载（vendor/zk/snarkjs.min.js）'));
        }
        if (opts.scores.length > RANGE_PROOF_SIZE) {
            return Promise.reject(new Error('当前电路最多支持 ' + RANGE_PROOF_SIZE + ' 个候选人'));
        }

        var input = {
            scores: paddedScores(opts.scores),
            salt: String(opts.salt),
            voter: BigInt(String(opts.voter)).toString(),
            maxScore: Number(opts.maxScore)
        };

        return global.snarkjs.groth16
            .fullProve(input, RANGE_PROOF_WASM, RANGE_PROOF_ZKEY)
            .then(function (res) {
                return global.snarkjs.groth16
                    .exportSolidityCallData(res.proof, res.publicSignals)
                    .then(function (calldata) {
                        var parts = JSON.parse('[' + calldata + ']');
                        return {
                            commitment: res.publicSignals[0],
                            maxScore: res.publicSignals[1],
                            proof: { a: parts[0], b: parts[1], c: parts[2] },
                            publicSignals: res.publicSignals
                        };
                    });
            });
    }

    // ---------------- 对外 API ----------------
    var ZKCrypto = {
        // 曲线与常量
        CURVE_NAME: 'alt_bn128',
        CURVE: { P: P, N: N, G: G, H: H },
        RANGE_PROOF_SIZE: RANGE_PROOF_SIZE,

        // 原语
        mod: mod,
        pointAdd: pointAdd,
        pointMul: pointMul,
        isOnCurve: isOnCurve,
        keccak: keccak,
        keccakText: keccakText,
        bytesToHex: bytesToHex,
        hexToBytes: hexToBytes,
        utf8: utf8,
        serializePoint: serializePoint,
        deserializePoint: deserializePoint,
        commitmentHash: commitmentHash,
        revealDigest: revealDigest,
        rangeDigest: rangeDigest,
        deriveBlinding: deriveBlinding,
        randomSalt: randomSalt,
        generateRangeProof: generateRangeProof,

        /**
         * 在本地生成承诺：返回 { commitments: [128hex...], commitmentHash: '0x…' }
         * 明文分数与 secret 不离开浏览器（spec.md 第 6 节）。
         */
        buildCommitments: function (opts) {
            var scores = opts.scores.map(Number);
            var secret = String(opts.secret);
            var count = scores.length;
            var chain = [];

            for (var i = 0; i < count; i++) {
                chain.push(deriveBlinding(secret, i, count).then(function (r) {
                    return { r: r };
                }));
            }

            return Promise.all(chain).then(function (blinds) {
                var commitments = [];
                for (var i = 0; i < count; i++) {
                    var point = commitPoint(scores[i], blinds[i].r);
                    commitments.push(serializePoint(point));
                }
                return {
                    commitments: commitments,
                    commitmentHash:
                        '0x' + bytesToHex(commitmentHash(opts.votingId, opts.voter, scores, secret, opts.maxScore))
                };
            });
        },

        /** 揭晓期本地校验：C_i 是否真的对应 (scores, secret) */
        verifyCommitments: function (opts) {
            var scores = opts.scores.map(Number);
            var secret = String(opts.secret);
            var count = scores.length;
            var tasks = [];
            for (var i = 0; i < count; i++) {
                (function (idx) {
                    tasks.push(deriveBlinding(secret, idx, count).then(function (r) {
                        var expected = serializePoint(commitPoint(scores[idx], r));
                        var actual = String(opts.commitments[idx] || '').toLowerCase();
                        return expected === actual;
                    }));
                })(i);
            }
            return Promise.all(tasks).then(function (results) {
                return results.every(Boolean);
            });
        }
    };

    global.ZKCrypto = ZKCrypto;
})(window);
