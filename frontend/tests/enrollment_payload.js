/**
 * P3.2 enrollment 载荷生成器（测试与前端接入共用同一套密码学）
 *
 * 从 stdin 读取 JSON：
 *   {
 *     "votingId": 1,
 *     "threshold": 2,
 *     "enrollingUserId": 2,
 *     "voters": [ {"userId": 2, "wallet": "0x..."}, ... ],
 *     "payload": {"scores": [7,9,0], "secret": "...", "salt": "..."}
 *   }
 *
 * 输出 JSON（stdout 只有 JSON，便于 Python 调用）：
 *   {
 *     "keyPublications": [ {"userId", "publicKey", "message"}, ... ],
 *     "enrollment": {
 *        "votingId", "escrow", "envelopes", "manifest", "manifestMessage"
 *     }
 *   }
 *
 * 注意：manifest 与服务器端 Python 必须使用同一套规范序列化
 * （递归排序键 + 紧凑分隔符 + UTF-8）。这里的 canonicalJson 就是唯一实现。
 */
const RC = require('../recovery-crypto.js');
const { canonicalJson, sha256Hex } = require('./test-utils.js');

async function build(input) {
    const voters = input.voters;
    const threshold = Number(input.threshold);
    const votingId = Number(input.votingId);
    const enrolling = voters.find((v) => v.userId === input.enrollingUserId);

    if (!enrolling) throw new Error('enrollingUserId 不在 voters 列表中');

    // 份额只发给**其他**评委：自己丢掉浏览器时，自己的那份也一起丢了，留给自己没有恢复意义。
    const recipients = voters.filter((v) => v.userId !== enrolling.userId);
    if (recipients.length === 0) throw new Error('活动至少需要两位评委才能做门限恢复');
    if (!(threshold >= 1 && threshold <= recipients.length)) {
        throw new Error('threshold 必须满足 1 ≤ k ≤ n（n = 其他评委数）');
    }

    // 1. 每个评委生成 ECDH P-256 长期公钥（私钥由上层加密后持久化）
    const keyPairs = [];
    const publicKeys = [];
    const keyPublications = [];
    for (const voter of voters) {
        const pair = await RC.generateKeyPair();
        const publicKey = await RC.exportPublicKey(pair.publicKey);
        keyPairs.push(pair);
        publicKeys.push(publicKey);
        keyPublications.push({
            userId: voter.userId,
            publicKey,
            message: `ZK-SealedWeigh.recovery.key.v1|${voter.userId}|${publicKey}`
        });
    }

    // 2. 丢失方生成主密钥 + 托管密文，并拆成 n 份（n = 其他评委数）
    const masterKey = RC.randomBytes(RC.MASTER_KEY_BYTES);
    const escrow = await RC.encryptEscrow(input.payload, masterKey, {
        votingId, voter: enrolling.wallet
    });
    const shares = RC.splitSecret(masterKey, threshold, recipients.length);

    // 3. 每一份加密给对应评委（顺序与 recipients 一一对应）
    const envelopes = [];
    for (let i = 0; i < recipients.length; i++) {
        const index = voters.findIndex((v) => v.userId === recipients[i].userId);
        envelopes.push(await RC.wrapShareFor(shares[i], publicKeys[index], {
            votingId, from: enrolling.wallet, to: recipients[i].wallet
        }));
    }

    // 4. 签名清单：只含哈希与公开参数，绝不含明文
    const manifest = {
        schema: 'ZK-SealedWeigh.recovery.manifest.v1',
        votingId,
        voter: enrolling.wallet,
        threshold,
        escrowHash: await sha256Hex(canonicalJson(escrow)),
        recipients: recipients.map((v) => v.userId),
        envelopeHashes: await Promise.all(
            envelopes.map(async (env) => sha256Hex(canonicalJson(env))))
    };

    return {
        keyPublications,
        // 仅测试用：生产环境私钥必须由上层用钱包派生密钥加密后再持久化
        privateKeys: Object.fromEntries(await Promise.all(voters.map(async (voter, index) => [
            voter.userId, await RC.exportPrivateKey(keyPairs[index].privateKey)
        ]))),
        enrollment: {
            votingId,
            escrow,
            envelopes,
            manifest,
            manifestMessage: canonicalJson(manifest)
        }
    };
}

async function main() {
    let raw = '';
    process.stdin.setEncoding('utf8');
    for await (const chunk of process.stdin) raw += chunk;
    const input = JSON.parse(raw || '{}');
    const output = await build(input);
    process.stdout.write(JSON.stringify(output));
}

main().catch((error) => {
    process.stderr.write('enrollment_payload failed: ' + error.message + '\n');
    process.exit(1);
});
