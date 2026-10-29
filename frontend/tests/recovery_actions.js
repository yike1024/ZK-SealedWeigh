/**
 * P3.3 客户端动作：份额转发（share）与本地重构（recover）。
 *
 * 用法：node frontend/tests/recovery_actions.js share|recover < input.json
 *
 * share 输入：
 *   { votingId, requestId, requesterWallet, trusteeWallet,
 *     trusteePrivateJwk, enrollmentEnvelope, requesterPublicKey }
 * share 输出：
 *   { envelope, message }     // message 由评委钱包签名后提交到 sharebox
 *
 * recover 输入：
 *   { votingId, requesterWallet, requesterPrivateJwk, escrow,
 *     shares: [{ fromWallet, envelope }] }
 * recover 输出：
 *   { recovered }             // 明文只出现在本地标准输出，不经过服务器
 */
const RC = require('../recovery-crypto.js');
const { canonicalJson, sha256Hex } = require('./test-utils.js');

async function doShare(input) {
    const privateKey = await RC.importPrivateKey(input.trusteePrivateJwk);

    // 1. 解开请求者当初发给我的那份份额
    const share = await RC.unwrapShare(input.enrollmentEnvelope, privateKey, {
        votingId: input.votingId,
        from: input.requesterWallet,
        to: input.trusteeWallet
    });

    // 2. 按请求者的公钥重新加密（只有请求者能解开）
    const envelope = await RC.wrapShareFor(share, input.requesterPublicKey, {
        votingId: input.votingId,
        from: input.trusteeWallet,
        to: input.requesterWallet
    });

    const message = canonicalJson({
        schema: 'ZK-SealedWeigh.recovery.share.v1',
        requestId: Number(input.requestId),
        votingId: Number(input.votingId),
        from: input.trusteeWallet,
        to: input.requesterWallet,
        envelopeHash: await sha256Hex(canonicalJson(envelope))
    });

    return { envelope, message };
}

async function doRecover(input) {
    const privateKey = await RC.importPrivateKey(input.requesterPrivateJwk);

    const shares = [];
    for (const item of input.shares) {
        shares.push(await RC.unwrapShare(item.envelope, privateKey, {
            votingId: input.votingId,
            from: item.fromWallet,
            to: input.requesterWallet
        }));
    }

    const masterKey = RC.combineShares(shares);
    const recovered = await RC.decryptEscrow(input.escrow, masterKey, {
        votingId: input.votingId,
        voter: input.requesterWallet
    });

    return { recovered };
}

async function main() {
    const mode = process.argv[2];
    let raw = '';
    process.stdin.setEncoding('utf8');
    for await (const chunk of process.stdin) raw += chunk;
    const input = JSON.parse(raw || '{}');

    let output;
    if (mode === 'share') {
        output = await doShare(input);
    } else if (mode === 'recover') {
        output = await doRecover(input);
    } else {
        throw new Error('用法: node recovery_actions.js share|recover');
    }
    process.stdout.write(JSON.stringify(output));
}

main().catch((error) => {
    process.stderr.write('recovery_actions failed: ' + error.message + '\n');
    process.exit(1);
});
