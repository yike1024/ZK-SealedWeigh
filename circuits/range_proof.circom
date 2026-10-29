pragma circom 2.0.0;

/*
 * ScoreRangeProof —— 分数的范围证明（协议 P2.5）
 *
 * 目标：在不泄露任何分数的前提下，向链上证明
 *   (1) 每位候选人的分数都在 [0, maxScore] 内；
 *   (2) 这组分数与一个公开的 Poseidon 承诺绑定。
 *
 * 为什么这样设计
 * --------------
 * 阶段一（commit）链上只有 Pedersen 承诺点 C_i = v_i·G + r_i·H，评委不能公开 v_i。
 * 若要在链上直接证明「C_i 里的 v_i 在范围内」，电路内必须做椭圆曲线标量乘
 * （v_i·G + r_i·H），约束数会膨胀到数万，本地可信设置成本很高。
 *
 * 因此这里采用**双承诺 + 绑定**的结构：
 *   · Pedersen 承诺 C_i  —— 负责隐藏（信息论隐藏，链上可重算校验）
 *   · Poseidon 承诺 H    —— 负责把「范围已证明的分数向量」钉在链上
 * 揭晓时提交 (scores, salt)，链上重算 Poseidon 并与阶段一存的 commitment 比对，
 * 于是「揭晓的分数 ∈ 范围」由这份证明背书，而 Pedersen 保证分数没被改过。
 *
 * 安全性要点
 * ----------
 *   · Num2Bits(8) 不只是取位——它还强制 scores[i] < 2^8 且等于各位重构值，
 *     否则恶意的域元素（如 p-1）会让 LessEqThan 比较结果失去意义（可靠性问题）。
 *   · salt 必须保密且足够随机；否则小范围分数可被枚举（字典攻击）。
 */

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

template ScoreRangeProof(n) {
    // 私有输入：分数向量、盐、评委地址
    signal input scores[n];
    signal input salt;
    // voter 作为**私有**输入参与哈希：
    // 证明本身不暴露地址，但承诺值隐含了它，因此他人无法把自己的承诺套用别人的证明
    // （合约在揭晓时用真实 voter 重算 Poseidon，对不上即失败）。
    signal input voter;

    // 满分：作为输入传入，并透传为**输出**（输出天然是公开信号）。
    // 这样可防止把一个 maxScore=100 的证明复用到 maxScore=10 的活动。
    signal input maxScore;

    // 公开输出：Poseidon 承诺（链上比对用）——声明在前，故 publicSignals[0] = commitment
    signal output commitment;
    signal output maxScoreOut;

    // ---------- 1) 范围约束：0 <= scores[i] <= maxScore ----------
    component bits[n];
    component leq[n];
    for (var i = 0; i < n; i++) {
        // 强制为 8 bit 无符号整数（同时完成重构校验，消除域元素歧义）
        bits[i] = Num2Bits(8);
        bits[i].in <== scores[i];

        // scores[i] <= maxScore
        leq[i] = LessEqThan(8);
        leq[i].in[0] <== scores[i];
        leq[i].in[1] <== maxScore;
        leq[i].out === 1;
    }

    // ---------- 2) 承诺绑定：commitment = Poseidon(scores, salt, voter) ----------
    // 注意：maxScore 不作为哈希输入——它由公开信号单独绑定即可，避免与链上 rangeHash 不一致
    component hash = Poseidon(n + 2);
    for (var i = 0; i < n; i++) {
        hash.inputs[i] <== scores[i];
    }
    hash.inputs[n] <== salt;
    hash.inputs[n + 1] <== voter;
    commitment <== hash.out;

    // 把满分透传到公开信号（放在最后，公开信号顺序 = [commitment, maxScoreOut]）
    maxScoreOut <== maxScore;
}

// 演示参数：3 位候选人（不足 3 位时由链上补 0；多于 3 位需重新编译电路）
component main = ScoreRangeProof(3);
