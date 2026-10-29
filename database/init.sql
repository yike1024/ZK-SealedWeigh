-- 零知识密封加权评审系统（ZK-SealedWeigh）数据库初始化脚本
-- 用法：sqlcmd -S "tcp:localhost,1433" -U sa -P <密码> -i database\init.sql
-- 说明：每张表用 GO 拆成独立批处理，避免某条语句报错中断后续所有语句。

IF DB_ID('ZKVotingSystem') IS NULL
    CREATE DATABASE ZKVotingSystem;
GO

USE ZKVotingSystem;
GO

-- ============ 用户表 ============
CREATE TABLE users (
    id INT IDENTITY(1,1) PRIMARY KEY,
    username NVARCHAR(50) NOT NULL UNIQUE,
    email NVARCHAR(100) NOT NULL UNIQUE,
    password_hash NVARCHAR(255) NOT NULL,
    role NVARCHAR(20) NOT NULL CHECK (role IN ('voter', 'publisher')),
    wallet_address NVARCHAR(42) NULL,
    is_test_account BIT NOT NULL DEFAULT 0,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    updated_at DATETIME2 NULL
);
GO

-- ============ 投票活动表 ============
CREATE TABLE voting_sessions (
    id INT IDENTITY(1,1) PRIMARY KEY,
    title NVARCHAR(200) NOT NULL,
    description NVARCHAR(MAX) NULL,
    creator_id INT NOT NULL FOREIGN KEY REFERENCES users(id),
    max_score INT NOT NULL DEFAULT 10,
    weight_type NVARCHAR(20) NOT NULL DEFAULT 'equal',
    commit_duration INT NOT NULL DEFAULT 24,
    score_duration INT NOT NULL DEFAULT 48,
    enable_zk_proof BIT NOT NULL DEFAULT 1,
    scoring_rules NVARCHAR(MAX) NULL,
    blockchain_id INT NULL,
    phase NVARCHAR(20) NOT NULL CHECK (phase IN ('commit', 'scoring', 'completed', 'cancelled')),
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    updated_at DATETIME2 NULL
);
GO

-- ============ 候选人表 ============
CREATE TABLE candidates (
    id INT IDENTITY(1,1) PRIMARY KEY,
    voting_id INT NOT NULL,
    name NVARCHAR(100) NOT NULL,
    order_index INT NOT NULL,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    FOREIGN KEY (voting_id) REFERENCES voting_sessions(id) ON DELETE CASCADE
);
GO

-- ============ 投票者表（含权重）============
CREATE TABLE voting_voters (
    id INT IDENTITY(1,1) PRIMARY KEY,
    voting_id INT NOT NULL,
    voter_id INT NOT NULL,
    weight FLOAT NOT NULL DEFAULT 1.0,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    updated_at DATETIME2 NULL,
    FOREIGN KEY (voting_id) REFERENCES voting_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (voter_id) REFERENCES users(id),
    UNIQUE (voting_id, voter_id)
);
GO

-- ============ 承诺表（仅 Pedersen）============
-- v2 密封契约（spec.md 第 6 节）：数据库只保存承诺点与承诺哈希。
-- 明文分数、secret、盲化因子一律不入库 —— 它们只存在于评委浏览器本地。
CREATE TABLE voting_commitments (
    id INT IDENTITY(1,1) PRIMARY KEY,
    voting_id INT NOT NULL,
    voter_id INT NOT NULL,
    commitment_hash NVARCHAR(255) NOT NULL,
    commitments NVARCHAR(MAX) NOT NULL,
    commitment_type NVARCHAR(20) NOT NULL DEFAULT 'pedersen' CHECK (commitment_type = 'pedersen'),
    blockchain_success BIT NOT NULL DEFAULT 0,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    FOREIGN KEY (voting_id) REFERENCES voting_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (voter_id) REFERENCES users(id),
    UNIQUE (voting_id, voter_id)
);
GO

-- ============ 评分表 ============
CREATE TABLE voting_scores (
    id INT IDENTITY(1,1) PRIMARY KEY,
    voting_id INT NOT NULL,
    voter_id INT NOT NULL,
    candidate_id INT NOT NULL,
    score INT NOT NULL,
    weight FLOAT NOT NULL DEFAULT 1.0,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    FOREIGN KEY (voting_id) REFERENCES voting_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (voter_id) REFERENCES users(id),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    UNIQUE (voting_id, voter_id, candidate_id)
);
GO

-- ============ Pedersen 曲线参数表 ============
CREATE TABLE pedersen_parameters (
    id INT IDENTITY(1,1) PRIMARY KEY,
    parameter_name NVARCHAR(100) UNIQUE NOT NULL,
    generator_x NVARCHAR(255) NOT NULL,
    generator_y NVARCHAR(255) NOT NULL,
    h_generator_x NVARCHAR(255) NOT NULL,
    h_generator_y NVARCHAR(255) NOT NULL,
    prime_modulus NVARCHAR(255) NOT NULL,
    curve_order NVARCHAR(255) NOT NULL,
    is_active BIT NOT NULL DEFAULT 1,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    description NVARCHAR(500) NULL
);
GO

-- ============ 门限恢复：评委公钥与密文清单（P3.2）============
-- 服务器只保存密文：escrow 是评委本地载荷的 AES-GCM 密文，
-- envelopes 是 Shamir 份额逐个加密给其他评委的密文。二者都不含明文分数/密码/salt。
IF OBJECT_ID('recovery_keys', 'U') IS NULL
BEGIN
    CREATE TABLE recovery_keys (
        id INT IDENTITY(1,1) PRIMARY KEY,
        user_id INT NOT NULL UNIQUE REFERENCES users(id),
        public_key NVARCHAR(256) NOT NULL,
        signature NVARCHAR(200) NOT NULL,
        created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME2 NULL
    );
END
GO

IF OBJECT_ID('recovery_enrollments', 'U') IS NULL
BEGIN
    CREATE TABLE recovery_enrollments (
        id INT IDENTITY(1,1) PRIMARY KEY,
        voting_id INT NOT NULL REFERENCES voting_sessions(id) ON DELETE CASCADE,
        voter_id INT NOT NULL REFERENCES users(id),
        threshold INT NOT NULL,
        escrow NVARCHAR(MAX) NOT NULL,
        envelopes NVARCHAR(MAX) NOT NULL,
        manifest NVARCHAR(MAX) NOT NULL,
        manifest_signature NVARCHAR(200) NOT NULL,
        created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME2 NULL,
        CONSTRAINT UQ_recovery_enrollment UNIQUE (voting_id, voter_id)
    );
END
GO

-- ============ 门限恢复：恢复请求与密文份额（P3.3）============
-- 服务器同样只保存密文；份额由其他评委解密后重新加密给请求者，服务器无法解开。
IF OBJECT_ID('recovery_requests', 'U') IS NULL
BEGIN
    CREATE TABLE recovery_requests (
        id INT IDENTITY(1,1) PRIMARY KEY,
        voting_id INT NOT NULL REFERENCES voting_sessions(id) ON DELETE CASCADE,
        voter_id INT NOT NULL REFERENCES users(id),
        threshold INT NOT NULL,
        status NVARCHAR(20) NOT NULL DEFAULT 'open'
            CHECK (status IN ('open', 'collected', 'cancelled')),
        created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        updated_at DATETIME2 NULL,
        CONSTRAINT UQ_recovery_request UNIQUE (voting_id, voter_id)
    );
END
GO

IF OBJECT_ID('recovery_shares', 'U') IS NULL
BEGIN
    CREATE TABLE recovery_shares (
        id INT IDENTITY(1,1) PRIMARY KEY,
        request_id INT NOT NULL REFERENCES recovery_requests(id),
        from_voter_id INT NOT NULL REFERENCES users(id),
        envelope NVARCHAR(MAX) NOT NULL,
        message NVARCHAR(MAX) NOT NULL,
        signature NVARCHAR(200) NOT NULL,
        created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
        CONSTRAINT UQ_recovery_share UNIQUE (request_id, from_voter_id)
    );
END
GO

-- ============ 种子数据：Pedersen 参数（alt_bn128 / BN254，协议 v3）============
-- 换曲线的唯一原因：EVM 只为 alt_bn128 提供 ecAdd/ecMul 预编译（EIP-196/197），
-- 链上才能真正验证 C = v·G + r·H；secp256k1 在链上无法经济地验算。
-- H = hash_to_point(sha256("ZK-SealedWeigh.Pedersen.H.v3" || counter))，counter=2（NUMS）
INSERT INTO pedersen_parameters
    (parameter_name, generator_x, generator_y, h_generator_x, h_generator_y,
     prime_modulus, curve_order, description)
VALUES
    ('alt_bn128',
     '1',
     '2',
     '16139254226949296955864123352546410254086001627506180211472043396790745768897',
     '4198662241582192156483318552039300890084634087347638369833980459110414988790',
     '21888242871839275222246405745257275088696311157297823662689037894645226208583',
     '21888242871839275222246405745257275088548364400416034343698204186575808495617',
     'alt_bn128 (BN254), y^2 = x^3 + 3 - EIP-196/197 verifiable on-chain');
GO

-- ============ 种子数据：用户 ============
-- 四个账号口令相同，均为 bcrypt 哈希（首次登录后可自行修改）
-- voter3 用于多评委门限恢复压力测试（3 评委 k=2），对应 Hardhat 第 4 个账户
INSERT INTO users (username, email, password_hash, role, wallet_address) VALUES
    ('admin',  'admin@zkvoting.com',  '$2b$12$qWuErsjweyS7sKuh.AaaZO6E1pLqGYQIFivdccNHe6pemXBhTljXO', 'publisher', '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'),
    ('voter1', 'voter1@zkvoting.com', '$2b$12$qWuErsjweyS7sKuh.AaaZO6E1pLqGYQIFivdccNHe6pemXBhTljXO', 'voter',     '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'),
    ('voter2', 'voter2@zkvoting.com', '$2b$12$qWuErsjweyS7sKuh.AaaZO6E1pLqGYQIFivdccNHe6pemXBhTljXO', 'voter',     '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC'),
    ('voter3', 'voter3@zkvoting.com', '$2b$12$qWuErsjweyS7sKuh.AaaZO6E1pLqGYQIFivdccNHe6pemXBhTljXO', 'voter',     '0x90F79bf6EB2c4f870365E785982E1f101E93b906');
GO

-- ============ 种子数据：一个示例评审活动 ============
INSERT INTO voting_sessions
    (title, description, creator_id, max_score, weight_type, commit_duration, score_duration, enable_zk_proof, phase)
VALUES
    ('示例评审活动', '用 Pedersen 承诺做密封加权评审的示例', 1, 10, 'equal', 24, 48, 1, 'commit');
GO

INSERT INTO candidates (voting_id, name, order_index) VALUES
    (1, '候选方案 A', 0),
    (1, '候选方案 B', 1),
    (1, '候选方案 C', 2);
GO

INSERT INTO voting_voters (voting_id, voter_id, weight) VALUES
    (1, 2, 1.0),
    (1, 3, 1.0);
GO

PRINT 'Database ZKVotingSystem created successfully with Pedersen commitments.';
GO
