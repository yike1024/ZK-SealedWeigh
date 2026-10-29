// ZK工具库 - 前端API调用工具（修复钱包问题版本）
class ZKUtils {
    static baseURL = 'http://127.0.0.1:5000/api';

    // 设置认证token
    static setAuthToken(token) {
        localStorage.setItem('authToken', token);
        console.log('Token已存储到localStorage');
    }

    // 获取认证token
    static getAuthToken() {
        const token = localStorage.getItem('authToken');
        return token;
    }

    // 移除认证token
    static removeAuthToken() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('userInfo'); // 同时清除用户信息
        console.log('Token已从localStorage移除');
    }

    // 检查登录状态
    static isLoggedIn() {
        const hasToken = !!this.getAuthToken();
        console.log('登录状态检查:', hasToken ? '已登录' : '未登录');
        return hasToken;
    }

    // 修复的登录函数 - 增强版本
    static async login(username, password) {
        try {
            console.log('开始登录流程...');

            const response = await fetch(`${this.baseURL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            });

            console.log('登录响应状态:', response.status, response.statusText);

            if (!response.ok) {
                const errorText = await response.text();
                let errorData;
                try {
                    errorData = JSON.parse(errorText);
                } catch {
                    errorData = { message: errorText };
                }
                throw new Error(errorData.message || `登录失败: ${response.status}`);
            }

            const result = await response.json();
            console.log('登录响应数据:', result);

            if (result.success && result.data && result.data.token) {
                const token = result.data.token;
                console.log('获取到Token:', token.substring(0, 30) + '...');

                // 关键修复：确保 token 正确存储
                localStorage.setItem('authToken', token);
                console.log('Token已存储到localStorage');

                // 存储用户信息
                if (result.data.user) {
                    localStorage.setItem('userInfo', JSON.stringify(result.data.user));
                    console.log('用户信息已存储');
                }

                // 立即验证 token 是否存储成功
                const storedToken = localStorage.getItem('authToken');
                console.log('Token存储验证:', storedToken ? '成功' : '失败');
                console.log('存储的Token长度:', storedToken ? storedToken.length : 0);

                if (!storedToken) {
                    console.error('Token存储失败!');
                    throw new Error('Token存储失败');
                }

                console.log('登录流程完成');
                return result;
            } else {
                throw new Error(result.message || '登录响应格式错误');
            }
        } catch (error) {
            console.error('登录请求失败:', error);
            throw error;
        }
    }

    // 修复的 API 调用函数 - 增强认证处理
    static async apiCall(endpoint, options = {}) {
        const token = this.getAuthToken();

        console.log(`API请求: ${options.method || 'GET'} ${endpoint}`);
        console.log(`Token状态:`, token ? `存在 (${token.substring(0, 20)}...)` : '不存在');

        const config = {
            method: options.method || 'GET',
            headers: {
                'Content-Type': 'application/json',
                ...(token && { 'Authorization': `Bearer ${token}` }),
                ...options.headers
            },
            mode: 'cors',
            credentials: 'include'
        };

        if (options.body && (options.method === 'POST' || options.method === 'PUT' || options.method === 'PATCH')) {
            config.body = JSON.stringify(options.body);
        }

        try {
            const fullUrl = `${this.baseURL}${endpoint}`;
            console.log(`请求URL: ${fullUrl}`);
            console.log(`请求头:`, {
                'Content-Type': config.headers['Content-Type'],
                'Authorization': config.headers['Authorization'] ? 'Bearer ***' : '未设置'
            });

            const response = await fetch(fullUrl, config);

            console.log(`响应状态: ${response.status} ${response.statusText}`);

            // 处理认证失败
            if (response.status === 401) {
                console.warn('认证失败，清除本地token');
                this.removeAuthToken();

                // 如果是获取当前用户信息失败，不跳转，避免循环
                if (!endpoint.includes('/auth/me')) {
                    setTimeout(() => {
                        if (window.location.pathname !== '/index.html' &&
                            !window.location.pathname.endsWith('/')) {
                            console.log('跳转到登录页面');
                            window.location.href = 'index.html';
                        }
                    }, 1000);
                }

                throw new Error('认证失败，请重新登录');
            }

            if (!response.ok) {
                let errorText;
                try {
                    const errorData = await response.json();
                    errorText = errorData.message || JSON.stringify(errorData);
                } catch {
                    errorText = await response.text();
                }

                const error = new Error(`HTTP ${response.status}: ${errorText}`);
                error.status = response.status;
                throw error;
            }

            const data = await response.json();
            console.log('API响应成功');
            return data;

        } catch (error) {
            console.error('API请求错误:', error);

            // 如果是认证错误且不是获取用户信息，跳转到登录页
            if (error.message.includes('认证失败') && !endpoint.includes('/auth/me')) {
                setTimeout(() => {
                    if (window.location.pathname !== '/index.html' &&
                        !window.location.pathname.endsWith('/')) {
                        console.log('因认证失败跳转到登录页面');
                        window.location.href = 'index.html';
                    }
                }, 1500);
            }

            throw error;
        }
    }

    // 用户认证API - 增强版本
    static async register(userData) {
        try {
            console.log('尝试注册:', userData.username);

            const result = await this.apiCall('/auth/register', {
                method: 'POST',
                body: userData
            });

            if (result.success) {
                console.log('注册成功');
                this.showNotification('注册成功！', 'success');
            } else {
                console.error('注册失败:', result.message);
                this.showNotification(result.message || '注册失败', 'error');
            }

            return result;
        } catch (error) {
            console.error('注册请求失败:', error);
            const errorMsg = this.handleError(error, '注册');
            this.showNotification(errorMsg, 'error');
            throw error;
        }
    }

    static async getWalletStatus() {
        try {
            const result = await this.apiCall('/auth/wallet/status');
            return result;
        } catch (error) {
            console.error('获取钱包状态失败:', error);
            return {
                success: false,
                data: {
                    has_wallet: false,
                    status: 'error',
                    message: error.message
                }
            };
        }
    }

    // 获取当前用户信息 - 增强错误处理
    static async getCurrentUser() {
        console.log('获取当前用户信息...');

        // 先检查本地是否有用户信息
        const cachedUser = localStorage.getItem('userInfo');
        if (cachedUser) {
            console.log('使用缓存的用户信息');
            try {
                const userData = JSON.parse(cachedUser);
                return { success: true, data: userData };
            } catch (e) {
                console.warn('缓存的用户信息解析失败，重新获取');
            }
        }

        try {
            const result = await this.apiCall('/auth/me');

            // 缓存用户信息
            if (result.success && result.data) {
                localStorage.setItem('userInfo', JSON.stringify(result.data));
            }

            return result;
        } catch (error) {
            console.error('获取用户信息失败:', error);

            // 如果是认证错误，清除本地数据
            if (error.message.includes('认证失败')) {
                this.removeAuthToken();
            }

            throw error;
        }
    }

    // 投票相关API
    static async createVoting(votingData) {
        try {
            console.log('创建投票活动:', votingData);

            const result = await this.apiCall('/voting/', {  // 注意这里的斜杠
                method: 'POST',
                body: votingData
            });

            if (result.success) {
                console.log('投票创建成功:', result.data);
                this.showNotification('投票活动创建成功！', 'success');
            } else {
                console.error('投票创建失败:', result.message);
                this.showNotification('创建失败: ' + result.message, 'error');
            }

            return result;
        } catch (error) {
            console.error('创建投票请求失败:', error);
            const errorMsg = this.handleError(error, '创建投票');
            this.showNotification(errorMsg, 'error');
            throw error;
        }
    }

    static async getVotings(myOnly = false) {
        // 必须带结尾斜杠：后端 /api/voting 会 308 重定向到 /api/voting/，
        // 而带 Authorization 的跨源请求遇到重定向时部分浏览器会直接判失败（net::ERR_FAILED）
        const endpoint = myOnly ? '/voting/?my=true' : '/voting/';
        console.log('获取投票列表:', endpoint);
        return await this.apiCall(endpoint);
    }


static async getVotingById(votingId) {
    console.log('获取投票详情:', votingId);

    // 验证投票ID
    if (!votingId || votingId === 'undefined' || votingId === 'null') {
        console.error('无效的投票ID:', votingId);
        // 返回错误而不是调用API
        return {
            success: false,
            message: '投票ID无效',
            data: null
        };
    }

    return await this.apiCall(`/voting/${votingId}`);
}

    static async updateVotingPhase(votingId, phase) {
        console.log('更新投票阶段:', { votingId, phase });
        return await this.apiCall(`/voting/${votingId}/phase`, {
            method: 'PUT',
            body: { phase }
        });
    }

    static async deleteVoting(votingId) {
        console.log('删除投票:', votingId);
        return await this.apiCall(`/voting/${votingId}`, {
            method: 'DELETE'
        });
    }

    // 承诺生成已移至浏览器本地（frontend/zk-crypto.js），此处不再提供
    // 任何把明文分数/secret 发往后端的入口（spec.md 第 6 节）。

    // SHA256哈希函数
    static async sha256(message) {
        // 使用现代浏览器的 crypto API
        if (window.crypto && window.crypto.subtle) {
            const msgUint8 = new TextEncoder().encode(message);
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
            // 备选方案：简单的哈希函数
            let hash = 0;
            for (let i = 0; i < message.length; i++) {
                const char = message.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            return Math.abs(hash).toString(16).padStart(64, '0');
        }
    }

    static async submitCommitment(votingId, commitmentData) {
        try {
            console.log('提交承诺:', { votingId, commitmentData });

            const result = await this.apiCall(`/voting/${votingId}/commitments`, {
                method: 'POST',
                body: commitmentData
            });

            if (result.success) {
                console.log('承诺提交成功');

                // 若后端返回待签名摘要，则用钱包签名并交由后端代发上链
                if (result.data && result.data.onchain) {
                    result.data.onchain_result = await this.completeOnchainStep(votingId, result.data.onchain);
                }

                this.showNotification('承诺提交成功！', 'success');
            } else {
                console.error('承诺提交失败:', result.message);
                this.showNotification(result.message || '承诺提交失败', 'error');
            }

            return result;
        } catch (error) {
            console.error('提交承诺请求失败:', error);
            const errorMsg = this.handleError(error, '提交承诺');
            this.showNotification(errorMsg, 'error');
            throw error;
        }
    }

    static async verifyCommitment(votingId, verificationData) {
        try {
            console.log('验证 Pedersen 承诺...');

            const result = await this.apiCall(`/voting/${votingId}/commitments/verify`, {
                method: 'POST',
                body: verificationData
            });

            // 验证通过后若后端返回揭示阶段的待签名摘要，则签名并代发上链
            // salt 是范围证明的盲化因子，合约揭晓时会用 rangeHash 比对 rangeCommitments
            if (result && result.data && result.data.onchain) {
                result.data.onchain_result = await this.completeOnchainStep(
                    votingId, result.data.onchain, { salt: verificationData.salt });
            }

            return result;
        } catch (error) {
            console.error('验证 Pedersen 承诺失败:', error);
            throw error;
        }
    }

    // ==================== 链上签名 / 代发 ====================

    /**
     * 对后端提供的 32 字节摘要做 EIP-191 签名（与合约 _verifyVoterSig 一致）
     * 直接使用 window.ethereum，避免被 zk-wallet.js 覆盖 wallet 对象后失效
     */
    static async signDigest(digest) {
        const provider = (this.wallet && typeof this.wallet.getEthereumProvider === 'function')
            ? this.wallet.getEthereumProvider()
            : (typeof window !== 'undefined' ? window.ethereum : null);

        if (!provider) {
            throw new Error('未检测到以太坊钱包，无法完成链上签名');
        }

        const accounts = await provider.request({ method: 'eth_accounts' });
        if (!accounts || accounts.length === 0) {
            throw new Error('钱包未连接，请先连接钱包后再提交');
        }

        const signature = await provider.request({
            method: 'personal_sign',
            params: [digest, accounts[0]]
        });

        return { success: true, signature, address: accounts[0] };
    }

    /** 把签名结果交给后端 relayer 代发到链上；extra 用于附带 salt / 范围证明等动作参数 */
    static async relayOnChain(votingId, action, digest, signature, extra) {
        const body = Object.assign({ action, digest, signature }, extra || {});
        return await this.apiCall(`/voting/${votingId}/onchain/relay`, {
            method: 'POST',
            body
        });
    }

    /** 提交浏览器本地生成的范围证明（Groth16），签名绑定 commitment 后由 relayer 代发 */
    static async submitRangeProof(votingId, commitment, proof, digest, signature) {
        return await this.relayOnChain(votingId, 'range', digest, signature, { commitment, proof });
    }

    /** 完成一次链上代发（签名 -> relay），失败不影响后端已完成的 DB 流程 */
    static async completeOnchainStep(votingId, onchain, extra) {
        if (!onchain || !onchain.digest) {
            return { attempted: false };
        }
        try {
            const signed = await this.signDigest(onchain.digest);
            const relay = await this.relayOnChain(votingId, onchain.action, onchain.digest, signed.signature, extra);
            const ok = !!(relay && relay.success);
            if (ok) {
                this.showNotification('链上上链成功', 'success');
            } else {
                this.showNotification('链上代发失败：' + ((relay && relay.message) || '未知错误'), 'warning');
            }
            return { attempted: true, success: ok, relay };
        } catch (error) {
            console.warn('链上代发未完成:', error);
            this.showNotification('链上代发未完成：' + error.message, 'warning');
            return { attempted: true, success: false, error: error.message };
        }
    }

    static async getMyCommitment(votingId) {
        console.log('获取我的承诺:', votingId);
        return await this.apiCall(`/voting/${votingId}/commitments/my`);
    }

    // 调试承诺计算
    static async debugCommitmentCalculation(scores, secret, maxScore) {
        try {
            const debugResults = {};

            // 格式1: 标准对象格式（与后端一致）
            const commitmentData1 = {
                scores: scores,
                secret: secret,
                max_score: maxScore
            };
            const commitmentStr1 = JSON.stringify(commitmentData1, null, 0);
            const hash1 = await this.sha256(commitmentStr1);
            debugResults.standard_object = {
                data: commitmentData1,
                json: commitmentStr1,
                hash: `0x${hash1}`
            };

            // 格式2: 带排序的格式
            const commitmentData2 = {
                scores: scores,
                secret: secret,
                max_score: maxScore
            };
            const commitmentStr2 = JSON.stringify(commitmentData2, Object.keys(commitmentData2).sort());
            const hash2 = await this.sha256(commitmentStr2);
            debugResults.sorted_keys = {
                data: commitmentData2,
                json: commitmentStr2,
                hash: `0x${hash2}`
            };

            // 格式3: 紧凑格式
            const commitmentData3 = {
                scores: scores,
                secret: secret,
                max_score: maxScore
            };
            const commitmentStr3 = JSON.stringify(commitmentData3);
            const hash3 = await this.sha256(commitmentStr3);
            debugResults.compact = {
                data: commitmentData3,
                json: commitmentStr3,
                hash: `0x${hash3}`
            };

            return debugResults;
        } catch (error) {
            console.error('调试承诺计算失败:', error);
            throw error;
        }
    }

    // 评分相关API
    static async submitScore(scoreData) {
        console.log('提交评分:', scoreData);
        return await this.apiCall('/scores', {
            method: 'POST',
            body: scoreData
        });
    }

    static async submitBatchScores(scoresData) {
        console.log('批量提交评分:', scoresData);
        return await this.apiCall('/scores/batch', {
            method: 'POST',
            body: scoresData
        });
    }

    static async getVotingResults(votingId) {
        console.log('获取投票结果:', votingId);
        return await this.apiCall(`/voting/${votingId}/results`);
    }

    // 权重相关API
    static async getVotingWeights(votingId) {
        console.log('获取投票权重:', votingId);
        return await this.apiCall(`/weights/voting/${votingId}/weights`);
    }

    static async updateVoterWeight(votingId, voterId, weight) {
        console.log('更新投票者权重:', { votingId, voterId, weight });
        return await this.apiCall(`/weights/voting/${votingId}/voter/${voterId}`, {
            method: 'PUT',
            body: { weight }
        });
    }

    static async updateBatchWeights(votingId, updates) {
        console.log('批量更新权重:', { votingId, updates });
        return await this.apiCall(`/weights/voting/${votingId}/batch-weights`, {
            method: 'PUT',
            body: updates
        });
    }

    // 中断恢复：协议 v2 起停用（不存在单方代他人写分的入口）
    static async recoverMissingScores(recoveryData) {
        console.warn('recoverMissingScores 已于协议 v2 停用', recoveryData);
        this.showNotification('该功能已停用：缺失评分只能由评委本人重新揭晓', 'warning');
        return { success: false, code: 'RECOVERY_REMOVED', message: '该接口已于协议 v2 停用' };
    }

    // 区块链相关API
    static async getBlockchainStatus() {
        console.log('获取区块链状态');

        // 如果未登录，返回未连接状态
        if (!this.isLoggedIn()) {
            console.log('用户未登录，返回默认区块链状态');
            return {
                success: true,
                data: {
                    connected: false,
                    message: '用户未登录'
                }
            };
        }

        return await this.apiCall('/blockchain/status');
    }

    static async createVotingOnBlockchain(votingData) {
        try {
            console.log('创建区块链投票:', votingData);

            const result = await this.apiCall('/blockchain/create-test-voting', {
                method: 'POST',
                body: votingData
            });

            if (result.success) {
                console.log('区块链投票创建成功:', result.data);
                this.showNotification('区块链投票创建成功！', 'success');
            } else {
                console.error('区块链投票创建失败:', result.message);
                this.showNotification('区块链创建失败: ' + result.message, 'warning');
            }

            return result;
        } catch (error) {
            console.error('区块链投票创建请求失败:', error);
            return { success: false, message: error.message };
        }
    }

    static async submitCommitmentOnBlockchain(votingId, commitmentData) {
        try {
            console.log('提交区块链承诺:', { votingId, commitmentData });

            const result = await this.apiCall('/blockchain/submit-commitment', {
                method: 'POST',
                body: {
                    voting_id: votingId,
                    ...commitmentData
                }
            });

            if (result.success) {
                console.log('区块链承诺提交成功');
                this.showNotification('区块链承诺提交成功！', 'success');
            } else {
                console.error('区块链承诺提交失败:', result.message);
                this.showNotification('区块链提交失败: ' + result.message, 'warning');
            }

            return result;
        } catch (error) {
            console.error('区块链承诺提交请求失败:', error);
            return { success: false, message: error.message };
        }
    }

    static async getBlockchainVotingStatus(votingId) {
        try {
            const result = await this.apiCall(`/blockchain/voting/${votingId}/status`);
            return result;
        } catch (error) {
            console.error('获取区块链状态失败:', error);
            return { success: false, message: error.message };
        }
    }

    static async revealScoresOnBlockchain(votingId, revealData) {
        try {
            console.log('区块链揭示评分:', { votingId, revealData });

            const result = await this.apiCall('/blockchain/reveal-scores', {
                method: 'POST',
                body: {
                    voting_id: votingId,
                    ...revealData
                }
            });

            if (result.success) {
                console.log('区块链评分揭示成功');
                this.showNotification('区块链评分揭示成功！', 'success');
            } else {
                console.error('区块链评分揭示失败:', result.message);
                this.showNotification('区块链揭示失败: ' + result.message, 'warning');
            }

            return result;
        } catch (error) {
            console.error('区块链评分揭示请求失败:', error);
            return { success: false, message: error.message };
        }
    }

    // 区块链工具函数
    static generateNullifier(secret, data) {
        // 生成简单的nullifier（在实际系统中应该更复杂）
        const nullifierData = `${secret}:${data}:${Date.now()}:${Math.random()}`;
        return `0x${this.simpleHash(nullifierData)}`;
    }

    static simpleHash(input) {
        // 简单的哈希函数，用于演示
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16).padStart(64, '0');
    }

    static async generateZKProof(scores, secret, maxScore) {
        try {
            // 模拟生成零知识证明
            const proof = {
                commitment: await this.sha256(JSON.stringify(scores) + secret),
                nullifier: this.generateNullifier(secret, JSON.stringify(scores)),
                proof_data: {
                    scores_hash: await this.sha256(JSON.stringify(scores)),
                    range_proof: `range_${maxScore}_${scores.length}`,
                    consistency_proof: `consistency_${Date.now()}`
                },
                public_signals: {
                    commitment: await this.sha256(JSON.stringify(scores) + secret),
                    nullifier: this.generateNullifier(secret, JSON.stringify(scores)),
                    merkle_root: '0x' + '0'.repeat(64)
                }
            };

            return proof;
        } catch (error) {
            console.error('生成ZK证明失败:', error);
            throw error;
        }
    }

    // 修复的钱包连接功能
    static wallet = {
        // 改进的 MetaMask 检测
        isMetaMaskInstalled() {
            try {
                return typeof window.ethereum !== 'undefined' &&
                       (window.ethereum.isMetaMask ||
                        window.ethereum.providers?.some(p => p.isMetaMask) ||
                        !!window.ethereum._metamask);
            } catch (error) {
                console.warn('MetaMask 检测失败:', error);
                return false;
            }
        },

        // 获取可用的以太坊提供商
        getEthereumProvider() {
            if (typeof window.ethereum !== 'undefined') {
                // 处理多个提供商的情况
                if (window.ethereum.providers) {
                    return window.ethereum.providers.find(p => p.isMetaMask) || window.ethereum;
                }
                return window.ethereum;
            }

            // 检查旧版本的 MetaMask
            if (typeof window.web3 !== 'undefined') {
                return window.web3.currentProvider;
            }

            return null;
        },

        // 改进的钱包连接方法
        async connectWallet() {
            try {
                const provider = this.getEthereumProvider();

                if (!provider) {
                    throw new Error('未检测到以太坊钱包。请安装 MetaMask 或其他兼容钱包。');
                }

                console.log('连接钱包...', provider);

                // 请求账户访问
                const accounts = await provider.request({
                    method: 'eth_requestAccounts'
                });

                if (accounts.length === 0) {
                    throw new Error('用户拒绝连接钱包');
                }

                const walletAddress = accounts[0];
                console.log('钱包连接成功:', walletAddress);

                // 获取链ID
                const chainId = await provider.request({
                    method: 'eth_chainId'
                });

                // 设置事件监听器
                this.setupEventListeners(provider);

                return {
                    success: true,
                    address: walletAddress,
                    chainId: chainId,
                    provider: provider
                };

            } catch (error) {
                console.error('钱包连接失败:', error);

                // 提供更友好的错误信息
                let userFriendlyError = error.message;
                if (error.code === 4001) {
                    userFriendlyError = '用户拒绝连接钱包';
                } else if (error.code === -32002) {
                    userFriendlyError = '钱包连接请求已在进行中，请检查 MetaMask 弹窗';
                }

                return {
                    success: false,
                    error: userFriendlyError,
                    code: error.code
                };
            }
        },

        // 改进的获取当前钱包方法
        async getCurrentWallet() {
            try {
                const provider = this.getEthereumProvider();

                if (!provider) {
                    return {
                        success: false,
                        error: '未检测到以太坊钱包',
                        installed: false
                    };
                }

                const accounts = await provider.request({
                    method: 'eth_accounts'
                });

                if (accounts.length === 0) {
                    return {
                        success: false,
                        error: '钱包未连接',
                        installed: true,
                        connected: false
                    };
                }

                return {
                    success: true,
                    address: accounts[0],
                    installed: true,
                    connected: true
                };
            } catch (error) {
                console.error('获取钱包地址失败:', error);
                return {
                    success: false,
                    error: error.message,
                    installed: this.isMetaMaskInstalled()
                };
            }
        },

        // 改进的事件监听器设置
        setupEventListeners(provider = null) {
            const ethereum = provider || this.getEthereumProvider();
            if (!ethereum) return;

            try {
                // 监听账户变化
                ethereum.on('accountsChanged', (accounts) => {
                    console.log('账户变化:', accounts);
                    this.handleAccountsChanged(accounts);
                });

                // 监听链变化
                ethereum.on('chainChanged', (chainId) => {
                    console.log('链变化:', chainId);
                    this.handleChainChanged(chainId);
                });

                // 监听连接事件
                ethereum.on('connect', (connectInfo) => {
                    console.log('钱包连接:', connectInfo);
                });

                // 监听断开事件
                ethereum.on('disconnect', (error) => {
                    console.log('钱包断开:', error);
                    this.handleDisconnect();
                });

            } catch (error) {
                console.warn('设置钱包事件监听器失败:', error);
            }
        },

        // 处理账户变化
        handleAccountsChanged(accounts) {
            if (accounts.length === 0) {
                this.showWalletNotification('钱包已断开', 'warning');
                this.updateUIOnDisconnect();
            } else {
                this.showWalletNotification(`已切换到账户: ${accounts[0].substring(0, 8)}...`, 'info');
                this.updateUIOnConnect(accounts[0]);
            }
        },

        // 处理链变化
        handleChainChanged(chainId) {
            this.showWalletNotification(`网络已切换: ${this.getNetworkName(chainId)}`, 'info');
        },

        // 处理断开连接
        handleDisconnect() {
            this.showWalletNotification('钱包连接已断开', 'warning');
            this.updateUIOnDisconnect();
        },

        // 显示钱包通知
        showWalletNotification(message, type = 'info') {
            ZKUtils.showNotification(`${message}`, type);
        },

        // 获取网络名称
        getNetworkName(chainId) {
            const networks = {
                '0x1': '以太坊主网',
                '0x3': 'Ropsten测试网',
                '0x4': 'Rinkeby测试网',
                '0x5': 'Goerli测试网',
                '0x2a': 'Kovan测试网',
                '0x7a69': '本地开发网',
                '0x539': '本地开发网',
                '0xaa36a7': 'Sepolia测试网'
            };
            return networks[chainId] || `未知网络 (${chainId})`;
        },

        // 更新UI - 连接状态
        updateUIOnConnect(address) {
            // 更新页面上的钱包显示
            const walletElements = document.querySelectorAll('.wallet-address, .user-wallet');
            walletElements.forEach(element => {
                element.textContent = `${address.substring(0, 6)}...${address.substring(38)}`;
                element.style.display = 'inline';
            });

            // 保存连接状态
            localStorage.setItem('walletConnected', 'true');
            localStorage.setItem('walletAddress', address);
        },

        // 更新UI - 断开状态
        updateUIOnDisconnect() {
            // 隐藏钱包显示
            const walletElements = document.querySelectorAll('.wallet-address, .user-wallet');
            walletElements.forEach(element => {
                element.style.display = 'none';
            });

            // 清除本地存储
            localStorage.removeItem('walletConnected');
            localStorage.removeItem('walletAddress');
        },

        // 断开钱包连接
        async disconnectWallet() {
            try {
                // MetaMask 没有真正的断开连接方法，我们只是清除本地状态
                this.updateUIOnDisconnect();
                console.log('钱包已断开');
                return { success: true };
            } catch (error) {
                console.error('断开钱包失败:', error);
                return { success: false, error: error.message };
            }
        },

        // 签名消息
        async signMessage(message) {
            try {
                const wallet = await this.getCurrentWallet();
                if (!wallet.success) {
                    throw new Error('请先连接钱包');
                }

                const provider = this.getEthereumProvider();
                const signature = await provider.request({
                    method: 'personal_sign',
                    params: [message, wallet.address]
                });

                return {
                    success: true,
                    signature: signature,
                    address: wallet.address,
                    message: message
                };
            } catch (error) {
                console.error('签名失败:', error);
                return {
                    success: false,
                    error: error.message
                };
            }
        },

        // 验证钱包网络
        async checkNetwork(expectedChainId = '0x7a69') {
            try {
                const chainId = await window.ethereum.request({
                    method: 'eth_chainId'
                });

                if (chainId !== expectedChainId) {
                    return {
                        success: false,
                        currentChain: chainId,
                        expectedChain: expectedChainId,
                        error: `请切换到正确的网络。当前: ${this.getNetworkName(chainId)}，需要: ${this.getNetworkName(expectedChainId)}`
                    };
                }

                return {
                    success: true,
                    chainId: chainId
                };
            } catch (error) {
                return {
                    success: false,
                    error: error.message
                };
            }
        },

        // 切换到指定网络
        async switchNetwork(chainId = '0x7a69') {
            try {
                await window.ethereum.request({
                    method: 'wallet_switchEthereumChain',
                    params: [{ chainId: chainId }]
                });
                return { success: true };
            } catch (error) {
                // 如果网络未添加，尝试添加
                if (error.code === 4902) {
                    return await this.addNetwork(chainId);
                }
                return { success: false, error: error.message };
            }
        },

        // 添加网络（用于本地开发）
        async addNetwork(chainId = '0x7a69') {
            try {
                await window.ethereum.request({
                    method: 'wallet_addEthereumChain',
                    params: [{
                        chainId: chainId,
                        chainName: 'Local Hardhat Network',
                        rpcUrls: ['http://127.0.0.1:8545'],
                        nativeCurrency: {
                            name: 'Ethereum',
                            symbol: 'ETH',
                            decimals: 18
                        },
                        blockExplorerUrls: []
                    }]
                });
                return { success: true };
            } catch (error) {
                return { success: false, error: error.message };
            }
        }
    };

    // 工具函数
    static showNotification(message, type = 'info', duration = 3000) {
        // 移除现有通知
        const existingNotifications = document.querySelectorAll('.zk-notification');
        existingNotifications.forEach(notification => notification.remove());

        // 创建通知元素
        const notification = document.createElement('div');
        notification.className = `zk-notification zk-notification-${type}`;
        notification.innerHTML = `
            <div class="zk-notification-content">
                <span class="zk-notification-icon">${this.getNotificationIcon(type)}</span>
                <span class="zk-notification-message">${message}</span>
            </div>
        `;

        // 添加样式
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 16px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 10000;
            max-width: 400px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            animation: zkSlideIn 0.3s ease;
            font-family: system-ui, -apple-system, sans-serif;
        `;

        // 设置背景颜色
        const colors = {
            success: '#27ae60',
            error: '#e74c3c',
            info: '#3498db',
            warning: '#f39c12'
        };
        notification.style.background = colors[type] || colors.info;

        // 添加动画样式
        if (!document.querySelector('#zk-notification-styles')) {
            const style = document.createElement('style');
            style.id = 'zk-notification-styles';
            style.textContent = `
                @keyframes zkSlideIn {
                    from {
                        transform: translateX(100%);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
                .zk-notification-content {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .zk-notification-icon {
                    font-size: 16px;
                }
                .zk-notification-message {
                    flex: 1;
                }
            `;
            document.head.appendChild(style);
        }

        document.body.appendChild(notification);

        // 自动移除
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'zkSlideIn 0.3s ease reverse';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }
        }, duration);

        return notification;
    }

    static getNotificationIcon(type) {
        // 统一使用内联 SVG，不再使用 emoji
        const svg = (body) =>
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
            'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + body + '</svg>';
        const icons = {
            success: svg('<path d="M20 6L9 17l-5-5"/>'),
            error: svg('<path d="M18 6L6 18M6 6l12 12"/>'),
            info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'),
            warning: svg('<path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4M12 17h.01"/>')
        };
        return icons[type] || icons.info;
    }

    static handleError(error, operation) {
        if (error.message.includes('Failed to fetch')) {
            return `无法连接到服务器，请检查：\n1. 后端服务是否运行在 http://127.0.0.1:5000\n2. 防火墙是否阻止了连接\n3. 网络连接是否正常`;
        }
        if (error.message.includes('Network Error')) {
            return `网络错误，请检查网络连接`;
        }
        if (error.message.includes('认证失败')) {
            this.removeAuthToken();
            setTimeout(() => {
                if (window.location.pathname !== '/index.html' &&
                    !window.location.pathname.endsWith('/')) {
                    window.location.href = 'index.html';
                }
            }, 1000);
            return `认证失败，请重新登录`;
        }
        if (error.status === 403) {
            return `权限不足，无法执行此操作`;
        }
        if (error.status === 404) {
            return `请求的资源不存在: ${error.responseText || '请检查URL是否正确'}`;
        }
        if (error.status === 500) {
            return `服务器内部错误，请稍后重试`;
        }
        return `${operation}失败: ${error.message}`;
    }

    static formatDate(dateString) {
        try {
            if (!dateString) return '未知时间';

            const date = new Date(dateString);
            if (isNaN(date.getTime())) {
                return '无效日期';
            }

            return date.toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (error) {
            console.error('日期格式化错误:', error);
            return '日期错误';
        }
    }

    static formatDateTime(dateString) {
        try {
            if (!dateString) return '未知时间';

            const date = new Date(dateString);
            if (isNaN(date.getTime())) {
                return '无效日期';
            }

            return date.toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        } catch (error) {
            console.error('日期时间格式化错误:', error);
            return '日期错误';
        }
    }

    // 数据验证工具
    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    static validateUsername(username) {
        if (!username || username.length < 3) {
            return { isValid: false, error: '用户名至少需要3个字符' };
        }
        if (username.length > 50) {
            return { isValid: false, error: '用户名不能超过50个字符' };
        }
        const usernameRegex = /^[a-zA-Z0-9_]+$/;
        if (!usernameRegex.test(username)) {
            return { isValid: false, error: '用户名只能包含字母、数字和下划线' };
        }
        return { isValid: true, error: null };
    }

    // 测试连接
    static async testConnection() {
        try {
            const result = await this.apiCall('/health');
            console.log('后端连接测试成功:', result);
            return true;
        } catch (error) {
            console.error('后端连接测试失败:', error);
            return false;
        }
    }

    // 调试工具
    static async debugCommitment(scores, secret, maxScore) {
        try {
            const commitmentData = {
                scores: scores,
                secret: secret,
                max_score: maxScore
            };

            const commitmentStr = JSON.stringify(commitmentData, null, 0);
            const hash = await this.sha256(commitmentStr);

            return {
                data: commitmentData,
                json: commitmentStr,
                hash: `0x${hash}`,
                hash_raw: hash
            };
        } catch (error) {
            console.error('调试承诺失败:', error);
            throw error;
        }
    }

    // 认证调试工具
    static async debugAuth() {
        console.group('认证调试信息');
        console.log('当前页面:', window.location.href);
        console.log('Token存在:', !!this.getAuthToken());
        console.log('Token内容:', this.getAuthToken() ? this.getAuthToken().substring(0, 20) + '...' : '无');
        console.log('后端地址:', this.baseURL);

        // 检查本地缓存的用户信息
        const cachedUser = localStorage.getItem('userInfo');
        console.log('缓存的用户信息:', cachedUser ? '存在' : '不存在');

        // 测试token有效性
        const token = this.getAuthToken();
        if (token) {
            try {
                console.log('测试token有效性...');
                const userResult = await this.getCurrentUser();
                console.log('Token测试结果:', userResult.success ? '有效' : '无效');
                if (userResult.success) {
                    console.log('用户信息:', userResult.data);
                } else {
                    console.log('错误信息:', userResult.message);
                }
            } catch (error) {
                console.error('Token测试失败:', error);
            }
        }
        console.groupEnd();
    }

    // 区块链调试工具
    static async debugBlockchain() {
        console.group('区块链调试信息');

        // 只在已登录状态下调试区块链
        if (!this.isLoggedIn()) {
            console.log('用户未登录，跳过区块链调试');
            console.groupEnd();
            return;
        }

        try {
            const status = await this.getBlockchainStatus();
            console.log('区块链连接状态:', status.data);
        } catch (error) {
            console.error('区块链状态获取失败:', error);
        }
        console.groupEnd();
    }

    // 钱包调试工具
    static async debugWallet() {
        console.group('钱包调试信息');

        console.log('当前页面:', window.location.href);
        console.log('全局 ethereum:', typeof window.ethereum);
        console.log('全局 web3:', typeof window.web3);

        if (window.ethereum) {
            console.log('window.ethereum 存在');
            console.log('isMetaMask:', window.ethereum.isMetaMask);
            console.log('提供商数量:', window.ethereum.providers?.length || 1);
            console.log('链ID:', window.ethereum.chainId);
            console.log('网络版本:', window.ethereum.networkVersion);
        } else {
            console.log('window.ethereum 不存在');
        }

        // 测试钱包功能
        const wallet = await this.wallet.getCurrentWallet();
        console.log('钱包状态:', wallet);

        console.groupEnd();

        return {
            ethereumAvailable: !!window.ethereum,
            metaMaskInstalled: this.wallet.isMetaMaskInstalled(),
            walletStatus: wallet
        };
    }

    // 确认对话框
    static confirmAction(message, title = '确认操作') {
        return new Promise((resolve) => {
            const confirmed = window.confirm(`${title}\n\n${message}`);
            resolve(confirmed);
        });
    }

    // 防抖函数
    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // 节流函数
    static throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    // 获取URL参数
    static getUrlParam(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
    }

    // 设置URL参数
    static setUrlParam(name, value) {
        const urlParams = new URLSearchParams(window.location.search);
        urlParams.set(name, value);
        window.history.replaceState({}, '', `${window.location.pathname}?${urlParams}`);
    }

    // 移除URL参数
    static removeUrlParam(name) {
        const urlParams = new URLSearchParams(window.location.search);
        urlParams.delete(name);
        window.history.replaceState({}, '', `${window.location.pathname}?${urlParams}`);
    }

    // 复制到剪贴板
    static copyToClipboard(text) {
        return new Promise((resolve, reject) => {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(resolve).catch(reject);
            } else {
                // 备用方法
                const textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.style.position = 'fixed';
                textArea.style.left = '-999999px';
                textArea.style.top = '-999999px';
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                try {
                    document.execCommand('copy');
                    resolve();
                } catch (err) {
                    reject(err);
                }
                document.body.removeChild(textArea);
            }
        });
    }

    // 下载文件
    static downloadFile(content, filename, contentType = 'text/plain') {
        const blob = new Blob([content], { type: contentType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    // 生成随机ID
    static generateId(length = 8) {
        return Math.random().toString(36).substring(2, 2 + length);
    }

    // 格式化数字
    static formatNumber(num, decimals = 2) {
        if (isNaN(num)) return '0';
        return parseFloat(num).toFixed(decimals);
    }

    // 格式化文件大小
    static formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // 检查是否是移动设备
    static isMobile() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    }

    // 检查是否是触摸设备
    static isTouchDevice() {
        return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    }

    // 获取设备信息
    static getDeviceInfo() {
        return {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            isMobile: this.isMobile(),
            isTouch: this.isTouchDevice(),
            screenWidth: window.screen.width,
            screenHeight: window.screen.height
        };
    }

    // 存储本地数据
    static setLocalData(key, data) {
        try {
            localStorage.setItem(`zk_${key}`, JSON.stringify(data));
            return true;
        } catch (error) {
            console.error('存储本地数据失败:', error);
            return false;
        }
    }

    // 获取本地数据
    static getLocalData(key, defaultValue = null) {
        try {
            const data = localStorage.getItem(`zk_${key}`);
            return data ? JSON.parse(data) : defaultValue;
        } catch (error) {
            console.error('获取本地数据失败:', error);
            return defaultValue;
        }
    }

    // 移除本地数据
    static removeLocalData(key) {
        try {
            localStorage.removeItem(`zk_${key}`);
            return true;
        } catch (error) {
            console.error('移除本地数据失败:', error);
            return false;
        }
    }

    // 清除所有本地数据
    static clearAllLocalData() {
        try {
            const keys = Object.keys(localStorage).filter(key => key.startsWith('zk_'));
            keys.forEach(key => localStorage.removeItem(key));
            return true;
        } catch (error) {
            console.error('清除本地数据失败:', error);
            return false;
        }
    }

    // 检查浏览器支持
    static checkBrowserSupport() {
        const features = {
            fetch: typeof fetch === 'function',
            localStorage: typeof localStorage !== 'undefined',
            crypto: typeof crypto !== 'undefined',
            promise: typeof Promise !== 'undefined',
            webWorker: typeof Worker !== 'undefined'
        };

        const unsupported = Object.keys(features).filter(key => !features[key]);

        return {
            supported: unsupported.length === 0,
            features: features,
            unsupported: unsupported
        };
    }

    static async verifyPedersenCommitment(votingId, verificationData) {
        try {
            console.log('验证 Pedersen 承诺...');

            const result = await this.apiCall(`/voting/${votingId}/verify-pedersen`, {
                method: 'POST',
                body: verificationData
            });

            return result;
        } catch (error) {
            console.error('验证 Pedersen 承诺失败:', error);
            throw error;
        }
    }

    // 性能监控
    static performance = {
        marks: new Map(),

        mark(name) {
            this.marks.set(name, performance.now());
        },

        measure(name, startMark, endMark) {
            const start = this.marks.get(startMark);
            const end = this.marks.get(endMark);
            if (start && end) {
                const duration = end - start;
                console.log(`${name}: ${duration.toFixed(2)}ms`);
                return duration;
            }
            return null;
        },

        clear() {
            this.marks.clear();
        }
    };

    // 错误监控
    static errorHandler = {
        init() {
            window.addEventListener('error', this.handleError.bind(this));
            window.addEventListener('unhandledrejection', this.handlePromiseRejection.bind(this));
        },

        handleError(event) {
            const error = {
                message: event.message,
                filename: event.filename,
                lineno: event.lineno,
                colno: event.colno,
                stack: event.error?.stack,
                timestamp: new Date().toISOString()
            };

            console.error('全局错误:', error);
        },

        handlePromiseRejection(event) {
            const error = {
                message: event.reason?.message || 'Promise rejection',
                stack: event.reason?.stack,
                timestamp: new Date().toISOString()
            };

            console.error('Promise拒绝:', error);
        }
    };

    // 初始化钱包连接状态
    static async initWalletConnection() {
        try {
            const wallet = await this.wallet.getCurrentWallet();
            if (wallet.success) {
                this.wallet.updateUIOnConnect(wallet.address);
            }
        } catch (error) {
            console.warn('初始化钱包连接状态失败:', error);
        }
    }

    // 初始化
    static init() {
        console.log('ZKUtils 初始化完成');

        // 初始化错误监控
        this.errorHandler.init();

        // 初始化钱包连接
        this.initWalletConnection();

        // 认证/区块链调试仅在需要时手动调用 debugAuth() / debugBlockchain()，
        // 不随页面加载自动执行，避免每个页面多发一次请求并污染控制台。
    }
}

// 确保ZKUtils在全局可用
window.ZKUtils = ZKUtils;

// 页面加载时初始化
document.addEventListener('DOMContentLoaded', function() {
    ZKUtils.init();
});

// 导出供模块化使用
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ZKUtils;
}