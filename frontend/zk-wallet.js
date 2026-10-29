// frontend/zk-wallet.js
if (typeof ZKUtils === 'undefined') {
    throw new Error('请先加载核心工具类zk-utils.js');
}

// 扩展ZKUtils，添加钱包功能
ZKUtils.wallet = {
    /**
     * 检查MetaMask是否已安装
     */
    isMetaMaskInstalled() {
        return typeof window.ethereum !== 'undefined' && window.ethereum.isMetaMask;
    },

    /**
     * 获取当前连接的钱包
     */
    async getCurrentWallet() {
        try {
            if (!this.isMetaMaskInstalled()) {
                return { success: false, message: '未检测到MetaMask，请安装后重试' };
            }

            // 请求用户授权
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            if (accounts.length === 0) {
                return { success: false, message: '用户未授权钱包访问' };
            }

            return {
                success: true,
                address: accounts[0],
                chainId: await window.ethereum.request({ method: 'eth_chainId' })
            };
        } catch (error) {
            console.error('获取钱包失败:', error);
            return { success: false, message: error.message };
        }
    },

    /**
     * 连接钱包
     */
    async connectWallet() {
        try {
            if (!this.isMetaMaskInstalled()) {
                return { success: false, message: '未检测到MetaMask，请安装后重试' };
            }

            // 监听账户变化
            window.ethereum.on('accountsChanged', (accounts) => {
                if (accounts.length === 0) {
                    ZKUtils.showNotification('钱包已断开连接', 'warning');
                    this.disconnectWallet();
                } else {
                    ZKUtils.showNotification('钱包账户已更新', 'info');
                    window.location.reload();
                }
            });

            // 监听链变化
            window.ethereum.on('chainChanged', () => {
                ZKUtils.showNotification('网络已切换，页面将刷新', 'info');
                window.location.reload();
            });

            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            return {
                success: true,
                address: accounts[0]
            };
        } catch (error) {
            console.error('连接钱包失败:', error);
            return { success: false, message: error.message };
        }
    },

    /**
     * 断开钱包连接
     */
    async disconnectWallet() {
        // MetaMask没有直接断开连接的API，清除本地状态
        ZKUtils.removeAuthToken();
        return { success: true };
    }
};

// 标记钱包模块已加载
window.walletModuleLoaded = true;
console.log('钱包模块初始化完成');