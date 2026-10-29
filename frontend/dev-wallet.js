/* =============================================================================
   dev-wallet.js —— 仅本地开发用的 EIP-1193 provider（P3.9）

   用途：没有 MetaMask 时，把 Hardhat 节点的已解锁账户包装成 window.ethereum，
        以便在浏览器里完整走通"发布公钥 / 登记 / 请求 / 协助 / 重构"。

   启用条件（缺一不可）：
     · URL 带 ?devwallet=1 或 ?devwallet=0x...（显式账户地址）
     · 页面主机名为 localhost / 127.0.0.1

   安全边界：
     · 私钥始终留在 Hardhat 节点，浏览器只调用 personal_sign / eth_sign；
     · 仅监听本机 8545，绝不在非 localhost 页面生效；
     · 这是开发工具，生产环境应使用 MetaMask，不得用它代替真实钱包验收。
   ========================================================================== */
(function () {
    'use strict';

    var params = new URLSearchParams(window.location.search);
    var requested = params.get('devwallet');
    if (!requested) return;

    var host = window.location.hostname;
    if (host !== 'localhost' && host !== '127.0.0.1') return;

    // 默认使用 Hardhat 账户 #1（种子账号 voter1）
    var DEFAULT_ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    var address = /^0x[0-9a-fA-F]{40}$/.test(requested) ? requested : DEFAULT_ADDRESS;
    var rpcUrl = params.get('devrpc') || 'http://127.0.0.1:8545';
    var listeners = {};

    function rpc(method, rpcParams) {
        return fetch(rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: Date.now(),
                method: method,
                params: rpcParams || []
            })
        }).then(function (response) {
            return response.json();
        }).then(function (payload) {
            if (payload.error) {
                throw new Error(payload.error.message || '本地 RPC 调用失败');
            }
            return payload.result;
        });
    }

    var provider = {
        isMetaMask: false,
        isDevWallet: true,
        selectedAddress: address,
        chainId: '0x7a69',

        request: function (args) {
            var method = args && args.method;
            var callParams = (args && args.params) || [];
            switch (method) {
                case 'eth_requestAccounts':
                case 'eth_accounts':
                    return Promise.resolve([address]);
                case 'eth_chainId':
                    return Promise.resolve('0x7a69');
                case 'net_version':
                    return Promise.resolve('31337');
                case 'personal_sign':
                    return rpc('personal_sign', [callParams[0], callParams[1] || address]);
                case 'eth_sign':
                    return rpc('eth_sign', [callParams[0], callParams[1]]);
                default:
                    return rpc(method, callParams);
            }
        },

        on: function (event, handler) {
            listeners[event] = listeners[event] || [];
            listeners[event].push(handler);
        },

        removeListener: function (event, handler) {
            var list = listeners[event] || [];
            var index = list.indexOf(handler);
            if (index >= 0) list.splice(index, 1);
        }
    };

    window.ethereum = provider;
    window.__DEV_WALLET__ = { address: address, rpcUrl: rpcUrl };

    document.addEventListener('DOMContentLoaded', function () {
        var badge = document.getElementById('devWalletBadge');
        if (badge) {
            badge.style.display = 'block';
            badge.textContent = '开发钱包（Hardhat 已解锁账户）：' + address + ' · 仅本地演示，不代表真实钱包验收';
        }
    });

    console.log('[dev-wallet] 已启用', address, '->', rpcUrl);
})();
