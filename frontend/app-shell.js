/* =============================================================================
   app-shell.js —— 应用壳层单一真源（侧边栏 + 顶栏）
   规范见 frontend/DESIGN.md 第 5 节。

   作用：所有应用内页面（dashboard / create-voting / admin / results /
   weight-management / wallet-management / score）只需在 <head> 里引入本脚本，
   即可自动获得：
     · 一致的左侧导航（按 location.pathname 自动高亮当前项）
     · 一致的顶栏（面包屑 + 用户名 + 角色标签 + 钱包状态 + 退出登录）
     · 页面原有正文自动被搬入 <main class="main stack">，无需各自复制壳层 HTML
   登录页 index.html 不套壳，不引入本脚本。
   ========================================================================== */
(function () {
    'use strict';

    /* ---------------- 导航配置（唯一真源） ---------------- */
    var NAV = [
        { key: 'dashboard', href: 'dashboard.html',        label: '仪表板',   icon: 'grid',   group: 'console' },
        { key: 'create',    href: 'create-voting.html',    label: '创建评审', icon: 'plus',   group: 'console', roles: ['publisher'] },
        { key: 'results',   href: 'results.html',          label: '结果查询', icon: 'chart',  group: 'console' },
        { key: 'weight',    href: 'weight-management.html', label: '权重管理', icon: 'scale',  group: 'console', roles: ['publisher'] },
        { key: 'recovery',  href: 'recovery.html',          label: '恢复中心', icon: 'shield', group: 'account' },
        { key: 'wallet',    href: 'wallet-management.html', label: '钱包管理', icon: 'wallet', group: 'account' }
    ];

    var GROUPS = [
        { id: 'console', label: '评审主控台' },
        { id: 'account', label: '账户' }
    ];

    /* 页面 → 导航高亮项 + 面包屑 */
    var PAGES = {
        'dashboard.html':         { active: 'dashboard', crumb: '仪表板' },
        'create-voting.html':     { active: 'create',    crumb: '创建评审' },
        'admin.html':             { active: 'create',    crumb: '评审管理' },
        'results.html':           { active: 'results',   crumb: '结果查询' },
        'weight-management.html': { active: 'weight',    crumb: '权重管理' },
        'recovery.html':          { active: 'recovery',  crumb: '恢复中心' },
        'wallet-management.html': { active: 'wallet',    crumb: '钱包管理' },
        'score.html':             { active: 'dashboard', crumb: '参与评分' }
    };

    var ROLE_LABELS = { publisher: '活动发布者', voter: '评分者' };

    /* 内联 SVG（禁止 emoji） */
    var ICONS = {
        grid:   '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
        plus:   '<path d="M12 5v14M5 12h14"/>',
        chart:  '<path d="M4 19V5M4 19h16"/><path d="M8 16v-5M12.5 16V8M17 16v-3"/>',
        scale:  '<path d="M12 4v16M6 8h12M7.5 8l-2 8h9l-2-8"/>',
        wallet: '<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 10h18M16.5 14.5h.01"/>',
        shield: '<path d="M12 3l7 3v6c0 4.2-2.9 7.6-7 9-4.1-1.4-7-4.8-7-9V6l7-3z"/><path d="M9.5 12.5l1.8 1.8 3.4-3.6"/>',
        link:   '<path d="M10 13a5 5 0 0 0 7.1.1l3-3a5 5 0 0 0-7.1-7.1l-1.2 1.2"/><path d="M14 11a5 5 0 0 0-7.1-.1l-3 3A5 5 0 0 0 11 21l1.2-1.2"/>'
    };

    function svg(name) {
        return '<svg class="icon icon-sm" viewBox="0 0 24 24" aria-hidden="true">' + (ICONS[name] || '') + '</svg>';
    }

    function basename() {
        var path = window.location.pathname.split('/').pop() || '';
        return path.split('?')[0] || '';
    }

    function readUser() {
        try {
            var raw = localStorage.getItem('userInfo');
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    function shortAddress(addr) {
        if (!addr || addr.length < 12) return addr || '';
        return addr.substring(0, 6) + '…' + addr.substring(addr.length - 4);
    }

    /* ---------------- 侧边栏 ---------------- */
    function buildSidebar(activeKey) {
        var aside = document.createElement('aside');
        aside.className = 'sidebar';

        var html = ''
            + '<div class="brand">'
            +   '<span class="brand-mark">' + svg('shield') + '</span>'
            +   '<span class="brand-text">'
            +     '<span class="brand-name">ZK-SealedWeigh</span><br>'
            +     '<span class="brand-sub">密封加权评审</span>'
            +   '</span>'
            + '</div>';

        GROUPS.forEach(function (group) {
            var items = NAV.filter(function (item) { return item.group === group.id; });
            if (!items.length) return;

            html += '<nav class="nav-group" data-group="' + group.id + '">'
                 +  '<div class="nav-group-label">' + group.label + '</div>';

            items.forEach(function (item) {
                var roles = item.roles ? ' data-roles="' + item.roles.join(',') + '"' : '';
                var active = item.key === activeKey ? ' active' : '';
                var badge = item.key === 'recovery'
                    ? '<span class="nav-badge" id="recoveryNavBadge" style="display:none;"></span>'
                    : '';
                html += '<a class="nav-item' + active + '" href="' + item.href + '"' + roles + '>'
                     +    svg(item.icon)
                     +    '<span>' + item.label + '</span>'
                     +    badge
                     +  '</a>';
            });

            html += '</nav>';
        });

        html += '<div class="nav-foot">本地链 · chainId 31337</div>';
        aside.innerHTML = html;
        return aside;
    }

    /* 角色可见性：未取到角色时全部展示，取到后隐藏无权项与空分组 */
    function applyRole(role) {
        var items = document.querySelectorAll('.nav-item[data-roles]');
        Array.prototype.forEach.call(items, function (el) {
            var need = (el.getAttribute('data-roles') || '').split(',');
            el.style.display = (!role || need.indexOf(role) !== -1) ? '' : 'none';
        });

        var groups = document.querySelectorAll('.nav-group');
        Array.prototype.forEach.call(groups, function (group) {
            var visible = group.querySelectorAll('.nav-item:not([style*="none"])');
            var hasVisible = Array.prototype.some.call(visible, function (el) {
                return el.style.display !== 'none';
            });
            group.style.display = hasVisible ? '' : 'none';
        });
    }

    /* ---------------- 顶栏 ---------------- */
    function buildTopbar(crumb) {
        var header = document.createElement('header');
        header.className = 'topbar';
        header.innerHTML = ''
            + '<div class="crumb">首页 / <strong>' + crumb + '</strong></div>'
            + '<div class="topbar-right">'
            +   '<span class="welcome">欢迎，<strong id="currentUserName"></strong></span>'
            +   '<span class="user-role" id="currentUserRole"></span>'
            +   '<span class="wallet-status" id="walletStatusBadge" style="display:none;">'
            +     svg('link').replace('icon-sm', 'wallet-icon')
            +     '<span id="walletAddressShort"></span>'
            +   '</span>'
            +   '<button type="button" class="btn btn-small btn-secondary" onclick="logout()">退出登录</button>'
            + '</div>';
        return header;
    }

    /* ---------------- 用户态注入 ---------------- */
    function fillUser(user) {
        var nameEl = document.getElementById('currentUserName');
        var roleEl = document.getElementById('currentUserRole');
        var badgeEl = document.getElementById('walletStatusBadge');
        var addrEl = document.getElementById('walletAddressShort');
        var role = user && user.role;

        if (nameEl) nameEl.textContent = (user && (user.username || user.name)) || '未登录';
        if (roleEl) {
            roleEl.textContent = ROLE_LABELS[role] || '';
            roleEl.className = 'user-role' + (role ? ' ' + role : '');
        }
        if (badgeEl && addrEl) {
            if (user && user.wallet_address) {
                addrEl.textContent = shortAddress(user.wallet_address);
                badgeEl.style.display = 'inline-flex';
                badgeEl.title = '钱包地址: ' + user.wallet_address;
            } else {
                badgeEl.style.display = 'none';
            }
        }

        applyRole(role);
    }

    function refreshUser() {
        if (!window.ZKUtils || typeof ZKUtils.getCurrentUser !== 'function') return;
        ZKUtils.getCurrentUser().then(function (res) {
            if (res && res.success && res.data) {
                try { localStorage.setItem('userInfo', JSON.stringify(res.data)); } catch (e) { /* 忽略 */ }
                fillUser(res.data);
            }
        }).catch(function () { /* 未登录或后端不可达时保持既有渲染 */ });
    }

    /* 统一退出登录（页面若自有 logout 会被本实现覆盖，行为一致） */
    window.logout = function () {
        if (window.ZKUtils && typeof ZKUtils.removeAuthToken === 'function') {
            ZKUtils.removeAuthToken();
        }
        window.location.href = 'index.html';
    };

    /* ---------------- 活动选择列表 ----------------
       供缺少 ?id= 的活动级页面（结果查询 / 权重管理）使用：
       侧边导航点进来时不再弹原生 alert 并跳回仪表板，而是就地给出可选择的活动。 */
    var PHASE_NAMES = {
        commit: '承诺阶段',
        scoring: '评分阶段',
        completed: '结果公布',
        cancelled: '已取消'
    };

    function renderVotingPicker(opts) {
        var container = document.getElementById(opts.containerId);
        if (!container) return Promise.resolve();

        if (opts.loadingId) {
            var loading = document.getElementById(opts.loadingId);
            if (loading) loading.style.display = 'none';
        }

        container.style.display = 'block';
        container.innerHTML = ''
            + '<div class="card">'
            +   '<div class="card-head"><h3>选择评审活动</h3></div>'
            +   '<div id="zk-picker-list"><div class="loading">加载活动列表...</div></div>'
            + '</div>';

        if (!window.ZKUtils || typeof ZKUtils.getVotings !== 'function') return Promise.resolve();

        return ZKUtils.getVotings(false).then(function (res) {
            var list = document.getElementById('zk-picker-list');
            if (!list) return;
            var votings = (res && res.data) || [];

            if (!votings.length) {
                list.className = 'empty-state';
                list.innerHTML = '<p>暂无可选评审活动</p>';
                return;
            }

            list.className = '';
            list.innerHTML = ''
                + '<table class="table">'
                +   '<thead><tr><th>评审活动</th><th>阶段</th><th>创建时间</th><th></th></tr></thead>'
                +   '<tbody>'
                +   votings.map(function (voting) {
                        return '<tr>'
                            + '<td>'
                            +   '<div class="activity-title">' + voting.title + '</div>'
                            +   '<div class="text-subtle">' + (voting.description || '暂无描述') + '</div>'
                            + '</td>'
                            + '<td><span class="phase-badge ' + (voting.phase || '') + '">'
                            +   (PHASE_NAMES[voting.phase] || voting.phase || '') + '</span></td>'
                            + '<td class="text-subtle">' + ZKUtils.formatDate(voting.created_at) + '</td>'
                            + '<td><a class="btn btn-small" href="' + opts.target + '?id=' + voting.id + '">'
                            +   opts.action + '</a></td>'
                            + '</tr>';
                    }).join('')
                +   '</tbody>'
                + '</table>';
        }).catch(function (error) {
            var list = document.getElementById('zk-picker-list');
            if (!list) return;
            list.className = 'alert is-danger';
            list.textContent = '加载活动列表失败: ' + error.message;
        });
    }

    /* ---------------- 恢复中心待办徽标（P3.10 / P3.11） ---------------- */
    var lastPendingAssist = null;
    var badgeTimer = null;

    function refreshRecoveryBadge() {
        var badge = document.getElementById('recoveryNavBadge');
        if (!badge || !window.ZKUtils || typeof ZKUtils.apiCall !== 'function') return;
        if (typeof ZKUtils.isLoggedIn === 'function' && !ZKUtils.isLoggedIn()) return;

        ZKUtils.apiCall('/recovery/overview').then(function (result) {
            var count = (result && result.success && result.data)
                ? Number(result.data.pendingAssist) || 0 : 0;
            if (count > 0) {
                badge.textContent = String(count);
                badge.style.display = 'inline-flex';
                badge.setAttribute('aria-label', count + ' 个待协助恢复请求');
            } else {
                badge.style.display = 'none';
                badge.removeAttribute('aria-label');
            }

            // 数量增加时提示一次；首次加载不提醒
            if (lastPendingAssist !== null && count > lastPendingAssist &&
                window.ZKUtils && typeof ZKUtils.showNotification === 'function') {
                ZKUtils.showNotification('有新的恢复协助请求，请前往恢复中心', 'info');
            }
            lastPendingAssist = count;
        }).catch(function () {
            /* 未登录或后端不可达时静默，不影响导航 */
        });
    }

    function startRecoveryBadgePolling() {
        if (badgeTimer) return;
        badgeTimer = window.setInterval(function () {
            if (!document.hidden) refreshRecoveryBadge();
        }, 15000);
    }

    document.addEventListener('visibilitychange', function () {
        if (!document.hidden) refreshRecoveryBadge();
    });

    /* 对外暴露给页面调用的共享能力 */
    window.ZKShell = {
        renderVotingPicker: renderVotingPicker,
        refreshRecoveryBadge: refreshRecoveryBadge
    };

    /* ---------------- 组装 ---------------- */
    function mount() {
        if (document.querySelector('.app-shell')) return; // 已套壳则不重复

        var page = basename();
        var meta = PAGES[page] || {};
        var crumb = meta.crumb || (document.querySelector('.page-title') || {}).textContent || document.title;
        var user = readUser();

        var shell = document.createElement('div');
        shell.className = 'app-shell';

        var column = document.createElement('div');
        column.className = 'app-column';
        column.appendChild(buildTopbar(crumb));

        var main = document.createElement('main');
        main.className = 'main stack';

        /* 把页面原有正文搬进主区（script/style/link 留在原地，不搬动） */
        var movable = [];
        Array.prototype.forEach.call(document.body.children, function (el) {
            var tag = el.tagName;
            if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'LINK' || tag === 'NOSCRIPT' || tag === 'TEMPLATE') return;
            movable.push(el);
        });
        movable.forEach(function (el) { main.appendChild(el); });

        column.appendChild(main);
        shell.appendChild(buildSidebar(meta.active));
        shell.appendChild(column);
        document.body.insertBefore(shell, document.body.firstChild);

        fillUser(user);
        refreshUser();
        refreshRecoveryBadge();
        startRecoveryBadgePolling();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', mount);
    } else {
        mount();
    }
})();
