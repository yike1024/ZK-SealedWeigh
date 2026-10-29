# DESIGN.md — 零知识密封加权评审系统（ZK-SealedWeigh）前端设计语言

> 本文件是本项目前端的**唯一设计依据**。任何页面、组件的视觉实现都必须引用这里定义的
> 设计令牌与规范，**不得在组件里写死颜色、圆角、阴影或时长**。
>
> 风格定位：**瑞士国际主义（结构与秩序）× 现代金融科技（可信赖）× 密码学严谨性**。
> 明确排除：蓝紫渐变、玻璃拟态、发光线条、装饰性科技图案、16px 大圆角、厚重阴影、emoji 图标。

---

## 1. 视觉基调

| 维度 | 原则 |
|---|---|
| 气质 | 极简、克制、精致、可信、耐看 |
| 层次手段 | **留白 + 细分隔线 + 字重字号**（优先），阴影仅作辅助 |
| 密度 | 信息紧凑但呼吸充分；表格/列表行高一致 |
| 结构 | 12 列思维，左右边距与模块间距恒定；侧边导航 + 顶栏为统一骨架 |
| 禁止 | 渐变文字、渐变按钮、`backdrop-filter`、`translateY` 悬浮位移、循环动画 |

---

## 2. 色彩系统（令牌见 `style.css` 的 `:root`）

| 角色 | 色值 | 变量 | 使用场景 |
|---|---|---|---|
| 主背景 | `#F7F7F5` | `--bg-app` | 页面底色 |
| 面板 | `#FFFFFF` | `--surface` | 卡片、表格、表单 |
| 次级面板 | `#EFEFED` | `--surface-2` | 表头、代码块 |
| 主文字 | `#202124` | `--fg` | 标题、正文 |
| 次级文字 | `#6B7075` | `--fg-muted` | 描述、辅助信息 |
| 弱文字 | `#8A8F94` | `--fg-subtle` | 时间戳、单位 |
| 分隔线 | `#E5E6E4` | `--border` | 边框、分隔 |
| 深色底 | `#181A1B` | `--ink` | 侧边栏、统计主卡 |
| 深灰面板 | `#242729` | `--ink-surface` | 深色模式面板 |
| **莫兰迪蓝** | `#7D96AA` | `--accent` | 主按钮、选中态、焦点环、进度 |
| 浅雾蓝 | `#DCE5EB` | `--accent-soft` | 标签底、选中行底 |
| 深灰蓝 | `#526A7A` | `--accent-strong` | 深色底上的强调、链接 |
| 成功 | `#3F7D62` | `--ok` | 已完成、验证通过 |
| 警告 | `#B4842F` | `--warn` | 待处理、需注意 |
| 危险 | `#B4544A` | `--danger` | 失败、不可逆操作 |
| 信息 | `#526A7A` | `--info` | 中性提示 |

**视觉配比**：白/浅灰 ≈ 60% · 黑/深灰 ≈ 25% · 莫兰迪蓝 ≈ 10% · 状态色 ≈ 5%。
**蓝色是锚点不是背景**：只出现在主按钮、选中导航项、输入焦点、进度条与关键链接上；
次级按钮一律中性（白底 + 边框 + 次级文字色）。

**状态不得仅靠颜色传达**：`.badge` / `.phase-badge` / `.activity-status` 必须同时具备
**文字**（阶段名/状态名），必要时加内联 SVG 图标。色盲用户仅凭颜色也应能区分。

---

## 3. 字体与排版

```
--font-sans: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI",
             "PingFang SC", "Microsoft YaHei", "Hiragino Sans GB", sans-serif
--font-mono: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace
```
- **不引入外部字体/图标 CDN**（离线可用、零新增依赖）；`Inter` 缺失时逐级回退到中文字体。
- 哈希、地址、区块号等技术标识一律用 `--font-mono`。

| 层级 | 字号 / 行高 / 字重 | 用途 |
|---|---|---|
| Display | 30 / 1.2 / 600，`letter-spacing:-0.02em` | 登录页品牌标题 |
| H1 | 24 / 1.3 / 600，`-0.01em` | 页面标题 |
| H2 | 18 / 1.4 / 600 | 区块标题 |
| H3 | 15 / 1.45 / 600 | 卡片内小标题 |
| Body | 15 / 1.65 / 400 | 正文（基准 15px，非 14px） |
| Small | 13 / 1.55 / 400 | 辅助说明 |
| Caption | 12 / 1.5 / 500，`letter-spacing:0.02em` | 标签、表头、时间戳 |

---

## 4. 间距 / 圆角 / 阴影 / 动效

- **间距**（4 的倍数）：`4 / 8 / 12 / 16 / 24 / 32 / 48 / 64` → `--sp-1…--sp-8`。卡片内边距 24px、卡片间距 24px、页面左右边距 24px（窄屏 16px）。
- **圆角**（收敛）：`--r-sm:2px`（标签/输入）· `--r-md:4px`（按钮）· `--r-lg:6px`（卡片）。**禁止 ≥12px 的胶囊与大圆角**（`border-radius:999px` 仅允许真正的圆点）。
- **阴影**：`--shadow-1: 0 1px 2px rgba(24,26,27,.05)`（默认）· `--shadow-2: 0 2px 8px rgba(24,26,27,.06)`（浮层）。**卡片默认可有可无，靠边框区分层次**。
- **动效**：`--dur-1:120ms`（悬停/按下）· `--dur-2:180ms`（展开/淡入）· `--dur-3:240ms`（页面级）。缓动 `--ease: cubic-bezier(.2,.7,.3,1)`。
  - 只用 `opacity` 与 `transform`，**不动 `width/height`**（进度条除外，用 `transition: width`）。
  - 页面进入：内容整体 `opacity 0→1` + `translateY(4px→0)`，错落间隔 40ms，不做整页飞入。
  - 必须支持 `prefers-reduced-motion: reduce`（已在 `style.css` 末尾统一降级）。

---

## 5. 应用骨架

```
.app-shell   = 左侧 .sidebar (232px, 深色 --ink) + 右侧 (.topbar + .main)
.sidebar     : .brand(品牌) + .nav-group(分组) + .nav-item(项，选中用左侧 2px 莫兰迪蓝 + 浅色文字)
.topbar      : 左=面包屑/页面名，右=用户身份 .user-role + 钱包状态 + 退出
.main        : .page-header(.page-title + .page-desc + .page-actions) + 内容区 .stack
```
- 侧边栏仅用于**应用内页面**（dashboard / create-voting / results / weight / wallet…）；登录页 `index.html` 使用居中的 `.auth-card`，**不套壳**。
- 窄屏（≤900px）侧边栏折叠为顶部横向滚动条；`.main` 边距降为 16px。

---

## 6. 组件规范（class 名与状态）

| 组件 | class | 状态 |
|---|---|---|
| 按钮 | `.btn`（主/莫兰迪蓝）· `.btn-secondary`（中性）· `.btn-ghost` · `.btn-danger` · `.btn-small` · `.btn-block` | default / hover / **active** / `disabled` / `.is-loading` |
| 输入 | `.input` · `.field` · `.field-hint` · `.field-error` | 默认 / `:focus-visible`（焦点环 3px 浅雾蓝）/ `.is-invalid` |
| 卡片 | `.card` · `.card-head` · `.card-body` | — |
| 表格 | `.table` · `.table th/td` | 行 `:hover` = `--surface-2`；选中行 `--accent-soft` |
| 状态标签 | `.badge` + `.badge.is-ok/.is-warn/.is-danger/.is-info/.is-neutral` | 文字 + 底色 + 内联 SVG |
| 阶段徽章 | `.phase-badge` + `.commit` / `.scoring` / `.completed`（`.results` 为兼容别名） / `.cancelled` | 必须同时有文字 |
| 流程指示 | `.steps` · `.step` (`.is-done`/`.is-current`/`.is-todo`) | 当前步用莫兰迪蓝，完成步用成功色 |
| 统计 | `.stat-item`（浅）· `.stat-card`（深色 ink）· `.stat-number` · `.stat-label` | 数字变化 240ms 计数 |
| 空/载/错 | `.empty-state` · `.loading` · `.alert`（`.alert.is-ok/is-warn/is-danger/is-info`） | 三态必须齐备 |
| 键值展示 | `.kv` · `.kv-k` · `.kv-v`（等宽） | 用于哈希、地址、交易号 |
| 通知 | `.toast`（新）· 兼容 `zk-utils.js` 的 `.zk-notification` | — |

> **JS 耦合（禁止改名）**：`.tab-btn`+`.active` · `.phase-badge {phase}` · `.user-role {role}` ·
> `.activity-item {status}` · `.activity-status {status}` · `.committed-badge` · `.scored-badge` ·
> `.result-bar`+`.winner` · `.zk-notification-{type}`。

---

## 7. 图标

- **一律使用内联 SVG**：`viewBox="0 0 24 24"`、`fill="none"`、`stroke="currentColor"`、
  `stroke-width="1.5"`、`stroke-linecap="round"`、尺寸 `20/16px`。
- **禁止 emoji 充当功能图标**（`🔐🔗💰📊➕📋🎯📝🏆🔧` 等全部替换）。
- 不引入图标库依赖；图标以 `.icon` 包裹并继承 `currentColor`。

---

## 8. 业务状态语言（本系统的动画主线）

| 阶段 | 界面语言 | 禁止 |
|---|---|---|
| 评审初始化 / 建活动 | 步骤指示器第 1 步高亮；按钮 `.is-loading` | 全屏动画 |
| 权重配置 | 表格行内编辑，变更行淡底 | 弹跳、发光 |
| 数据提交与密封 | 步骤 2；进度条平滑推进；成功徽章 `.badge.is-ok` | 粒子爆炸 |
| 密封数据验证 | 校验结果用 `.alert` + 文字（**不得以动效暗示未完成的验证已成功**） | 虚假成功态 |
| 结果揭示 / 恢复 | 步骤 4；结果条 `width` 过渡 240ms | 数字乱跳特效 |
| 链上交易确认 | `.kv` 展示交易哈希（等宽可复制）+ 状态徽章；确认后徽章才变成功 | 把哈希铺满页面 |
| 流程完成 | `.phase-badge.completed` + 成功色 | — |

**铁律**：动画只表达**真实**业务状态；任何密码学验证/链上确认未真正返回成功前，
界面不得呈现成功视觉。专业信息（哈希/区块号）**按需展示**，不常驻视觉焦点。

---

## 9. 无障碍与响应式

- 正文对比度 ≥ 4.5:1；焦点必须可见（`:focus-visible` 3px 浅雾蓝环）。
- 可点击元素最小 44×44px（`.btn-small` 视觉可小，但外扩热区）。
- 断点：`≤900px` 侧栏折叠；`≤768px` 网格单列、表单行换行；`≤480px` 边距 16px。
- 禁止横向滚动；`prefers-contrast: high` 下加粗边框。

---

## 10. Do / Don't

**Do**：用 token；用留白与细线分层；主操作只有一个莫兰迪蓝按钮；状态用「颜色+文字+图标」三重编码；
微交互只服务反馈；每页保留加载/空/错误三态。

**Don't**：写死 hex；渐变与发光；大圆角胶囊；卡片套卡片；emoji 图标；
用颜色单独表达状态；删掉任何原有业务入口；为美观牺牲响应速度。
