**中文** | [English](./USAGE.en.md)

# X-Monitor 使用手册

本文讲怎么用。架构与设计取舍见 [DESIGN.md](./DESIGN.md),已验证到什么程度和已知缺口见 [PROGRESS.md](./PROGRESS.md)。凡是**没有在真实环境验证过**的地方,本文都会直接写明。

## 1. 它是什么

X-Monitor 在 AI 编程助手(Claude Code、Codex、Gemini CLI、OpenCode……)和它要执行的操作之间插一层检查:危险命令、敏感文件读写、外泄、供应链、持久化后门,以及对监控自身的规避。命中规则的操作可以被**事前拦截**、要求**人工确认**,或只**记录**。所有事件写入本机的哈希链审计库,仪表盘只监听 `127.0.0.1` 并需要令牌;默认零遥测,数据不出本机。

## 2. 安装与启动

需要 Go 1.26 以上(纯 Go,无 cgo)。

```sh
make build            # 产出 bin/xmond  bin/xmon  bin/xmon-hook
export PATH="$PWD/bin:$PATH"
xmon start            # 启动守护进程 xmond(后台)
xmon status           # 看守护进程、代理地址、仪表盘地址、规则数
xmon ui --open        # 打印并在浏览器打开带令牌的仪表盘地址
xmon doctor           # 自检,并列出主机上正在运行的 AI 及下一步该做什么
```

- `xmon stop` 停止守护进程;`xmon start --foreground` 前台运行(调试用)。
- 数据目录是 `~/.xmon`(可用环境变量 `XMON_HOME` 改)。令牌在 `~/.xmon/token`。
- `make cross` 检查四个平台(linux amd64/arm64、darwin arm64、windows amd64)都能编译;`make test` 跑测试。

## 3. 先弄懂"受管"

X-Monitor 里一个 AI 有三种状态,仪表盘"总览 → 检测到的 AI"和"会话"页都会标出来:

| 状态 | 含义 | 能做到什么 |
|---|---|---|
| **受管** | 通过 `xmon run` 启动 | `xmon run` 给它注入指向本机代理的 `BASE_URL`,它的每次工具调用经过 L4 代理,在响应流里被事前拦截;还可叠加沙箱 |
| **Hook 拦截** | 没用 `xmon run`,但装了原生 Hook(Claude Code 的 hooks / OpenCode 的插件),且已收到它的 Hook 上报 | 每次工具调用前先问 `xmon-hook`,可事前拦截,不经过代理 |
| **未受管** | 只是被进程树扫描看到 | 只有 L3 进程树、L2 文件、L1 系统层的**观测**,没有事前拦截 |

卡片上还有两个会让人误解的中间态:

- **待重启生效**:插件文件已经写进配置,但还没收到这个 AI 的任何 Hook 上报。大多数 AI 只在启动时加载插件/Hook,**重启它**才会生效。
- 已经在运行的 AI(例如你先开了 opencode 再启动 X-Monitor)不会因为后来装了监控而自动变成"受管"——它的启动环境里没有代理地址。要么用 `xmon run` 重新启动它,要么装 Hook 并重启它。

## 4. 各个 AI 怎么接入

| AI | 推荐接入 | 命令 | 拦截深度 | 验证状态 |
|---|---|---|---|---|
| Claude Code | 代理 + 原生 Hook | `xmon run -- claude`;另装 Hook:`xmon install` | 事前阻断(代理改写响应流;Hook 在工具调用前) | 协议适配器只用合成样本验证过,未对真实 Claude Code 联调 |
| Codex CLI | 代理 | `xmon run --agent codex -- codex` | 事前阻断(OpenAI Chat;**Responses 流式只透传、不拦截**) | 同上 |
| Gemini CLI / Z.ai CLI | 代理 | `xmon run --agent gemini -- gemini` | 事前阻断(Gemini `generateContent`) | 环境变量名与 Z.ai 端点路径未核实 |
| Cursor(CLI)、Aider、GLM、CodeGeeX | 代理(OpenAI 兼容) | `xmon run --agent cursor -- …`(`aider`/`glm`/`codegeex` 同理) | 事前阻断 | 未联调 |
| **OpenCode** | **原生 Hook 插件** | `xmon install --agent opencode`,**然后重启 opencode** | 事前阻断每次工具调用(插件同步调用 `xmon-hook`,退出码 2 即拦截) | 用 node 驱动真实插件对运行中的守护进程验证过;**未在真实 OpenCode 里重启加载验证** |
| 其它未列出的 | 代理(退回 OpenAI 兼容) | `xmon run --agent <名字> -- <命令>` | 取决于它是否遵守 `OPENAI_BASE_URL` | — |
| GUI 桌面端(Cursor 桌面、Windsurf、JetBrains AI……) | 无 | — | **仅观测**(证书固定/不走代理);「覆盖能力」页如实标注 | 配套工具(改配置安装器、MITM)没做 |

**关于 OpenCode 与代理:** OpenCode 的接口地址来自 `opencode.json` 里各 provider 的设置,不是一个 `BASE_URL` 环境变量,而 `xmon run` 没有它的内置档案(会退回只设 `OPENAI_BASE_URL`)。所以对 OpenCode,**请用插件**;让它走代理需要自己把 provider 的 `baseURL` 指到 `http://127.0.0.1:7789/p/<provider>`,这条路径我们没有验证过。

`xmon run` 的细节:

```sh
xmon run [--agent X] [--sandbox] -- <命令…>
```

- 不写 `--agent` 时用命令名当 Agent 名;未知名字会提示并按 OpenAI 兼容处理。
- 它会在需要时自动拉起守护进程,登记一个 `zs_…` 会话,把代理地址注入环境变量(Claude 用 `ANTHROPIC_BASE_URL`,Codex/Cursor/Aider 用 `OPENAI_BASE_URL`,Gemini/Z.ai 用 `GOOGLE_GEMINI_BASE_URL`),并设置 `XMON_SESSION`、`XMON_AGENT`。
- `--sandbox` 另加内核级限制(见第 9 节);请求了沙箱但不可用时**拒绝启动**,不会悄悄不带沙箱运行。
- 守护进程故障时 `xmon run` 目前不会退回直连:配置里有 `proxy.fail_open`,但**没有任何代码读取它**(未实现)。

## 5. 日常使用

### 5.1 介入级别

```sh
xmon mode               # 查看
xmon mode active        # 命中规则就拦截/确认(默认)
xmon mode paused        # 只记录,从不拦截、不弹确认——想先观察时用
xmon mode stopped       # 不介入也不记录
```

仪表盘总览里的分段控件等价。

### 5.2 审批

命中"需确认"的规则时,操作会暂停等你决定,超时(默认 90 秒,`approval.timeout_s`)按**拒绝**处理。三个入口:

- 仪表盘"审批台"页:本次放行 / 本会话放行 / 拒绝;
- 命令行:`xmon pending`,`xmon approve <id>`,`xmon deny <id>`;
- 桌面通知(`approval.desktop_notify: true`)。

> 已知缺口:代理等待审批期间不会向客户端发保活,客户端可能先超时;因为代理目前整段缓冲响应,Agent 此时本来也还没收到任何内容(见 PROGRESS.md 缺口 1、2)。

### 5.3 规则

内置 92 条默认规则(86 条移植自 cc-monitor,6 条自我保护 `xmon_*`)。

```sh
xmon rules test "rm -rf ~"          # 看某条命令命中哪条规则、风险与动作
```

规则分三种动作:`block`(拦截)、`confirm`(人工确认)、`log`(放行并记录)。你的自定义/调整保存在 `~/.xmon/rules.json`,与内置规则合并,**修改后自动热加载**;`rules.defaults_snapshot.json` 是内置规则快照,用来在升级时合并。`downgradable: false` 的规则(如自我保护)不能被降级。

### 5.4 命令行看事件

```sh
xmon tail -f                  # 实时事件流
xmon tail --risk high         # 只看高风险
xmon verify                   # 校验审计哈希链(防篡改)
```

## 6. 仪表盘逐页说明

用 `xmon ui --open` 打开。第一次带令牌访问后,令牌存在浏览器 localStorage 并从地址栏移除;没有令牌时页面会显示"未授权"和令牌输入框。右上角:`⚙` 外观设置、`中 / EN` 语言切换。

- **总览**:状态卡(介入级别、受管会话、待审批、已拦截、防护层状态)→ **检测到的 AI** → 10 类威胁卡 → 活动 → 工具调用 → 趋势 → 分布。**每个数字都能点开**看它统计的事件,有测试保证"卡片数字 = 列表条数"。"受管会话(运行中)"卡点开进入会话页。
- **检测到的 AI**:来自进程树扫描,列出主机上所有正在运行的 AI,标明 受管 / Hook 拦截 / 待重启生效 / 未受管、拦截深度、验证状态,并给出下一步命令(带复制按钮)。
- **审批台**:待处理的确认请求。
- **事件**:实时事件表,可按风险过滤。**"自动滚动到最新"开关**:开着时新事件立刻显示并回到顶部;关掉后列表冻结,新事件只累计成"有 N 条新事件,点击显示"。
- **操作时间线**:每个会话一条泳道,颜色是该时段最坏风险,红框表示有拦截;点泳道或时间槽看**会话操作流程图**(可缩放、平移、有小地图和节点详情)。
- **会话**:所有被监测的 AI 一行一个——受管会话、未受管进程、Hook 上报会话、导入的历史会话,每行带**心跳**。心跳颜色越深、波形越大表示越近有活动;只有 5 分钟内才会跳动。状态:工作中 / 空闲 / 待审批 / 已结束。点一行看它的事件。
  - 受管会话用根进程号判断存活;只通过 Hook 上报的会话没有进程号,存活是**启发式**的(该 AI 有进程在跑,或 5 分钟内有活动)。
- **状态**:账号额度、模型使用统计、会话状态板(见第 7 节)。
- **覆盖能力**:每种 AI 能被拦截到什么深度,以及为什么。
- **外观设置(⚙)**:10 套主题(默认"标准配色",浅色与深色都有)、界面字体 7 种、字号 12–18px、恢复默认。字体只引用系统字体名,不下载任何字体;没安装的字体会退回备选。

## 7. 状态页与额度

状态页有三块:

1. **账号额度**:Anthropic 套餐的 5 小时窗口和每周额度(含按模型的限额、额外花费)。进度条配色方案可选。**默认开启**,风险见下。
2. **模型使用统计**:按模型汇总被审计的工具调用次数、拦截数、涉及会话和 Agent。**不统计 token**——代理只改写工具调用,不计量用量。模型只在经代理(`xmon run`)的请求里才会记录,Hook 上报没有这个信息。
3. **会话状态**:每个 AI 一张卡:心跳、目录、Git 分支、事件与拦截数、最后活动;点击看事件。

### 账号额度(默认开启,请先读风险)

不想要时,在 `~/.xmon/config.yaml` 加:

```yaml
usage:
  anthropic_enabled: false
```

然后 `xmon stop && xmon start`。开启时守护进程会读取本机 Claude Code 的 OAuth 登录令牌(Linux/其它:`~/.claude/.credentials.json`;macOS 另读钥匙串项 `Claude Code-credentials`,第一次会弹系统确认框),向 `api.anthropic.com/api/oauth/usage` 发一次只读请求,结果缓存 3 分钟。

- 令牌只在内存里用于这一次请求,只发给 Anthropic 的这个固定地址(**地址不可配置**,改配置文件无法把令牌送到别处),不写盘、不进日志、不会出现在任何接口返回里。
- 这是 CC-Monitor 和 ccstatusline 用的**非公开、逆向得到**的接口,可能随时变化;用订阅令牌给第三方工具查询**也可能不符合服务条款**,是否开启请自己判断。
- 令牌过期时不会发送,页面会提示在 Claude Code 里跑一次命令刷新或 `/login`。
- 没有 Anthropic 以外的额度来源:其它服务商(含 Z.ai)没有实现,也没有编造。
- **验证状态:** 客户端用本地假服务器测试过(请求头、解析、缓存、过期令牌不发送、错误里不含令牌);**没有用真实凭证对真实 Anthropic 接口运行过**,页面渲染用的是按其响应形状构造的样例数据。

## 8. 导入 CC-Monitor

如果你仍在用 CC-Monitor(继续管 Claude Code 的 Hook),可以把它的审计库**只读**导入:

```sh
xmon import                          # 默认 ~/.cc-monitor/events.db
xmon import --from /path/to/events.db
xmon import -f                       # 后台增量跟随
```

按原始行号去重,事件映射进统一事件模型并并入哈希链;全程不修改对方的数据库。导入的会话在"会话"页显示为"导入",在时间线里是 `ext:` 泳道。

## 9. 内核级阻断(可选)

代理与 Hook 之外的最后一道防线:即使 Agent 绕开了工具调用,系统层仍能限制它。

```sh
xmon policy init            # 生成 ~/.xmon/enforce-policy.json(可编辑)
xmon policy show            # 查看策略和当前平台的沙箱可用性
xmon run --sandbox -- claude
xmon policy firewall        # 生成 Windows 防火墙(netsh)命令,只打印,不执行
```

| 档位 | 平台 | 状态 |
|---|---|---|
| `sandbox-exec` 沙箱 | macOS | **已实测** |
| Landlock | Linux | 只做过编译与类型检查,**没有在 Linux 上运行过**;只限制写,不限制读和执行 |
| exec 后即杀(`probe.enforce: true`) | 需要 L1 探针(root) | 有毫秒级窗口,未实机验证 |
| Windows 防火墙规则 | Windows | 只生成命令,**从未应用过** |
| macOS ESF AUTH 客户端 | macOS | 通过编译和链接,**没有 entitlement 无法运行** |
| BPF-LSM | Linux | **没做** |

L1 系统层采集(bpftrace / eslogger+nettop / Sysmon)由 `probe.enabled`(`auto`|`off`)控制,需要 root。

## 10. 配置参考

文件:`~/.xmon/config.yaml`,样例见 [config.sample.yaml](./config.sample.yaml)。改完需要重启 `xmond`(规则文件是例外,会热加载)。

| 键 | 默认 | 说明 |
|---|---|---|
| `mode` | `active` | `active` / `paused` / `stopped` |
| `ui_addr` | `127.0.0.1:7788` | 仪表盘;非回环地址必须带令牌 |
| `proxy_addr` | `127.0.0.1:7789` | LLM 代理 |
| `proxy.fail_open` | `false` | **未实现**:配置项存在,但目前没有代码使用 |
| `proxy.dlp_action` | `alert` | 凭据即将发给模型时:`alert` 告警 / `redact` 脱敏 |
| `proxy.routes.<名字>` | 见代码 | 覆盖各服务商的上游地址 |
| `proxy.confirm_ping_s` | `10` | **未实现**:审批等待期间的保活间隔,目前没有代码使用 |
| `glm.enabled` | `false` | 语义审计(L5),**默认关**;开启后需 `ZAI_API_KEY`,会把(脱敏后的)操作发给 Z.ai |
| `approval.timeout_s` | `90` | 确认超时按拒绝处理 |
| `approval.desktop_notify` | `true` | 桌面通知 |
| `storage.retention_days` / `max_events` | `30` / `1000000` | 保留期与上限 |
| `probe.enabled` / `probe.enforce` | `auto` / `false` | L1 探针与 exec 后即杀 |
| `usage.anthropic_enabled` | `true` | 状态页账号额度,见第 7 节 |

环境变量:`XMON_HOME`(数据目录)、`XMON_STRICT=1`(`xmon-hook` 连不上守护进程时**拒绝**而不是放行)、`XMON_HOOK`(覆盖 OpenCode 插件里 `xmon-hook` 的路径)、`XMON_SESSION` / `XMON_AGENT`(`xmon run` 注入)。

## 11. 数据与隐私

`~/.xmon/` 下:`events.db`(审计库,哈希链)、`config.yaml`、`token`、`rules.json`、`xmond.log`、`enforce-policy.json`、`tracked-roots.json`,以及 `xmond.sock` / `hook.sock`(本地套接字)。

- 数据只留本机;不开 GLM、并关闭账号额度(默认开启)就不会有任何出站请求(代理转发 Agent 自己的 LLM 流量不算)。
- 仪表盘只绑定 `127.0.0.1`,所有接口和 WebSocket 都要令牌。
- 监控自己的配置与数据受保护:Agent 写/删 `~/.xmon` 会被 `xmon_self_*` 规则直接拦截。

## 12. 排错

| 现象 | 原因与办法 |
|---|---|
| 仪表盘一片空白 / "未授权" | 缺令牌。运行 `xmon ui --open`,或把 `~/.xmon/token` 粘到页面的输入框 |
| 页面提示无法连接 xmond | `xmon status` 看守护进程;`xmon start` |
| 本机设了 `HTTP_PROXY` 后 `curl` 访问 `127.0.0.1` 失败 | 加 `--noproxy '*'` 或设 `NO_PROXY=127.0.0.1` |
| AI 显示"未受管" | 见第 3 节:用 `xmon run` 启动,或装 Hook 并重启它 |
| 显示"待重启生效" | 重启那个 AI,让它加载插件 |
| 装了 OpenCode 插件还是没拦截 | 确认 `~/.config/opencode/plugins/xmon.js` 存在、opencode 已重启、守护进程在运行(守护进程不可达时默认放行,设 `XMON_STRICT=1` 改为拒绝) |
| 总览里"系统层观测"数字一直在涨 | L3 会把你当前 AI 会话的整个进程树都记作观测事件,属正常现象 |
| 回复要等整段生成完才出现 | 已知缺口:代理整段缓冲 SSE 后才改写转发(PROGRESS.md 缺口 1) |
| Unix 套接字路径过长报错 | `XMON_HOME` 设短一点(套接字路径需短于 104 字符) |

## 13. 目前不能指望的

完整清单与优先级见 [PROGRESS.md](./PROGRESS.md),最重要的几条:协议适配器只用合成数据验证过;Linux 与 Windows 代码没在对应系统上运行过;代理非流式;GUI 桌面端只有观测;OpenCode 走代理、账号额度对真实接口都没有验证。
