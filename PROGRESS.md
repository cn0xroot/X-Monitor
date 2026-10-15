**中文** | [English](./PROGRESS.en.md)

# X-Monitor 项目进度

> 版本 `v0.1.0-dev` · 更新于 2026-10-14 · 设计见 [DESIGN.md](./DESIGN.md) · 用法见 [README.md](./README.md)

本文档只记录**事实**:做了什么、验证到了什么程度、还缺什么。设计意图和实际落地不一致的地方,在这里以实际为准。

## 状态图例

| 标记 | 含义 |
|---|---|
| ✅ | 已实现,并在本机(macOS)实际运行验证过 |
| 🟡 | 已实现且能编译,但**没有在目标环境实际运行过**(缺平台、缺特权或缺 entitlement) |
| 🔶 | 部分实现,有已知缺口(见「已知缺口」) |
| ⬜ | 未开始 |

## 先说最重要的两点

1. **所有协议适配器都只用合成的 SSE 样本验证过,从未对真实的 Claude Code / Codex / Gemini CLI,或真实上游 API 跑过。** 端到端测试里的"上游"是我写的假服务。真实流里可能出现样本没覆盖的事件形态(thinking 块、签名增量、ping 等;适配器对未知事件是原样透传,但没有被真实流验证)。
2. **只在一台 macOS 上跑过。** Linux 和 Windows 的代码都只做了交叉编译和 `go vet`,没有在对应系统上运行过。

## 总览

| 项 | 数据 |
|---|---|
| Go 包 | 28 个(`internal/`),3 个二进制(`xmon` / `xmond` / `xmon-hook`) |
| 代码量 | 非测试约 11.8k 行,测试约 3.5k 行 |
| 测试 | 116 个 Go 测试 + 3747 条前端断言(`web/timeline_test.js`)全部通过(macOS);真实 Chrome 驱动脚本点击 30 个下钻目标 0 失败(脚本在 /tmp,未纳入仓库) |
| 默认规则 | 92 条(移植 cc-monitor 86 条 + 6 条自我保护) |
| 交叉编译 | linux/amd64、linux/arm64、darwin/arm64、windows/amd64 均通过 |
| 依赖 | 纯 Go、无 cgo;gorilla/websocket、fsnotify、modernc sqlite、regexp2、yaml.v3 |

详细使用方法见 [USAGE.md](./USAGE.md)。

## 路线图对照(DESIGN.md §21)

| 阶段 | 计划内容 | 实际状态 |
|---|---|---|
| P1 MVP | 事件模型、存储、规则、CLI、进程树、L4 代理、托管启动、Hook、文件监控 | ✅ 已完成(代理有流式缓冲缺口,见下) |
| P2 UI + GLM | Web UI、审批台、GLM 引擎、会话关联、DLP | 🔶 已实现;GLM 只对本地假服务器测过;UI 未在真实浏览器里点过 |
| P3 增强层 | Linux eBPF、macOS ESF、Windows ETW、交叉验证、MITM | 🔶 见下表:采集用子进程后端,**没有**自写 eBPF/ESF/ETW 内核采集;MITM 未做 |
| P4 高级功能 | 会话回放、网络地图、集中管理、SIEM、GLM 报告 | ⬜ 未开始(Responses/Gemini 适配器已提前做了) |

## 按模块进度

### 核心判断链路

| 模块 | 状态 | 说明 |
|---|---|---|
| 规则引擎(`internal/rules`) | ✅ | RE2 优先,Python 专有语法(前瞻)回退带超时的回溯引擎;用户规则与默认规则合并、热更新。移植了 cc-monitor 的回归测试 |
| shell 解析 / 跨工作区检测 | ✅ | 移植自 cc-monitor(引号/heredoc 感知、剥 sudo/env、递归 `bash -c`)。macOS 路径已适配 |
| 决策引擎(`internal/decide`) | ✅ | 规则快路径 → 会话关联 → 缓存 → GLM。测试证明 GLM 不能推翻规则的拦截 |
| 会话关联 | ✅ | 目前只有"读敏感信息后外连"(`read_then_egress`)和提示注入污点两条序列规则 |
| GLM 客户端(`internal/glm`) | 🟡 | 防注入 prompt、schema 校验、熔断、脱敏已实现,并用本地假 HTTP 服务测过请求形状、脱敏、超时、熔断、非法输出被拒;**没有对真实 Z.ai 接口调用过** |
| DLP(`internal/dlp`) | ✅ | 常见密钥格式检测与脱敏 |
| 工具归一化(`internal/toolclass`) | ✅ | Claude Code / Codex / Cursor / Gemini 的工具名映射;`apply_patch` 展开为逐文件调用 |

### 拦截层

| 层 | 状态 | 说明 |
|---|---|---|
| L4 代理:Anthropic Messages | 🔶 | 流改写已用合成样本端到端验证;**缺口:整段缓冲**(见下) |
| L4 代理:OpenAI Chat(含 GLM/智谱/DeepSeek 兼容) | 🔶 | 同上 |
| L4 代理:Gemini `generateContent`(Z.ai CLI) | 🔶 | 同上;Z.ai 的 Gemini 端点路径是按命名惯例推断的,**未核实** |
| L4 代理:OpenAI Responses | 🔶 | 非流式可改写;**流式只透传,不做拦截** |
| L4b Hook(Claude Code) | 🟡 | `xmon-hook` + UDS 网关 + 与代理按 `tool_call_id` 去重已实现;**未对真实 Claude Code 验证**(含 hook 输入字段名,如 `tool_use_id`) |
| L3 进程树 | ✅ | `ps` 轮询 + 向下传播标记。轮询抓不到毫秒级短命进程(设计已声明) |
| L2 文件监控 | 🔶 | fsnotify;**缺口:只监控守护进程启动时的工作目录,不跟随各会话的项目根** |
| 交叉验证(`internal/correlate`) | ✅ 逻辑 / 🟡 联调 | 绕过检测逻辑有测试;与特权 L1 探针联调未验证 |

### L1 系统层

| 项 | 状态 | 说明 |
|---|---|---|
| Linux 采集(bpftrace 子进程) | 🟡 | 脚本和解析已写,需 root + bpftrace;**没在 Linux 上跑过** |
| macOS 采集(eslogger exec + nettop 网络) | 🟡 | 需 root;未用特权实际跑过 |
| Windows 采集(Sysmon 事件日志) | 🟡 | 需管理员 + 已装 Sysmon;**没在 Windows 上跑过** |
| 托管沙箱:macOS `sandbox-exec` | ✅ | 真实沙箱的单元测试 + 端到端(模拟 Agent 写凭据/读令牌/删监控目录/跑 `nc` 均被内核拒绝) |
| 托管沙箱:Linux Landlock | 🟡 | 已实现,附带 Linux 上自动运行的测试;**没在 Linux 主机上跑过** |
| exec 后即杀 | ✅ 逻辑 / 🟡 联调 | 用真实进程测过;有毫秒级窗口;与特权探针联调未验证 |
| Windows 防火墙锁定(`netsh`) | 🟡 | 命令生成有测试;**没在 Windows 上应用过** |
| macOS ESF AUTH 客户端 | 🟡 | 源码类型检查、编译、链接通过;**需 Apple ES entitlement 才能运行,从未执行** |
| Linux BPF-LSM | ⬜ | 未做(需要目标内核 BTF 与 Linux 上的 clang) |

### 周边能力

| 模块 | 状态 | 说明 |
|---|---|---|
| 存储 + 哈希链(`internal/store`) | ✅ | SQLite、哈希链校验、保留期清理 |
| 审批台(`internal/approval`) | 🔶 | 通道:Web、CLI、桌面通知;**缺口:代理等待审批期间不发保活**(见下) |
| Web UI(`web/`) | ✅ | 单文件仪表盘 + WebSocket;总览(参照 CC-Monitor 首页:状态卡、介入级别、10 类威胁、活动、趋势、分布,**每个数字可点开看明细**,有 Go 一致性测试保证)、操作时间线与会话流程图(移植 CC-Monitor)、**会话列表 + 心跳**、**检测到的 AI**、10 套主题(默认"标准配色",移植 CC-Monitor)、中英双语(309 词条对齐)、外观设置弹窗(主题色块 / 7 种界面字体 / 12–18px 字号,仅用系统字体名,不下载任何字体)、事件页"自动滚动到最新"开关。已在真实 Chrome 里驱动验证 |
| 多 AI 检测与 OpenCode Hook | 🔶 | `internal/agents` 收录 CC-Monitor 的 10 个 Agent 定义 + OpenCode;L3 首轮扫描也上报已在运行的 Agent;`/api/detected`、`xmon doctor` 列出并给出下一步命令;`xmon install --agent opencode` 写入插件(幂等)。**已用 node 驱动真实插件对运行中的守护进程验证阻断/放行/入库;未在真实 OpenCode 里重启加载过** |
| 状态页(账号额度 / 模型统计 / 会话板) | 🔶 | 模型统计:代理把请求模型记入审计事件(Gemini 从路径取),按模型聚合工具调用数,**不统计 token**;会话板含 Git 分支;账号额度见 `internal/usage`——**默认开启**(`usage.anthropic_enabled: false` 关闭),读取本机 Claude Code OAuth 令牌查询非公开接口,端点写死不可配置,令牌不落盘不进日志。**客户端只用本地假服务器测过,未对真实接口跑过** |
| 会话列表与心跳(`internal/sessionview`) | 🔶 | 覆盖**所有** AI:`xmon run` 受管会话、主机上未受管进程、原生 Hook 上报会话、CC-Monitor 导入历史;工作中(5 分钟内有活动)/空闲/待审批/已结束四态。**局限:仅 Hook 上报的会话没有进程号可查,存活判断是启发式(该 Agent 有进程在跑,或 5 分钟内有活动)** |
| CLI(`xmon`) | ✅ | start/stop/status/run/install/tail/rules/approve/pending/mode/verify/import/policy/doctor |
| CC-Monitor 只读导入(`xmon import`) | ✅ | 去重、哈希链并入、端到端验证 |
| GUI 客户端识别 + 能力分级 | 🔶 | 识别与「覆盖能力」标注已实现;**配套工具没做**(见下) |
| 双语文档 | ✅ | README / PROGRESS 中英文;DESIGN.md 仅中文 |

## 已知缺口

按影响从大到小。前三条会直接影响日常使用,建议优先处理。

| # | 缺口 | 影响 | 位置 |
|---|---|---|---|
| 1 | **代理整段缓冲 SSE 后才改写转发**,不是边收边转 | 所有受管 Agent 的回复要等模型完整生成后才一次性出现,交互延迟明显;长回复可能触发客户端超时。DESIGN §7.4 描述的"文本即时流出、只缓冲工具调用"**没有实现** | `internal/proxy/server.go`(`io.ReadAll(resp.Body)`),适配器接口也是接收完整 `[]byte` |
| 2 | **审批等待期间代理不发保活**,`proxy.confirm_ping_s` 配置项没有任何代码使用 | 需要人工确认时,Agent 一侧的连接静默等待最长 90 秒,可能被客户端超时断开;而且因为缺口 1,此时客户端本来就什么都没收到 | `internal/gate`、`internal/proxy` |
| 3 | **GUI 档位的配套工具没做**:没有"改应用配置指向代理"的安装器(`xmon install` 目前只支持 Claude Code 与 OpenCode),也没有系统代理 + 选择性 MITM | 「覆盖能力」页里 `config` / `proxy` 档描述的是**理论上可达到**的程度,目前没有工具能实际达到;GUI 客户端实际只有观测 | `cmd/xmon/install.go`、(无 MITM 代码) |
| 4 | OpenAI Responses 流式只透传 | 使用该协议且开流式的 Agent,工具调用**不会被拦截** | `internal/proxy/adapter_responses.go` |
| 5 | L2 文件监控只覆盖守护进程启动目录 | 其它项目目录里的敏感写入不会被 L2 看到 | `cmd/xmond/main.go` |
| 6 | 外部事实未核实:Z.ai Gemini 端点路径(`api/geminiv1beta`)、`glm-4.5` 模型 ID 与 `thinking` 参数、`GOOGLE_GEMINI_BASE_URL` 环境变量名、Claude Code hook 输入字段 | 对应功能在真实环境可能需要调整配置 | `internal/config/config.go`、`cmd/xmon/run.go` |
| 7 | 代理客户端 PID 反查靠每次请求调用 `lsof` | 请求量大时有额外开销;Windows 无此实现 | `internal/proxy/pidlookup.go` |
| 8 | Hook 的 `post` 阶段只做确认,不做审计分析 | 工具执行结果不参与判断 | `internal/hookgw` |
| 9 | Linux Landlock 只限制写,读和执行不受限;`~/.claude` 等必须可写 | 沙箱防护面比 macOS 窄;Agent 配置文件的篡改防护仍靠 L4/Hook | `internal/enforce/landlock_linux.go` |
| 10 | `AUTH_RENAME` 只检查源路径 | ESF 客户端对重命名到受保护路径不设防 | `macos/XmonES/main.swift` |
| 11 | **`proxy.fail_open` 配置项没有任何代码读取** | 文档/样例里写着"守护进程故障时退回直连",实际不会;守护进程挂了,`xmon run` 启动的 Agent 的 LLM 请求会失败 | `internal/config/config.go`、`cmd/xmon/run.go` |
| 12 | OpenCode 经代理没有内置档案,也未验证 | `xmon run --agent opencode` 只会设 `OPENAI_BASE_URL`;OpenCode 的接口地址来自 `opencode.json` 的 provider 设置。目前对 OpenCode 只有原生 Hook 插件这一条可靠路径 | `cmd/xmon/run.go` |
| 13 | 账号额度没有用真实凭证对真实接口跑过 | 客户端用本地假服务器测过;`/api/oauth/usage` 是非公开接口,可能变化 | `internal/usage` |

## 下一步（建议优先级）

**P0 — 影响可用性**
1. 把代理改成真正的流式转发:适配器改为读 `io.Reader`,文本事件即时下发,只缓冲 `tool_use` 块(缺口 1)。
2. 审批等待期间的 SSE 保活(缺口 2)。

**P1 — 补齐宣称的能力**
3. OpenAI Responses 流式拦截(缺口 4)。
4. L2 跟随各会话的项目根(缺口 5)。
5. 用真实 Claude Code / Gemini CLI / Codex 做一次联调,核实缺口 6 的外部事实。
6. 在 Linux 主机上跑 `go test ./internal/enforce/` 和 `xmon run --sandbox` 端到端;跑通 bpftrace 探针。
7. GUI 档位的配套工具:Cursor 等支持自定义端点的客户端的配置安装器;系统代理 + 选择性 MITM(含证书固定探测与自动降级)。

**P2 — 增强**
8. Windows 实机验证(Sysmon 探针、防火墙锁定)。
9. 申请 Apple ES entitlement,实机验证 `XmonES`。
10. Linux BPF-LSM。
11. 会话回放、GLM 报告、SIEM 导出、集中管理。

## 阶段记录

| 阶段 | 内容 |
|---|---|
| 设计 | 研读 cc-monitor 与 ArgusBPF,评审需求方案(修正了"拦截请求而非响应"等 10 余处问题),输出 DESIGN.md |
| 核心实现 | 事件模型、规则引擎(移植 cc-monitor)、shell 解析、跨工作区检测、决策引擎、GLM、DLP、存储与哈希链、审批台 |
| 拦截层 | L4 代理(Anthropic / OpenAI Chat / Responses / Gemini)、L4b Hook、L3 进程树、L2 文件、交叉验证 |
| L1 采集 | bpftrace / eslogger+nettop / Sysmon 子进程后端(子代理并行完成 macOS nettop 与 Windows 部分) |
| 体验与生态 | Web UI、CLI、GUI 客户端识别与能力分级、CC-Monitor 只读导入 |
| 改名与双语 | 统一为 X-Monitor / `xmon` / `~/.xmon`;README 与 Web UI 中英双语 |
| 多 AI 与可视化 | 会话列表与心跳、检测到的 AI、OpenCode 插件、10 套主题、dataviz 配色校验(见下) |
| 内核级阻断 | 静态策略、macOS 沙箱(已实测)、Linux Landlock、exec 后即杀、Windows 防火墙规则、ESF AUTH 客户端、`tracked-roots.json` |

## 本阶段修复的主要问题

这些都是真实跑起来才发现的,均有回归测试,**不要回退**:

- **L2 文件监控反馈环**:监视自己的 `~/.xmon` 导致 100 万事件。现忽略自身文件、同路径 500ms 防抖、全局限流(超限发一条 `fs_event_storm`),守护进程写配置前预告。
- **会话归因失效**:`xmon run` 发送的 `RootPID` 被静默丢弃。现抽出 `internal/ctlproto`,两端共用类型,守护进程严格解码。
- **L3 把自己的 `ps` 轮询算作 Agent 子进程**:现排除守护进程整棵子树。
- **Web UI 无令牌时一片空白**:现显示"未授权"并提供令牌输入;令牌存 localStorage 并从地址栏清除。
- **活动卡片等数字点不开**:现全部可下钻,`TestEveryOverviewNumberMatchesItsDrillDown` 保证"卡片数字 = 列表条数"。
- **`todowrite` 被当成文件写入**、**opencode 的工具名/字段别名**:已在 `toolclass` 修正。
- **Agent 辅助进程被当成第二个 Agent**(opencode 的常驻 `opencode.exe serve`):同类 Agent 的子进程归入父进程树。
- **Hook 上报的实时会话被标成"导入/已结束"**:现区分 `hook` 与 `imported`。

## 配色校验(dataviz)

图表的类别色(`--cat-1..6`)分浅色/深色两套,用 dataviz 的 `validate_palette.js` 在实际用到的表面色上验证:浅色套在"标准配色"面板色和白色上全部通过;深色套在 dark / dracula / midnight / ocean / forest / sunset / rose 的面板色上全部通过;**Nord 的中间调面板(#3b4252)上对比度检查为 WARN(<3:1)**,靠带文字标签的条形图与表格弥补。KPI 数字一律用墨色,状态由"图标 + 文字"的胶囊表达,不再只靠颜色。

## 来源与许可

移植自 [cc-monitor](https://github.com/cn0xroot/cc-monitor)(MIT):规则集、shell 分段解析、跨工作区检测、审批与规则合并思路、交叉验证思路、**操作时间线 / 会话流程图 / 心跳指示器 / 主题配色 / OpenCode 插件协议**(`web/timeline.js`、`internal/agentcfg`、`internal/sessionview` 为按其设计重写或移植)。借鉴 [ArgusBPF](https://github.com/cn0xroot/ArgusBPF) 的**设计思路**(Agent 签名、采集降级、事件模型):该仓库没有附带许可证文件,因此本项目**没有复制它的任何代码**,相关实现均为重写。详见 [NOTICE](./NOTICE)。
