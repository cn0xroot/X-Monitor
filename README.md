**中文** | [English](./README.en.md)

# X-Monitor

跨平台 AI 编程助手安全监控系统。在 AI Agent 与 LLM 之间、以及操作系统层面,实时发现并拦截危险操作:系统破坏、数据泄露、供应链攻击、持久化后门、以及对监控自身的规避。

设计文档见 [DESIGN.md](./DESIGN.md)。本项目移植了 [cc-monitor](https://github.com/cn0xroot/cc-monitor) 的部分代码(MIT,见 [NOTICE](./NOTICE)),并借鉴 [ArgusBPF](https://github.com/cn0xroot/ArgusBPF) 的设计思路(该仓库未附许可证,未复制其代码)。

**详细使用方法见 [USAGE.md](./USAGE.md)**(安装、接入各个 AI、受管/未受管、仪表盘各页、额度、配置、排错)。

项目进度、验证状态与已知缺口见 [PROGRESS.md](./PROGRESS.md)。

## 为什么需要它

AI 编程助手能自主执行命令、读写文件、发起网络请求。一旦被提示注入劫持,或依赖/脚本本身有问题,就可能 `rm -rf`、把 `.env`/SSH 私钥发往外部、`curl | bash` 装恶意包、写 crontab/git hooks 后门。本工具在这些操作真正发生之前介入。

## 五层架构(底四层零权限、全平台)

| 层 | 作用 | 跨平台 | 权限 | 阻断 |
|---|---|---|---|---|
| L5 意图层 | GLM 语义审计:理解意图、消解误报、识别未知威胁 | ✅ | 无 | 语义级 |
| L4 通信层 | 拦截 Agent↔LLM 的工具调用,改写响应流做事前阻断 | ✅ | 无 | 请求级 |
| L4b Hook | 有原生 Hook 的 Agent(如 Claude Code)直接拦截 | ✅ | 无 | 事前 |
| L3 进程层 | 进程树追踪、会话归属 | ✅ | 无 | 仅监控 |
| L2 文件层 | 敏感文件/工作区变更监控 | ✅ | 无 | 仅监控 |
| L1 系统层 | eBPF / eslogger / Sysmon 内核事件,交叉验证绕过;可选内核级阻断(见下) | 按平台 | root | 增强 |

核心判断发生在 **L4 响应流改写**:Agent 要执行的工具调用出现在 LLM 返回的流里,代理缓冲该调用、交给决策引擎评估,放行则原样下发,拦截则替换成一段说明文本并把 `stop_reason` 改为结束——Agent 不会报错,模型能看到拒绝原因,会话继续。

## 快速开始

```sh
make build          # 产出 bin/xmond bin/xmon bin/xmon-hook(纯 Go,无 cgo)
./bin/xmon start    # 启动守护进程

# 托管方式启动任意 Agent(自动注入代理环境变量)
./bin/xmon run -- claude
./bin/xmon run --agent codex -- codex
./bin/xmon run --agent gemini -- gemini     # Z.ai CLI 同样基于 Gemini CLI

# 打开仪表盘(终端会打印带 token 的地址)
open http://127.0.0.1:7788/?token=...
```

Claude Code 还可以装原生 Hook(事前阻断体验最好,与代理按 tool_call_id 去重):

```sh
./bin/xmon install            # 写入 ~/.claude/settings.json 的 Pre/PostToolUse
```

## CLI

```
xmon start|stop|status            守护进程
xmon run [--agent X] [--sandbox] -- <cmd…>   托管启动 Agent(--sandbox:内核级沙箱)
xmon install [--agent X]          注册 Hook(claude-code | opencode;OpenCode 装好后需重启)
xmon tail [-f] [--risk high]      实时事件流(WebSocket)
xmon rules test "<command>"       看某条命令命中哪条规则
xmon approve <id> | deny <id>     处理审批
xmon pending                      待审批列表
xmon mode active|paused|stopped   介入级别
xmon verify                       校验审计哈希链
xmon import [--from <db>] [-f]     只读导入 CC-Monitor 的 events.db,汇入统一看板
xmon policy init|show|firewall    内核级阻断策略(生成/查看/Windows 防火墙规则)
xmon doctor                       自检(守护进程/token/代理/GLM/正在运行的 AI 及其 Hook 状态)
xmon ui [--open]                  打印/打开带令牌的仪表盘地址
```

### 与 CC-Monitor 并存

X-Monitor 的规则、shell 解析、跨工作区检测、审批台等能力本就移植自 [CC-Monitor](https://github.com/cn0xroot/cc-monitor)(MIT,见 NOTICE)。若你仍在运行 CC-Monitor(继续管 Claude Code 的 Hook),可用 `xmon import` **只读**导入它的审计库(默认 `~/.cc-monitor/events.db`),把事件映射进 X-Monitor 的统一事件模型与哈希链审计,按原始行号去重、`-f` 可后台增量跟随。全程不修改 CC-Monitor 的数据库。

## 仪表盘

`xmon ui --open` 打开。总览、审批台、事件、操作时间线、**会话**、覆盖能力六个页签,右上角可切换中英文;⚙ **外观设置**(沿用 CC-Monitor)可选 **10 套主题**(默认"标准配色",浅色与深色都有)、界面字体(7 种,只引用系统字体名)和字号(12–18px)。事件页有"自动滚动到最新"开关,关闭后列表冻结、新事件只显示计数。

- **检测到的 AI**:来自进程树扫描,列出主机上**所有**正在运行的 AI(不只是 Claude Code),标明受管/未受管、拦截深度、Hook 是否已装,以及下一步该运行的命令。
- **会话 + 心跳**:每个 AI 一行——`xmon run` 受管会话、未受管进程、Hook 上报会话、导入的历史会话。心跳颜色越深、波形越大表示越近有活动,5 分钟内才跳动;状态为 工作中 / 空闲 / 待审批 / 已结束。点击一行查看它的事件。
- 总览里的**每个数字都能点开**看对应的事件。仅监听 127.0.0.1,需要令牌。

## 支持的 Agent

Claude Code、**OpenCode**、Codex、Cursor、Gemini CLI、**Z.ai CLI(= Gemini CLI)**、GLM/CodeGeeX、Aider、Antigravity、Grok CLI 等(进程识别表收录 CC-Monitor 的全部 Agent 定义;其中 Claude Code 与 OpenCode 另有原生 Hook,其余经 `xmon run` 走代理拦截,识别到但未受管的只做进程树观测)。规则按**规范化工具类别**编写(`exec.shell`/`fs.write`/`net.fetch`…),各 Agent 的原始工具名由适配器映射,因此"支持任意 Agent"是架构能力而非逐个硬编码。

协议适配器已实现:Anthropic Messages、OpenAI Chat Completions(含 GLM/智谱/DeepSeek 兼容接口)、OpenAI Responses、**Google Gemini `generateContent`**。

## 决策引擎

规则快路径(<1ms,92 条默认规则含自我保护)→ 会话关联(如"读敏感文件后外连"升级)→ 决策缓存 → GLM 语义分析。合并矩阵保证:**GLM 可以把任何判定升级,但只能在受控条件下把"需确认"降为"放行",规则判定为拦截的它改不了**;送入 GLM 的内容先经 DLP 脱敏,且云端分析默认关闭、需显式开启。

## 隐私

数据默认全部留在本机(SQLite + 防篡改哈希链),代码无遥测。仪表盘默认只绑 `127.0.0.1` 且需要 token。GLM 云端分析是唯一的可选外发,开启后发送前自动脱敏。

## 平台支持

| 能力 | Linux | macOS | Windows |
|---|---|---|---|
| L4 代理 / L4b Hook / L3 进程 / L2 文件 / L5 GLM | ✅ | ✅ | ✅ |
| L1 采集(可选,需特权) | bpftrace(eBPF),需 root | eslogger(exec)+ nettop(网络),需 root | Sysmon 事件日志,需管理员 + 已装 Sysmon |

L1 为可选增强,缺失时核心四层照常工作,仪表盘会显示降级状态。

## 内核级阻断(L1 enforcement)

正则规则没法跑在内核里,所以内核层用一份**静态策略**(`~/.xmon/enforce-policy.json`:禁写路径、禁读路径、禁执行程序),由 `xmon policy init` 生成、可手工编辑。三档机制,**验证状态如实标注**:

| 机制 | 平台 | 作用 | 验证状态 |
|---|---|---|---|
| 托管沙箱 `xmon run --sandbox` | macOS:`sandbox-exec`;Linux:Landlock(内核 ≥5.13) | 对 Agent 整棵进程树做**内核强制**,拒绝是确定性的(不是事后杀进程)。macOS:禁写凭据/启动文件/监控自身目录、禁读监控令牌、禁执行 `nc` 等。Linux(Landlock):**只限制写**——写入只允许在项目目录、临时目录等白名单根之下;读和执行不受限 | macOS:**已测试**(单元测试跑真实沙箱 + 端到端)。Linux:已实现并通过交叉编译与 vet,附带 Linux 上自动运行的测试,**尚未在 Linux 主机上实际运行** |
| exec 后即杀 `probe.enforce: true` | Linux / macOS / Windows(取决于 L1 探针) | 探针看到受管进程树里执行了策略禁止的程序就终止它;只作用于受管进程树,对已在运行的 Agent 也有效。**有毫秒级窗口**(程序已启动才被杀) | 策略匹配与终止逻辑已用真实进程测试;与特权探针联调**未验证** |
| Windows 防火墙锁定 | Windows | `xmon policy firewall` 生成 `netsh` 规则,让指定 Agent 程序只能访问本机回环(即只能经 X-Monitor 代理),防绕过 L4 直连 LLM;默认只打印、`--apply` 才执行 | 命令生成已测试;**未在 Windows 上应用过** |
| macOS ESF AUTH | macOS | `macos/XmonES`:Endpoint Security AUTH 客户端,可在 exec/open/unlink/rename 前同步拒绝 | 源码已通过类型检查并可编译链接;**需 Apple 的 ES entitlement 才能运行,从未实际执行过**(详见 `macos/XmonES/README.md`) |
| Linux BPF-LSM | Linux | — | **未实现**(需要目标内核的 BTF/`vmlinux.h` 与 Linux 上的 clang 才能编译、验证;当前用 Landlock 覆盖托管模式) |

注意:沙箱的拒绝**不能被用户在运行时批准**(与 L4 的"需确认"不同),所以默认策略只覆盖 Agent 没有正当理由去写的位置。`~/.claude` 等 Agent 自身状态目录在 Linux 的 Landlock 模式下必须可写(Landlock 不能在已授权目录里挖例外),其配置文件的篡改防护仍由 L4/Hook 的规则负责。

## 许可证

Proprietary — All Rights Reserved。移植自 cc-monitor / ArgusBPF 的部分见 NOTICE(MIT)。
