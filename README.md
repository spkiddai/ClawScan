# ClawScan

OpenClaw 安全审计工具。自动采集本机 OpenClaw 运行环境信息，集成 `openclaw security audit` 审计结果，生成结构化 HTML / JSON 安全报告。

---

## 功能

- 采集主机信息（hostname / OS / 扫描时间）
- 检测 OpenClaw 安装状态（npm 优先，再检测 PATH）及运行状态（进程检测）
- 安装且运行时通过 `openclaw config file` 获取准确的配置文件路径
- 解析 `openclaw.json`，提取网关配置、消息渠道（Channels）、模型配置（Models）
- 配置中的环境变量占位符（`${FOO}`）自动识别并显示变量名
- 采集 `openclaw skills list --eligible --json`，展示技能启用与加载状态
- 执行 `openclaw security audit --deep --json`，解析攻击面与风险项
- 风险分级展示：`critical`（红）/ `warn`（橙）/ `info`（蓝）
- 未安装 OpenClaw 时仍可扫描本地残留文件并生成报告
- 输出 HTML 报告（默认自动用浏览器打开）或 JSON 报告

---

## 报告结构

| # | 区块 | 说明 |
|---|------|------|
| 1 | 主机信息 | hostname、OS、Node/NPM 版本、扫描时间 |
| 2 | OpenClaw 信息 | 安装状态、运行状态、版本、主目录、配置文件、网关 IP/端口/监听地址 |
| 3 | 消息渠道 | 渠道名、启用状态、私聊白名单数、群聊白名单数 |
| 4 | 模型配置 | 提供方、模型 URL、模型列表 |
| 5 | 技能配置 | 技能名称、是否启用、允许加载、技能来源 |
| 6 | 攻击面分析 | 提权工具、Hooks、浏览器控制、群组配置等 |
| 7 | 风险列表 | 等级、检查项 ID、标题、描述、修复建议 |

---

## 安装

### 直接下载

从 [Releases](https://github.com/spkiddai/clawscan/releases) 下载对应平台的预编译二进制文件：

| 平台 | 文件 |
|------|------|
| Linux x86_64 | `clawscan-linux-amd64` |
| Linux ARM64 | `clawscan-linux-arm64` |
| macOS x86_64 | `clawscan-darwin-amd64` |
| macOS Apple Silicon | `clawscan-darwin-arm64` |
| Windows x86_64 | `clawscan-windows-amd64.exe` |
| Windows ARM64 | `clawscan-windows-arm64.exe` |

### 从源码构建

```bash
git clone https://github.com/spkiddai/clawscan.git
cd clawscan

# 构建当前平台
make build

# 构建全平台（6 个二进制）
make build-all
```

> 依赖 Go 1.24+

---

## 使用

```bash
# 生成 HTML 报告（默认，自动打开浏览器）
./clawscan -o report.html

# 生成 JSON 报告
./clawscan -o report.json -f json

# 指定 OpenClaw 安装目录
./clawscan -o report.html --openclaw-home /custom/path/.openclaw

# 静默模式（仅返回退出码，不输出任何内容）
./clawscan -o report.html -q

# 不自动打开浏览器
./clawscan -o report.html --no-open

# 查看版本
./clawscan -v
```

### 参数说明

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--output` | `-o` | 自动生成路径 | 报告输出路径 |
| `--format` | `-f` | `html` | 输出格式：`html` / `json` |
| `--openclaw-home` | — | `~/.openclaw` | 指定 OpenClaw 目录 |
| `--no-open` | — | false | 不自动打开浏览器 |
| `--quiet` | `-q` | false | 静默模式，仅返回退出码 |
| `--version` | `-v` | — | 显示版本号 |

---

## 项目结构

```
clawscan/
├── cmd/clawscan/         # 程序入口
├── internal/
│   ├── app/              # CLI 解析与主流程编排
│   ├── collector/        # 信息采集（主机、OpenClaw、渠道、模型、技能）
│   ├── audit/            # 执行 openclaw security audit
│   ├── report/           # HTML / JSON 报告生成
│   │   └── template/     # HTML 模板
│   ├── models/           # 数据结构定义
│   ├── platform/         # 跨平台抽象（进程、服务、路径）
│   └── browser/          # 浏览器打开
├── Makefile
├── go.mod
└── README.md
```

---

## 开发

```bash
# 运行测试
make test

# 清理构建产物
make clean
```

---

## 环境变量

| 变量 | 说明 |
|------|------|
| `OPENCLAW_HOME` | 覆盖 OpenClaw 默认目录（优先级高于 `--openclaw-home`） |
