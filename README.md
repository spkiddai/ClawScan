# ClawScan

OpenClaw 安全审计工具。自动采集本机 OpenClaw 运行环境信息，集成 `openclaw security audit` 审计结果，生成结构化 HTML / JSON 安全报告。

---

## 功能

- 采集主机信息（hostname / OS / 架构 / 扫描时间）
- 扫描 OpenClaw 本地安装情况（目录、配置文件、工作目录、版本）
- 解析 `openclaw.json`，提取网关配置、消息渠道（Channels）、模型配置（Models）
- 执行 `openclaw security audit --deep --json`，解析攻击面与风险项
- 风险分级展示：`critical`（红）/ `warn`（橙）/ `info`（蓝）
- 未安装 OpenClaw 时仍可扫描本地残留文件并生成报告
- 输出 HTML 报告（默认自动用浏览器打开）或 JSON 报告

---

## 报告结构

| # | 区块 | 说明 |
|---|------|------|
| 1 | 主机信息 | hostname、OS、CPU 架构、扫描时间 |
| 2 | OpenClaw 信息 | 版本、主目录、配置文件、工作目录、网关 IP/端口/监听地址 |
| 3 | 消息渠道 | 渠道名、状态、私聊白名单、群聊白名单 |
| 4 | 模型配置 | 提供方、模型 URL、模型列表 |
| 5 | 攻击面分析 | 提权工具、Webhook 钩子、内部钩子、浏览器控制、信任模型 |
| 6 | 风险列表 | 等级、检查项 ID、标题、描述、修复建议 |

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

### 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 无风险或仅有提示 |
| `1` | 存在警告级（Info）风险 |
| `2` | 存在警告级（Warning）风险 |
| `3` | 存在严重（Critical）风险 |

---

## 项目结构

```
clawscan/
├── cmd/clawscan/         # 程序入口
├── internal/
│   ├── app/              # CLI 解析与主流程编排
│   ├── collector/        # 信息采集（主机、OpenClaw、渠道、模型）
│   ├── parser/           # 配置文件解析与安全检查
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
