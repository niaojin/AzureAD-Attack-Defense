# Learning Objective 6：PIM 绕过与令牌窃取（Privilege Escalation via PIM Bypass & Token Theft）

> **基于 Azure AD Attack & Defense Playbook 项目资料整理**
>
> **实验场景**：本实验演示了如何利用配置不当的 Web 应用窃取访问令牌（Access Token），并通过 PIM（Privileged Identity Management）机制中的逻辑漏洞实现权限提升。
>
> **前置依赖**：
> - 已通过 [Learning Objective 5](traget5.md) 使用 TAP 进入 `Oil Corp - Geology` 租户
> - 已获得 `explorationsyncuserX` 的有效凭据
>
> **相关资料位置**：
> - Token 理论：[ReplayOfPrimaryRefreshToken.md](ReplayOfPrimaryRefreshToken.md)
> - 身份监控：[IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md)
> - 安全配置：[config/AadSecConfigV3.json](config/AadSecConfigV3.json)
> - MITRE 映射：[media/mitre/Chapter6/AADPB-CP6-TTPs.json](media/mitre/Chapter6/AADPB-CP6-TTPs.json)
> - 检测查询：[queries/](queries/) 目录下的 KQL 文件

---

## 目录

- [1. 核心目标](#1-核心目标)
- [2. 理论基础](#2-理论基础)
  - [2.1 PIM (Privileged Identity Management) 机制](#21-pim-privileged-identity-management-机制)
  - [2.2 访问令牌 (Access Token) 的生命周期与验证逻辑](#22-访问令牌-access-token-的生命周期与验证逻辑)
  - [2.3 PIM 激活后的令牌验证漏洞](#23-pim-激活后的令牌验证漏洞)
- [3. 实验前置条件](#3-实验前置条件)
- [4. 实验步骤详解](#4-实验步骤详解)
- [5. 检测方法](#5-检测方法)
- [6. 防御策略](#6-防御策略)
- [7. MITRE ATT&CK 映射](#7-mitre-attck-映射)
- [8. 参考资料](#8-参考资料)

---

## 1. 核心目标

### 攻击链概览

```
┌──────────────────────────────────────────────────────────────────────┐
│                      攻击链条 (Attack Chain)                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  1. 初始状态       explorationsyncuserX 已通过 TAP 进入目标租户         │
│     │                                                                  │
│     ├─ 尝试激活 PIM 角色                                              │
│     └─ 失败：需要 MFA ✓                                                │
│                                                                        │
│  2. 侦察阶段       发现 secureiam Web 应用                              │
│     │                                                                  │
│     ├─ 枚举租户资源                                                    │
│     └─ 发现 https://secureiam.azurewebsites.net/                       │
│                                                                        │
│  3. 令牌窃取       从 Web App 获取 PrivUser 的 Access Token            │
│     │                                                                  │
│     ├─ 访问 secureiam 应用                                             │
│     ├─ 应用暴露了 Access Token                                        │
│     └─ Token 具有 Group.ReadWrite.All 权限                            │
│                                                                        │
│  4. 角色激活       利用 Web App 激活 PrivUser 的 PIM 角色              │
│     │                                                                  │
│     ├─ 点击 "Assign Role" 按钮                                        │
│     └─ PIM 角色在云端激活（绕过 MFA）                                  │
│                                                                        │
│  5. 令牌滥用       使用激活前获取的 Token 执行提权操作                  │
│     │                                                                  │
│     ├─ 将 explorationsyncuserX 添加到 GeoAdmins 组                     │
│     ├─ 操作成功！旧 Token 获得新权限                                   │
│     └─ 访问 Key Vault 获取机密                                         │
│                                                                        │
└──────────────────────────────────────────────────────────────────────┘
```

### 核心技术点

| 阶段 | 技术点 | 为什么有效 |
|------|--------|-----------|
| **PIM 枚举** | 发现合格角色分配 | PIM 允许用户具有"合格"权限，需要激活才能使用 |
| **MFA 障碍** | 无法完成激活 | PIM 激活通常要求 MFA，攻击者没有该租户的 MFA 设备 |
| **令牌窃取** | 从 Web App 获取 Token | 应用程序配置不当，直接暴露了 Access Token |
| **角色激活** | 通过 Web App 绕过 MFA | 应用可能使用托管身份或受信任会话激活角色 |
| **令牌复用** | 旧 Token 获得新权限 | Microsoft Graph API 在某些场景下验证实时权限而非 Token 声明 |

---

## 2. 理论基础

### 2.1 PIM (Privileged Identity Management) 机制

#### 2.1.1 PIM 的设计目的

Privileged Identity Management (PIM) 是 Microsoft Entra ID 提供的**即时权限管理**解决方案，旨在：

- **减少持久性特权暴露**：用户平时没有特权权限，仅在需要时激活
- **提高特权操作可见性**：所有激活和使用行为都被记录审计
- **强制多因素认证**：激活特权角色时通常要求 MFA

> **参考资料**：[What is Privileged Identity Management?](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)

#### 2.1.2 PIM 角色类型

```
┌─────────────────────────────────────────────────────────────────┐
│                   PIM 角色分配类型                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Eligible (合格分配)              Active (活动分配)              │
│  ────────────────────────          ────────────────────────     │
│                                                                 │
│  ● 用户平时不拥有该权限             ● 用户始终拥有该权限           │
│  ● 需要时手动激活                  ● 无需激活步骤                │
│  ● 通常需要 MFA 激活               ● 风险暴露更高                │
│  ● 激活有时间限制                  ● 无时间限制                   │
│  ● 推荐用于大多数场景              ● 仅用于紧急账户                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 2.1.3 PIM 激活流程

正常情况下的 PIM 激活流程：

```
┌─────────────────────────────────────────────────────────────────┐
│                    正常 PIM 激活流程                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  用户请求激活                                                     │
│     │                                                           │
│     ├─ 检查用户是否有合格分配                                    │
│     ├─ 验证用户身份（密码）                                       │
│     ├─ 要求 MFA 验证 ← 关键安全控制                             │
│     ├─ 提供激活理由                                              │
│     ├─ 系统审批（如果配置了审批流程）                              │
│     └─ 激活成功，获得临时权限（通常 1-8 小时）                     │
│                                                                 │
│  新 Token 生成                                                   │
│     │                                                           │
│     └─ 用户重新登录或刷新 Token                                 │
│     └─ 新 Token 包含激活后的角色声明                             │
│     └─ 可以执行特权操作                                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**攻击障碍**：攻击者通过 TAP 进入租户，但没有该租户的 MFA 设备，无法完成激活。

> **参考资料**：[Activate my Microsoft Entra roles in PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-activate-role)

---

### 2.2 访问令牌 (Access Token) 的生命周期与验证逻辑

#### 2.2.1 令牌类型

根据 [ReplayOfPrimaryRefreshToken.md:820-876](ReplayOfPrimaryRefreshToken.md#L820-L876)，Microsoft Entra ID 生态系统中存在多种令牌：

| 令牌类型 | 用途 | 有效期 | 签发者 |
|---------|------|--------|--------|
| **PRT (Primary Refresh Token)** | 设备级 SSO 令牌，用于获取其他令牌 | 14 天 | Entra ID |
| **RT (Refresh Token)** | 用于获取新的 Access Token | 最长 90 天 | Entra ID |
| **AT (Access Token)** | 访问受保护资源的 API | 默认 60-90 分钟<br>CAE: 20-28 小时 | Entra ID |
| **ID Token** | 包含用户身份信息 | 与 AT 相同 | Entra ID |

#### 2.2.2 Access Token 结构

Access Token 是一个 **JWT (JSON Web Token)**，包含以下关键声明：

```json
{
  "aud": "https://graph.microsoft.com",        // Audience（目标资源）
  "iss": "https://sts.windows.net/...",        // Issuer（签发者）
  "sub": "AQABkE-...",                         // Subject（用户唯一标识）
  "upn": "PrivUser@oilcorpgeology.onmicrosoft.com",  // User Principal Name
  "groups": ["Group-ID-1", "Group-ID-2"],      // 用户所属组 ID
  "roles": ["GroupAdmin"],                     // 分配的角色
  "scp": "Group.ReadWrite.All",                // Granted permissions
  "iat": 1234567890,                           // Issued At（签发时间）
  "exp": 1234567890,                           // Expiration（过期时间）
  "acr": "1",                                  // Authentication Context Reference
  "amr": ["mfa"]                               // Authentication Methods Reference
}
```

**关键声明说明**：

| 声明 | 说明 | 对权限的影响 |
|------|------|-------------|
| `scp` | 授予的权限范围 | 决定可以调用哪些 API |
| `roles` | 应用角色分配 | 类似于目录角色，但针对应用 |
| `groups` | 用户所属组 | 用于组-based 访问控制 |
| `amr` | 认证方法 | `mfa` 表示已完成多因素认证 |

> **参考资料**：[Microsoft identity platform access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)

#### 2.2.3 令牌验证的两个层面

```
┌─────────────────────────────────────────────────────────────────┐
│              令牌验证的两个层面                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  层面 1：令牌本身的有效性                                        │
│  ─────────────────────────────                                   │
│                                                                 │
│  ● 签名验证：确保令牌未被篡改                                     │
│  ● 过期检查：exp > 当前时间                                       │
│  ● 受众检查：aud == 请求的资源                                    │
│  ● 签发者验证：iss 来自可信身份提供者                             │
│                                                                 │
│  ─────────────────────────────────────────────────────────────  │
│                                                                 │
│  层面 2：授权时的实时状态检查                                     │
│  ─────────────────────────────                                   │
│                                                                 │
│  ● 用户是否仍然存在（未被删除/禁用）                               │
│  ● 用户的组成员资格是否仍然有效                                   │
│  ● 用户的角色分配是否仍然激活                                     │
│  ● 是否满足条件访问策略                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**关键发现**：在某些情况下，Microsoft Graph API 的组成员操作主要检查**层面 2**（实时状态），而不严格要求 Token 中的 `groups` 声明必须包含目标组。

---

### 2.3 PIM 激活后的令牌验证漏洞

#### 2.3.1 漏洞原理

**正常预期**：
```
激活 PIM 角色 → 获取新 Token → 新 Token 包含角色声明 → 执行特权操作
```

**实际发现**：
```
获取旧 Token → 激活 PIM 角色 → 旧 Token 获得新权限
                ↑
            通过 Web App 绕过 MFA
```

#### 2.3.2 为什么会出现这种情况？

**理论解释**：

1. **实时权限检查**：Microsoft Graph API 的 `New-MgGroupMember` 操作在执行时，会：
   - 验证 Token 的有效性（签名、过期时间）
   - 检查调用者（`PrivUser`）在 Entra ID 中的实时状态
   - 验证 `PrivUser` 是否具有修改组成员的权限
   - **不严格检查** Token 是否是在 PIM 激活后签发的

2. **缓存和一致性考虑**：Azure AD 可能有多个副本，实时状态检查比 Token 声明检查更可靠

3. **向后兼容性**：某些旧的应用逻辑可能不依赖 Token 中的角色声明

#### 2.3.3 类比：门禁卡与排班表

```
场景类比：
────────────────────────────────────────────────────────────────────

  ┌─────────────────────────────────────────────────────────────┐
  │                                                               │
  │   门禁卡 (Token)              排班系统 (Entra ID)            │
  │   ─────────────               ─────────────                  │
  │                                                               │
  │   持卡人：PrivUser             当前状态：                     │
  │   签发时间：08:00              角色：已激活 (09:00)          │
  │   角色声明：无                  ──────────────────             │
  │                                                               │
  │   [进入机房] ──验证──→ 刷卡 ──检查──→ 排班系统              │
  │                      │              │                        │
  │                      │              └─ 显示"正在值班"        │
  │                      │                                       │
  │                      └─ 允许进入！                            │
  │                                                               │
  └───────────────────────────────────────────────────────────────┘

关键点：门禁系统检查的是排班系统中的实时状态，
       而不是门禁卡上打印的角色信息！
```

---

## 3. 实验前置条件

### 3.1 必需条件

| 条件 | 说明 | 为什么需要 |
|------|------|-----------|
| **已进入目标租户** | 通过 Objective 5 使用 TAP 进入 `Oil Corp - Geology` 租户 | 访问租户资源的前提 |
| **有效的用户凭据** | `explorationsyncuserX` 的用户名和密码 | 从 [users.csv] 中获取 |
| **Web 应用访问** | 能够访问 `https://secureiam.azurewebsites.net/` | 用于窃取 Token 和激活角色 |
| **PowerShell 环境** | 安装了 Microsoft Graph PowerShell 模块 | 用于执行提权操作 |

### 3.2 环境配置说明

**为什么需要这些条件**：

1. **跨租户访问**：Objective 5 中配置的跨租户同步允许 `explorationsyncuserX` 进入目标租户，这是整个攻击链的基础

2. **PIM 合格分配**：`explorationsyncuserX` 在目标租户中有 `Groups Administrator` 的合格分配，这是提权的目标

3. **Web 应用漏洞**：`secureiam` 应用配置不当，直接暴露了 Access Token，这是窃取凭据的途径

4. **PrivUser 的 PIM 资格**：`PrivUser` 也有 PIM 资格，可以通过 Web App 激活，这是绕过 MFA 的关键

### 3.3 前置实验依赖

```
实验依赖链：
────────────────────────────────────────────────────────────────────

  Objective 1-4: 获得初始访问和权限提升
        │
        ▼
  Objective 5: 使用 TAP 绕过 MFA，进入目标租户
        │
        ├─ 获得 explorationsyncuserX 凭据
        ├─ 生成 TAP（Temporary Access Pass）
        ├─ 使用 TAP 登录（绕过 MFA）
        └─ 跨租户移动到 Oil Corp - Geology
        │
        ▼
  Objective 6: [当前] PIM 绕过与令牌窃取
        │
        ├─ 发现 PIM MFA 障碍
        ├─ 窃取 PrivUser 的 Access Token
        ├─ 通过 Web App 激活 PIM 角色
        └─ 使用旧 Token 完成提权
```

---

## 4. 实验步骤详解

### 步骤 1：枚举当前权限与障碍 (Reconnaissance)

#### 目的
验证当前用户在新租户中的权限状态，确认 PIM 激活的 MFA 障碍。

#### 操作步骤

**通过 Azure 门户枚举**：

1. 访问 `https://portal.azure.com`
2. 确认已登录到 `Oil Corporation - Geology` 租户
3. 导航到 **Microsoft Entra ID** → **My Feed** → **View Role Information**
4. 点击 **Eligible assignments** 标签

#### 预期结果

```powershell
# 发现的合格分配
DisplayName                      RoleDefinitionId
-----------                      -----------------
Groups Administrator             fe930be7-5e62-47db-91af-98c3a49a38b1
```

#### 尝试激活

1. 点击 **Activate** 按钮
2. 选择激活原因
3. 点击 **Activate**

#### 失败原因

```
┌─────────────────────────────────────────────────────────────────┐
│  Additional verification required                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  You need to provide additional verification to complete this   │
│  request. Please follow the instructions on the screen to       │
│  complete multi-factor authentication.                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**为什么需要这一步**：
- 验证攻击场景的真实性：PIM 确实受到 MFA 保护
- 确定需要寻找其他路径来完成提权
- 作为后续绕过成功的对比基准

---

### 步骤 2：横向移动发现 Web 应用 (Discovery)

#### 目的
在无法直接激活 PIM 的情况下，寻找其他可利用的资源。

#### 操作步骤

1. 在 Azure 门户中，点击 **All Resources**
2. 浏览资源列表，寻找可疑或配置不当的应用
3. 发现名为 `secureiam` 的 App Service

#### 预期发现

```
┌─────────────────────────────────────────────────────────────────┐
│  secureiam                                                       │
├─────────────────────────────────────────────────────────────────┤
│  Resource Type:   App Service                                   │
│  Status:          Running                                       │
│  URL:             https://secureiam.azurewebsites.net/          │
│  Location:        East US                                        │
└─────────────────────────────────────────────────────────────────┘
```

**分析**：
- 这是一个内部工具应用
- URL 暗示与 IAM（身份和访问管理）相关
- 内部工具通常权限配置较为宽松
- 可能存在凭据泄露风险

**为什么这样设计**：
- 攻击者需要进行横向移动寻找突破口
- 内部应用是常见的攻击目标
- 符合真实攻击场景中的侦察行为

---

### 步骤 3：从 Web 应用窃取 Access Token (Token Theft)

#### 目的
利用 `secureiam` 应用的配置漏洞，窃取特权用户的 Access Token。

#### 操作步骤

1. 访问 `https://secureiam.azurewebsites.net/`
2. 点击页面上的 **"Get Started"** 或 **"Fetch Access_Token"** 按钮
3. 观察页面响应

#### 预期结果

页面直接显示了一个 Access Token：

```json
{
  "token_type": "Bearer",
  "expires_in": 4300,
  "ext_expires_in": 4300,
  "expires_on": "1234567890",
  "not_before": "1234567890",
  "resource": "https://graph.microsoft.com",
  "access_token": "eyJ0eXAiOiJKV1QiLCJub25jZSI6..."
}
```

#### 令牌解码分析

使用 [jwt.ms](https://jwt.ms/) 或 PowerShell 解码 Token：

```powershell
# 解码查看 Token 内容
$token = "eyJ0eXAiOiJKV1QiLCJub25jZSI6..."
$parts = $token.Split('.')
$payload = $parts[1]
# 添加 padding 使其长度为 4 的倍数
$payload += '=' * (4 - ($payload.Length % 4))
$decoded = [System.Text.Encoding]UTF8.GetString([System.Convert]::FromBase64String($payload))
$decoded | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

**关键发现**：

```json
{
  "aud": "https://graph.microsoft.com",
  "upn": "PrivUser@oilcorpgeology.onmicrosoft.com",
  "scp": "Group.ReadWrite.All RoleManagement.ReadWrite.Directory",
  "roles": []
}
```

| 字段 | 值 | 含义 |
|------|-----|------|
| `aud` | `https://graph.microsoft.com` | 此 Token 用于访问 Microsoft Graph API |
| `upn` | `PrivUser@...` | 这是一个特权账号！ |
| `scp` | `Group.ReadWrite.All` | 可以读取和修改所有组（高危权限） |
| `roles` | 空 | 当前没有应用角色（PIM 未激活） |

**为什么能成功窃取 Token**：
- Web 应用配置不当，直接在页面上暴露了 Token
- 没有使用适当的安全存储机制（如 Azure Key Vault）
- 可能是开发/调试遗留的问题
- 没有实施最小权限原则

---

### 步骤 4：使用窃取的 Token 连接 MgGraph (Exploitation)

#### 目的
验证窃取的 Token 是否有效，并准备后续操作。

#### 操作步骤

```powershell
# 将窃取的 Token 存储到变量
$GraphAccessToken = "eyJ0eXAiOiJKV1QiLCJub25jZSI6..."

# 使用 Token 连接 MgGraph
$secureToken = ConvertTo-SecureString -AsPlainText -Force $GraphAccessToken
Connect-MgGraph -AccessToken $secureToken

# 验证当前上下文
Get-MgContext
```

#### 预期结果

```powershell
# 输出示例
Scopes                   : {Group.ReadWrite.All}
TenantId                 : geology-tenant-id
TenantDomain             : oilcorpgeology.onmicrosoft.com
Account                  : PrivUser@oilcorpgeology.onmicrosoft.com
```

**验证确认**：
- ✓ 当前身份是 `PrivUser`
- ✓ 具有 `Group.ReadWrite.All` 权限
- ✓ Token 有效，可以调用 Microsoft Graph API

**为什么需要这一步**：
- 确保 Token 确实可用
- 确认 Token 的权限范围
- 为后续的提权操作做准备

---

### 步骤 5：利用 Web 应用激活 PIM 角色 (Privilege Escalation)

#### 目的
通过 Web 应用的功能激活 `PrivUser` 的 PIM 角色，绕过 MFA 要求。

#### 背景分析

枚举发现 `PrivUser` 也有 PIM 合格分配：
```powershell
# 通过 MgGraph 查询 PrivUser 的合格分配
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq 'privuser-id'"
```

发现 `PrivUser` 有一个名为 `GroupAdmin` 的自定义 PIM 角色。

#### 操作步骤

1. 回到 `https://secureiam.azurewebsites.net/`
2. 点击页面上的 **"Assign Role"** 或 **"Activate Role"** 按钮
3. 观察操作结果

#### 预期结果

```
┌─────────────────────────────────────────────────────────────────┐
│  Role Activation Successful!                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User: PrivUser@oilcorpgeology.onmicrosoft.com                  │
│  Role: GroupAdmin                                                │
│  Status: Active                                                  │
│  Duration: 8 hours                                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**关键点**：
- ✓ 角色激活成功
- ✓ 无需 MFA 验证
- ✓ Web App 在后台以 `PrivUser` 身份调用 Azure API
- ✓ PIM 角色在云端已激活

**为什么能绕过 MFA**：
- Web App 可能使用托管身份（Managed Identity）或服务主体
- App 可能已建立受信任的会话
- PIM 策略可能对服务主体豁免 MFA 要求

> **参考资料**：[Privileged Identity Management (PIM) API](https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagement-root)

---

### 步骤 6：使用"旧"令牌执行提权操作 (The Exploit)

#### 目的
利用 PIM 角色激活后的实时权限，使用激活前获取的 Token 完成提权。

#### 核心逻辑

```
当前状态：
────────────────────────────────────────────────────────────────────

  时间轴：     08:00              09:00              09:15
                          ┌──────────────────┐
              获取 Token    │  激活 PIM 角色    │   使用旧 Token
                          │  (通过 Web App)   │   执行提权
                          └──────────────────┘

  Token：       [Token A]          [Token A]           [Token A]
                     │                  │                   │
                     │                  │                   ▼
  云端状态：   PrivUser          PrivUser            PrivUser
               (未激活)          (已激活!)           (已激活!)

  操作：       无法提权 ────→     激活成功     ────→    提权成功!
                                    ▲                  │
                                    │                  │
                            Web App 绕过 MFA         │
                                                       │
                                    关键漏洞：           │
                            旧 Token + 新权限 = 成功！ │
```

#### 操作步骤

```powershell
# 1. 获取目标组的 ID
$GeoAdmins = Get-MgGroup -Filter "DisplayName eq 'GeoAdmins'"
$groupId = $GeoAdmins.Id

# 2. 获取我们自己的用户 ID（跨租户 Guest 用户）
$currentUserUPN = "explorationsyncuserX_oilcorporation.onmicrosoft.com#EXT#@..."
$currentUser = Get-MgUser -UserId $currentUserUPN
$userId = $currentUser.Id

# 3. 执行添加操作（使用之前窃取的 Token）
New-MgGroupMember -GroupId $groupId -DirectoryObjectId $userId -Verbose
```

#### 预期结果

```powershell
# 输出示例
DisplayName     Id                                   GroupTypes
-----------     --                                   -----------
Exploration...  explorationsyncuserX-guest-id       {}
```

**操作成功！**

**验证提权结果**：
```powershell
# 确认用户已添加到组
Get-MgGroupMember -GroupId $groupId
```

#### 为什么能成功？

**技术解释**：

1. **实时权限检查**：`New-MgGroupMember` cmdlet 在执行时：
   - 验证 Token 的签名和过期时间（Token 仍然有效）
   - 向 Azure AD 查询 `PrivUser` 的实时状态
   - 发现 `PrivUser` 的 `GroupAdmin` 角色已激活
   - 允许操作继续

2. **不检查 Token 签发时间**：API 没有验证 Token 是在角色激活前还是激活后签发的

3. **组成员检查的宽松性**：Microsoft Graph 的组成员操作主要依赖实时状态检查，而非 Token 声明

---

### 步骤 7：访问 Key Vault 获取机密 (Objective Complete)

#### 目的
验证提权后的访问权限，完成最终目标。

#### 操作步骤

1. 回到 Azure 门户（使用 `explorationsyncuserX` 登录的会话）
2. 点击 **刷新** 或重新点击 **All Resources**
3. 观察现在可见的资源
4. 进入 **GeologyVault** (Key Vault)
5. 导航到 **Secrets**
6. 查看 `OilSecret` 的值

#### 预期结果

```
┌─────────────────────────────────────────────────────────────────┐
│  GeologyVault / Secrets                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Name           : OilSecret                                     │
│  Value          : FLAG{PIM_Bypass_Token_Theft_Success}          │
│  Activation Date : [Current Date]                                │
│  Expiration Date : [Future Date]                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**✓ 目标达成！**

通过以下攻击链成功获取机密：
1. PIM 枚举发现 MFA 障碍
2. 发现配置不当的 Web 应用
3. 从 Web 应用窃取 Access Token
4. 通过 Web 应用激活 PIM 角色
5. 利用实时权限检查漏洞使用旧 Token 完成提权
6. 访问 Key Vault 获取 Flag

---

## 5. 检测方法

### 5.1 基于 MITRE ATT&CK 的检测策略

根据 [media/mitre/Chapter6/AADPB-CP6-TTPs.json](media/mitre/Chapter6/AADPB-CP6-TTPs.json)，本实验涉及以下 TTPs：

| 战术 | 技术 | 说明 | 检测方法 |
|------|------|------|----------|
| **TA0006 - Credential Access** | T1528 | Steal Application Access Token | 监控异常的令牌请求 |
| **TA0004 - Privilege Escalation** | T1078 | Valid Accounts | 监控组成员变更 |
| **TA0003 - Persistence** | T1078 | Valid Accounts | 监控角色激活 |
| **TA0008 - Lateral Movement** | T1550 | Use Alternate Authentication Material | 监控跨租户活动 |

### 5.2 关键审计事件

#### 5.2.1 令牌窃取检测

基于 [ReplayOfPrimaryRefreshToken.md:500-560](ReplayOfPrimaryRefreshToken.md#L500-L560)，以下是关键检测点：

**Entra ID Identity Protection 检测**：

```kql
// 异常令牌特征检测
AADUserRiskEvents
| where RiskType == "anomalousToken"
   or RiskType == "unfamiliarSigninProperties"
| project Timestamp, UserPrincipalName, RiskType, RiskDetail, DetectionTimingType
```

**关键指标**：
- 异常令牌生命周期
- 不熟悉的登录属性
- 匿名 IP 地址
- 非典型地理位置

#### 5.2.2 PIM 角色激活检测

```kql
// 检测 PIM 角色激活事件
AuditLogs
| where Category == "RoleManagement"
| where OperationName == "Activate role"
   or OperationName == "Add member to role"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend RoleName = tostring(TargetResources[0].modifiedProperties[3].newValue)
| extend ActivatedBy = iff(
    isnotempty(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
  )
| project Timestamp, TargetUser, RoleName, ActivatedBy, IPAddress
```

#### 5.2.3 组成员变更检测

```kql
// 检测敏感组的成员变更
AuditLogs
| where Category == "GroupManagement"
| where OperationName == "Add member to group"
| extend TargetGroup = tostring(TargetResources[0].displayName)
| where TargetGroup contains "Admin" or TargetGroup contains "Privileged"
| extend AddedMember = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend InitiatedBy = iff(
    isnotempty(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
  )
| project Timestamp, TargetGroup, AddedMember, InitiatedBy
```

### 5.3 高级检测场景

#### 5.3.1 令牌复用检测

基于 [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md)，监控以下场景：

```kql
// 检测同一用户在短时间内的多次令牌请求
let suspiciousTokens = SigninLogs
| where TimeGenerated > ago(1h)
| summarize TokenCount = count() by UserPrincipalName, IPAddress
| where TokenCount > 10
| project UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1h)
| where UserPrincipalName in (suspiciousTokens)
| project Timestamp, UserPrincipalName, IPAddress, AppDisplayName
```

#### 5.3.2 Web 应用异常访问检测

```kql
// 检测来自异常 IP 的 Web 应用访问
let suspiciousApps = materialize (
    _GetWatchlist('WebApplications')
    | where ['IsSensitive'] == true
    | project ApplicationId
);
CloudAppEvents
| where ActionType in ("AppLogin", "UserLogin")
| where ApplicationId in (suspiciousApps)
| extend IsAnomalousIP = iff(
    IPAddress in ("Tor", "VPN", "Anonymous"),
    true,
    false
  )
| where IsAnomalousIP == true
| project Timestamp, AccountDisplayName, ApplicationId, IPAddress
```

### 5.4 项目中的检测查询

项目中提供的 KQL 查询文件可用于检测类似攻击：

| 查询文件 | 用途 | 位置 |
|---------|------|------|
| `AiTM/HuntUserActivities.kql` | 狩猎可疑用户活动 | [queries/AiTM/HuntUserActivities.kql](queries/AiTM/HuntUserActivities.kql) |
| `MDA-Hunt-Multi-Stage-Incident.kql` | 多阶段事件检测 | [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/MDA-Hunt-Multi-Stage-Incident.kql) |

---

## 6. 防御策略

### 6.1 针对 PIM 的安全配置

#### 6.1.1 PIM 最佳实践

基于 [config/AadSecConfigV3.json](config/AadSecConfigV3.json)，以下是推荐配置：

| 配置项 | 推荐值 | 原因 |
|--------|--------|------|
| **激活时长** | 最长 4 小时 | 限制风险暴露窗口 |
| **MFA 要求** | 始终要求 | 防止令牌复用攻击 |
| **审批流程** | 敏感角色需要审批 | 增加额外的安全控制 |
| **通知设置** | 激活时通知管理员 | 提高可见性 |

#### 6.1.2 监控和告警

```powershell
# 配置 PIM 激活通知
$notificationSettings = @{
    "DefaultUserRoleScope" = @(
        @{
            "notifyAdminOnActivation" = $true
            "notificationRecipient" = "security@contoso.com"
        }
    )
}
```

### 6.2 针对 Web 应用的安全加固

#### 6.2.1 令牌存储最佳实践

**不安全的做法**（本实验中的问题）：
```html
<!-- 直接在页面暴露 Token -->
<div id="token">eyJ0eXAiOiJKV1QiLCJub25jZSI6...</div>
```

**安全的做法**：
```csharp
// 使用 Azure Key Vault 存储和获取 Token
public async Task<string> GetAccessToken()
{
    var client = new SecretClient(
        new Uri("https://your-keyvault.vault.azure.net/"),
        new DefaultAzureCredential());

    KeyVaultSecret secret = await client.GetSecretAsync("graph-api-token");
    return secret.Value;
}
```

#### 6.2.2 应用权限最小化

根据项目配置建议 [config/AadSecConfigV3.json:126-130](config/AadSecConfigV3.json#L126-L130)：

```json
{
  "Name": "permissionGrantPolicyIdsAssignedToDefaultUserRole",
  "RecommendedValue": "ManagePermissionGrantsForSelf.microsoft-user-default-low",
  "Severity": "High"
}
```

**建议措施**：
1. 定期审查应用权限
2. 移除不必要的权限授予
3. 使用最小权限原则
4. 启用应用管理员工作流

### 6.3 针对 Token 窃取的防御

#### 6.3.1 Continuous Access Evaluation (CAE)

基于 [ReplayOfPrimaryRefreshToken.md:307-390](ReplayOfPrimaryRefreshToken.md#L307-L390)，启用 CAE 可以：

- **实时撤销令牌**：在关键事件发生时立即撤销
- **减少令牌生命周期风险**：即使令牌有效期长，也能及时撤销
- **提高安全性**：不依赖令牌过期时间

```powershell
# 为应用启用 CAE
Update-MgServicePrincipal -ServicePrincipalId $app.Id `
    -Info @{
        "tokenIssuancePolicies@odata.bind": [
            "https://graph.microsoft.com/v1.0/policies/tokenIssuancePolicies/{policy-id}"
        ]
    }
```

#### 6.3.2 条件访问策略

配置以下条件访问策略：

| 策略 | 配置 | 目标 |
|------|------|------|
| **敏感应用访问** | 要求 MFA + 合规设备 | 保护高价值应用 |
| **异常位置检测** | 阻止来自高风险位置 | 防止令牌在异常地点使用 |
| **impossible travel** | 检测不可能的旅行 | 识别令牌复用 |

### 6.4 安全监控和响应

#### 6.4.1 部署安全工具

根据 [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md)，部署：

1. **Microsoft Defender XDR**：提供全面的威胁检测
2. **Microsoft Sentinel**：SIEM 解决方案，用于日志分析和告警
3. **Entra ID Protection**：身份特定的威胁检测

#### 6.4.2 建立响应流程

```
┌─────────────────────────────────────────────────────────────────┐
│                   安全事件响应流程                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 检测阶段                                                     │
│     ├─ SIEM 告警                                               │
│     ├─ 身份风险提示                                             │
│     └─ 异常行为检测                                             │
│                                                                 │
│  2. 调查阶段                                                     │
│     ├─ 确认事件范围                                             │
│     ├─ 分析攻击路径                                             │
│     └─ 确定受影响资源                                           │
│                                                                 │
│  3. 遏制阶段                                                     │
│     ├─ 撤销所有 Refresh Token                                   │
│     ├─ 禁用受影响账户                                           │
│     └─ 隔离受影响设备                                           │
│                                                                 │
│  4. 根除阶段                                                     │
│     ├─ 移除恶意应用权限                                         │
│     ├─ 清理组成员关系                                           │
│     └─ 重置凭据                                                │
│                                                                 │
│  5. 恢复阶段                                                     │
│     ├─ 恢复正常访问                                             │
│     ├─ 更新安全策略                                             │
│     └─ 文档化经验教训                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. MITRE ATT&CK 映射

### 7.1 战术和技术映射

基于 [media/mitre/Chapter6/AADPB-CP6-TTPs.json](media/mitre/Chapter6/AADPB-CP6-TTPs.json)：

#### TA0006 - Credential Access (凭据访问)

| 技术 | 子技术 | 描述 | 本实验中的应用 |
|------|--------|------|----------------|
| **T1528** | - | Steal Application Access Token | 从 `secureiam` 应用窃取 Access Token |

**检测方法**：
- 监控异常的令牌请求模式
- 检测令牌在不寻常的 IP/位置使用
- 审计令牌的生命周期异常

#### TA0004 - Privilege Escalation (权限提升)

| 技术 | 子技术 | 描述 | 本实验中的应用 |
|------|--------|------|----------------|
| **T1078** | - | Valid Accounts | 利用有效账户（PrivUser）进行权限提升 |

**检测方法**：
- 监控敏感组的成员变更
- 检测 PIM 角色的异常激活
- 审计特权操作的时间模式

#### TA0003 - Persistence (持久化)

| 技术 | 子技术 | 描述 | 本实验中的应用 |
|------|--------|------|----------------|
| **T1078** | - | Valid Accounts | 将自己添加到管理员组实现持久化 |

**检测方法**：
- 监控组的创建和修改
- 检测异常的组成员添加
- 审计管理单元的变更

#### TA0008 - Lateral Movement (横向移动)

| 技术 | 子技术 | 描述 | 本实验中的应用 |
|------|--------|------|----------------|
| **T1550** | - | Use Alternate Authentication Material | 使用窃取的 Token 进行跨租户访问 |

**检测方法**：
- 监控跨租户的活动
- 检测来自不寻常位置的认证
- 审计令牌在多个设备/地点的使用

### 7.2 攻击流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                     攻击流程映射到 ATT&CK                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [Reconnaissance] ─── TA0043 - Reconnaissance                 │
│       │                                                         │
│       ├─ 枚举 PIM 角色                                        │
│       ├─ 发现 Web 应用                                        │
│       └─ T1594 - Determine User Trust                         │
│                                                                 │
│  [Credential Access] ─── TA0006 - Credential Access            │
│       │                                                         │
│       ├─ 窃取 Access Token                                    │
│       └─ T1528 - Steal Application Access Token               │
│                                                                 │
│  [Privilege Escalation] ─── TA0004 - Privilege Escalation      │
│       │                                                         │
│       ├─ 激活 PIM 角色                                        │
│       ├─ 添加用户到管理员组                                    │
│       └─ T1078 - Valid Accounts                                │
│                                                                 │
│  [Persistence] ─── TA0003 - Persistence                        │
│       │                                                         │
│       ├─ 保持对资源的访问                                      │
│       └─ T1078 - Valid Accounts                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.3 可视化映射

项目的 MITRE ATT&CK 映射文件：
- **SVG 图表**：[media/mitre/Chapter6/AADCP6TTps.svg](media/mitre/Chapter6/AADCP6TTps.svg)
- **JSON 数据**：[media/mitre/Chapter6/AADPB-CP6-TTPs.json](media/mitre/Chapter6/AADPB-CP6-TTPs.json)

---

## 8. 参考资料

### 8.1 项目内部文件

| 主题 | 文件路径 | 说明 |
|------|----------|------|
| **Token 理论** | [ReplayOfPrimaryRefreshToken.md](ReplayOfPrimaryRefreshToken.md) | PRT、RT、AT 的深入解析，包括令牌生命周期和验证逻辑 |
| **身份监控** | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | 身份安全监控最佳实践和检测策略 |
| **安全配置** | [config/AadSecConfigV3.json](config/AadSecConfigV3.json) | EIDSCA 安全配置模板，包含推荐的安全设置 |
| **MITRE 映射** | [media/mitre/Chapter6/AADPB-CP6-TTPs.json](media/mitre/Chapter6/AADPB-CP6-TTPs.json) | Chapter 6 的 MITRE ATT&CK TTP 映射数据 |
| **跨租户移动** | [LateralMovementADEID.md](LateralMovementADEID.md) | 横向移动防御策略和检测方法 |
| **前置实验** | [traget5.md](traget5.md) | TAP 绕过 MFA 实验文档（Objective 5） |
| **检测查询** | [queries/AiTM/HuntUserActivities.kql](queries/AiTM/HuntUserActivities.kql) | 狩猎可疑用户活动的 KQL 查询 |

### 8.2 官方文档

| 主题 | 链接 |
|------|------|
| **PIM 配置** | [What is Privileged Identity Management?](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure) |
| **PIM 激活** | [Activate my Microsoft Entra roles in PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-activate-role) |
| **Access Token** | [Microsoft identity platform access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens) |
| **PIM API** | [Privileged Identity Management (PIM) API](https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagement-root) |
| **CAE** | [What is Continuous Access Evaluation?](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation) |
| **身份令牌** | [Microsoft identity platform security tokens](https://learn.microsoft.com/en-us/entra/identity-platform/security-tokens) |
| **PRT 概念** | [Primary Refresh Token concept](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token) |

### 8.3 社区资源

| 资源 | 链接 |
|------|------|
| **项目主页** | [AzureAD-Attack-Defense-frame GitHub](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense-frame) |
| **原作者** | Thomas Naunheim, Sami Lamppu |
| **许可证** | MIT License |
| **贡献指南** | 欢迎提交 PR 和 Issue |

### 8.4 相关工具

| 工具 | 用途 | 链接 |
|------|------|------|
| **AADInternals** | PowerShell 模块，用于 Entra ID 操作 | [https://o365blog.com/aadinternals/](https://o365blog.com/aadinternals/) |
| **MgGraph** | Microsoft Graph PowerShell 模块 | [Microsoft.Graph PowerShell](https://www.powershellgallery.com/packages/Microsoft.Graph) |
| **EIDSCA** | Entra ID Security Config Analyzer | [AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md) |
| **TokenTactics** | Token 操作工具 | [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2) |

---

## 附录：快速参考

### 常用 PowerShell 命令

```powershell
# 连接 MgGraph
Connect-MgGraph -Scopes "Group.ReadWrite.All", "User.Read.All"

# 获取用户信息
Get-MgUser -UserId "user@contoso.com"

# 获取组信息
Get-MgGroup -Filter "DisplayName eq 'GroupName'"

# 添加用户到组
New-MgGroupMember -GroupId $groupId -DirectoryObjectId $userId

# 查询 PIM 角色分配
Get-MgRoleManagementDirectoryRoleAssignment

# 激活 PIM 角色
Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests/"

# 撤销用户 Refresh Token
Revoke-AzureADUserAllRefreshToken -ObjectId "user@contoso.com"
```

### KQL 检测查询

```kql
// 检测异常的组成员变更
AuditLogs
| where Category == "GroupManagement"
| where OperationName == "Add member to group"
| extend TargetGroup = tostring(TargetResources[0].displayName)
| where TargetGroup contains "Admin"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project Timestamp, TargetGroup, InitiatedBy, IPAddress

// 检测 PIM 角色激活
AuditLogs
| where Category == "RoleManagement"
| where OperationName == "Activate role"
| extend RoleName = tostring(TargetResources[0].displayName)
| extend ActivatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project Timestamp, RoleName, ActivatedBy

// 检测异常的令牌使用
SigninLogs
| where Status.errorCode == 0
| extend IsHighRisk = iff(
    RiskDetail == "mcasImpossibleTravel" or
    RiskDetail == "anonymousIPAddress",
    true,
    false
  )
| where IsHighRisk == true
| project Timestamp, UserPrincipalName, IPAddress, RiskDetail
```

---

**文档版本**：v2.0
**最后更新**：基于 Azure AD Attack & Defense Playbook 项目
**维护者**：Claude Code
**项目许可**：MIT License
