# Learning Objective 7：基于 Claims 的权限提升与逻辑应用触发

_作者：基于实验手册 Learning Objective 7（KC2 Start），参考 AzureAD-Attack-Defense-frame 项目_

_创建时间：2025年1月_

*"基于声明的权限提升是一种攻击，攻击者利用 Web 应用程序对身份提供商（IdP）颁发的不安全 Claims 的盲目信任，通过修改自己租户中可控的用户属性，来欺骗目标应用程序授予不应有的管理员权限。"*

*MITRE ATT&CK: [有效账户: 云账户 (T1078.004)](https://attack.mitre.org/techniques/T1078/004/), [权限提升: 有效账户 (T1068)](https://attack.mitre.org/techniques/T1068/), [滥用权限提升机制 (T1548)](https://attack.mitre.org/techniques/T1548/)*

---

- [Learning Objective 7：基于 Claims 的权限提升与逻辑应用触发](#learning-objective-7基于-claims-的权限提升与逻辑应用触发)
  - [引言](#引言)
    - [Kill Chain 2 (KC2) 背景](#kill-chain-2-kc2-背景)
    - [为什么这种攻击如此有效](#为什么这种攻击如此有效)
  - [理论基础](#理论基础)
    - [基于声明的授权 (Claims-Based Authorization)](#基于声明的授权-claims-based-authorization)
    - [OpenID Connect 和 ID Token](#openid-connect-和-id-token)
    - [Azure App Service 认证 (Easy Auth)](#azure-app-service-认证-easy-auth)
    - [Azure Logic Apps 作为后端触发器](#azure-logic-apps-作为后端触发器)
  - [攻击](#攻击)
    - [实验环境和前置条件](#实验环境和前置条件)
    - [步骤 1：访问应用并初次尝试 (侦察)](#步骤-1访问应用并初次尝试-侦察)
    - [步骤 2：修改身份属性 (漏洞利用)](#步骤-2修改身份属性-漏洞利用)
    - [步骤 3：利用新身份再次登录 (权限提升)](#步骤-3利用新身份再次登录-权限提升)
    - [步骤 4：触发逻辑应用并获取凭据 (达成目标)](#步骤-4触发逻辑应用并获取凭据-达成目标)
  - [MITRE ATT&CK 框架](#mitre-attck-框架)
  - [检测](#检测)
    - [Entra ID 审计日志](#entra-id-审计日志)
    - [Microsoft Sentinel 检测规则](#microsoft-sentinel-检测规则)
    - [KQL 查询用于威胁狩猎](#kql-查询用于威胁狩猎)
  - [缓解措施](#缓解措施)
    - [应用层面的安全实践](#应用层面的安全实践)
    - [身份验证和授权最佳实践](#身份验证和授权最佳实践)
    - [监控和告警](#监控和告警)
  - [技术背景和参考资料](#技术背景和参考资料)
    - [项目内参考资料文件](#项目内参考资料文件)
    - [延伸阅读](#延伸阅读)

---

## 引言

### Kill Chain 2 (KC2) 背景

这个目标标志着 **Kill Chain 2 (KC2)** 的开始。KC2 与 KC1 的主要区别在于：

| 特征 | Kill Chain 1 (KC1) | Kill Chain 2 (KC2) |
|------|---------------------|---------------------|
| 初始访问 | 需要目标租户的凭据 | 使用攻击者租户的合法账号 |
| 攻击载体 | 凭据窃取/破解 | 逻辑漏洞和配置缺陷 |
| 身份验证 | 目标租户 IdP | 攻击者控制的 IdP |
| 权限来源 | 目标环境授权 | 跨租户信任漏洞 |

### 为什么这种攻击如此有效

| 因素 | 说明 |
|------|------|
| **跨租户联邦身份验证** | 目标应用接受来自外部租户（`nomomoreoil`）的身份验证，建立了信任关系 |
| **可控的用户属性** | 攻击者对自己租户中的用户属性（如 Email）拥有完全控制权 |
| **不安全的授权逻辑** | 应用盲目信任 Token 中的可变 Claims（如 Email）进行权限判断 |
| **缺乏源验证** | 应用不验证 Claims 的来源和可信度，只检查值的内容 |
| **自动化后端触发** | Logic App 作为后端触发器可以执行高权限操作（创建用户） |

---

## 理论基础

### 基于声明的授权 (Claims-Based Authorization)

基于声明的授权是现代身份验证和授权的核心概念。在 Claims-Based 模型中：

**什么是 Claims？**

Claims 是关于用户或实体的声明或断言，由身份提供商（IdP）颁发。常见的 Claims 包括：

| Claim 类型 | 说明 | 示例值 |
|------------|------|--------|
| `sub` | Subject：用户的唯一标识符 | `abc123xyz` |
| `email` | 用户的电子邮件地址 | `user@example.com` |
| `name` | 用户的显示名称 | `John Doe` |
| `groups` | 用户所属的组 | `["Admins", "Users"]` |
| `roles` | 用户的角色 | `["Administrator"]` |

**Claims-Based 授权的正确实现：**

```csharp
// 安全的做法：使用不可变的 Object ID 和预定义的角色
public bool IsAdmin(ClaimsPrincipal user)
{
    // 获取用户的 Object ID（不可变）
    var objectId = user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;

    // 查询数据库或配置来验证该用户是否真的是管理员
    return _adminService.IsUserAdmin(objectId);
}
```

**有缺陷的实现（本实验场景）：**

```csharp
// 危险的做法：直接检查可变的 Email Claim
public bool IsAdmin(ClaimsPrincipal user)
{
    // 直接从 Email 字符串判断 - 极其危险！
    var email = user.FindFirst("email")?.Value;
    return email?.Contains("admin") ?? false;
}
```

### OpenID Connect 和 ID Token

OpenID Connect (OIDC) 是在 OAuth 2.0 之上构建的身份验证层。

**ID Token 结构：**

ID Token 是一个 JWT (JSON Web Token)，包含三个部分：

```
eyJhbGciOiJSUzI1NiIs... (Header)
eyJpc3MiOiJodHRwczovL... (Payload)
SflKxwRJSMeKKF2QT4f... (Signature)
```

**Payload 中的关键 Claims：**

```json
{
  "iss": "https://sts.windows.net/tenant-id/",
  "sub": "user-unique-id",
  "aud": "client-id",
  "exp": 1642000000,
  "email": "student1@nomoreoil.onmicrosoft.com",
  "name": "Student 1"
}
```

**Token 验证流程：**

1. 应用接收 IdP 颁发的 ID Token
2. 验证 Token 签名（确保来自可信 IdP）
3. 验证 Token 受众（aud claim）
4. 验证 Token 有效期（exp claim）
5. **关键步骤**：从 Token 中提取 Claims 用于授权

**本场景的漏洞：**

应用在第5步中，直接使用了 `email` claim 进行授权决策，而没有：
- 验证 Email 是否来自可信租户
- 验证 Email 是否经过管理员审核
- 使用不可变的标识符（Object ID）进行授权

### Azure App Service 认证 (Easy Auth)

Azure App Service 提供内置的身份验证功能，称为 "Easy Auth"。

**Easy Auth 工作原理：**

```
┌─────────┐      ┌──────────┐      ┌─────────┐      ┌──────────┐
│  用户   │ ──>  │ App Svc │ ──>  │ Azure AD│ ──>  │  Token   │
│ Browser │      │ Easy Auth│      │  IdP    │      │ Response │
└─────────┘      └──────────┘      └─────────┘      └──────────┘
                      │                                   │
                      ▼                                   ▼
              ┌──────────────┐                   ┌─────────────┐
              │ HTTP Headers │                   │ ID Token    │
              │ X-MS-TOKEN-  │ <─────────────────│ + Claims    │
              │ AAD-ID-TOKEN │                   │             │
              └──────────────┘                   └─────────────┘
```

**应用可用的环境变量：**

当使用 Easy Auth 时，应用可以通过 HTTP 头部访问 Token：

| 头部 | 说明 |
|------|------|
| `X-MS-TOKEN-AAD-ID-TOKEN` | ID Token（包含用户 Claims） |
| `X-MS-TOKEN-AAD-ACCESS-TOKEN` | Access Token（用于调用 API） |
| `X-MS-CLIENT-PRINCIPAL-NAME` | 用户名称 |
| `X-MS-CLIENT-PRINCIPAL-ID` | 用户 Object ID |

**配置 Easy Auth 支持多租户：**

在 `authsettings.json` 中配置：

```json
{
  "idToken": "enabled",
  "tokenStoreEnabled": true,
  "allowedAudiences": ["api://my-app"],
  "defaultProvider": "AzureActiveDirectory",
  "multiTenant": true
}
```

### Azure Logic Apps 作为后端触发器

Azure Logic Apps 是一个云端服务，用于工作流自动化和应用程序集成。

**Logic App 在本场景中的作用：**

```
┌──────────────┐      HTTP POST       ┌──────────────┐
│  Web App     │ ──────────────────> │  Logic App   │
│  Frontend    │     Add User Req    │  Backend     │
└──────────────┘                      └──────────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │ 1. 验证请求来源  │
                                    │ 2. 生成用户凭据  │
                                    │ 3. 调用 Graph API│
                                    │ 4. 创建用户      │
                                    │ 5. 添加到组      │
                                    └──────────────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │  返回用户凭据    │
                                    └──────────────────┘
```

**Logic App 工作流设计（推测）：**

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "actions": {
      "HTTP_Request": {
        "type": "Request",
        "inputs": {
          "schema": {}
        }
      },
      "Validate_Admin": {
        "type": "If",
        "expression": "@contains(triggerOutputs()['headers']['X-MS-CLIENT-PRINCIPAL-NAME'], 'admin')",
        "actions": {
          "Create_User": {
            "type": "Http",
            "inputs": {
              "method": "POST",
              "uri": "https://graph.microsoft.com/v1.0/users",
              "body": {
                "accountEnabled": true,
                "displayName": "WellPlanner@{rand()}",
                "passwordProfile": {
                  "password": "@{guid()}"
                }
              }
            }
          }
        }
      }
    }
  }
}
```

---

## 攻击

### 实验环境和前置条件

**目标应用架构：**

```
┌─────────────────────────────────────────────────────────────────┐
│                      目标环境 (oilcorporation)                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐         ┌─────────────────┐               │
│  │  Drill Planning │ ──────> │   Logic App     │               │
│  │   Web App       │  HTTP   │   (Backend)     │               │
│  │                 │         │                 │               │
│  │  Easy Auth      │         │  - Create User  │               │
│  │  (Multi-tenant) │         │  - Add to Group │               │
│  └─────────────────┘         └─────────────────┘               │
│         │                                                     │
│         │ OIDC Redirect                                      │
│         ▼                                                     │
│  ┌─────────────────┐         ┌─────────────────┐               │
│  │ Azure AD        │ <────── │ Azure AD        │               │
│  │ oilcorporation  │  Fed.   │ nomoreoil       │               │
│  │                 │         │ (攻击者租户)     │               │
│  └─────────────────┘         └─────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

**实验前置条件：**

| 条件 | 说明 | 为什么需要 |
|------|------|-----------|
| 攻击者租户 (`nomoreoil`) | 攻击者拥有完全控制权的租户 | 作为身份验证源，提供可控的用户属性 |
| 目标应用多租户配置 | 应用接受外部租户登录 | 建立跨租户信任关系，允许攻击者登录 |
| 攻击者租户管理员权限 | 可以修改用户属性 | 需要修改 Email 属性来实施攻击 |
| 目标用户 (`studentX`) | 在攻击者租户中存在的用户 | 用于登录目标应用的主账号 |
| Logic App 后端集成 | 应用连接到 Logic App | 最终目标是触发后端创建用户 |

**步骤设计原理：**

攻击链条的设计遵循了"侦察 → 利用 → 提升 → 执行"的经典模式：

1. **侦察**：了解应用的授权逻辑和功能
2. **利用**：利用可修改的属性来绕过授权检查
3. **提升**：获取管理员权限，解锁高级功能
4. **执行**：触发后端自动化流程，实现最终目标

### 步骤 1：访问应用并初次尝试 (侦察)

**目标：** 了解应用的授权机制和可访问功能。

**操作步骤：**

| 步骤 | 操作 | 预期结果 |
|------|------|----------|
| 1 | 访问 `https://drillplanning.azurewebsites.net/` | 加载应用主页 |
| 2 | 点击 "Sign in with Microsoft" | 重定向到 Microsoft 登录页面 |
| 3 | 输入 `studentX@nomoreoil.onmicrosoft.com` | 选择身份验证方式 |
| 4 | 完成身份验证（可能需要 MFA） | 重定向回应用 |
| 5 | 观察界面 | 应用显示权限提示信息 |

**观察要点：**

应用显示提示信息："Please use your work email as your access is determined based on email ID"

这个提示透露了两个关键信息：
1. 应用的授权逻辑基于 **Email ID**
2. Email 的内容决定了用户的权限级别

**普通用户界面特征：**

```
┌─────────────────────────────────────────┐
│  Drill Planning Application            │
├─────────────────────────────────────────┤
│  Welcome, Student X                    │
│                                         │
│  [Dashboard]  [Reports]  [Settings]    │
│                                         │
│  You have limited access.              │
│  Contact admin for full permissions.   │
└─────────────────────────────────────────┘
```

**为什么这一步很重要：**

侦察阶段的目的是收集信息，了解：
- 应用的授权机制
- 当前用户的权限级别
- 可能的提升路径
- 应用中存在的敏感功能

### 步骤 2：修改身份属性 (漏洞利用)

**目标：** 修改攻击者租户中用户的 Email 属性，使其包含 "admin" 关键字。

**原理说明：**

在多租户应用场景中，应用信任 IdP 颁发的 Token。如果应用直接使用 Token 中的可变 Claims（如 Email）进行授权决策，攻击者可以：

1. 修改自己租户中的用户属性
2. 重新登录获取新的 Token
3. 新 Token 包含修改后的 Claims
4. 应用使用修改后的 Claims 进行授权

**操作步骤：**

| 步骤 | 操作路径 | 说明 |
|------|----------|------|
| 1 | 登录 [Azure Portal](https://portal.azure.com) | 使用攻击者租户管理员账号 |
| 2 | 搜索 "Microsoft Entra ID" | 进入 Identity 管理界面 |
| 3 | 点击 "Users" | 浏览所有用户 |
| 4 | 搜索并选择 `studentX` | 定位目标用户 |
| 5 | 点击 "Edit properties" | 进入属性编辑界面 |
| 6 | 切换到 "Contact Information" 标签 | 查找 Email 字段 |
| 7 | 修改 Email 为 `adminstudentX@oilcorporation.onmicrosoft.com` | **关键步骤**：添加 "admin" 前缀 |
| 8 | 点击 "Save" | 保存更改 |

**Email 修改策略：**

| 原始 Email | 修改后 Email | 策略说明 |
|------------|--------------|----------|
| `student1@nomoreoil.onmicrosoft.com` | `adminstudent1@oilcorporation.onmicrosoft.com` | 添加 admin 前缀 + 伪造域名 |
| `student1@nomoreoil.onmicrosoft.com` | `admin@nomoreoil.onmicrosoft.com` | 简单替换为 admin |
| `student1@nomoreoil.onmicrosoft.com` | `student1admin@nomoreoil.onmicrosoft.com` | 添加 admin 后缀 |

**为什么选择这种修改方式：**

根据侦察阶段收集的信息，应用检查 Email 是否包含 "admin" 字符串。因此，最直接的攻击方式是在 Email 中添加 "admin" 关键字。

### 步骤 3：利用新身份再次登录 (权限提升)

**目标：** 使用修改后的 Email 重新登录，获取包含新 Claims 的 Token。

**操作步骤：**

| 步骤 | 操作 | 技术细节 |
|------|------|----------|
| 1 | 返回 Drill Planning 应用 | 回到目标应用 |
| 2 | 点击 "Logout" | 清除当前会话 |
| 3 | 点击 "Sign in" | 发起新的身份验证请求 |
| 4 | 使用相同的账号登录 | `studentX@nomoreoil.onmicrosoft.com` |
| 5 | 完成身份验证 | Azure AD 颁发新的 ID Token |

**后台流程（技术细节）：**

```
1. 应用向 Azure AD 发送 OIDC 授权请求
   GET https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
       client_id={app_client_id}&
       response_type=id_token&
       redirect_uri={app_uri}&
       scope=openid+profile+email&
       nonce={nonce}&
       prompt=login

2. Azure AD 验证用户身份

3. Azure AD 颁发新的 ID Token（包含修改后的 Email）
   {
     "email": "adminstudent1@oilcorporation.onmicrosoft.com",
     "name": "Student 1",
     ...
   }

4. 应用接收 Token 并提取 Claims
   var email = principal.FindFirst("email")?.Value;
   // email = "adminstudent1@oilcorporation.onmicrosoft.com"

5. 应用执行授权检查
   if (email.Contains("admin"))
   {
       // 授予管理员权限！
   }
```

**权限提升成功标志：**

应用界面发生变化：

```
┌─────────────────────────────────────────┐
│  Drill Planning Application            │
├─────────────────────────────────────────┤
│  Welcome, Admin!                       │
│                                         │
│  [Dashboard] [Reports] [Settings]      │
│  [ADD USER]  ← 新出现的管理员按钮       │
│                                         │
│  Administrator access granted.         │
└─────────────────────────────────────────┘
```

**对比变化：**

| 特征 | 普通用户视图 | 管理员视图 |
|------|-------------|-----------|
| 欢迎消息 | "Welcome, Student X" | "Welcome, Admin!" |
| 可用菜单 | Dashboard, Reports, Settings | + ADD USER |
| 权限提示 | "Limited access" | "Administrator access" |
| 功能限制 | 无法创建用户 | 可以创建新用户 |

### 步骤 4：触发逻辑应用并获取凭据 (达成目标)

**目标：** 使用管理员权限触发后端 Logic App，在目标租户中创建新用户。

**操作步骤：**

1. 点击新出现的 **"ADD USER"** 按钮
2. 等待 10-15 秒（Logic App 执行时间）
3. 页面显示新创建用户的凭据

**后台流程（推测）：**

```
┌─────────────────────────────────────────────────────────────┐
│                    Web App Frontend                         │
│  用户点击 "ADD USER" 按钮                                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              HTTP POST 请求                                  │
│  POST /api/adduser                                          │
│  Headers:                                                   │
│    Authorization: Bearer {access_token}                     │
│    X-MS-CLIENT-PRINCIPAL-NAME: adminstudent1@...            │
│  Body: {}                                                   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Logic App                                │
│  1. 接收 HTTP 请求                                          │
│  2. 验证请求者身份（检查 Email 中是否包含 "admin"）         │
│  3. 生成随机用户名和密码                                    │
│  4. 调用 Microsoft Graph API 创建用户                       │
│  5. 将用户添加到 DrillingIT 组                              │
│  6. 返回用户凭据                                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Microsoft Graph API                            │
│  POST https://graph.microsoft.com/v1.0/users                │
│  {                                                          │
│    "accountEnabled": true,                                  │
│    "displayName": "WellPlanner1",                           │
│    "mailNickname": "WellPlanner1",                          │
│    "userPrincipalName": "WellPlanner1@oilcorporation.onmicrosoft.com",│
│    "passwordProfile": {                                     │
│      "password": "18Vu&3rOQH",                              │
│      "forceChangePasswordNextSignIn": false                 │
│    }                                                        │
│  }                                                          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  目标租户 (oilcorporation)                   │
│  新用户已创建！                                             │
│  Username: WellPlanner1@oilcorporation.onmicrosoft.com      │
│  Password: 18Vu&3rOQH                                       │
│  Group Membership: DrillingIT                               │
└─────────────────────────────────────────────────────────────┘
```

**获取的凭据：**

```
┌─────────────────────────────────────────┐
│  User Created Successfully!             │
├─────────────────────────────────────────┤
│  Username: WellPlanner1@                │
│             oilcorporation.onmicrosoft.com│
│                                         │
│  Password: 18Vu&3rOQH                   │
│                                         │
│  Group: DrillingIT                      │
└─────────────────────────────────────────┘
```

**攻击成果总结：**

| 成果 | 说明 |
|------|------|
| 初始状态 | 攻击者租户的普通用户，无目标环境访问权限 |
| 权限提升 | 通过修改 Email 属性，获取目标应用的管理员权限 |
| 用户创建 | 在目标租户中创建新用户 `WellPlannerX` |
| 组成员身份 | 新用户被添加到特权组 `DrillingIT` |
| 持久化 | 获得目标环境的合法凭据，可进行后续渗透 |

---

## 总结与效果

**攻击链条：**

```
┌─────────────────────────────────────────────────────────────────┐
│                       完整攻击链条                               │
└─────────────────────────────────────────────────────────────────┘

1. 侦察 (Reconnaissance)
   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
   │ 访问目标应用 │ ───> │ 收集权限信息 │ ───> │ 识别授权逻辑 │
   └──────────────┘      └──────────────┘      └──────────────┘
                                                      │
                                                      ▼
                                         发现应用基于 Email 进行授权

2. 利用 (Exploitation)
   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
   │ 修改用户Email │ <── │ 攻击者租户   │ <── │ 攻击者控制    │
   │ 添加admin前缀 │      │ 管理员权限   │      │             │
   └──────────────┘      └──────────────┘      └──────────────┘

3. 提升 (Privilege Escalation)
   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
   │ 重新登录应用 │ ───> │ 获取新Token  │ ───> │ 绕过授权检查 │
   └──────────────┘      └──────────────┘      └──────────────┘
                                                      │
                                                      ▼
                                         获取管理员权限，解锁 ADD USER 功能

4. 执行 (Execution)
   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
   │ 触发Logic App│ ───> │ 创建目标用户 │ ───> │ 获取用户凭据 │
   └──────────────┘      └──────────────┘      └──────────────┘
                                                      │
                                                      ▼
                                         在目标租户中建立持久化访问
```

**战果对比：**

| 维度 | 攻击前 | 攻击后 |
|------|-------|-------|
| 身份 | 攻击者租户普通用户 | 目标租户特权用户 |
| 权限 | 无目标环境访问 | 目标应用管理员 |
| 资产 | 无 | 目标租户用户账号 + 凭据 |
| 持久化 | 无 | 持久化访问能力 |

---

## MITRE ATT&CK 框架

### 本攻击场景的 TTP 映射

基于 Claims 的权限提升攻击被映射到以下 MITRE ATT&CK 技术：

| 战术 | 技术 | 子技术 | 描述 |
|------|------|--------|------|
| **初始访问** | [T1078](https://attack.mitre.org/techniques/T1078/) | .004 有效账户：云账户 | 攻击者使用有效的云账户获取目标系统的初始访问 |
| **权限提升** | [T1068](https://attack.mitre.org/techniques/T1068/) | - 利用应用程序授权漏洞提升权限 |
| **防御规避** | [T1548](https://attack.mitre.org/techniques/T1548/) | - 滥用权限提升机制绕过安全控制 |

### 攻击流程 TTP 详细说明

```
初始访问 (T1078.004)
├── 使用攻击者租户的有效云账户登录目标应用
├── 利用多租户身份验证配置
└── 建立对目标应用的初始访问

权限提升 (T1068)
├── 修改可控的用户属性（Email）
├── 利用应用程序对可变 Claims 的信任
└── 提升至应用程序管理员权限

防御规避 (T1548)
├── 绕过应用程序的授权检查
├── 利用配置缺陷（基于 Email 的授权）
└── 伪装成合法管理员用户
```

### 相关 ATT&CK 子技术

| 子技术 | 应用场景 |
|--------|----------|
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) - 凭据访问：Unsecured Credentials | Logic App 可能暴露新创建的用户凭据 |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) - 有效账户：云账户 | 使用创建的云账户进行后续操作 |

---

## 检测

### Entra ID 审计日志

**检测位置：** Microsoft Entra ID 审计日志

**关键审计事件：**

| 事件类别 | 操作名称 | 检测价值 |
|----------|----------|----------|
| 用户属性 | Update user | 检测 Email 属性的异常修改 |
| 应用程序 | Service principal sign-in | 检测来自外部租户的登录 |
| 审计 | Provisioning | 检测 Logic App 创建的用户 |

**查看审计日志的步骤：**

1. 登录 [Microsoft Entra 管理中心](https://entra.microsoft.com)
2. 导航到 "审计日志"
3. 筛选活动："Update user"
4. 查看修改的属性字段

### Microsoft Sentinel 检测规则

**检测规则设计思路：**

1. 检测用户 Email 属性的异常修改（添加 admin 关键字）
2. 检测来自外部租户的管理员级别登录
3. 检测 Logic App 创建用户后立即登录的行为

**自定义检测规则（ARM 模板格式）：**

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workspace": {
      "type": "string"
    }
  },
  "resources": [
    {
      "id": "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/claims-privilege-escalation')]",
      "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/claims-privilege-escalation')]",
      "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
      "kind": "Scheduled",
      "apiVersion": "2021-10-01-preview",
      "properties": {
        "name": "Claims-Based Privilege Escalation Detection",
        "description": "检测用户通过修改 Email 属性包含 'admin' 关键字来实现权限提升的行为",
        "severity": "High",
        "enabled": true,
        "query": "let timeRange = 1h;\nAuditLogs\n| where TimeGenerated > ago(timeRange)\n| where Category == 'UserManagement'\n| where ActivityDisplayName has 'Update user'\n| where TargetResources has 'email'\n| extend ModifiedProperties = parse_json(TargetResources)[0].ModifiedProperties\n| mv-apply Property = ModifiedProperties on (\n    where Property.Name =~ 'Email'\n    | extend OldEmail = Property.OldValue, NewEmail = Property.NewValue\n)\n| where NewEmail contains 'admin' and OldEmail !contains 'admin'\n| project TimeGenerated, UserPrincipalName, InitiatedBy, OldEmail, NewEmail\n| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "tactics": [
          "PrivilegeEscalation",
          "DefenseEvasion"
        ],
        "techniques": [
          "T1068",
          "T1548"
        ],
        "entityMappings": [
          {
            "entityType": "Account",
            "fieldMappings": [
              {
                "identifier": "FullName",
                "columnName": "AccountCustomEntity"
              }
            ]
          }
        ]
      }
    }
  ]
}
```

### KQL 查询用于威胁狩猎

**狩猎 1：检测 Email 属性修改添加 admin 关键字**

```kusto
// 狩猎用户添加 admin 关键字到 Email 的行为
let timeRange = 7d;
AuditLogs
| where TimeGenerated > ago(timeRange)
| where Category == "UserManagement"
| where ActivityDisplayName has "Update user"
| extend TargetUser = TargetResources[0].userPrincipalName
| extend ModifiedProperties = TargetResources[0].ModifiedProperties
| mv-apply Property = ModifiedProperties on (
    where Property.Name =~ "Email"
    | extend OldEmail = Property.OldValue, NewEmail = Property.NewValue
)
| where NewEmail contains "admin" and OldEmail !contains "admin"
| project TimeGenerated,
          TargetUser,
          InitiatedBy = InitiatedBy.user.userPrincipalName,
          OldEmail,
          NewEmail,
          CorrelationId
| order by TimeGenerated desc
```

**狩猎 2：检测外部租户用户获取管理员权限**

```kusto
// 狩猎来自外部租户的管理员级别活动
let timeRange = 24h;
let externalTenantSignIn =
    SigninLogs
    | where TimeGenerated > ago(timeRange)
    | where HomeTenantId != ResourceTenantId  // 外部租户登录
    | where ConditionalAccessStatus == "success"
    | project TimeGenerated,
              UserPrincipalName,
              HomeTenantId,
              ResourceTenantId,
              AppId,
              CorrelationId;
let adminActivities =
    AuditLogs
    | where TimeGenerated > ago(timeRange)
    | where Category in ("UserManagement", "ApplicationManagement")
    | where ActivityDisplayName contains "Add" or
           ActivityDisplayName contains "Create" or
           ActivityDisplayName contains "Update"
    | extend CorrelationId = CorrelationId
    | project TimeGenerated, ActivityDisplayName, CorrelationId;
externalTenantSignIn
| join kind=inner adminActivities on CorrelationId
| project TimeGenerated,
          UserPrincipalName,
          ActivityDisplayName,
          AdminActivityTime = adminActivities_TimeGenerated
| order by TimeGenerated desc
```

**狩猎 3：检测 Logic App 创建的用户立即登录**

```kusto
// 狩猎新创建用户立即登录的行为（可能是后门创建）
let timeRange = 1d;
let createdUsers =
    AuditLogs
    | where TimeGenerated > ago(timeRange)
    | where Category == "UserManagement"
    | where ActivityDisplayName == "Add user"
    | extend CreatedUser = TargetResources[0].userPrincipalName
    | extend CreatedTime = TimeGenerated
    | project CreatedTime, CreatedUser;
let immediateSignIns =
    SigninLogs
    | where TimeGenerated > ago(timeRange)
    | project SigninTime = TimeGenerated, UserPrincipalName;
createdUsers
| join kind=inner (immediateSignIns) on $left.CreatedUser == $right.UserPrincipalName
| where SigninTime - CreatedTime < time(5minute)  // 5分钟内登录
| project CreatedTime, SigninTime, CreatedUser, TimeDiff = SigninTime - CreatedTime
| order by CreatedTime desc
```

---

## 缓解措施

### 应用层面的安全实践

**问题根源：** 应用使用可变的、用户可控的 Claims（如 Email）进行授权决策。

**解决方案 1：使用不可变的标识符**

```csharp
// 安全的做法
public bool IsAdmin(ClaimsPrincipal user)
{
    // 使用不可变的 Object ID
    var objectId = user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;

    // 从可信源（数据库或配置）验证权限
    return _adminService.IsUserAdmin(objectId);
}
```

**解决方案 2：验证租户来源**

```csharp
// 验证用户来自可信租户
public bool IsFromTrustedTenant(ClaimsPrincipal user)
{
    var tenantId = user.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value;
    var trustedTenantIds = _configuration.GetSection("TrustedTenantIds").Get<string[]>();

    return trustedTenantIds.Contains(tenantId);
}
```

**解决方案 3：使用应用角色**

```json
// 在应用注册中定义应用角色
{
  "appRoles": [
    {
      "allowedMemberTypes": ["User"],
      "displayName": "Application Administrator",
      "id": "1b19509b-32b1-4e9f-b71d-4e2a1b000000",
      "isEnabled": true,
      "description": "Can administer the application",
      "value": "ApplicationAdmin"
    }
  ]
}
```

```csharp
// 检查应用角色
public bool IsAdmin(ClaimsPrincipal user)
{
    return user.IsInRole("ApplicationAdmin");
}
```

**解决方案 4：实现白名单机制**

```csharp
// 白名单管理员用户
private readonly HashSet<string> _adminObjectIds = new()
{
    "12345678-1234-1234-1234-123456789012",
    "87654321-4321-4321-4321-210987654321"
};

public bool IsAdmin(ClaimsPrincipal user)
{
    var objectId = user.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
    return _adminObjectIds.Contains(objectId);
}
```

### 身份验证和授权最佳实践

**多租户应用安全清单：**

| 最佳实践 | 说明 | 优先级 |
|----------|------|--------|
| **使用不可变标识符** | 使用 Object ID 而非 Email 进行授权 | 高 |
| **租户白名单** | 限制接受哪些租户的身份 | 高 |
| **应用角色** | 使用 App Roles 而非 Claims 字符串匹配 | 高 |
| **最小权限原则** | Logic App 使用 Managed Identity 和最小权限 | 中 |
| **审计日志** | 记录所有授权决策和敏感操作 | 中 |
| **定期审查** | 定期审查应用程序权限和用户访问 | 中 |

**配置多租户应用的最佳实践：**

```json
{
  "identityProviders": {
    "azureActiveDirectory": {
      "enabled": true,
    "multiTenant": true,
      "tenantWhiteList": [
        "target-tenant-id-1",
        "target-tenant-id-2"
      ]
    }
  },
  "authorization": {
    "policy": "roleBased",
    "roleClaimType": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
    "adminRole": "ApplicationAdmin"
  }
}
```

**Logic App 安全配置：**

| 控制措施 | 说明 | 配置方式 |
|----------|------|----------|
| 使用 Managed Identity | 避免在 Logic App 中硬编码凭据 | 在 Logic App 设置中启用系统分配的 MSI |
| 最小权限授权 | 只授予创建用户的必要权限 | 使用 Graph API 的细粒度权限 |
| 输入验证 | 验证请求者身份和权限 | 在工作流开始时检查用户角色 |
| 审计日志 | 记录所有创建用户操作 | 将操作写入 Log Analytics |
| 条件访问 | 对 Logic App 端点应用 CA 策略 | 限制可以触发 Logic App 的用户和位置 |

### 监控和告警

**关键监控指标：**

| 监控领域 | 检测方法 | 告警阈值 |
|----------|----------|----------|
| 用户属性修改 | AuditLogs - Update user | Email 添加 "admin" 关键字 |
| 外部租户登录 | SigninLogs - HomeTenantId != ResourceTenantId | 管理员级别操作 |
| Logic App 触发 | Logic App 审计日志 | 来自外部租户的触发 |
| 新用户创建 | AuditLogs - Add user | 立即登录（< 5分钟） |

**推荐的告警规则配置：**

```kusto
// 告警规则：Email 属性添加 admin 关键字
AuditLogs
| where Category == "UserManagement"
| where ActivityDisplayName has "Update user"
| where TargetResources has "email"
| extend ModifiedProperties = parse_json(TargetResources)[0].ModifiedProperties
| mv-apply Property = ModifiedProperties on (
    where Property.Name =~ "Email"
    | where Property.NewValue contains "admin" and Property.OldValue !contains "admin"
)
| project TimeGenerated, UserPrincipalName, InitiatedBy
```

---

## 技术背景和参考资料

### 项目内参考资料文件

以下文件来自 AzureAD-Attack-Defense-frame 项目，可作为进一步学习的参考：

**核心文档：**
| 文件 | 路径 | 说明 |
|------|------|------|
| 项目概述 | [README.md](README.md) | 包含项目完整概述、章节结构、MITRE ATT&CK 框架映射 |
| 身份安全监控 | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | Microsoft 生态系统中身份安全的综合监控指南 |
| 横向移动防护 | [LateralMovementADEID.md](LateralMovementADEID.md) | 防止从 AD 横向移动到 Entra ID 的检查清单 |

**MITRE ATT&CK 映射文件：**
| 文件 | 路径 | 说明 |
|------|------|------|
| 攻击场景组合映射 | [media/mitre/Update-Jan-2025/Attacks-combined-2025.json](media/mitre/Update-Jan-2025/Attacks-combined-2025.json) | 所有攻击场景的 MITRE ATT&CK 映射 |
| 检测规则映射 | [media/mitre/Rules/Rules_Combined.json](media/mitre/Rules/Rules_Combined.json) | Microsoft 安全产品的检测规则覆盖 |

**检测查询文件：**
| 文件 | 路径 | 说明 |
|------|------|------|
| AAD 连接器账户监控 | [queries/AADConnectorAccount-OutsideOfWatchList.json](queries/AADConnectorAccount-OutsideOfWatchList.json) | 使用监视列表检测 AAD Connect 账户活动 |
| AAD Connect 登录异常 | [queries/AADConnect-SignInsOutsideServerIP.json](queries/AADConnect-SignInsOutsideServerIP.json) | 检测来自非预期服务器 IP 的 AAD Connect 登录 |

**配置文件：**
| 文件 | 路径 | 说明 |
|------|------|------|
| Entra ID 安全配置 | [config/AadSecConfig.json](config/AadSecConfig.json) | 安全配置检查的参考文件 |
| EIDSCA 部署模板 | [config/deploy/AADSCA-Playbook.arm.json](config/deploy/AADSCA-Playbook.arm.json) | Entra ID 安全配置分析器部署模板 |

### 延伸阅读

**Microsoft 官方文档：**
1. [Authentication and authorization in Azure App Service](https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization)
2. [Microsoft identity platform ID tokens](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens)
3. [What is Azure Logic Apps?](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview)
4. [Security best practices for app registration](https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration)

**安全研究：**
1. [Abusing Azure AD OAuth 2.0 Authorization Codes](https://posts.specterops.io/)
2. [Azure AD External Identities Security Considerations](https://www.cloud-architekt.net/)
3. [Token Manipulation in Azure AD](https://aadinternals.com/)

---

## 总结

Learning Objective 7 展示了一种基于 Claims 的权限提升攻击技术，其核心是利用应用程序对身份提供商颁发的可变 Claims 的不安全信任。

**关键要点：**

| 领域 | 关键教训 |
|------|----------|
| **应用安全** | 永远不要使用可变的 Claims（如 Email）作为授权依据 |
| **多租户设计** | 实施租户白名单，验证用户来源 |
| **标识符选择** | 使用不可变的 Object ID 而非可变的属性 |
| **后端安全** | Logic App 应使用 Managed Identity 和最小权限 |
| **监控检测** | 监控用户属性修改和外部租户的管理员活动 |

**防御优先级：**

| 优先级 | 控制 | 实施 |
|--------|------|------|
| 关键 | 修复授权逻辑 | 使用 Object ID + 白名单进行授权 |
| 高 | 条件访问 | 限制外部租户的访问范围 |
| 高 | 监控告警 | 检测用户属性异常修改 |
| 中 | Logic App 安全 | 使用 MSI 和最小权限 |
| 中 | 应用角色 | 使用 App Roles 替代 Claims 匹配 |

通过理解攻击机制、实施适当的检测规则并遵循安全编码实践，组织可以有效防御基于 Claims 的权限提升攻击。