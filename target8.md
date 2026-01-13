# Learning Objective 8：逻辑应用滥用、MFA 注册劫持与 B2B 渗透

> **基于 AzureAD-Attack-Defense-frame 项目资料优化**
>
> 参考文档：
> - [ConsentGrant.md](ConsentGrant.md) - OAuth 权限和同意框架
> - [PasswordSpray.md](PasswordSpray.md) - 密码攻击和 MFA 配置
> - [LateralMovementADEID.md](LateralMovementADEID.md) - 横向移动和 MFA 安全
> - [AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md) - Logic App 安全配置

---

## **概述**

本学习目标侧重于 **Azure 资源的数据平面利用（Logic App）**、**API 逻辑漏洞挖掘** 以及 **MFA 注册滥用**。你将利用上一步获取的用户权限，分析自动化流程，发现隐藏的后门逻辑，并利用新创建的账号进行持久化和跨租户访问。

---

## **1. 核心目标**

| 阶段 | 目标 | 描述 |
|------|------|------|
| **侦察** | 枚举并分析 Logic App | 利用 `WellPlannerX` 用户的权限，读取并分析 Azure Logic App（逻辑应用）的工作流定义 |
| **利用** | 触发隐藏逻辑分支 | 发现 Logic App 内部的逻辑分支，通过构造特定的 HTTP 请求触发隐藏功能，获取敏感凭据 |
| **持久化** | MFA 注册劫持 | 对于新获取的账号 `simulationuserX`，利用其处于"首次登录未注册 MFA"的状态，攻击者抢先绑定自己的 MFA 设备 |
| **横向移动** | B2B 跨租户访问 | 利用 B2B 协作机制，通过 `Reservoir Mgmt App` 访问另一个租户（Oil Corp Reservoir） |

---

## **2. 理论基础**

### **2.1 Azure Logic App 的 HTTP 触发器与 SAS 签名**

Azure Logic Apps 是一种云端工作流编排服务，用于连接不同的系统和服务。当 Logic App 配置了 HTTP 触发器时，可以通过 HTTP 请求来启动工作流。

#### **工作原理**

```
攻击者 → HTTP 请求 + SAS 签名 → Logic App HTTP 触发器
                                         ↓
                                    Switch 条件判断
                                    ↙          ↘
                              /display       /execute
                                  ↓              ↓
                            返回凭据        创建新用户
```

#### **关键权限**

要获取 Logic App 的触发 URL，需要以下权限：

| 权限 | 描述 | 风险等级 |
|------|------|----------|
| `Microsoft.Logic/workflows/read` | 读取 Logic App 定义 | 中 |
| `Microsoft.Logic/workflows/triggers/listCallbackUrl/action` | 获取带签名的触发 URL | **高** |

> **理论基础来源**：[AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md:105-120) - 详细说明了 Logic App 使用 Managed Identity 进行身份验证的最佳实践

#### **SAS 签名机制**

Logic App 的 HTTP 触发器使用 Shared Access Signature (SAS) 进行身份验证：

```
https://<logic-app-name>.azurewebsites.net/api/<trigger-name>?
    sp=<permissions>&
    sv=<version>&
    sig=<signature>&
    <additional-parameters>
```

**签名组件说明：**
- `sp` (signed permissions): 授予的权限（如读取、写入）
- `sv` (signed version): SAS 版本
- `sig` (signature): 使用密钥生成的 HMAC 签名
- `se`/`st`: 过期时间/开始时间

---

### **2.2 API 逻辑漏洞与 Switch 分支**

Logic App 的工作流定义是 JSON 格式的，可能包含敏感的业务逻辑。开发者常使用 `Switch` 语句来处理不同的请求路径。

#### **漏洞场景**

```json
{
  "type": "Switch",
  "expression": "@triggerOutputs()['queries']['action']",
  "cases": [
    {
      "case": "display",
      "actions": {
        "Return_Credentials": {
          "type": "Response",
          "inputs": {
            "body": {
              "username": "TonyLMarshall",
              "password": "P@ssw0rd123!"
            }
          }
        }
      }
    },
    {
      "case": "execute",
      "actions": {
        "Create_User": {
          "type": "ApiConnection",
          "inputs": {
            "host": {
              "connection": {
                "name": "@parameters('$connections')['azuread']['connectionId']"
              }
            }
          }
        }
      }
    }
  ]
}
```

> **类比理解**：Logic App 就像一台自动贩卖机。普通人只能看外观，但如果你有 `listCallbackUrl` 权限，就相当于你有了一把钥匙，能打开贩卖机的维护面板，看到里面的一根特殊的"启动线"（URL）。只要接通这根线（发送请求），贩卖机就会吐出货物。

---

### **2.3 MFA 首次注册竞争（First-Use Trust）**

这是云安全中极常见的问题。账号开启了 MFA，但还没绑定手机。

#### **攻击原理**

```
时间线：
T0: 管理员创建账号 simulationuser_X，密码设为复杂密码
T1: 管理员将密码通过"安全"渠道（如邮件）告知用户
T2: 攻击者在 T1 之前获取到密码
T3: 攻击者抢先登录，绑定自己的 MFA 设备
T4: 真正的用户尝试登录，发现 MFA 已被绑定，无法访问
```

> **类比（抢注新房）**：开发商交房了（账号创建），门锁是智能锁（MFA），但还没录指纹。窃贼偷到了钥匙（密码），先冲进去把自己的指纹录入系统。现在窃贼成了房子的合法主人，真正的业主反而被锁在门外。

#### **理论基础来源**

[LateralMovementADEID.md](LateralMovementADEID.md:380-395) - 文档详细说明了 MFA 配置的最佳实践和安全注意事项

---

### **2.4 Azure AD B2B 协作机制**

Azure AD B2B (Business-to-Business) 允许跨租户的用户协作。

#### **B2B 工作原理**

```
┌─────────────────┐         邀请         ┌─────────────────┐
│  租户 A (资源)  │ <───────────────── │  租户 B (主租户) │
│  Oil Corp       │                     │  Oil Corp       │
│                 │      Guest 用户      │  Reservoir      │
│                 │ <───────────────── │                 │
└─────────────────┘                      └─────────────────┘
     simulationuser_X  ←──────────────────  主租户身份
```

#### **关键概念**

| 概念 | 描述 |
|------|------|
| **Guest 用户** | 来自其他租户的受邀用户，在资源租户中身份为 "Member" |
| **租户切换** | 用户可以在多个租户之间切换，无需重新登录 |
| **权限继承** | Guest 用户保留主租户的权限，同时拥有资源租户授予的权限 |

> **理论基础来源**：[PasswordSpray.md](PasswordSpray.md:170-190) 中关于 B2B Guest 用户登录日志的详细说明

---

## **3. 实验条件与前提**

### **3.1 必需条件**

| 条件 | 描述 | 原因 |
|------|------|------|
| **WellPlannerX 用户权限** | 需要具有 `Microsoft.Logic/workflows/read` 和 `listCallbackUrl` 权限 | 用于枚举和获取 Logic App 的触发 URL |
| **Logic App 存在** | 目标环境中必须部署有可访问的 Logic App | Logic App 是攻击的主要目标 |
| **HTTP 触发器配置** | Logic App 必须配置了 HTTP 触发器 | 否则无法通过 HTTP 请求触发 |
| **新创建的账号** | `simulationuser_X` 账号已创建但 MFA 未配置 | 用于 MFA 注册劫持攻击 |

### **3.2 为什么需要这些条件？**

1. **WellPlannerX 权限要求**：
   - `Microsoft.Logic/workflows/read`：允许读取 Logic App 的工作流定义，这是发现隐藏逻辑分支的前提
   - `listCallbackUrl`：允许获取带有 SAS 签名的触发 URL，这是触发 Logic App 的关键

2. **Logic App 存在**：
   - Logic App 是 Azure 的自动化工作流服务，常用于连接不同的系统和服务
   - 由于其工作流定义可能包含敏感的业务逻辑，成为攻击者的目标

3. **HTTP 触发器配置**：
   - HTTP 触发器允许通过 HTTP 请求启动 Logic App
   - 如果没有 HTTP 触发器，攻击者无法远程触发工作流

4. **新创建的账号**：
   - 新账号通常存在 MFA 未配置的窗口期
   - 攻击者可以利用这个窗口期抢先绑定自己的 MFA 设备

---

## **4. 实验步骤与设计理由**

### **步骤 1：枚举 Logic App 及其定义 (Reconnaissance)**

#### **操作步骤**

```powershell
# 1. 使用 WellPlannerX 登录
Connect-AzAccount -Credential $creds

# 2. 发现资源
Get-AzResource

# 3. 读取 Logic App 定义
(Get-AzLogicApp -Name WellPlanningLogicApp ...).Definition
```

#### **为什么这样设计？**

1. **使用低权限账号**：模拟真实攻击场景，攻击者通常只有有限的权限
2. **枚举资源**：了解目标环境中有哪些 Logic App 可供利用
3. **读取工作流定义**：工作流定义是 JSON 格式，包含所有业务逻辑，分析它可以发现隐藏的功能分支

> **检测点**：根据 [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md)，异常的 Logic App 读取活动可能被记录在审计日志中

---

### **步骤 2：获取触发 URL 并探测逻辑 (Enumeration)**

#### **操作步骤**

```powershell
# 获取触发 URL
Get-AzLogicAppTriggerCallbackUrl -Name WellPlanningLogicApp -TriggerName manual ...
# 返回：https://prod-70.eastus.logic.azure.com/...&sig=xxxx

# 发送探测请求
Invoke-RestMethod -Method POST -Uri 'URL'
```

#### **为什么这样设计？**

1. **获取触发 URL**：
   - `listCallbackUrl` 返回的 URL 包含 SAS 签名，用于身份验证
   - 签名有时效性，过期后需要重新获取

2. **发送探测请求**：
   - 探测请求可以帮助了解 Logic App 的预期输入格式
   - 响应可能包含错误信息，泄露内部逻辑结构

---

### **步骤 3：触发隐藏分支获取凭据 (The Exploit)**

#### **操作步骤**

```powershell
# 触发 'Display' 分支
Invoke-RestMethod -Method GET -Uri 'URL/invoke/display?...'

# 触发 'Execute' 分支
Invoke-RestMethod -Method GET -Uri 'URL/invoke/execute?...'
```

#### **为什么这样设计？**

1. **分析 Switch 分支**：
   - 通过读取工作流定义，发现不同的路径（display/execute）会触发不同的操作
   - `display` 路径返回现有用户凭据
   - `execute` 路径创建新用户并返回凭据

2. **逐步探测**：
   - 先尝试 `display` 分支，获取 `TonyLMarshall` 的凭据
   - 发现 Tony 账号已配置 MFA，无法使用
   - 尝试 `execute` 分支，动态创建 `simulationuser_X` 账号

---

### **步骤 4：MFA 注册劫持 (Persistence & Bypass)**

#### **操作步骤**

```
1. 访问 https://portal.azure.com
2. 使用 simulationuser_X 登录
3. 系统提示"需要更多信息"
4. 点击下一步，进入 MFA 注册页面
5. 使用自己的手机扫描二维码
6. 完成 MFA 绑定
```

#### **为什么这样设计？**

1. **利用窗口期**：
   - 新创建的账号通常存在 MFA 未配置的窗口期
   - 第一个完成 MFA 注册的人将拥有该账号的控制权

2. **绕过 MFA**：
   - 一旦攻击者绑定了自己的 MFA 设备，就完全控制了该账号
   - 真正的用户无法登录，因为 MFA 已被绑定

> **缓解措施参考**：[LateralMovementADEID.md](LateralMovementADEID.md:380-400) 详细说明了如何配置 MFA 注册策略以防止此类攻击

---

### **步骤 5：利用 B2B 协作跨租户访问 (Lateral Movement)**

#### **操作步骤**

```
1. 访问 https://reservoirmgmtapp.azurewebsites.net/
2. 使用 simulationuser_X 登录
3. 同意应用 reservoirguestreg 的权限请求
4. 在 Azure 门户点击头像 -> Switch Directory
5. 切换到 Oil Corporation - Reservoir 租户
```

#### **为什么这样设计？**

1. **B2B 邀请机制**：
   - `simulationuser_X` 是 Oil Corp Reservoir 租户的 Guest 用户
   - Guest 用户可以访问资源租户授予的应用

2. **租户切换**：
   - 一旦通过 B2B 邀请，用户可以在租户之间切换
   - 这为攻击者提供了横向移动的机会

> **理论基础**：[PasswordSpray.md](PasswordSpray.md:170-190) 说明了 B2B Guest 用户的登录行为和日志记录

---

## **5. 检测与缓解**

### **5.1 检测方法**

| 检测方法 | 工具/日志 | 检测内容 |
|----------|-----------|----------|
| **审计日志** | Entra ID Audit Logs | Logic App 的 `listCallbackUrl` 调用 |
| **登录日志** | Entra ID Sign-in Logs | 异常的登录位置和设备 |
| **KQL 查询** | Microsoft Sentinel | 检测 Logic App 创建的用户立即登录 |

#### **KQL 检测查询示例**

```kusto
// 检测 Logic App 创建的用户立即登录
AuditLogs
| where Category == "UserManagement"
| where ActivityDisplayName has "Add user"
| where TargetResources[0].modifiedProperties[*].newValue contains "simulationuser"
| join (
    SigninLogs
    | where Identity contains "simulationuser"
) on $left.TargetResources[0].id == $left.UserId
| where TimeGenerated < createdDateTime + timedelta(minutes=5)
```

### **5.2 缓解措施**

| 缓解措施 | 优先级 | 实施难度 | 效果 |
|----------|--------|----------|------|
| **限制 Logic App 权限** | 高 | 中 | 减少可获取触发 URL 的用户范围 |
| **使用 Managed Identity** | 高 | 低 | 避免在 Logic App 中硬编码凭据 |
| **MFA 注册策略** | **高** | 低 | 限制 MFA 注册的条件和位置 |
| **条件访问策略** | 高 | 中 | 限制可以触发 Logic App 的用户和位置 |
| **B2B Guest 用户限制** | 中 | 低 | 限制 Guest 用户的访问权限 |

#### **具体缓解措施**

1. **Logic App 安全配置**：
   - 使用 Managed Identity 而不是硬编码凭据
   - 限制 `listCallbackUrl` 权限给最小必要的用户
   - 对 Logic App 端点应用条件访问策略

   > 参考文档：[AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md:105-120)

2. **MFA 注册策略**：
   - 配置条件访问策略，要求从可信位置注册 MFA
   - 限制 MFA 注册的条件，防止攻击者利用窗口期

   > 参考文档：[LateralMovementADEID.md](LateralMovementADEID.md:380-400)

3. **B2B Guest 用户管理**：
   - 限制 Guest 用户的访问权限
   - 定期审查 Guest 用户列表
   - 对 Guest 用户应用额外的条件访问策略

   > 参考文档：[PasswordSpray.md](PasswordSpray.md:170-190)

---

## **6. 参考资料与文件位置**

### **6.1 项目内参考资料**

| 文档 | 路径 | 相关内容 |
|------|------|----------|
| **Consent Grant 攻击** | [ConsentGrant.md](ConsentGrant.md) | OAuth 权限和同意框架，权限滥用 |
| **密码攻击** | [PasswordSpray.md](PasswordSpray.md) | MFA 配置，B2B Guest 用户登录日志 |
| **横向移动** | [LateralMovementADEID.md](LateralMovementADEID.md) | MFA 安全配置，MFA 注册策略 |
| **安全配置分析** | [AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md) | Logic App 安全配置，Managed Identity |
| **AiTM 攻击** | [Adversary-in-the-Middle.md](Adversary-in-the-Middle.md) | 中间人攻击，会话劫持 |

### **6.2 官方参考资料**

| 主题 | 官方文档链接 |
|------|--------------|
| **Logic Apps HTTP 触发器** | [Call, trigger, or nest logic apps by using HTTPS endpoints](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-http-endpoint) |
| **Azure AD B2B 协作** | [What is B2B collaboration in Microsoft Entra External ID?](https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b) |
| **MFA 注册策略** | [Configure MicrosoftEntra multifactor authentication registration policy](https://learn.microsoft.com/en-us/entra/identity/protection/howto-identity-protection-configure-mfa-policy) |
| **条件访问** | [What is Conditional Access?](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview) |
| **Managed Identity** | [What are managed identities for Azure resources?](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) |

### **6.3 检测规则模板**

项目中的检测规则模板位于：`config/ruletemplates/`

| 规则模板 | 文件位置 | 描述 |
|----------|----------|------|
| **Policy Change Detected** | [config/ruletemplates/Policy-change-detected.json](config/ruletemplates/Policy-change-detected.json) | 检测策略变更 |
| **Posture Issue Detected** | [config/ruletemplates/Posture-issue-detected.json](config/ruletemplates/Posture-issue-detected.json) | 检测配置问题 |

---

## **7. MITRE ATT&CK 映射**

| TTP | 描述 | 相关技术 |
|-----|------|----------|
| **T1110.003** | Password Spray (凭证访问) | 暴力破解，密码喷射 |
| **T1078.004** | Valid Accounts: Cloud Accounts (有效账户：云账户) | 使用被盗账户 |
| **T1550.001** | Application Access Token (应用程序访问令牌) | 窃取和使用访问令牌 |
| **T1528** | Steal Application Access Token (窃取应用程序访问令牌) | 令牌窃取 |
| **T1566.002** | Spearphishing Link (鱼叉式网络钓鱼链接) | 钓鱼攻击 |
| **T1136.003** | Create Account: Cloud Account (创建账户：云账户) | 创建新用户 |

---

## **8. 总结**

本学习目标演示了如何利用 Azure Logic App 的数据平面权限、API 逻辑漏洞和 MFA 注册窗口期进行攻击。主要收获包括：

1. **权限滥用**：低权限账号可能拥有读取 Logic App 工作流定义的权限
2. **逻辑漏洞**：工作流定义中的 Switch 分支可能包含隐藏的功能
3. **MFA 劫持**：新创建的账号存在 MFA 未配置的窗口期
4. **B2B 渗透**：Guest 用户可以跨租户访问，提供横向移动的机会

**关键要点**：
- 遵循最小权限原则，限制 Logic App 的访问权限
- 使用 Managed Identity 而不是硬编码凭据
- 配置 MFA 注册策略，防止攻击者利用窗口期
- 定期审查 Guest 用户和 B2B 邀请
- 监控 Logic App 的审计日志，检测异常活动
