# 需求文档 — Debian/Ubuntu VPS 初始化套件

> 本文档根据现有项目代码整理而成，用于说明项目的目标、功能需求与约束。
> 说明：Google Authenticator 双因素认证（`vps_auth.sh`）与网络管理切换（`vps_netplan.sh`）暂不纳入本版需求，将另行单独处理。

## 1. 项目概述

本项目是一套用于 **Debian / Ubuntu 系统 VPS** 的初始化与加固脚本套件，帮助用户在新服务器上快速完成用户创建、SSH 加固、系统更新、防火墙、防暴力破解、网络优化等基础配置。

- **目标用户**：需要批量或重复初始化 VPS 的运维人员 / 个人开发者。
- **多环境（Profile）支持**：
  - **home**：家庭 / 局域网环境，需通过局域网代理访问外网，使用内网 DNS。
  - **vps**：个人所有的公网 VPS，直连互联网，使用公共 DNS。
  - **public**：他人所有、需代为维护的公网主机。
  - 公共默认值集中在 **common** 层，各 profile 只覆盖差异项。
- **本版覆盖范围**：配置生成（`vps_generate.sh`）、系统初始化（`vps_init.sh`）；含多 Profile 重构（第 8 章）。

## 2. 设计原则

| 原则 | 说明 |
|---|---|
| 占位符机制 | 公共库中的脚本使用 `__PLACEHOLDER__` 占位符，脚本本身不含真实值，可直接公开。 |
| 配置与脚本分离 | 真实值集中在私有配置源 `vps_config.sh`，仅本地保管、不入公共库。 |
| 单文件部署 | 生成含所有真实值与多 profile 的单文件 `vps_deploy.sh`，远程仅需 copy/paste 一次即可运行。 |
| 多 Profile | 一份配置源可保存 `common` 公共层与多个环境 profile（`home` / `vps` / `public`），运行时选择其一。 |
| Drop-in 配置 | 采用现代 Linux 的 drop-in 机制（`sudoers.d`、`sshd_config.d` 等），避免直接改动系统主配置文件。 |
| 幂等性 | 关键操作（建用户、写 sudoers、写 Include 指令等）在执行前检查是否已存在，可重复运行。 |
| 隐私安全 | 含真实值的 `vps_config.sh`、`vps_deploy.sh` 必须纳入 `.gitignore`，不上传公共库。 |

## 3. 功能需求

### FR-1 配置生成（`vps_generate.sh`）

> 本项为 **多 Profile 重构** 的核心，详见第 8 章。`vps_generate.sh` 负责从私有配置源 `vps_config.sh` 生成含真实值、内嵌多 profile 的单文件 `vps_deploy.sh`。

- **FR-1.1 配置源 `vps_config.sh`**
  - 采用 **bash 片段格式**，可被 `source` 直接读取，无外部依赖。
  - 内含 `PROFILES=( ... )` 列表与 `profile_common` 及各环境 profile 函数（`profile_home` / `profile_vps` / `profile_public`）。
  - 每个 profile 函数体内以 `变量=值` 方式定义配置项；数组字段（SSH 公钥等）沿用原生 `( "..." "..." )` 写法。
  - 该文件仅本地保管，纳入 `.gitignore`，不上传公共库。

- **FR-1.2 收集配置（交互录入，可选）**
  - 交互式收集各配置项：管理员用户名、SSH 端口、DNS 搜索域、局域网代理地址、家庭 DNS（主/备）、Git 用户名、Git 邮箱、SSH 公钥（多条）等。
  - 支持循环录入多个 profile，并单独录入一次 `common` 公共层。
  - 用户名输入校验：不允许包含空格；直接回车可跳过某项；数组字段逐行输入、空行结束。

- **FR-1.3 生成单文件 `vps_deploy.sh`**
  - 前置条件：存在配置源 `vps_config.sh`（或经 FR-1.2 录入得到）。
  - 以公共库中的 `vps_init.sh` 为模板：
    - 用真实的 `PROFILES` 列表替换 `__PROFILE_LIST__`；
    - 用真实的 `profile_common` 及各 profile 函数体替换 `__PROFILE_FUNCS__`；
    - 删除模板中“加载外部配置”的相关逻辑。
  - 输出**单个** `vps_deploy.sh`，内嵌全部真实值与所有 profile，无需任何外部文件即可运行，并赋予可执行权限。
  - `vps_deploy.sh` 含真实值，纳入 `.gitignore`，不上传公共库。

### FR-2 系统初始化（`vps_init.sh`）

以 root 身份运行的交互式菜单脚本。

- **FR-2.0 环境准备与 Profile 选择**
  - **Profile 选择**：启动时确定当前 profile。支持两种方式（详见第 8 章）：
    - 命令行参数 `--profile <name>` 直接指定；
    - 无参数时列出 `PROFILES` 供交互选择。
  - 加载顺序：先执行 `profile_common`，再执行选中的 `profile_<name>`，实现公共默认值 + 环境差异覆盖。
  - 校验选中的 profile 存在；未设置 `ADMIN_USER` 时报错退出。
  - Family/局域网类 profile 生效时，导出 `http_proxy` / `https_proxy`，并为 APT 写入代理配置（`/etc/apt/apt.conf.d/90-proxy.conf`）。
  - 校验运行身份为 root、操作系统为 Ubuntu 或 Debian（不限版本）。

- **FR-2.1 首次系统初始化（菜单 1，批量子步骤，每步可选 y/N）**
  - **User**：创建 `ADMIN_USER`（已存在则跳过）、设置 root 与该用户密码、加入 sudoers（`/etc/sudoers.d/90-user-env`，NOPASSWD）、复制 `/root/*.sh` 到用户目录。
  - **SSH**：写入 drop-in（`/etc/ssh/sshd_config.d/90-vps-init.conf`），设置 `PermitRootLogin prohibit-password`、`UseDNS no`；可选修改监听端口为 `SSH_PORT`；确保主配置含 Include 指令；重启 ssh。
  - **Update**：更新系统并安装常用工具（wget、curl、git、tmux、htop、vim、zsh、jq 等），启用 NTP 时间同步。
  - **UFW**：安装并配置防火墙（放行 22、`SSH_PORT`、80、443、2443、8443、60001-60005/udp 等）并启用。
  - **TZ**：设置时区（默认 `Asia/Shanghai`）。
  - **BBR**：写入 `sysctl.conf` 网络与性能调优参数，启用 BBR 拥塞控制（`fq` 队列）。

- **FR-2.2 安装 Docker（菜单 2）**
  - 通过官方脚本安装 Docker，将 `ADMIN_USER` 加入 docker 组。
  - Family 环境可选为 Docker 配置代理（`docker.service.d/http-proxy.conf`）。
  - 预拉取常用镜像（smokeping、ubuntu、alpine）。

- **FR-2.3 修改主机名（菜单 3）**
  - 交互输入新主机名，更新 `hostname`、`/etc/hostname`、`/etc/hosts` 并调用 `hostnamectl`。

- **FR-2.4 系统服务调优（菜单 4，各项可选 y/N）**
  - **rc.local**：创建并启用 `rc-local` 服务。
  - **Disable resolve**：关闭 `systemd-resolved` 相关服务，写入静态 `/etc/resolv.conf`（按环境选用 VPS/Family DNS）。
  - **Journal**：设置日志上限（VPS 64M / Family 128M）与保留期（7 天）。
  - **Sudoers**：追加 sudo 超时（30 分钟）与代理环境变量继承。
  - **Ping**：为 `/bin/ping` 授予 `cap_net_raw` 权限。

- **FR-2.5 用户环境配置（菜单 6，本地权限）**
  - 可选配置 Git 全局信息（用户名、邮箱、编辑器等）。
  - 可选写入 `ADMIN_USER` 的 `~/.ssh/authorized_keys`（来自 `SSH_AUTHORIZED_KEYS`）。
  - 克隆并执行环境配置仓库（environment-config）。

- **FR-2.6 环境验证（菜单 7，本地权限）**
  - 输出系统信息、BBR 状态、端口监听（TCP/UDP）、UFW 状态。

- **FR-2.7 防暴力破解登录（fail2ban）**
  - 使用 **fail2ban** 防护 SSH 暴力破解，仅保护 SSH（`sshd` jail），暂不含其他服务（预留扩展）。
  - 安装 fail2ban 并启用开机自启。
  - 与现有 UFW 集成：使用 `banaction = ufw`，通过 UFW 执行封禁，无需修改 `before.rules`。
  - 复用 `TRUSTED_IPS` 作为 `ignoreip` 白名单，避免误封受信 IP（自动包含 `127.0.0.1/8 ::1`）。
  - jail 监听端口应与实际 SSH 端口一致（取 `SSH_PORT`，未设置时为 22）。
  - 关键参数（提供合理默认，可按需调整）：`maxretry`、`findtime`、`bantime`。
  - 采用 drop-in 配置文件（如 `/etc/fail2ban/jail.d/90-vps-sshd.local`），不直接改动 `jail.conf`；配置具备幂等性，重复运行不产生重复内容。
  - 配置完成后重启/重载 fail2ban 使其生效。

## 4. 配置项清单

配置项按层级组织于 profile 中：`common` 层放公共默认值，各环境 profile（`home` / `vps` / `public`）覆盖差异项。

| 变量 / 占位符 | 含义 | 建议所属层 |
|---|---|---|
| `ADMIN_USER` / `__ADMIN_USER__` | 日常管理用普通用户名 | profile（必填） |
| `SSH_PORT` / `__SSH_PORT__` | SSH 监听端口 | profile |
| `TIMEZONE` | 时区（默认 `Asia/Shanghai`） | common |
| `DOMAIN` / `__DOMAIN__` | DNS 搜索域 | profile |
| `PROXY_HTTP` / `__PROXY_HTTP__` | 局域网 HTTP 代理地址（home） | profile |
| `DNS_PRIMARY` / `DNS_SECONDARY` | DNS 服务器（默认 `1.1.1.1` / `8.8.4.4`，profile 可覆盖为内网 DNS） | common（profile 可覆盖） |
| `JOURNAL_MAX_SIZE` | 日志上限（默认 `64M`，profile 可覆盖） | common（profile 可覆盖） |
| `GIT_NAME` / `GIT_EMAIL` | Git 全局用户名与邮箱 | common |
| `SSH_AUTHORIZED_KEYS[]` | 写入用户 authorized_keys 的公钥列表 | common 或 profile |
| `TRUSTED_IPS[]` | 受信任 IP 列表，作为 fail2ban `ignoreip` 白名单 | common 或 profile |
| `F2B_MAXRETRY` | fail2ban 最大失败次数（默认建议 5） | common（内置默认） |
| `F2B_FINDTIME` | fail2ban 统计时间窗（默认建议 10m） | common（内置默认） |
| `F2B_BANTIME` | fail2ban 封禁时长（默认建议 1h，可设更长） | common（内置默认） |
| `PROFILES[]` | 可选 profile 名称列表（`home` `vps` `public`） | 顶层 |

## 5. 非功能需求

- **NFR-1 安全**：默认禁用 root 密码登录、防火墙默认启用、fail2ban 防暴力破解 SSH、sudoers 使用独立 drop-in 文件、不在公开脚本中保存真实敏感信息。
- **NFR-2 幂等**：重复运行不应产生重复配置或破坏已有状态。
- **NFR-3 可移植**：兼容 Ubuntu / Debian，不限制具体版本。
- **NFR-4 可维护**：通过 drop-in、profile 分层与配置源分离，便于升级与差异化管理。
- **NFR-5 隐私**：含真实值的文件（`vps_config.sh`、`vps_deploy.sh`）必须纳入 `.gitignore`。
- **NFR-6 最少文件部署**：目标主机通常刚完成 OS 安装、缺乏工具，只能通过 copy/paste 传输文件；部署产物必须为单文件、零外部依赖。

## 6. 运行环境与前置条件

- 操作系统：Debian 或 Ubuntu。
- 权限：`vps_deploy.sh`（由 `vps_init.sh` 模板生成）需以 root 运行；用户环境相关步骤在目标用户下执行。
- 建议执行顺序：本地 `vps_generate.sh` 生成 `vps_deploy.sh` → copy/paste 到目标主机 → 运行并选择 profile → 菜单 1（首次初始化）→ 菜单 6（用户环境）→ 菜单 7（验证）。

## 7. 约束与已知事项

- 部分增强配置（网卡改名、swap 重建、保留空间调整、apt 源/代理、移除 snap 等）需手工执行，详见 `vps_enhance.md`。
- 双因素认证与网络管理切换（netplan）不在本版需求范围，后续单独处理。

## 8. 多 Profile 重构需求

本次重构目标：将原先"一个配置文件对应一组参数、生成多个独立单文件"的机制，改造为"一份配置源保存多套 profile、生成一个内嵌全部 profile 的单文件"。

### 8.1 背景与动机

- 待初始化主机分属三类环境：**home**（家庭局域网，经代理上网、内网 DNS）、**vps**（个人公网 VPS）、**public**（他人所有、需代为维护的公网主机）。
- 目标主机刚装完 OS、缺工具，只能 copy/paste 传输 → 要求部署产物为**单文件**。
- 代码需上传公共 git 库 → 公开文件不得含真实配置；真实配置须私有。

### 8.2 文件角色划分

| 文件 | 位置 | 内容 | 公开性 |
|---|---|---|---|
| `vps_init.sh` | 公共 git | 占位符模板：含多 profile 结构（`__PROFILE_LIST__` / `__PROFILE_FUNCS__`）与 profile 选择逻辑 | 公开 |
| `vps_generate.sh` | 公共 git | 生成器：读取/录入配置源，注入模板生成单文件 | 公开 |
| `vps_config.sh` | 本地私有 | bash 片段配置源，含 `common` + 多个 profile 真实值 | `.gitignore` |
| `vps_deploy.sh` | 本地私有 | 生成的单文件部署脚本，内嵌全部真实值与 profile | `.gitignore` |

### 8.3 配置源 `vps_config.sh` 格式

- 采用 bash 片段（可 `source`），无外部依赖。
- 结构：
  - `PROFILES=(home vps public)` — profile 列表。
  - `profile_common()` — 公共默认值（时区、Git、公钥等）。
  - `profile_home()` / `profile_vps()` / `profile_public()` — 各环境差异项。
- 数组字段沿用原生 `( "..." "..." )` 写法，无需自定义分隔符。

### 8.4 Profile 选择与加载（`vps_init.sh` / `vps_deploy.sh`）

- 支持 `--profile <name>` 参数指定；无参数时列出 `PROFILES` 交互选择（默认行为）。
- 加载顺序：`profile_common` → 选中的 `profile_<name>`（公共值先设，环境值后覆盖）。
- 校验选中 profile 是否存在，不存在则报错。
- `common` 为固定的公共层名称（不出现在可选列表中，始终先加载）。

### 8.5 生成流程（`vps_generate.sh`）

1. 获取配置：读取现有 `vps_config.sh`，或交互式录入（含循环录入多个 profile 与一次 common）。
2. 以 `vps_init.sh` 为模板，替换 `__PROFILE_LIST__`、`__PROFILE_FUNCS__`，并删除加载外部配置的逻辑。
3. 输出单个 `vps_deploy.sh`，赋可执行权限。

### 8.6 兼容性

- 本版**不再使用** `vps_init.env`；由 `vps_config.sh`（多 profile）取代其配置源角色。
- 原"生成多个独立单文件"的模式由"生成一个内嵌多 profile 的单文件"取代。
