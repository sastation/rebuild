# Debian/Ubuntu  初始化套件



## Debian/Ubuntu  初始化脚本

> 通过 drop-in 配置文件与多 profile 配置源管理，生成单文件部署脚本，避免直接修改系统配置。
### 文件说明

| 文件 | 用途 | 公开性 |
|---|---|---|
| `vps_init.sh` | 主初始化模板：多 profile、用户创建、SSH 加固、防火墙、BBR、fail2ban 等 | 公开 |
| `vps_generate.sh` | 生成器：从配置源生成单文件 `vps_deploy.sh` | 公开 |
| `vps_config.sh.example` | 配置源示例（复制为 `vps_config.sh` 填入真实值） | 公开 |
| `vps_config.sh` | 私有配置源：`common` + 多 profile 真实值 | `.gitignore` |
| `vps_deploy.sh` | 生成的单文件部署脚本（内嵌全部 profile） | `.gitignore` |
| `vps_auth.sh` | Google Authenticator 双因素认证配置 | 公开 |
| `vps_netplan.sh` | 网络管理从 ifupdown 切换为 netplan | 公开 |

### Profile 说明

一份配置源可保存多套 profile，`common` 为公共层，各 profile 覆盖差异项：

- **home** — 家庭 / 局域网，经代理上网、内网 DNS（`AREA="Family"`）
- **vps** — 个人公网 VPS（`AREA="VPS"`）
- **public** — 他人所有、代为维护的公网主机（`AREA="VPS"`）



### 快速开始

#### 1. 准备配置源并生成部署脚本

```bash
cp vps_config.sh.example vps_config.sh   # 编辑填入真实值
./vps_generate.sh                        # 生成 vps_deploy.sh
```

`vps_generate.sh` 两种模式：

- **1) 生成** — 从已有 `vps_config.sh` 生成单文件 `vps_deploy.sh`。
- **2) 录入** — 交互录入 common 与多个 profile，写入 `vps_config.sh` 后可立即生成。

#### 2. 部署到目标主机

将生成的单文件 `vps_deploy.sh` copy/paste 到目标主机，以 root 运行：

```bash
./vps_deploy.sh                 # 交互选择 profile
./vps_deploy.sh --profile vps   # 直接指定 profile
```

首次使用建议按以下步骤：

```
选项 1 → First-time system setup（批量执行：用户、SSH、更新、防火墙、时区、BBR、fail2ban）
选项 6 → 配置 ADMIN_USER 的 git / SSH 公钥 / 环境
选项 7 → 验证配置
```

#### 3. Google Authenticator（可选）

```bash
./vps_auth.sh
```

- **1) System-wide setup** — 安装 Google Authenticator PAM 模块，配置受信 IP 白名单
- **2) Local user setup** — 为当前用户生成密钥和随机备用码

### 菜单详解

#### Root Permission

| 选项 | 功能 | 包含子步骤 |
|---|---|---|
| 1. First-time system setup | 完整系统初始化 | User → SSH → Update → UFW → TZ → BBR → fail2ban |
| 2. Install Docker | 安装 Docker 并 pull 常用镜像 | 可选配置代理 |
| 3. Change hostname | 修改服务器主机名 | |
| 4. Adjust system services | 系统服务调优 | rc.local / systemd-resolved / Journal 日志 / sudoers / ping 权限 |
| 5. Setup fail2ban | 防暴力破解登录（SSH，经 UFW 封禁） | 复用 TRUSTED_IPS 作 ignoreip 白名单 |

#### Local Permission

| 选项 | 功能 |
|---|---|
| 6. Setup environment | 配置 ADMIN_USER 的 git、SSH 公钥、开发环境 |
| 7. Verify ENV | 查看系统版本、BBR 状态、防火墙、端口监听 |

### 配置管理

#### 配置源与占位符机制

- 公共库中的 `vps_init.sh` 使用 `__PROFILE_LIST__` / `__PROFILE_FUNCS__` 等占位符，不含真实值，可直接公开。
- 真实值集中在私有配置源 `vps_config.sh`（bash 片段，多 profile），由 `vps_generate.sh` 注入生成单文件 `vps_deploy.sh`。
- 配置源结构参见 `vps_config.sh.example`：`PROFILES=(...)` + `profile_common` + 各 `profile_<name>`。

#### Drop-in 配置文件

脚本采用现代 Linux 的 drop-in 机制，避免直接修改系统配置：

| 配置文件 | 说明 |
|---|---|
| `/etc/sudoers.d/90-user-env` | sudoers 规则（NOPASSWD、超时、代理继承） |
| `/etc/ssh/sshd_config.d/90-vps-init.conf` | SSH 服务端配置（PermitRootLogin、UseDNS） |
| `/etc/ssh/sshd_config.d/90-vps-auth.conf` | Google Auth ChallengeResponse 配置 |
| `/etc/apt/apt.conf.d/90-proxy.conf` | APT 代理（Family 环境） |
| `/etc/fail2ban/jail.d/90-vps-sshd.local` | fail2ban SSH 防护（banaction=ufw、ignoreip） |


### 隐私与安全

- 公共库中的 `vps_init.sh` 使用占位符，不含真实个人信息
- `vps_config.sh`、`vps_deploy.sh` 含真实值，已加入 `.gitignore`，请勿上传公共库
- fail2ban 复用 `TRUSTED_IPS` 作为 `ignoreip`，避免误封受信 IP
- Google Authenticator 备用码每次运行随机生成，不落盘
