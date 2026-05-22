# Debian/Ubuntu  初始化套件


## 一键重装系统（DD系统）

```bash
# Debian 专用，支持在 debian/ubuntu 中重新安装纯净 debian
./zdebian.sh

# 源自 bin456789/reinstall
./bin456789_reinstall.sh

# 源自 leitbogioro/Tools
./reinstallNET.sh

```



## Debian/Ubuntu  初始化脚本

> 通过 drop-in 配置文件和独立 env 文件管理，避免直接修改系统配置。
### 文件说明

| 文件 | 用途 |
|---|---|
| `vps_init.sh` | 主初始化脚本：用户创建、SSH 加固、防火墙、BBR 等 |
| `vps_auth.sh` | Google Authenticator 双因素认证配置 |
| `generate.sh` | 个人配置生成器（两种模式） |
| `vps_init.env` | 个人配置（由 generate.sh 生成，包含真实值） |
| `vps_netplan.sh` | 网络管理从 ifupdown 切换为 netplan |



### 快速开始

#### 1. 生成个人配置

```bash
./generate.sh
```

选择模式：

- **1) vps_init.env** — 交互式输入，生成独立配置文件。之后 `vps_init.sh` / `vps_auth.sh` 会自动加载。
- **2) vps_private.sh** — 从已有的 `vps_init.env` 读取，生成含真实值的完整独立脚本，无需 env 文件。

#### 2. 运行初始化

以 root 身份运行：

```bash
./vps_init.sh
```

首次使用建议按以下步骤：

```
选项 1 → First-time system setup（批量执行：用户、SSH、系统更新、防火墙、时区、BBR）
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
| 1. First-time system setup | 完整系统初始化 | User → SSH → Update → UFW → TZ → BBR |
| 2. Install Docker | 安装 Docker 并 pull 常用镜像 | 可选配置代理 |
| 3. Change hostname | 修改服务器主机名 | |
| 4. Adjust system services | 系统服务调优 | rc.local / systemd-resolved / Journal 日志 / sudoers / ping 权限 |

#### Local Permission

| 选项 | 功能 |
|---|---|
| 6. Setup environment | 配置 ADMIN_USER 的 git、SSH 公钥、开发环境 |
| 7. Verify ENV | 查看系统版本、BBR 状态、防火墙、端口监听 |

### 配置管理

#### 占位符机制

脚本中的个人信息（用户名、域名、代理地址、SSH 公钥等）使用 `__PLACEHOLDER__` 占位符，可直接公开。

真实值通过 `vps_init.env` 覆盖（位于脚本同目录），格式：

```bash
ADMIN_USER="your-name"
SSH_PORT="22"
DOMAIN="your.domain"
PROXY_HTTP="http://proxy.lan:8080"
DNS_FAMILY_PRIMARY="192.168.1.1"
GIT_NAME="Your Name"
GIT_EMAIL="your@email.com"
SSH_AUTHORIZED_KEYS=(
    "ssh-ed25519 AAAA... key1"
    "ssh-ed25519 AAAA... key2"
)
TRUSTED_IPS=(
    "1.2.3.4/32"
    "5.6.7.0/24"
)
```

使用 `generate.sh` 生成此文件，也可手动编辑。

#### Drop-in 配置文件

脚本采用现代 Linux 的 drop-in 机制，避免直接修改系统配置：

| 配置文件 | 说明 |
|---|---|
| `/etc/sudoers.d/90-user-env` | sudoers 规则（NOPASSWD、超时、代理继承） |
| `/etc/ssh/sshd_config.d/90-vps-init.conf` | SSH 服务端配置（PermitRootLogin、UseDNS） |
| `/etc/ssh/sshd_config.d/90-vps-auth.conf` | Google Auth ChallengeResponse 配置 |
| `/etc/apt/apt.conf.d/90-proxy.conf` | APT 代理（Family 环境） |


### 隐私与安全

- 脚本中的 `__PLACEHOLDER__` 不含真实个人信息
- `vps_init.env` 包含真实值，建议加入 `.gitignore`
- `vps_private.sh` 为含真实值的完整脚本，注意保管，建议加入 `.gitignore`
- Google Authenticator 备用码每次运行随机生成，不落盘
