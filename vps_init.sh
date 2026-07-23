#!/bin/bash
set -euo pipefail

# ============================================================
# Fixed constants — do not contain personal data
# ============================================================
APT_PROXY_CONF="/etc/apt/apt.conf.d/90-proxy.conf"
SUDOERS_FILE="/etc/sudoers.d/90-user-env"

# 默认值（可被 profile 覆盖）
ADMIN_USER=""
SSH_PORT=""
TIMEZONE="Asia/Shanghai"
DOMAIN=""
PROXY_HTTP=""
AREA="VPS"
DNS_PRIMARY="1.1.1.1"
DNS_SECONDARY="8.8.4.4"
JOURNAL_MAX_SIZE="64M"
GIT_NAME=""
GIT_EMAIL=""
SSH_AUTHORIZED_KEYS=()
TRUSTED_IPS=()
F2B_MAXRETRY="5"
F2B_FINDTIME="10m"
F2B_BANTIME="1h"

# ============================================================
# Profiles — 真实值由 vps_generate.sh 注入到 vps_deploy.sh
# ============================================================
PROFILES=( __PROFILE_LIST__ )

profile_common() {
    # __COMMON_BODY__
    :
}

# __PROFILE_FUNCS__

# ============================================================
# Runtime variables (do not edit)
# ============================================================
ID="$(id -u)"
OSName="$(awk -F'"' '/^NAME=/ {print $2}' /etc/os-release | awk '{print $1}')"
OSVersion="$(awk -F'"' '/VERSION_ID=/ {print $2}' /etc/os-release)"
Separator="$(printf '%*s' 50 | tr ' ' '*')"
SELECTED_PROFILE=""
USER_HOME=""

# ============================================================
# Functions
# ============================================================

ProfileExists() {
    # 判断 profile 是否在 PROFILES 列表中
    local name="$1" p
    for p in "${PROFILES[@]}"; do
        [[ "${p}" = "${name}" ]] && return 0
    done
    return 1
}

SelectProfile() {
    # 确定当前 profile：命令行参数优先，否则交互选择
    if [[ -z "${SELECTED_PROFILE}" ]]; then
        if [[ ${#PROFILES[@]} -eq 0 ]]; then
            echo "ERROR: No profiles defined."
            echo "       Generate vps_deploy.sh via ./vps_generate.sh first."
            exit 1
        fi
        echo "=> Select profile"
        local i=1 name
        for name in "${PROFILES[@]}"; do
            echo "  ${i}) ${name}"
            i=$((i + 1))
        done
        local choice
        read -p "Enter number or name [1]: " choice
        choice="${choice:-1}"
        if [[ "${choice}" =~ ^[0-9]+$ ]]; then
            SELECTED_PROFILE="${PROFILES[$((choice - 1))]:-}"
        else
            SELECTED_PROFILE="${choice}"
        fi
    fi

    if ! ProfileExists "${SELECTED_PROFILE}"; then
        echo "ERROR: profile '${SELECTED_PROFILE}' not found."
        echo "       Available: ${PROFILES[*]}"
        exit 1
    fi

    echo "Selected profile: ${SELECTED_PROFILE}"

    # 加载顺序：common 先，profile 后覆盖
    profile_common
    "profile_${SELECTED_PROFILE}"

    # 校验必要配置
    if [[ -z "${ADMIN_USER}" || "${ADMIN_USER}" == __* ]]; then
        echo "ERROR: ADMIN_USER is not set in profile '${SELECTED_PROFILE}'."
        exit 1
    fi

    # 派生运行时变量
    USER_HOME="/home/${ADMIN_USER}"

    # 代理与 APT 代理配置（PROXY_HTTP 有值则生效）
    if [[ -n "${PROXY_HTTP}" ]]; then
        export http_proxy="${PROXY_HTTP}"
        export https_proxy="${PROXY_HTTP}"
        if [[ "${ID}" -eq 0 ]]; then
            echo "Acquire::http::Proxy \"${PROXY_HTTP}\";" > "${APT_PROXY_CONF}"
            echo "Acquire::https::Proxy \"${PROXY_HTTP}\";" >> "${APT_PROXY_CONF}"
        fi
    fi
}

Root() {
    # 判断当前用户是否为 root
    if [[ "${ID}" -ne 0 ]]; then
        echo "Please run script as root!"
        exit 1
    fi
}

OS() {
    # 判断当前OS是否为 Ubuntu 或 Debian（不限制版本）
    if [[ "${OSName}" = "Ubuntu" ]] || [[ "${OSName}" = "Debian" ]]; then
        return 0
    else
        echo "OS is not Ubuntu or Debian..."
        exit 2
    fi
}

Hostname() {
    # 修改服务器名称
    echo "=> Change hostname"
    printf "Please input new hostname: "
    read opt

    hostname "${opt}"
    echo "${opt}" > /etc/hostname
    hostnamectl set-hostname "${opt}"   # u18 or later command
    echo "127.0.0.1       ${opt}" >> /etc/hosts
}

User() {
    # 增加用户 ADMIN_USER，修改 root/ADMIN_USER 密码，修改 sudoers
    echo "=> Add user ${ADMIN_USER}, update root & ${ADMIN_USER} password"

    # 检查用户 ADMIN_USER 若没有则创建
    if id "${ADMIN_USER}" &>/dev/null; then
        echo "User ${ADMIN_USER} already exists. Skipping useradd."
    else
        useradd -m -s /bin/bash "${ADMIN_USER}"
    fi

    while true; do
        read -s -p "Input new password: " newP && echo
        read -s -p "Input password again: " secondP && echo

        if [[ "${newP}" != "${secondP}" ]]; then
            echo "Not match!"
        else
            break
        fi
    done

    echo "root:${newP}" | chpasswd
    echo "${ADMIN_USER}:${newP}" | chpasswd

    # Add into sudoers
    echo "=> Add ${ADMIN_USER} into sudoers (${SUDOERS_FILE})"
    apt update 2>/dev/null || true
    apt install sudo -y
    if [[ ! -f "${SUDOERS_FILE}" ]] || ! grep -q "^${ADMIN_USER}" "${SUDOERS_FILE}" 2>/dev/null; then
        echo "${ADMIN_USER}   ALL=(ALL:ALL) NOPASSWD:ALL" >> "${SUDOERS_FILE}"
        chmod 0440 "${SUDOERS_FILE}"
    else
        echo "${ADMIN_USER} already in sudoers, skipping."
    fi

    # 复制初始化脚本到 ADMIN_USER 目录
    cp /root/*.sh "${USER_HOME}/" 2>/dev/null || echo "No .sh files in /root to copy"
    chown "${ADMIN_USER}":"${ADMIN_USER}" "${USER_HOME}"/*.sh 2>/dev/null || true
    chmod 755 "${USER_HOME}"/*.sh 2>/dev/null || true

    # 写入 SSH 公钥到 root（幂等）
    if [[ ${#SSH_AUTHORIZED_KEYS[@]} -gt 0 ]]; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        for key in "${SSH_AUTHORIZED_KEYS[@]}"; do
            grep -qF "${key}" /root/.ssh/authorized_keys 2>/dev/null && continue
            echo "${key}" >> /root/.ssh/authorized_keys
        done
    fi
}

SSH() {
    # 修改 sshd 配置（通过 drop-in 文件）
    echo "=> Setup ssh server"
    read -rsp $'Press enter to continue...\n'

    SSHD_CONFIG="/etc/ssh/sshd_config"
    DROPIN_DIR="/etc/ssh/sshd_config.d"
    DROPIN_FILE="${DROPIN_DIR}/90-vps-init.conf"

    echo "=> Write ${DROPIN_FILE}"
    mkdir -p "${DROPIN_DIR}"

    # 写入 drop-in 配置
    {
        echo "# Managed by vps_init.sh"
        echo "PermitRootLogin prohibit-password"
        echo "UseDNS no"
        echo "#GatewayPorts yes"
    } > "${DROPIN_FILE}"

    # 修改 sshd 的监听端口
    read -p "=> Setup ssh server => Change port to ${SSH_PORT}? === (y/No) " opt
    case "${opt}" in
        y|yes)
            # 注释掉 sshd_config 中的 Port 行，避免双端口监听
            sed -i 's/^Port /#Port /' "${SSHD_CONFIG}"
            echo "Port ${SSH_PORT}" >> "${DROPIN_FILE}"
            ;;
    esac

    # 确保 sshd_config 包含 Include 指令
    if ! grep -qF "Include ${DROPIN_DIR}/*.conf" "${SSHD_CONFIG}" 2>/dev/null; then
        {
            echo ""
            echo "Include ${DROPIN_DIR}/*.conf"
        } >> "${SSHD_CONFIG}"
    fi

    service ssh restart
}

Update() {
    # 更新系统及安装必要的应用
    echo "=> Update system & install necessary packages"
    apt -y update
    apt -y upgrade

    apt -y install sudo wget curl traceroute nmap whois git tmux htop
    apt -y install mtr dnsutils hping3
    apt -y install net-tools rsync psmisc tree cron
    apt -y install screen zsh vim bc jq mosh file
    apt -y install systemd-timesyncd
    timedatectl set-ntp true
    systemctl restart systemd-timesyncd
}

Enable_RC_Local() {
    # 开启 rc.local 服务
    if [[ -f /etc/rc.local ]]; then
        echo "/etc/rc.local already exists, skipping."
        return
    fi
    cat > /etc/rc.local << 'EOF'
#!/bin/bash
sleep 1
EOF
    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local
}

Disable_Resolve() {
    # 关闭 systemd-resolved 服务，创建 /etc/resolv.conf，使用静态 DNS
    if [[ ! -f /etc/resolv.conf-bak ]]; then
        mv /etc/resolv.conf /etc/resolv.conf-bak
    fi
    resolv_file="/etc/resolv.conf"
    {
        echo "#domain ${DOMAIN}"
        echo "search ${DOMAIN}"
        echo "nameserver ${DNS_PRIMARY}"
        [[ -n "${DNS_SECONDARY}" ]] && echo "nameserver ${DNS_SECONDARY}"
    } > "${resolv_file}"

    if systemctl status systemd-resolved-varlink.socket &> /dev/null; then
        systemctl disable --now systemd-resolved-varlink.socket
    fi
    
    if systemctl status systemd-resolved-monitor.socket &> /dev/null; then
        systemctl disable --now systemd-resolved-monitor.socket
    fi 
    
    if systemctl status systemd-resolved.service &> /dev/null; then
        systemctl disable --now systemd-resolved.service
    fi
}

Set_Journal() {
    # 设置日志大小
    fs="/etc/systemd/journald.conf"
    sed -i "s/^#\{0,1\}SystemMaxUse=.*/SystemMaxUse=${JOURNAL_MAX_SIZE}/g" "${fs}"
    sed -i "s/^#\{0,1\}MaxRetentionSec=.*/MaxRetentionSec=7d/g" "${fs}"
    systemctl restart systemd-journald

    journalctl --disk-usage
}

Modify_Sudoers() {
    # 在 sudoers.d 中添加选项：继承代理环境、设置超时时间（幂等）
    grep -q "Defaults timestamp_timeout=30" "${SUDOERS_FILE}" 2>/dev/null \
        && echo "Defaults already set, skipping." \
        || echo "Defaults timestamp_timeout=30" >> "${SUDOERS_FILE}"
    grep -q "Defaults env_keep=" "${SUDOERS_FILE}" 2>/dev/null \
        && echo "Defaults env_keep already set, skipping." \
        || echo "Defaults env_keep=\"http_proxy https_proxy HTTP_PROXY HTTPS_PROXY\"" >> "${SUDOERS_FILE}"
    chmod 0440 "${SUDOERS_FILE}"
    echo "=> Updated ${SUDOERS_FILE}"
}

Set_Ping() {
    # ubuntu/debian set ping permission
    setcap cap_net_raw+ep /bin/ping 2>/dev/null || true
}

UFW() {
    # 配置防火墙
    echo "=> Setup firewall"
    apt -y install ufw
    ufw allow 22/tcp
    [[ -n "${SSH_PORT}" ]] && ufw allow "${SSH_PORT}/tcp"
    ufw allow 80
    ufw allow 443
    ufw allow 2443
    ufw allow 8443
    ufw allow 60001:60005/udp
    ufw allow from 172.17.0.1/24 to 172.17.0.1/24

    echo "Y" | ufw enable
}

TZ() {
    # 更改时区
    echo "=> Change timezone to ${TIMEZONE}"
    timedatectl set-timezone "${TIMEZONE}"
}

BBR() {
    # 安装及配置 BBR（通过 sysctl.d drop-in，幂等）
    echo "=> Enable BBR"
    cat > /etc/sysctl.d/90-vps-bbr.conf << 'EOF'
# --- 核心网络配置 (旁路由必需) ---
#net.ipv4.ip_forward=1
#net.ipv4.conf.all.send_redirects=0
#net.ipv4.conf.default.send_redirects=0
#net.ipv4.conf.all.accept_redirects=0
#net.ipv4.conf.default.accept_redirects=0

# --- Docker 与高并发相关 ---
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
net.core.somaxconn=32768
net.core.netdev_max_backlog=5000
fs.file-max=65536

# --- 网络性能调优 ---
vm.swappiness=10
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# --- 禁用 IPv6 ---
#net.ipv6.conf.all.disable_ipv6=1
#net.ipv6.conf.default.disable_ipv6=1
EOF

    # conntrack 参数（仅模块可用时追加）
    if modprobe -n nf_conntrack 2>/dev/null; then
        modprobe nf_conntrack 2>/dev/null || true
        cat >> /etc/sysctl.d/90-vps-bbr.conf << 'EOF'
# --- 设置连接参数 ---
# 小内存主机设置最大连接数限制 = nf_conntrack_buckets * 4
#net.netfilter.nf_conntrack_buckets = 4096
#net.netfilter.nf_conntrack_max = 16384

# 缩短 TIME_WAIT 和 ESTABLISHED 的超时时间
net.netfilter.nf_conntrack_tcp_timeout_established = 1200
net.netfilter.nf_conntrack_tcp_timeout_syn_sent=30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
EOF
    fi

    sysctl -p /etc/sysctl.d/90-vps-bbr.conf
}

Docker_Proxy() {
    # 设置 Docker 服务使用代理
    mkdir -p /etc/systemd/system/docker.service.d
    cat > /etc/systemd/system/docker.service.d/http-proxy.conf << EOF
[Service]
Environment="HTTP_PROXY=${PROXY_HTTP}"
Environment="HTTPS_PROXY=${PROXY_HTTP}"
Environment="NO_PROXY=localhost,127.0.0.0/8,*.lan"
EOF
    systemctl daemon-reload
    systemctl show --property Environment docker
    systemctl restart docker
}

Docker() {
    # 安装 Docker
    echo "=> Install docker"
    read -rsp $'Press enter to continue...\n'

    curl -sSL https://get.docker.com/ | sh
    usermod -aG docker "${ADMIN_USER}"

    if [[ -n "${PROXY_HTTP}" ]]; then
        read -p "=> Setup Docker => Set proxies? === (y/No) " opt
        case "${opt}" in
            y|yes) Docker_Proxy ;;
        esac
    fi

    docker pull linuxserver/smokeping || true
    docker pull ubuntu || true
    docker pull alpine || true
}

SetupUserEnv() {
    # 对用户 ADMIN_USER 的环境进行配置
    echo "=> Setup ${ADMIN_USER} env"

    read -p "=> Setup git global? === (y/No) " opt
    if [[ "${opt}" = "y" ]] || [[ "${opt}" = "yes" ]]; then
        git config --global user.email "${GIT_EMAIL}"
        git config --global user.name "${GIT_NAME}"
        git config --global core.editor "vim"
        git config --global core.pager 'less -F -X'
        git config --global push.default matching
    fi

    read -p "=> Setup .ssh/authorized_keys? === (y/No) " opt
    if [[ "${opt}" = "y" ]] || [[ "${opt}" = "yes" ]]; then
        mkdir -p "${USER_HOME}/.ssh"
        chmod 700 "${USER_HOME}/.ssh"
        for key in "${SSH_AUTHORIZED_KEYS[@]}"; do
            grep -qF "${key}" "${USER_HOME}/.ssh/authorized_keys" 2>/dev/null && continue
            echo "${key}" >> "${USER_HOME}/.ssh/authorized_keys"
        done
    fi

    echo "=> Setup env"
    read -rsp $'Press enter to continue...\n'
    cd ~
    mkdir -p coding/github
    cd coding/github
    if [[ -d environment-config ]]; then
        echo "environment-config already exists, skipping clone."
    else
        git clone --depth=1 https://github.com/sastation/environment-config.git
    fi
    cd environment-config
    ./run.sh
}

Verify() {
    # 基本信息
    echo "UID: ${ID}"
    echo "OSName: ${OSName}"
    echo "OSVersion: ${OSVersion}"
    
    # 验证配置
    echo "======"
    sudo sysctl net.ipv4.tcp_available_congestion_control
    sudo lsmod | grep bbr || true
    echo "======"
    sudo netstat -lntp
    sudo netstat -lnup
    echo "======"
    if [ -x /usr/sbin/ufw ]; then
        echo "UFW Status:"
        sudo ufw status
    fi
}

F2B() {
    # 防暴力破解登录：fail2ban 保护 SSH，通过 UFW 执行封禁
    echo "=> Setup fail2ban (SSH brute-force protection)"
    apt -y install fail2ban

    local jail_dir="/etc/fail2ban/jail.d"
    local jail_file="${jail_dir}/90-vps-sshd.local"
    local ssh_port="${SSH_PORT:-22}"

    # 组装 ignoreip：本地 + 受信 IP
    local ignore="127.0.0.1/8 ::1"
    if [[ ${#TRUSTED_IPS[@]} -gt 0 ]]; then
        ignore="${ignore} ${TRUSTED_IPS[*]}"
    fi

    mkdir -p "${jail_dir}"
    # 覆盖式写入，保证幂等
    cat > "${jail_file}" << EOF
[DEFAULT]
backend  = systemd
banaction = ufw
ignoreip = ${ignore}

[Definition]
allowipv6 = auto

[sshd]
enabled  = true
port     = ${ssh_port}
maxretry = ${F2B_MAXRETRY}
findtime = ${F2B_FINDTIME}
bantime  = ${F2B_BANTIME}
EOF

    systemctl enable --now fail2ban
    systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban
    echo "=> fail2ban configured (${jail_file})"
    fail2ban-client status sshd 2>/dev/null || true
}



# ============================================================
# Main
# ============================================================
MAX=30

# 解析命令行参数：--profile <name> / -p <name>
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile|-p)
            SELECTED_PROFILE="${2:-}"
            shift 2
            ;;
        --profile=*)
            SELECTED_PROFILE="${1#*=}"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

SelectProfile

while [[ "${MAX}" -gt 0 ]]; do
    echo "${Separator}"
    echo "*** Root Permission ***"
    echo "* 1. First-time system setup"
    echo "* 2. Install Docker"
    echo "* 3. Change hostname"
    echo "* 4. Adjust system services"
    echo "* 5. Setup fail2ban"
    echo ""
    echo "*** Local Permission"
    echo "* 6. Setup environment of ${ADMIN_USER}"
    echo "* 7. Verify ENV"
    echo ""
    echo "* Q: Quit"
    echo "${Separator}"

    printf "Choice: "
    read opt

    case "${opt}" in
    1)
        Root
        OS

        read -p "=== Run User? === (y/No) " opt
        case "${opt}" in y|yes) User ;; esac

        read -p "=== Run SSH? === (y/No) " opt
        case "${opt}" in y|yes) SSH ;; esac

        read -p "=== Run Update? === (y/No) " opt
        case "${opt}" in y|yes) Update ;; esac

        read -p "=== Run UFW? === (y/No) " opt
        case "${opt}" in y|yes) UFW ;; esac

        read -p "=== Run TZ? === (y/No) " opt
        case "${opt}" in y|yes) TZ ;; esac

        read -p "=== Run BBR? === (y/No) " opt
        case "${opt}" in y|yes) BBR ;; esac

        read -p "=== Run fail2ban? === (y/No) " opt
        case "${opt}" in y|yes) F2B ;; esac
        ;;
    2)
        Docker
        ;;
    3)
        Hostname
        ;;
    4)
        read -p "=== Enable rc.local? === (y/No) " opt
        case "${opt}" in y|yes) Enable_RC_Local ;; esac

        read -p "=== Disable systemd-resolve? === (y/No) " opt
        case "${opt}" in y|yes) Disable_Resolve ;; esac

        read -p "=== Set Journal? === (y/No) " opt
        case "${opt}" in y|yes) Set_Journal ;; esac

        read -p "=== Change sudoers options? === (y/No) " opt
        case "${opt}" in y|yes) Modify_Sudoers ;; esac

        read -p "=== Set ping permission? === (y/No) " opt
        case "${opt}" in y|yes) Set_Ping ;; esac
        ;;
    5)
        Root
        OS
        F2B
        ;;
    6)
        SetupUserEnv
        ;;
    7)
        Verify
        ;;
    Q|q)
        break
        ;;
    *)
        printf 'The param [%s] is not valid, try again.\n' "${opt}"
        ;;
    esac

    MAX=$((MAX - 1))
done

exit 0

# Google Authenticator 安装配置移至独立脚本 vps_auth.sh
# 启用/修改 netplan 见脚本 vps_netplan.sh
