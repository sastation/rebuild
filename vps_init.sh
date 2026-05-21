#!/bin/bash
set -euo pipefail

# ============================================================
# Configuration — edit these values before running
# ============================================================

# 普通用户（用于日常管理）
ADMIN_USER="zwang"
USER_HOME="/home/${ADMIN_USER}"

# SSH
SSH_PORT="21622"

# 时区
TIMEZONE="Asia/Shanghai"

# DNS 搜索域
DOMAIN="lan wnict.com"

# 局域网代理地址（Family 环境使用）
PROXY_HTTP="http://pxy.lan:8080"

# DNS 服务器
DNS_VPS_PRIMARY="1.1.1.1"
DNS_VPS_SECONDARY="8.8.8.8"
DNS_FAMILY_PRIMARY="192.168.100.17"
DNS_FAMILY_SECONDARY="192.168.100.18"

# Journal 日志上限
JOURNAL_MAX_SIZE_VPS="64M"
JOURNAL_MAX_SIZE_FAMILY="128M"

# Git 配置
GIT_NAME="David Wang"
GIT_EMAIL="sa.station@gmail.com"

# SSH 公钥（写入 ADMIN_USER 的 authorized_keys）
SSH_AUTHORIZED_KEYS=(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILinYNuMVdOfusVcAJT+nz8Uw66q5OeEUy1XZLUhncj7 user"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOmketJKXswgywYP7rj7aM2ZsvRm51cyDQ+UR0jrBRA4 terminal"
)

# ============================================================
# Runtime variables (do not edit)
# ============================================================
ID="$(id -u)"
OSName="$(awk -F'"' '/^NAME=/ {print $2}' /etc/os-release | awk '{print $1}')"
OSVersion="$(awk -F'"' '/VERSION_ID=/ {print $2}' /etc/os-release)"
Area="VPS"     # 当前所处环境，在 DetectArea 中重新赋值
Separator="$(printf '%*s' 50 | tr ' ' '*')"

# ============================================================
# Functions
# ============================================================

DetectArea() {
    # 判断当前是否处于局域网中，值存入 $Area
    echo "=> Select environment type"
    echo "  1) Family"
    echo "  2) VPS"
    read -p "Enter choice [2]: " area_choice
    case "${area_choice}" in
        1) Area="Family" ;;
        *) Area="VPS" ;;
    esac
    echo "Selected area: ${Area}"

    if [[ "${Area}" = "Family" ]]; then
        export http_proxy="${PROXY_HTTP}"
        export https_proxy="${PROXY_HTTP}"
        if [[ "${ID}" -eq 0 ]]; then
            fs="/etc/apt/apt.conf.d/90proxy.conf"
            echo "Acquire::http::Proxy \"${PROXY_HTTP}\";" > "${fs}"
            echo "Acquire::https::Proxy \"${PROXY_HTTP}\";" >> "${fs}"
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
    echo "=> Add ${ADMIN_USER} into sudoers"
    apt install sudo -y
    if ! grep -q "^${ADMIN_USER}\s\+ALL=(ALL:ALL) NOPASSWD:ALL" /etc/sudoers; then
        echo "${ADMIN_USER}   ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers
    else
        echo "${ADMIN_USER} already in sudoers, skipping."
    fi

    # 复制初始化脚本到 ADMIN_USER 目录
    cp /root/*.sh "${USER_HOME}/" 2>/dev/null || echo "No .sh files in /root to copy"
    chown "${ADMIN_USER}":"${ADMIN_USER}" "${USER_HOME}"/*.sh 2>/dev/null || true
    chmod 755 "${USER_HOME}"/*.sh 2>/dev/null || true
}

SSH() {
    # 修改 /etc/ssh/sshd_config 的相关配置
    echo "=> Setup ssh server"
    read -rsp $'Press enter to continue...\n'

    # 修改 root 的登录方式
    echo "Change sshd_config deny / remote login"
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config

    # 修改配置选项
    {
        echo ""
        echo "UseDNS no"
        echo "#GatewayPorts yes"
    } >> /etc/ssh/sshd_config

    # 修改 sshd 的监听端口
    read -p "=> Setup ssh server => Change port to ${SSH_PORT}? === (y/No) " opt
    case "${opt}" in
        y|yes)
            sed -i "s/Port [0-9]\\+/Port ${SSH_PORT}/g" /etc/ssh/sshd_config
            sed -i "s/^#Port ${SSH_PORT}/Port ${SSH_PORT}/g" /etc/ssh/sshd_config
            ;;
    esac

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
        if [[ "${Area}" = "Family" ]]; then
            echo "nameserver ${DNS_FAMILY_PRIMARY}"
            echo "nameserver ${DNS_FAMILY_SECONDARY}"
        else
            echo "nameserver ${DNS_VPS_PRIMARY}"
            echo "nameserver ${DNS_VPS_SECONDARY}"
        fi
    } > "${resolv_file}"

    systemctl stop systemd-resolved*
    systemctl disable systemd-resolved*
}

Set_Journal() {
    # 设置日志大小
    fs="/etc/systemd/journald.conf"
    if [[ "${Area}" = "Family" ]]; then
        sed -i "s/^#\{0,1\}SystemMaxUse=.*/SystemMaxUse=${JOURNAL_MAX_SIZE_FAMILY}/g" "${fs}"
    else
        sed -i "s/^#\{0,1\}SystemMaxUse=.*/SystemMaxUse=${JOURNAL_MAX_SIZE_VPS}/g" "${fs}"
    fi
    sed -i "s/^#\{0,1\}MaxRetentionSec=.*/MaxRetentionSec=7d/g" "${fs}"
    systemctl restart systemd-journald

    journalctl --disk-usage
}

Modify_Sudoers() {
    # 在 /etc/sudoers 中添加选项：继承代理环境、设置超时时间
    sed -i "/Defaults\tenv_reset/aDefaults\ttimestamp_timeout=30" /etc/sudoers
    sed -i "/Defaults\tenv_reset/aDefaults\tenv_keep=\"http_proxy https_proxy HTTP_PROXY HTTPS_PROXY\"" /etc/sudoers
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
    ufw allow "${SSH_PORT}/tcp"
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
    # 安装及配置 BBR
    echo "=> Enable BBR"
    cat >> /etc/sysctl.conf << 'EOF'

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

    sysctl -p
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

    if [[ "${Area}" = "Family" ]]; then
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
        git config --global push.default matching
    fi

    read -p "=> Setup .ssh/authorized_keys? === (y/No) " opt
    if [[ "${opt}" = "y" ]] || [[ "${opt}" = "yes" ]]; then
        mkdir -p "${USER_HOME}/.ssh"
        chmod 700 "${USER_HOME}/.ssh"
        for key in "${SSH_AUTHORIZED_KEYS[@]}"; do
            echo "${key}" >> "${USER_HOME}/.ssh/authorized_keys"
        done
    fi

    echo "=> Setup env"
    read -rsp $'Press enter to continue...\n'
    cd ~
    mkdir -p coding/github
    cd coding/github
    git clone --depth=1 https://github.com/sastation/environment-config.git
    cd environment-config
    ./run.sh
}

Verify() {
    # 基本信息
    echo "${ID}"
    echo "${OSName}"
    echo "${OSVersion}"
    
    # 验证配置
    sysctl net.ipv4.tcp_available_congestion_control
    lsmod | grep bbr || true
    sudo ufw status
    sudo netstat -lntp
    sudo netstat -lnup
}



# ============================================================
# Main
# ============================================================
MAX=30

DetectArea

while [[ "${MAX}" -gt 0 ]]; do
    echo "${Separator}"
    echo "*** Root Permission ***"
    echo "* 1. First-time system setup"
    echo "* 2. Install Docker"
    echo "* 3. Change hostname"
    echo "* 4. Adjust system services"
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