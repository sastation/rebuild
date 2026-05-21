#/bin/bash

# TODO:
# 1. For Debian/11: add [PATH="..."] in /etc/environment
# 2. /etc/apt/sources.list
#   2.1 Ubuntu: deb http://mirror.0x.com/ubuntu main restricted universe multiverse
#   2.2 Debian: deb http://mirror.0x.com/debian main contrib non-free

ID=`id -u`
OSName=`cat /etc/os-release | grep -e "^NAME=" | awk -F'"' '{print $2}' | awk '{print $1}' `
OSVersion=`cat /etc/os-release | grep VERSION_ID | awk -F'"' '{print $2}'`
Area="VPS" # 当前所处环境，默认为 VPS 环境

DetectArea() {
    # 判断当前是否处于局域网中，值存入 $Area
    
    # 用户选择 1=Family, 2=VPS，默认 VPS
    echo "=> Select environment type"
    echo "  1) Family"
    echo "  2) VPS"
    read -p "Enter choice [2]: " area_choice
    case "$area_choice" in
        1) Area="Family" ;;
        *) Area="VPS" ;;
    esac
    echo "Selected area: $Area"
    
    if [ "$Area" = "Family" ]; then
        proxy="http://pxy.lan:8080"
        export http_proxy="$proxy"
        export https_proxy="$proxy"
        if [ `id -u` -eq 0 ];then
            fs="/etc/apt/apt.conf.d/90proxy.conf"
            echo "Acquire::http::Proxy \"$proxy\";" > $fs
            echo "Acquire::https::Proxy \"$proxy\";" >> $fs
            
        fi
    fi
}

Root() {
    # 判断当前用户是否为 root  
    if [ `id -u` -ne 0 ];then
        echo "Please run scirpt as root!"
        exit 1
    fi
}

OS() {
    # 判断当前OS是否为 Ubuntu 或 Debian（不限制版本）

    if [ "$OSName" = "Ubuntu" ] || [ "$OSName" = "Debian" ]; then
        return 0
    else
        echo "OS is not Ubuntu or Debian..."
        exit 2
    fi
}

Hostname() {
    # 修改服务器名称 
    #
    echo "=>Change hostname"
    printf "Please input new hostname: " 
    read opt
    
    hostname $opt
    echo $opt > /etc/hostname
    
    hostnamectl set-hostname $opt # u18 or later command
    
    echo "127.0.0.1       $opt" >> /etc/hosts

}

User() {
    # 增加用户zwang， 修改root/zwang密码，修改 sudoers 
    #
    echo "=>Add user zwang, update root & zwang password"
    # read -rsp $'Press enter to continue...\n'
    #
    
    # 检查用户 zwang 若没有则创建
    if id "zwang" &>/dev/null; then
        echo "User zwang already exists. Skipping useradd."
    else
        useradd -m -s /bin/bash zwang
    fi
    
    while true; do
        read -s -p "Input new password: " newP && echo
        read -s -p "Input password again: " secondP && echo

        if [ $newP != $secondP ]; then
            echo "Not match!"
        else
            break
        fi
    done

    echo "root:$newP" | chpasswd
    echo "zwang:$newP" | chpasswd

    #
    echo "=>Add zwang into sudoers"
    #
    apt install sudo -y
    # 避免重复添加 sudoers 条目
    if ! grep -q "^zwang\s\+ALL=(ALL:ALL) NOPASSWD:ALL" /etc/sudoers; then
        echo "zwang   ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers
    else
        echo "zwang already in sudoers, skipping."
    fi

    # 复制初始化脚本到 zwang 目录
    cp /root/*.sh ~zwang 2>/dev/null || echo "No .sh files in /root to copy"
    chown zwang:zwang ~zwang/*sh
    chmod 755 ~zwang/*sh
}

SSH() {
    # 修改/etc/ssh/sshd_config的相关配置 
    #
    comm="=>Setup ssh server"
    
    echo $comm
    read -rsp $'Press enter to continue...\n'

    # 修改root的登录方式，共有：PermitRootLogin [yes | no | prohibit-password | without-password]
    echo "change sshd_config deny / remote login"
    #sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config 
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config

    # 修改配置选项
    echo >> /etc/ssh/sshd_config
    echo "UseDNS no" >> /etc/ssh/sshd_config
    echo "#GatewayPorts yes" >> /etc/ssh/sshd_config
    
    # 修改sshd的监听端口
    read -p "=>Setup ssh server=>Change port to 21622? === (y/No)" opt
    case $opt in
    y|yes)
        sed -i 's/Port [0-9]\+/Port 21622/g' /etc/ssh/sshd_config
        sed -i 's/^#Port 21622/Port 21622/g' /etc/ssh/sshd_config 
    esac
    
    # 禁止口令登录
    #read -p "=>Setup ssh server=>Disable password login? === (y/No)" opt
    #case $opt in
    #y|yes)
    #    #sed -i 's/^ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    #    #sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' >> /etc/ssh/sshd_config
    #
    #    echo  >> /etc/ssh/sshd_config
    #    echo "Match User zwang" >> /etc/ssh/sshd_config
    #    echo "  PasswordAuthentication yes" >> /etc/ssh/sshd_config
    #esac
    
    service ssh restart
}

Update() {
    # 更新系统及安装必要的应用
    #
    echo "=>Update system & install necessary packages"
    # read -rsp $'Press enter to continue...\n'
    #
    apt -y update
    apt -y upgrade

    apt -y install sudo wget curl traceroute nmap whois git tmux htop 
    apt -y install mtr dnsutils hping3 # iperf3 nethogs iftop iptraf-ng
    apt -y install net-tools rsync psmisc tree cron # ntpdate
    apt -y install screen zsh vim bc jq mosh file # vim-nox for debian
    #apt -y install python3-click python3-distutils 
    
    # for debian to set timesync
    apt -y install systemd-timesyncd
    timedatectl set-ntp true
    systemctl restart systemd-timesyncd
}

Enable_RC_Local() {
    # 开启 rc.local 服务
    cat > /etc/rc.local << EOF
#!/bin/bash
sleep 1
EOF
    chmod +x /etc/rc.local
    
    systemctl enable rc-local # also rc.local before 20.04
    systemctl start rc-local
    
}

Disable_Resolve() {
    # 关闭 systemd-syst 服务，创建 /etc/resol.conf 文件，使用静态DNS
    mv /etc/resolv.conf /etc/resolv.conf-bak
    resolv_file="/etc/resolv.conf"
    echo "#domain lan wnict.com" >> $resolv_file
    echo "search lan wnict.com" >> $resolv_file
    if [ "$Area" = "Family" ]; then
        echo "nameserver 192.168.100.17" >> $resolv_file
        echo "nameserver 192.168.100.18" >> $resolv_file
    else
        echo "nameserver 1.1.1.1" >> $resolv_file
        echo "nameserver 8.8.8.8" >> $resolv_file
    fi

    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
}

Set_Journal() {
	# 设置日志大小，system* 硬盘空间，runtime* 内存空间
	fs="/etc/systemd/journald.conf"
	if [ "$Area" = "Family" ]; then
        sed -i "s/^#\{0,1\}SystemMaxUse=.*/SystemMaxUse=128M/g" $fs # 日志大小不超过 128MiB
    else
       sed -i "s/^#\{0,1\}SystemMaxUse=.*/SystemMaxUse=64M/g" $fs # 日志大小不超过 64MiB
    fi
	sed -i "s/^#\{0,1\}MaxRetentionSec=.*/MaxRetentionSec=7d/g" $fs # 保留 7 天内的日志
	systemctl restart systemd-journald
	
	# clean journal log size
	journalctl --disk-usage # how much disk has been used
	#journalctl --vacuum-size=64M # Retain only the past 64MiB, one-time
	#journalctl --vacuum-time=7d # Retain only the past 7 days, one-time
}


Modify_Sudoers() {
	# 禁止 MOTD News
    #sed -i "s/ENABLED=1/ENABLED=0/g" /etc/default/motd-news
    
	# 在/etc/sudoers中添加两个选项：1. 继承代理环境，2. 设置超时时间为30分钟 （-1为不超时）
	sed -i "/Defaults\tenv_reset/aDefaults\ttimestamp_timeout=30" /etc/sudoers
	sed -i "/Defaults\tenv_reset/aDefaults\tenv_keep=\"http_proxy https_proxy HTTP_PROXY HTTPS_PROXY\"" /etc/sudoers
}

Set_Ping() {
    # ubuntu/debian set ping permission
    setcap cap_net_raw+ep /bin/ping
}

UFW() {
    # 配置防火墙 
    # 
    echo "=>Setup firewall"
    # read -rsp $'Press enter to continue...\n'
    #
    apt -y install ufw
    # sed -i 's/IPV6=yes/IPV6=no/g' /etc/default/ufw
    ufw allow 22/tcp
    ufw allow 21622/tcp
    ufw allow 80
    ufw allow 443
    #ufw allow 989:995/tcp
    #ufw allow 989:995/udp
    ufw allow 2443
    ufw allow 8443
    ufw allow 60001:60005/udp
    ufw allow from 172.17.0.1/24 to 172.17.0.1/24
    
    echo "Y" | ufw enable
}

TZ() {
    # 更改时区到[CST|UTC]
    #
    echo "=>Change timezone to CST"
    
    #timedatectl set-timezone UTC
    timedatectl set-timezone Asia/Shanghai
}

BBR() {
    # 安装及配置BBR 
    #
    echo "=>Enable BBR"
    # read -rsp $'Press enter to continue...\n'
    #
cat >> /etc/sysctl.conf << EOF
# --- 核心网络配置 (旁路由必需) ---
#net.ipv4.ip_forward=1
## 禁用 IPv4 重定向
#net.ipv4.conf.all.send_redirects=0
#net.ipv4.conf.default.send_redirects=0
## 禁用接受 IPv4 重定向
#net.ipv4.conf.all.accept_redirects=0
#net.ipv4.conf.default.accept_redirects=0

# --- Docker 与高并发相关 ---
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
net.core.somaxconn=32768
net.core.netdev_max_backlog=5000
fs.file-max=65536

# --- 网络性能调优 ---
vm.swappiness=10  # 修改 Swappiness 的值, 0表示最大限度使用物理内存，100表示积极的使用swap
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# --- 禁用 IPv6 ---
#net.ipv6.conf.all.disable_ipv6=1
#net.ipv6.conf.default.disable_ipv6=1
EOF


    sysctl -p
    # reboot
}

Docker_Proxy() {
    # 设置Docker服务使用代理
    mkdir /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/http-proxy.conf << EOF
[Service]
Environment="HTTP_PROXY=http://pxy.lan:8080"
Environment="HTTPS_PROXY=http://pxy.lan:8080"
Environment="NO_PROXY=localhost,127.0.0.0/8,*.lan"
EOF
    systemctl daemon-reload
    systemctl show --property Environment docker
    systemctl restart docker
}

Docker() {
    # 安装 Docker 
    #
    echo "=>Install docker"
    read -rsp $'Press enter to continue...\n'

    curl -sSL https://get.docker.com/ | sh
    # curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
    
    # apt install docker.io
    
    usermod -aG docker zwang
    
    if [ "$Area" = "Family" ]; then
        read -p "=>Setup Docker=>Set proxies? === (y/No)" opt
        case $opt in
        y|yes)
            Docker_Proxy
        esac
    fi
    
    docker pull linuxserver/smokeping
    docker pull ubuntu
    docker pull alpine
    
}

ZWang() {
    # 对用户zwang的环境进行配置 
    #
    echo "=>Setup zwang env"
    
    read -p "=>Setup git global? === (y/No)" opt
    if [[ "$opt" == "y" || "$opt" == "yes" ]]; then
        git config --global user.email "sa.station@gmail.com"
        git config --global user.name "David Wang"
        git config --global core.editor "vim"
        git config --global push.default matching
    fi

    read -p "=>Setup .ssh/authorized_keys? === (y/No)" opt
    if [[ "$opt" == "y" || "$opt" == "yes" ]]; then
        #echo "=>setup authorized_keys"
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILinYNuMVdOfusVcAJT+nz8Uw66q5OeEUy1XZLUhncj7 user" >> ~/.ssh/authorized_keys
        echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOmketJKXswgywYP7rj7aM2ZsvRm51cyDQ+UR0jrBRA4 terminal" >> ~/.ssh/authorized_keys
    fi
    
    #
    echo "=>Setup env"
    read -rsp $'Press enter to continue...\n'
    #
    cd ~
    mkdir -p coding/github
    cd coding/github
    git clone --depth=1 https://github.com/sastation/environment-config.git
    cd environment-config
    ./run.sh
}

GoogleAuth() {
    # 安装及配置 google-authenticator 
    echo "=>Setup Google authenticator"
    read -rsp $'Press enter to continue...\n'

    apt update
    apt -y install libpam-google-authenticator
    apt -y install qrencode

    FS="/etc/pam.d/sshd"
    sed -i '3i\# white-ip list' $FS
    sed -i '4i\auth [success=1 default=ignore] pam_access.so accessfile=/etc/security/access_vps.conf' $FS
    sed -i '5i\# google authenticator plug' $FS
    sed -i '6i\auth required pam_google_authenticator.so nullok' $FS
    sed -i '7i\ ' $FS

    FS="/etc/ssh/sshd_config"
    sed -i 's/^ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' $FS

    cat>>/etc/security/access_vps.conf<<EOF
# skip one-time password if logging in from the trusted network
# only allow from trusted IP range
+ : ALL : 127.0.0.1/32
+ : ALL : 192.168.100.0/24      # family
+ : ALL : 38.59.244.146/32      # bsy
+ : ALL : 185.201.227.119/32    # hdr
+ : ALL : 173.82.251.188/32     # ccv
+ : ALL : 150.158.158.58/32     # tx-sh
+ : ALL : 43.156.103.92/32      # tx-sg
+ : ALL : 180.163.115.0/24      # ctrip-ct
+ : ALL : 114.86.129.1/24       # ctrip-ct
+ : ALL : 45.251.105.181/24     # ctrip-hk
- : ALL : ALL
EOF

}

GoogleAuth_Local() {
    # 对当前用户的 google_authenticator 环境进行配置 
    google-authenticator

    cd ~
    FS=".google_authenticator"
    chmod 600 $FS
    cat>>$FS<<EOF
64802810
64802811
64802812
64802813
64802814
64802815
64802816
64802817
64802818
64802819
EOF
    chmod 400 $FS
}

Verify() {
    # 验证配置 
    sysctl net.ipv4.tcp_available_congestion_control
    lsmod | grep bbr
    sudo ufw status
    sudo netstat -lntp
    sudo netstat -lnup
}

Test() {
    echo $ID
    echo $OSName
    echo $OSVersion
}

# Main
MAX=30
MASK=50

DetectArea

while [ $MAX -gt 0 ] 
do
    printf '%*s' $MASK|tr ' ' '*';echo
    echo "*** Root Permission ***"
    echo "* 0. Setup system for the first time" 
    echo "* 1. Install Docker"
    echo "* 2. Install Google Authenticator"
    echo "* 3. Change hostname"
    echo "* 4. Adjust system services"
    echo
    echo "*** Local Permission"
    echo "* 6. Setup environment of zwang"
    echo "* 7. Setup Local GoogleAuth"
    echo "* 8. Verify ENV"
    echo "* 9. Test something"
    echo 
    echo "* Q: Quit"
    printf '%*s' $MASK|tr ' ' '*';echo

    printf "Choice: "
    read opt

    case $opt in
    0)
        Root
        OS
        read -p "=== Run User? === (y/No)" opt
        case $opt in
        y|yes)
            User
        esac

        read -p "=== Run SSH? === (y/No)" opt
        case $opt in
        y|yes)
            SSH
        esac

        read -p "=== Run Update? === (y/No)" opt
        case $opt in
        y|yes)
            Update
        esac

        read -p "=== Run UFW? === (y/No)" opt
        case $opt in
        y|yes)
            UFW
        esac

        read -p "=== Run TZ? === (y/No)" opt
        case $opt in
        y|yes)
            TZ
        esac

        read -p "=== Run BBR? === (y/No)" opt
        case $opt in
        y|yes)
            BBR
        esac
    ;;
    1)
        Docker
    ;;
    2) 
        GoogleAuth
    ;;
    3)
        Hostname
    ;;
    4)
        read -p "=== Enable rc.local? === (y/No)" opt
        case $opt in
        y|yes)
            Enable_RC_Local
        esac
        
        read -p "=== Disable systemd-resolve? === (y/No)" opt
        case $opt in
        y|yes)
            Disable_Resolve
        esac
        
        read -p "=== Set Journal? === (y/No)" opt
        case $opt in
        y|yes)
            Set_Journal
        esac
        
        read -p "=== Change sudoers options? === (y/No)" opt
        case $opt in
        y|yes)
            Modify_Sudoers
        esac
        
        read -p "=== Set ping permission? === (y/No)" opt
        case $opt in
        y|yes)
            Set_Ping
        esac
    ;;
    6)
        ZWang
    ;;
    7)
        GoogleAuth_Local
    ;;
    8)
        Verify
    ;;
    9)
        Test
    ;;
    Q)
      break
    ;;
    *)
      printf 'The param [%s] is not valid, try again.\n' $opt
    esac

    MAX=`expr $MAX - 1`
done

exit 0

# 需手工执行的一些功能

# change network interface name
vi /etc/netplan/01-netcfg.yaml
  ...
  match:
    #name: interface-name
    macaddress: aa:bb:cc:dd:ee:ff
  set-name: eth0
  ...
netplan apply

# remove swap partation, and expand root partation
swapoff -a
parted /dev/sda rm 5
parted /dev/sda rm 2
parted /dev/sda resizepart 1 100%
resize2fs /dev/sda1
#echo "/swapfile                                 none            swap    sw              0       0" >> /etc/fstab

# create swap file
swapoff /swapfile
rm /swapfile
# dd if=/dev/zero of=swapfile bs=256M count=1
fallocate -l 256M /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
printf "\n/swapfile   none    swap    sw  0   0\n" >> /etc/fstab

# disable reserved block for root user
tune2fs -l /dev/sda1 | grep Reserved
tune2fs -m 1 /dev/sda1

# clone tools in family
git clone ssh://git@git.lan:/home/git/tools

# change source.list
cd /etc/apt
mv sources.list sources.list-backup
cat sources.list-backup | grep -v "^#" | grep -v "^$" >sources.list

# curl http://mirrors.ubuntu.com/mirrors.txt
# mirrors.huaweicloud.com, mirrors.163.com, mirrors.cn99.com
# mirrors.tuna.tsinghua.edu.cn, mirrors.cloud.tencent.com
sed -i "s/archive.ubuntu.com/mirrors.163.com/" sources.list
sed -i "s/security.ubuntu.com/mirrors.163.com/" sources.list

# change default path for debian
echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /etc/environment

# 将网卡名从ens3改为eth0
## 禁用 systemd 的可预测网卡名机制, 确保 biosdevname 工具不会干扰网卡命名
sudo vi /etc/default/grub 
  GRUB_CMDLINE_LINUX="... net.ifnames=0 biosdevname=0 ..."
## 更新 GRUB 配置，更新Initramfs(初始内存磁盘镜像)
sudo update-grub
sudo update-initramfs -u -k all
## 调整网络接口配置
sudo vi /etc/network/interfaces
  1,$ s/ens3/eth0/g
sudo reboot

# Debian 中使用 netplan 替换 ifupdown
# 见 vps netplan.sh