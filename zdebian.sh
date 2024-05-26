#!/bin/bash

echo_color() {
    color=$1; text=$2
    declare -A colors=(
        ['red']='\033[31m'
        ['aoiBlue']='\033[36m'
        ['green']='\033[32]'
        ['yellow']='\033[33]' 
    )
    echo -en "${colors[$color]}${text}\033[0m" # plain='\033[0m'
}
info() { echo_color "aoiBlue" "$*"; }
error() { echo_color "red" "$*"; }



# 程序主体入口
# 判断运行环境是否为 Debian/Ubuntu
OSName=$(grep -e "^NAME=" /etc/os-release | awk -F'"' '{print $2}' | awk '{print $1}')
if [ "$OSName" != 'Ubuntu' ] && [ "$OSName" != 'Debian' ]; then
    error "\nOnly support Debian/Ubuntu env...\n"; exit 1
fi

#判断是否为root用户
if [ "$EUID" -ne 0 ]; then
    error "\nError: Please run as ROOT.\n"; exit 1
fi

# 安装必要软件
info "\nInstall the required software...\n"
apt update; apt -y install wget net-tools

# 检查是否在CN
wget -qO - -L http://www.cloudflare.com/cdn-cgi/trace |
    grep -qx 'loc=CN' && is_in_china=true || is_in_china=false

# 按区域设置镜像站点与DNS
if $is_in_china; then
    domain="mirrors.tuna.tsinghua.edu.cn"
    dns="119.29.29.29 223.5.5.5"
else
    domain="ftp.debian.org"
    dns="1.1.1.1 8.8.8.8"
fi
info "-----------------------------------------------------------------\n"
echo "GitHub: https://github.com/sastation/rebuild"
echo "Is in China: " "$is_in_china"
info "-----------------------------------------------------------------\n"

# 选择Debian版本，默认为 [1] (Debian 12)
info "\nSelect version:\n"
echo "[1] Debian 12 bookworm"
echo "[2] Debian 11 bullseye"
echo "[3] Debian 10 buster"
read -rp "Please select [Default 1]:" version

if [ -z "$version" ] || [ "$version" == "1" ]; then
    version=1
    debian_version="bookworm"
elif [ "$version" == "2" ]; then
    debian_version="bullseye"
elif [ "$version" == "3" ]; then
    debian_version="buster"
else
    error "\nIncorrect option, ready to exit...\n"
    sleep 1; exit 1
fi

info "\nStart installing Debian $debian_version...\n"

# 定义hostname，默认为 sastation
info "\nSet hostname:\n"
read -rp "Please input [Default sastation]:" HostName
[[ -z "$HostName" ]] && HostName="sastation"

# 定义root password，默认为16位随机
info "\nSet root password\n"
read -rp "Please input [Enter directly to generate a random password]: " passwd
if [ -z "$passwd" ]; then
    # 生成随机密码
    LENGTH=16
    passwd=$(tr -dc 'A-Za-z0-9.:,_!*+' </dev/urandom | head -c $LENGTH)
    echo -n "Generated password: "; error "$passwd\n"
fi

# 定义ssh端口，默认为 22
info "\nSet ssh port\n"
read -rp "Please input [Default 22]: " sshPORT
[[ -z "$sshPORT" ]] && sshPORT=22

# 获得默认网卡名称、MAC
for v in 4 6; do
    if ethx=$(ip -$v route show default | head -1 | awk '{print $5}'); then
        mac_addr=$(ip link show dev "$ethx" | grep link/ether | head -1 | awk '{print $2}')
        break
    fi
done

# 获得默认网卡IP/CIDR、网关，若无ipv4则使用ipv6
ip_addr="$(ip -4 -o addr show scope global dev "$ethx" | head -1 | awk '{print $4}')"
ip_gateway="$(ip -4 route show default dev "$ethx" | head -1 | awk '{print $3}')"
if [ -z "$ip_gateway" ]; then
    ip_addr="$(ip -6 -o addr show scope global dev "$ethx" | head -1 | awk '{print $4}')"
    ip_gateway="$(ip -6 route show default dev "$ethx" | head -1 | awk '{print $3}')"
fi

# 显示网络信息
info "\nNetwork information:\n"
echo "NIC: $ethx"
echo "MAC: $mac_addr"
echo "IP: $ip_addr"
echo "Gateway: $ip_gateway"

# 是否使用静态IP
read -r -d '' network <<- EOF
d-i netcfg/disable_autoconfig boolean true
d-i netcfg/dhcp_failed note
d-i netcfg/dhcp_options select Configure network manually
d-i netcfg/get_ipaddress string $ip_addr
d-i netcfg/get_gateway string $ip_gateway
d-i netcfg/get_nameservers string $dns
d-i netcfg/confirm_static boolean true
EOF
info "\nDHCP or Static network.\n"
read -rp "Please input [Default: d/DHCP] [d|s]: " dhcp
if [ -z "$dhcp" ] || [ "$dhcp" == "d" ]; then
    network=""
fi

# 设置代理服务器, 默认为没有
info "\nProxy Server\n"
read -rp "Please enter [Default none]: " proxy

# Check if any disk is mounted
if [ -z "$(df -h)" ]; then
    error "\nNo disks are currently mounted...\n"; exit 1
fi

# 获得根分区序号
partition_root_number=$(df / | awk 'NR==2 {print $1}' | grep -oE '[0-9]+$')

# 获得根分区名称并过滤判断是否为[sda|vda]
DEVICE_PREFIX=$(df / | grep -oE '/dev/[a-z]+' | grep -oE 'sda|vda')
if [ -n "$DEVICE_PREFIX" ]; then
    echo "The root partition is mounted on a device with the prefix: $DEVICE_PREFIX"
else
    error "\nCould not determine the device naming prefix: sda or vda\n"; exit 1
    #DEVICE_PREFIX="sda"
fi

# UEFI系统需要一个EFI分区
EFI=""
if [ -d /sys/firmware/efi ]; then
    EFI="106 1 106 free \
    \$iflabel{ gpt } \$reusemethod{ } method{ efi } format{ } ."
fi

# 下载安装启动文件
echo -en "\n${aoiBlue}Download boot file...${plain}\n"
rm -rf /netboot
mkdir /netboot && cd /netboot || exit
wget https://$domain/debian/dists/$debian_version/main/installer-amd64/current/images/netboot/debian-installer/amd64/linux
wget https://$domain/debian/dists/$debian_version/main/installer-amd64/current/images/netboot/debian-installer/amd64/initrd.gz

# 生成无人值守安装配置文件
echo -e "${aoiBlue}Start configuring pre-installed file...${plain}"
mkdir temp_initrd
cd temp_initrd || exit 
gunzip -c ../initrd.gz | cpio -i

cat << EOF > preseed.cfg
### 本地化
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us
#d-i debian-installer/language string en
#d-i debian-installer/country string CN

### 账号设置
d-i passwd/make-user boolean false
d-i passwd/root-password password $passwd
d-i passwd/root-password-again password $passwd
d-i user-setup/allow-password-weak boolean true

### 网络设置
d-i netcfg/choose_interface select auto
$network

### Low memory mode
d-i lowmem/low note

### hostname
d-i netcfg/hostname string $HostName

### 镜像站点
d-i mirror/country string manual
#d-i mirror/http/hostname string deb.debian.org
d-i mirror/http/hostname string $domain
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string $proxy

### 时钟与时区
d-i time/zone string Asia/Shanghai
#d-i clock-setup/utc boolean true
#d-i clock-setup/ntp boolean true

### 分区设置
d-i partman-auto/disk string /dev/$DEVICE_PREFIX
#d-i partman-auto/choose_recipe select atomic
d-i partman-auto/method string regular
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true

d-i partman-basicfilesystems/no_swap boolean false
d-i partman-efi/non_efi_system boolean true
d-i partman-auto/expert_recipe string efi-root :: \
    $EFI \
    200 200 -1 ext4 \
    method{ format } format{ } use_filesystem{ } filesystem{ ext4 } mountpoint{ / } .

### Package selection
tasksel tasksel/first multiselect ssh-server
d-i pkgsel/upgrade select none
#tasksel tasksel/first multiselect minimal ssh-server
#d-i pkgsel/include string lrzsz net-tools vim rsync socat curl sudo wget telnet iptables gpg zsh python3 pip nmap

# Automatic updates are not applied, everything is updated manually.
d-i pkgsel/update-policy select none
d-i pkgsel/upgrade select none

d-i grub-installer/grub2_instead_of_grub_legacy boolean true
d-i grub-installer/only_debian boolean true
d-i grub-installer/bootdev string /dev/$DEVICE_PREFIX

### Write preseed
d-i preseed/late_command string \
sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin yes/g' /target/etc/ssh/sshd_config; \
sed -ri 's/^#?Port.*/Port ${sshPORT}/g' /target/etc/ssh/sshd_config; \

### Shutdown machine
d-i finish-install/reboot_in_progress note
EOF

find . | cpio -H newc -o | gzip -6 > ../initrd.gz && cd ..
#rm -rf temp_initrd 
#cat << EOF >> /etc/grub.d/40_custom
grubfile="/boot/grub/grub.cfg"
mv $grubfile "${grubfile}.bak"
cat <<EOF > $grubfile
set timeout=3
menuentry "zDebian Installer AMD64" {
    set root="(hd0,$partition_root_number)"
    linux /netboot/linux auto=true priority=critical lowmem/low=true preseed/file=/preseed.cfg
    initrd /netboot/initrd.gz
}
EOF

# # Modifying the GRUB DEFAULT option
# sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=2/' /etc/default/grub
# # Modify the GRUB TIMEOUT option
# sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=2/' /etc/default/grub
# update-grub 

info "\nConfiguration complete...\n"

info "\n[Finish] Enter: "; error "reboot"; info " to continue the installation.\n"
exit 0
