#!/bin/bash
# 用于重装debian系统的脚本，
# 只在debian，ubuntu系统中运行
# shellcheck disable=SC2086

# color
#underLine='\033[4m'
aoiBlue='\033[36m'
#blue='\033[34m'
#yellow='\033[33m'
#green='\033[32m'
red='\033[31m'
plain='\033[0m'


is_in_china() {
    if [ -z "$_is_in_china" ]; then
        wget -qO - -L http://www.cloudflare.com/cdn-cgi/trace |
            grep -qx 'loc=CN' && _is_in_china=true ||
            _is_in_china=false
    fi
    $_is_in_china
}


# 主进程
clear
# 检查是否是 root 用户
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please use the root user to execute this script."
    exit
fi

# 安装必要软件
echo -en "\n${aoiBlue}Installation dependencies...${plain}\n"
apt update
apt install wget net-tools -y

# 检查是否在CN
if is_in_china; then
    domain="mirrors.tuna.tsinghua.edu.cn"
    dns="119.29.29.29 223.5.5.5"
else
    domain="ftp.debian.org"
    dns="1.1.1.1 8.8.8.8"
fi

echo "-----------------------------------------------------------------"
echo -e "${aoiBlue}GitHub${plain}: https://github.com/sastation/rebuild"
echo -e "Is in China: " "$_is_in_china"
echo "-----------------------------------------------------------------"

# 选择Debian版本，默认为 1 (Debian 12)
echo -en "\n${aoiBlue}Supported Versions:${plain}\n"
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
    echo -e "${red}No correct option entered, ready to exit...${plain}"
    sleep 1
    exit
fi

echo -en "\n${aoiBlue}Start installing Debian $debian_version...${plain}\n"

# 定义hostname，默认为 sastation
echo -en "\n${aoiBlue}Set hostname:${plain}\n"
read -rp "Please input [Default sastation]:" HostName
[[ -z "$HostName" ]] && HostName="sastation"

# 定义root password，默认为16位随机
echo -ne "\n${aoiBlue}Set root password${plain}\n"
read -rp "Please input [Enter directly to generate a random password]: " passwd
if [ -z "$passwd" ]; then
    # 生成随机密码
    LENGTH=16
    passwd=$(tr -dc 'A-Za-z0-9.:,_!*+' </dev/urandom | head -c $LENGTH)
    echo -e "Generated password: ${red}$passwd${plain}"
fi

# 定义ssh端口，默认为 22
echo -ne "\n${aoiBlue}Set ssh port${plain}\n"
read -rp "Please input [Default 22]: " sshPORT
[[ -z "$sshPORT" ]] && sshPORT=22

# 获取并确认网卡名称
nics=$(ip link show | awk -F': ' '{print $2}')
i=0; interfaces=()
for nic in $nics; do
    [[ "$nic" == "lo" ]] && continue
    [[ "$nic" == "docker"* ]] && continue
    [[ "$nic" == "veth"* ]] && continue
    interfaces[i]=$nic
    i=$((i+1))
done
i=0
for interface in "${interfaces[@]}"; do
    # 显示网卡名称与IP
    echo "$i: $(ip -br address show $interface)"
    i=$((i+1))
done
echo; read -rp "Please confirm which is correct [Default 0]: " i
[[ -z $i ]] && i=0
interface="${interfaces[i]}"

# 获得网卡IP、掩码与网关
ip=$(ifconfig "$interface" | awk '/inet / {print $2}')
netmask=$(ifconfig "$interface" | awk '/netmask / {print $4}')
gateway=$(ip route | awk '/default/ {print $3}')

# 是否使用静态IP
read -r -d '' network <<- EOF
d-i netcfg/disable_autoconfig boolean true
d-i netcfg/dhcp_failed note
d-i netcfg/dhcp_options select Configure network manually
d-i netcfg/get_ipaddress string $ip
d-i netcfg/get_netmask string $netmask
d-i netcfg/get_gateway string $gateway
d-i netcfg/get_nameservers string $dns
d-i netcfg/confirm_static boolean true
EOF
echo -ne "\n${aoiBlue}DHCP or Static network. ${plain}\n"
read -rp "Please input [Default: d/DHCP] [d|s]: " dhcp
if [ -z "$dhcp" ] || [ "$dhcp" == "d" ]; then
    network=""
fi

# 代理服务器若有, 默认为空
echo -ne "\n${aoiBlue}Proxy Server${plain}\n"
read -rp "Please input [Default none]: " proxy

# Get the device number of the root directory
root_device=$(df / | awk 'NR==2 {print $1}')

# Extract the partition number from the device number
partitionr_root_number=$(echo "$root_device" | grep -oE '[0-9]+$')

# Check if any disk is mounted
if [ -z "$(df -h)" ]; then
    echo "No disks are currently mounted."
    exit 1
fi

# Extract the device name of the root partition
ROOT_DEVICE=$(df / | grep -oE '/dev/[a-z]+')

# Extract the device prefix (sda or vda)
DEVICE_PREFIX=$(echo "$ROOT_DEVICE" | grep -oE 'sda|vda')

# Check if the device prefix is present
if [ -n "$DEVICE_PREFIX" ]; then
    echo "The root partition is mounted on a device with the prefix: $DEVICE_PREFIX"
else
    echo "Could not determine the device naming prefix. Defaulting to sda."
    DEVICE_PREFIX="sda"
fi

# EFI disk 
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
    set root="(hd0,$partitionr_root_number)"
    linux /netboot/linux auto=true priority=critical lowmem/low=true preseed/file=/preseed.cfg
    initrd /netboot/initrd.gz
}
EOF

# # Modifying the GRUB DEFAULT option
# sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=2/' /etc/default/grub
# # Modify the GRUB TIMEOUT option
# sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=2/' /etc/default/grub
# update-grub 

echo -en "\n${aoiBlue}Configuration complete...${plain}\n"

echo -ne "\n[${aoiBlue}Finish${plain}] Input '${red}reboot${plain}' to continue the subsequential installation.\n"
exit 0