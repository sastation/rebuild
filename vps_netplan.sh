#!/bin/bash

# 确保脚本以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 或 root 用户运行此脚本！"
  exit 1
fi

echo "=== 开始检查网络管理工具 ==="

# 1. 判断是否使用 ifupdown 管理网络
if dpkg -l | grep -q ifupdown && [ -f /etc/network/interfaces ] && grep -qE "^\s*(auto|allow-hotplug)\s+[^lo]" /etc/network/interfaces; then
    echo "[INFO] 检测到当前系统正在使用 ifupdown 管理网络。"
else
    echo "[OK] 当前系统未使用 ifupdown 或已被清理，无需替换。"
    exit 0
fi

# 2. 自动获取当前活动的物理网卡信息
echo "[INFO] 正在获取当前网络配置信息..."

# 获取默认路由的网卡（原网卡名）
OLD_INTERFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
if [ -z "$OLD_INTERFACE" ]; then
    OLD_INTERFACE=$(ip -o link show | awk -F': ' '$3 !~ /lo|virbr|docker|ovs/ && $3 ~ /UP/ {print $2}' | head -n1)
fi

if [ -z "$OLD_INTERFACE" ]; then
    echo "[ERROR] 无法获取有效的网络接口，脚本终止，以防失联！"
    exit 1
fi

# 获取该网卡的 MAC 地址（重命名网卡的关键凭证）
MAC_ADDRESS=$(cat /sys/class/net/"$OLD_INTERFACE"/address)

if [ -z "$MAC_ADDRESS" ]; then
    echo "[ERROR] 无法获取网卡 $OLD_INTERFACE 的 MAC 地址，脚本终止！"
    exit 1
fi

# 获取当前 IP 地址和掩码
CURRENT_IP=$(ip -o -4 addr show dev "$OLD_INTERFACE" | awk '{print $4}' | head -n1)

# 获取当前网关
CURRENT_GATEWAY=$(ip route show default | awk '/default/ {print $3}' | head -n1)

# 获取当前 DNS
CURRENT_DNS=$(grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}' | paste -sd, - | sed 's/,/, /g')
if [ -z "$CURRENT_DNS" ]; then
    CURRENT_DNS="223.5.5.5, 8.8.8.8"
fi

TARGET_INTERFACE="eth0"

echo "----------------------------------------"
echo "检测到当前网络参数："
echo "原网卡名称: $OLD_INTERFACE"
echo "网卡 MAC  : $MAC_ADDRESS"
echo "目标新名称: $TARGET_INTERFACE"
echo "IP 地址   : $CURRENT_IP"
echo "网关地址  : $CURRENT_GATEWAY"
echo "DNS 服务器: [ $CURRENT_DNS ]"
echo "----------------------------------------"

# 3. 安装 netplan.io 和 systemd-networkd
echo "[INFO] 正在安装 netplan.io 及必要的组件..."
apt update -y
apt install -y netplan.io

systemctl enable systemd-networkd
systemctl start systemd-networkd

# 4. 创建 Netplan 配置文件（包含重命名逻辑）
NETPLAN_CONFIG="/etc/netplan/01-netcfg.yaml"
echo "[INFO] 正在生成 Netplan 配置文件: $NETPLAN_CONFIG"

# 判断当前是 DHCP 还是静态 IP
if grep -q "iface $OLD_INTERFACE inet dhcp" /etc/network/interfaces; then
    echo "[INFO] 检测为 DHCP 动态获取模式"
    cat << EOF > "$NETPLAN_CONFIG"
network:
  version: 2
  renderer: networkd
  ethernets:
    $TARGET_INTERFACE:
      match:
        macaddress: "$MAC_ADDRESS"
      set-name: $TARGET_INTERFACE
      dhcp4: true
      dhcp6: true
      dhcp-identifier: mac
EOF
else
    echo "[INFO] 检测为 Static 静态 IP 模式"
    cat << EOF > "$NETPLAN_CONFIG"
network:
  version: 2
  renderer: networkd
  ethernets:
    $TARGET_INTERFACE:
      match:
        macaddress: "$MAC_ADDRESS"
      set-name: $TARGET_INTERFACE
      dhcp4: no
      addresses:
        - $CURRENT_IP
      routes:
        - to: default
          via: $CURRENT_GATEWAY
      nameservers:
        addresses: [$CURRENT_DNS]
      dhcp6: true
EOF
fi

# 规范 Netplan 配置文件权限
chmod 600 "$NETPLAN_CONFIG"
echo "[OK] Netplan 配置文件创建成功并已限制权限。"

# 5. 禁用旧的 ifupdown 配置
echo "[INFO] 正在备份并清理 /etc/network/interfaces..."
cp /etc/network/interfaces /etc/network/interfaces.bak

cat << EOF > /etc/network/interfaces
# 本地回环网络接口
auto lo
iface lo inet loopback
EOF

# 6. 应用新网络配置
echo "[INFO] 正在备份当前手工 DNS 配置..."
cp /etc/resolv.conf /etc/resolv.conf.dns.bak

echo "[INFO] 正在应用 Netplan 配置并重命名网卡..."
netplan apply

echo "[INFO] 正在还原手工 DNS 配置..."
mv /etc/resolv.conf.dns.bak /etc/resolv.conf

# 7. 卸载旧的 ifupdown 工具
echo "[INFO] 正在卸载旧的 ifupdown 工具..."
apt purge -y ifupdown
apt autoremove -y

echo "=== [SUCCESS] 网络已成功切换为 Netplan，且网卡已重命名为 $TARGET_INTERFACE！ ==="
echo "请检查当前网卡名称和状态：ip a"


exit 0

# 使用 ifupdown 管理网络，设定透传 mac address 申请 dhcp ip
$ vi /etc/network/interface
# The primary network interface
allow-hotplug ens32
auto ens32
iface ens32 inet dhcp
   client no

$ systemctl restart networking


# 手动安装 netplany 替换 ifupdown 
apt update
apt install netplan.io

systemctl enable systemd-networkd
systemctl start systemd-networkd

mv /etc/network/interface /etc/network/interface.bak
apt purge ifupdown

# /etc/netplan/01-netcfg.yaml
# dhcp 配置模板
network:
  version: 2
  renderer: networkd
  ethernets:
    ens32:
      dhcp4: true
      dhcp6: true
      dhcp-identifier: mac
      match:
        macaddress: "00:0c:29:76:4e:b5"
      set-name: eth0

# 静态地址配置模板
network:
  version: 2
  renderer: networkd
  ethernets:
    ens32:
      dhcp4: false
      addresses: ["192.168.1.137/24"]
      routes:
        - to: default
          via: 192.168.1.1
      match:
        macaddress: "00:0c:29:76:4e:b5"
      set-name: eth0
      dhcp6: true