# vps 增强设置

> 本页内容需要手工执行



## 修改网络接口名称

```bash
# 方法一：使用 netplany 中的 set-name
$ vi /etc/netplan/01-netcfg.yaml
   ...
   dhcp-identifier: mac
   ...
   match:
     #name: interface-name
     macaddress: aa:bb:cc:dd:ee:ff
   set-name: eth0
   ...
$ netplan apply

# 方法二：修改 grub 中的参数
# 将网卡名从 ens3 改为 eth0
$ vi /etc/default/grub   
    GRUB_CMDLINE_LINUX="... net.ifnames=0 biosdevname=0 ..."
$ update-grub
$ update-initramfs -u -k all
$ vi /etc/network/interfaces   
	:1,$ s/ens3/eth0/g
$  reboot
```



## 移除交换分区，重设交换文件	

```bash
# remove swap partition
  swapoff -a
  parted /dev/sda rm 5
  parted /dev/sda rm 2
  parted /dev/sda resizepart 1 100%
  resize2fs /dev/sda1

# remove swap file
  swapoff /swapfile
  rm /swapfile

# create swap file
  fallocate -l 256M /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  printf "\n/swapfile   none    swap    sw  0   0\n" >> /etc/fstab
```



## 重设保留空间

```bash
# disable reserved block for root user
FS=$(df -h . | tail -n 1 | awk '{print $1}')
echo $FS # /dev/sda1
tune2fs -l $FS | grep Reserved
tune2fs -m 1 $FS
```

## Family 环境中的额外设置

```bash
#clone tools for family env
git clone ssh://git@git.lan:/home/git/tools
```

## 设置默认 PATH

```bash
echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> /etc/environment
```



## 正常使用 apt

```bash
# 方法一：使用代理
$ vi /etc/apt/apt.conf.d/90-proxies
Acquire::http::Proxy "http://pxy.lan:8080";
Acquire::https::Proxy "http://pxy.lan:8080";


方法二：修改源
# change source.list
  cd /etc/apt
  mv sources.list sources.list-backup
  cat sources.list-backup | grep -v "^#" | grep -v "^$" > sources.list
  sed -i "s/archive.ubuntu.com/mirrors.163.com/" sources.list
  sed -i "s/security.ubuntu.com/mirrors.163.com/" sources.list
```



## ubuntu 中的额外设置

```bash
# 移除 snap
apt -y purge snapd

# disable apt auto upgrade
systemctl disable --now unattended-upgrades

cat > /etc/apt/apt.conf.d/90-disable-updates.conf << 'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

# ubuntu 26.04 中关闭 systemd-resolve
systemctl disable --now systemd-resolved-varlink.socket
systemctl disable --now systemd-resolved-monitor.socket
systemctl disable --now systemd-resolve.service

```

