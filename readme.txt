# 使用说明

## 初始化一个新的 debian/ubuntu 操作系统
./"vps init.sh" - 用于基础初始化，最主要的是两个
  - 0. Setup system for the first time，用于整个系统的初始化
  - 6. Setup environment of zwang，特定用户的初始化
./vps netplan.sh - 用于将系统网络管理由 ifupdown 转换为 netplan

## 在现有系统中从源头重装操作系统
- reinstall.sh, https://github.com/bin456789/reinstall
- InstallNET.sh, https://github.com/leitbogioro/Tools/tree/master/Linux_reinstall
- zdebian.sh, 用于安装 debian
