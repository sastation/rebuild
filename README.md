# Rebuild
用于重装VPS操作系统脚本

## 0x01 zdebian.sh
- 本脚本用于安装debian, 可单独使用
- 只在Debian/Ubuntu下有效
- 基于[debian-dd](https://github.com/bihell/debian-dd)修改而来
- 用法：
```bash
bash zdebian.sh
# 交互式安装
```

## 0x02 rebuild.sh
- 本脚本用于安装 debian 或 ubuntu. (尚在开发中)
- 基于[reinstall](https://github.com/bin456789/reinstall)修改而来
- 用法：
```bash
bash rebuild.sh debian 10|11|12
                ubuntu 20.02|22.04
#不输入版本号则安装最新版
```