#!/bin/bash
# shellcheck disable=SC2086
# shellcheck disable=SC2317
# shellcheck disable=SC2154

# lsmem, lsblk: until-linux, unsquashfs: quashfs-tools
apt install -y gzip cpio curl grep util-linux lshw
apt install -y file squashfs-tools fdisk virt-what
#apt install -y efibootmgr findmnt
#apt install -y dmidecode virt-what dig
#install_pkg lsmem dmidecode lshw file dmidecode virt-what unsquashfs
#install_pkg gzip cpio lsblk fdisk curl grep

set -eE
confhome=https://raw.githubusercontent.com/bin456789/reinstall/main
github_proxy=https://mirror.ghproxy.com/https://raw.githubusercontent.com

# https://www.gnu.org/software/gettext/manual/html_node/The-LANGUAGE-variable.html
export LC_ALL=C


is_use_cloud_image() {
    [ -n "$cloud_image" ] && [ "$cloud_image" = 1 ]
}

is_in_china() {
    if [ -z $_is_in_china ]; then
        # 部分地区 www.cloudflare.com 被墙
        curl -L http://dash.cloudflare.com/cdn-cgi/trace |
            grep -qx 'loc=CN' && _is_in_china=true ||
            _is_in_china=false
    fi
    $_is_in_china
}

to_upper() {
    tr '[:lower:]' '[:upper:]'
}

to_lower() {
    tr '[:upper:]' '[:lower:]'
}

info() {
    upper=$(to_upper <<<"$@")
    echo_color_text '\e[32m' "***** $upper *****"
}

error() {
    echo_color_text '\e[31m' "Error: $*"
}

echo_color_text() {
    color="$1"
    shift
    plain="\e[0m"
    echo -e "$color$*$plain"
}

error_and_exit() {
    error "$@"
    exit 1
}


usage_and_exit() {
    reinstall____='./reinstall.sh'
    cat <<EOF
Usage: $reinstall____ ubuntu   20.04|22.04|24.04

Manual: https://github.com/bin456789/reinstall

EOF
    exit 1
}

# 检查是否为正确的系统名
verify_os_name() {
    if [ -z "$*" ]; then
        usage_and_exit
    fi

    for os in \
        'ubuntu   20.04|22.04|24.04' \
        'test     0.16|0.17|0.18|0.19' \
        ; do
        ds=$(awk '{print $1}' <<<"$os")
        vers=$(awk '{print $2}' <<<"$os" | sed 's \. \\\. g')
        finalos=$(echo "$@" | to_lower | sed -n -E "s,^($ds)[ :-]?(|$vers)$,\1:\2,p")
        if [ -n "$finalos" ]; then
            distro=$(echo $finalos | cut -d: -f1)
            releasever=$(echo $finalos | cut -d: -f2)
            # 默认版本号
            if [ -z "$releasever" ] && grep -q '|' <<<$os; then
                releasever=$(awk '{print $2}' <<<$os | awk -F'|' '{print $NF}')
            fi
            return
        fi
    done

    error "Please specify a proper os"
    usage_and_exit
}

test_img() {
    url=$1
    var_to_eval=$2
    expect_type='xz|gzip|qemu'
    info test url

    tmp_file=$tmp/reinstall-img-test
    echo $url
    # 有的服务器不支持 range，curl会下载整个文件
    # 用 dd 限制下载 1M
    # 并过滤 curl 23 错误（dd限制了空间）
    command curl --insecure --connect-timeout 10 -Lfr 0-1048575 "$url" \
            1> >(dd bs=1M count=1 of=$tmp_file iflag=fullblock 2>/dev/null) \
            2> >(grep -v 'curl: (23)' >&2)
    
    # gzip的mime有很多种写法，所以不用mime判断
    # 有些 file 版本输出的是 # ISO 9660 CD-ROM filesystem data ，要去掉开头的井号
    real_type=$(file -b $tmp_file | sed 's/^# //' | cut -d' ' -f1 | to_lower)
    if ! grep -wo "$real_type" <<< "$expect_type"; then
            error_and_exit "$url expected: $expect_type. actual: $real_type."
    fi
    [ -n "$var_to_eval" ] && eval $var_to_eval=$real_type
}

is_virt() {
    if [ -z "$_is_virt" ]; then
        # 综合两个命令的结果来判断
        if systemd-detect-virt -v; then
            _is_virt=true
        fi
        # virt-what 返回值始终是0，所以用是否有输出作为判断
        [[ -z "$_is_virt" ]] && [[ -n "$(vir-waht)" ]] && _is_virt=true
        
        [[ -z "$_is_virt" ]] && _is_virt=false
        echo "vm: $_is_virt"
    fi
    $_is_virt
}

insert_into_file() {
    file=$1
    location=$2
    regex_to_find=$3

    line_num=$(grep -E -n "$regex_to_find" "$file" | cut -d: -f1)

    found_count=$(echo "$line_num" | wc -l)
    if [ ! "$found_count" -eq 1 ]; then
        return 1
    fi

    case "$location" in
    before) line_num=$((line_num - 1)) ;;
    after) ;;
    *) return 1 ;;
    esac

    sed -i "${line_num}r /dev/stdin" "$file"
}

setos() {
    local step=$1
    local distro=$2
    local releasever=$3
    info set $step $distro $releasever

    setos_alpine() {
        is_virt && flavour=virt || flavour=lts

        # alpine aarch64 3.16/3.17 virt 没有直连链接
        if [ "$basearch" = aarch64 ] &&
            { [ "$releasever" = 3.16 ] || [ "$releasever" = 3.17 ]; }; then
            flavour=lts
        fi

        # 不要用https 因为甲骨文云arm initramfs阶段不会从硬件同步时钟，导致访问https出错
        if is_in_china; then
            mirror=http://mirrors.tuna.tsinghua.edu.cn/alpine/v$releasever
        else
            mirror=http://dl-cdn.alpinelinux.org/alpine/v$releasever
        fi
        eval ${step}_vmlinuz=$mirror/releases/$basearch/netboot/vmlinuz-$flavour
        eval ${step}_initrd=$mirror/releases/$basearch/netboot/initramfs-$flavour
        eval ${step}_modloop=$mirror/releases/$basearch/netboot/modloop-$flavour
        eval ${step}_repo=$mirror/main
    }

    setos_ubuntu() {
        # cloud image
        if is_in_china; then
            ci_mirror=https://mirror.nju.edu.cn/ubuntu-cloud-images
        else
            ci_mirror=https://cloud-images.ubuntu.com
        fi
        eval ${step}_img=$ci_mirror/releases/$releasever/release/ubuntu-$releasever-server-cloudimg-$basearch_alt.img
    }

    eval ${step}_distro=$distro
    eval ${step}_releasever=$releasever

    setos_$distro

    # 确定云镜像格式
    if is_use_cloud_image && [ "$step" = finalos ]; then
        # shellcheck disable=SC2154
        test_img $finalos_img finalos_img_type
    fi
}

curl() {
    # 添加 -f, --fail，不然 404 退出码也为0
    # 32位 cygwin 已停止更新，证书可能有问题，先添加 --insecure
    # centos 7 curl 不支持 --retry-connrefused --retry-all-errors
    # 因此手动 retry
    grep -o 'http[^ ]*' <<<"$@" >&2
    for i in $(seq 5); do
        if command curl --insecure --connect-timeout 10 -f "$@"; then
            return
        else
            ret=$?
            if [ $ret -eq 22 ]; then
                # 403 404 错误
                return $ret
            fi
        fi
        sleep 1
    done
}

# TODO: 多网卡 单网卡多IP
collect_netconf() {
    # linux
    # 通过默认网关得到默认网卡
    for v in 4 6; do
        if ethx=$(ip -$v route show default | head -1 | awk '{print $5}' | grep .); then
            mac_addr=$(ip link show dev $ethx | grep link/ether | head -1 | awk '{print $2}')
            break
        fi
    done

    for v in 4 6; do
        if ip -$v route show default dev $ethx | head -1 | grep -q .; then
            eval ipv${v}_gateway="$(ip -$v route show default dev $ethx | head -1 | awk '{print $3}')"
            eval ipv${v}_addr="$(ip -$v -o addr show scope global dev $ethx | head -1 | awk '{print $4}')"
        fi
    done

    info "Network Info"
    echo "MAC  Address: $mac_addr"
    echo "IPv4 Address: $ipv4_addr"
    echo "IPv4 Gateway: $ipv4_gateway"
    echo "IPv6 Address: $ipv6_addr"
    echo "IPv6 Gateway: $ipv6_gateway"
    echo
}

get_function_content() {
    declare -f "$1" | sed '1d;2d;$d'
}

# 脚本可能多次运行，先清理之前的残留
mkdir_clear() {
    dir=$1

    if [ -z "$dir" ] || [ "$dir" = / ]; then
        return
    fi

    # alpine 没有 -R
    # { umount $dir || umount -R $dir || true; } 2>/dev/null
    rm -rf $dir
    mkdir -p $dir
}

mod_initrd_alpine() {
    # hack 1 virt 内核添加 ipv6 模块
    if virt_dir=$(ls -d $tmp_dir/lib/modules/*-virt 2>/dev/null); then
        ipv6_dir=$virt_dir/kernel/net/ipv6
        if ! [ -f $ipv6_dir/ipv6.ko ]; then
            mkdir -p $ipv6_dir
            modloop_file=$tmp/modloop_file
            modloop_dir=$tmp/modloop_dir
            curl -Lo $modloop_file $nextos_modloop
            
            mkdir_clear $modloop_dir
            unsquashfs -f -d $modloop_dir $modloop_file 'modules/*/kernel/net/ipv6/ipv6.ko'
            find $modloop_dir -name ipv6.ko -exec cp {} $ipv6_dir/ \;
        fi
    fi
    insert_into_file init after 'configure_ip\(\)' <<EOF
        depmod
        modprobe ipv6
EOF

    # hack 2 设置 ethx
    # 3.16~3.18 ip_choose_if
    # 3.19 ethernets
    if grep -q ip_choose_if init; then
        ethernets_func=ip_choose_if
    else
        ethernets_func=ethernets
    fi

    # shellcheck disable=SC2317
    ip_choose_if() {
        ip -o link | grep "@mac_addr" | awk '{print $2}' | cut -d: -f1
        return
    }

    collect_netconf
    get_function_content ip_choose_if | sed "s/@mac_addr/$mac_addr/" |
        insert_into_file init after "$ethernets_func\(\)"

    # hack 3
    # udhcpc 添加 -n 参数，请求dhcp失败后退出
    # 使用同样参数运行 udhcpc6
    #       udhcpc -i "$device" -f -q # v3.17
    # $MOCK udhcpc -i "$device" -f -q # v3.18
    # $MOCK udhcpc -i "$iface" -f -q  # v3.19
    search='udhcpc -i'
    orig_cmd="$(grep "$search" init)"
    mod_cmd4="$orig_cmd -n || true"
    mod_cmd6="${mod_cmd4//udhcpc/udhcpc6}"
    sed -i "/$search/c$mod_cmd4 \n $mod_cmd6" init

    # hack 4 /usr/share/udhcpc/default.script
    # 脚本被调用的顺序
    # udhcpc:  deconfig
    # udhcpc:  bound
    # udhcpc6: deconfig
    # udhcpc6: bound
    # shellcheck disable=SC2317
    udhcpc() {
        if [ "$1" = deconfig ]; then
            return
        fi
        if [ "$1" = bound ] && [ -n "$ipv6" ]; then
            # shellcheck disable=SC2154
            ip -6 addr add "$ipv6" dev "$interface"
            ip link set dev "$interface" up
            return
        fi
    }

    get_function_content udhcpc |
        insert_into_file usr/share/udhcpc/default.script after 'deconfig\|renew\|bound'

    # 允许设置 ipv4 onlink 网关
    sed -Ei 's,(0\.0\.0\.0\/0),"\1 onlink",' usr/share/udhcpc/default.script

    # hack 5 网络配置
    is_in_china && is_in_china=true || is_in_china=false
    insert_into_file init after 'MAC_ADDRESS=' <<EOF
        . /alpine-network.sh \
        "$mac_addr" "$ipv4_addr" "$ipv4_gateway" "$ipv6_addr" "$ipv6_gateway" "$is_in_china"
EOF

    # hack 5 运行 trans.start
    # exec /bin/busybox switch_root $switch_root_opts $sysroot $chart_init "$KOPT_init" $KOPT_init_args # 3.17
    # exec              switch_root $switch_root_opts $sysroot $chart_init "$KOPT_init" $KOPT_init_args # 3.18
    # 1. alpine arm initramfs 时间问题 要添加 --no-check-certificate
    # 2. aws t4g arm 如果没设置console=ttyx，在initramfs里面wget https会出现bad header错误，chroot后正常
    # Connecting to raw.githubusercontent.com (185.199.108.133:443)
    # 60C0BB2FFAFF0000:error:0A00009C:SSL routines:ssl3_get_record:http request:ssl/record/ssl3_record.c:345:
    # ssl_client: SSL_connect
    # wget: bad header line: �
    insert_into_file init before '^exec (/bin/busybox )?switch_root' <<EOF
        # echo "wget --no-check-certificate -O- $confhome/trans.sh | /bin/ash" >\$sysroot/etc/local.d/trans.start
        # wget --no-check-certificate -O \$sysroot/etc/local.d/trans.start $confhome/trans.sh
        cp /trans.sh \$sysroot/etc/local.d/trans.start
        chmod a+x \$sysroot/etc/local.d/trans.start
        ln -s /etc/init.d/local \$sysroot/etc/runlevels/default/
EOF
}

mod_initrd() {
    info "mod $nextos_distro initrd"

    # 解压
    # 先删除临时文件，避免之前运行中断有残留文件
    tmp_dir=$tmp/reinstall
    mkdir_clear $tmp_dir
    cd $tmp_dir

    # shellcheck disable=SC2046
    # nonmatching 是精确匹配路径
    zcat /reinstall-initrd | cpio -idm

    curl -Lo $tmp_dir/trans.sh $confhome/trans.sh
    curl -Lo $tmp_dir/alpine-network.sh $confhome/alpine-network.sh

    mod_initrd_$nextos_distro

    # 显示大小
    du -sh .
  
    # 重建
    # 注意要用 cpio -H newc 不要用 cpio -c ，不同版本的 -c 作用不一样，很坑
    #       portable format.If you wish the old portable
    #       (ASCII) archive format, use "-H odc" instead.
    find . | cpio --quiet -o -H newc | gzip -1 >/reinstall-initrd
    cd - >/dev/null
}

# 记录主硬盘
find_main_disk() {
    if [ -n "$main_disk" ]; then
        return
    fi

    # centos7下测试     lsblk --inverse $mapper | grep -w disk     grub2-probe -t disk /
    # 跨硬盘btrfs       只显示第一个硬盘                            显示两个硬盘
    # 跨硬盘lvm         显示两个硬盘                                显示/dev/mapper/centos-root
    # 跨硬盘软raid      显示两个硬盘                                显示/dev/md127

    # 改成先检测 /boot/efi /efi /boot 分区？

    
    # lvm 显示的是 /dev/mapper/xxx-yyy，再用第二条命令得到sda
    mapper=$(mount | awk '$3=="/" {print $1}')
    xda=$(lsblk -rn --inverse $mapper | grep -w disk | awk '{print $1}' | sort -u)

    # 检测主硬盘是否横跨多个磁盘
    os_across_disks_count=$(wc -l <<<"$xda")
    if [ $os_across_disks_count -eq 1 ]; then
        info "Main disk: $xda"
    else
        error_and_exit "OS across $os_across_disks_count disk: $xda"
    fi

    # 可以用 dd 找出 guid?

    # centos7 blkid lsblk 不显示 PTUUID
    # centos7 sfdisk 不显示 Disk identifier
    # alpine blkid 不显示 gpt 分区表的 PTUUID
    # 因此用 fdisk

    # Disk identifier: 0x36778223                                  # gnu fdisk + mbr
    # Disk identifier: D6B17C1A-FA1E-40A1-BDCB-0278A3ED9CFC        # gnu fdisk + gpt
    # Disk identifier (GUID): d6b17c1a-fa1e-40a1-bdcb-0278a3ed9cfc # busybox fdisk + gpt
    # 不显示 Disk identifier                                        # busybox fdisk + mbr

    # 获取 xda 的 id
    
    main_disk=$(fdisk -l /dev/$xda | grep 'Disk identifier' | awk '{print $NF}' | sed 's/0x//')

    # 检查 id 格式是否正确
    if ! grep -Eix '[0-9a-f]{8}' <<<"$main_disk" &&
        ! grep -Eix '[0-9a-f-]{36}' <<<"$main_disk"; then
        error_and_exit "Disk ID is invalid: $main_disk"
    fi
}

build_nextos_cmdline() {
    if [ $nextos_distro = alpine ]; then
        nextos_cmdline="alpine_repo=$nextos_repo modloop=$nextos_modloop"
    elif [ $nextos_distro = debian ]; then
        nextos_cmdline="lowmem/low=1 auto=true priority=critical url=$nextos_ks"
    else
        # redhat
        nextos_cmdline="root=live:$nextos_squashfs inst.ks=$nextos_ks"
    fi

    if [ $nextos_distro = debian ]; then
        if [ "$basearch" = "x86_64" ]; then
            # debian 安装界面不遵循最后一个 tty 为主 tty 的规则
            # 设置ttyS0,tty0,安装界面还是显示在ttyS0
            :
        else
            # debian arm 在没有ttyAMA0的机器上（aws t4g），最少要设置一个tty才能启动
            # 只设置tty0也行，但安装过程ttyS0没有显示
            nextos_cmdline+=" console=ttyS0,115200 console=ttyAMA0,115200 console=tty0"
        fi
    else
        # nextos_cmdline+=" $(echo_tmp_ttys)"
        nextos_cmdline+=" console=ttyS0,115200 console=ttyAMA0,115200 console=tty0"
    fi
    # nextos_cmdline+=" mem=256M"
}

# 转换 finalos_a=1 为 finalos.a=1 ，排除 finalos_mirrorlist
build_finalos_cmdline() {
    if vars=$(compgen -v finalos_); then
        for key in $vars; do
            value=${!key}
            key=${key#finalos_}
            if [ -n "$value" ] && [ $key != "mirrorlist" ]; then
                finalos_cmdline+=" finalos.$key='$value'"
            fi
        done
    fi
}

build_extra_cmdline() {
    for key in confhome hold cloud_image kernel deb_hostname main_disk; do
        value=${!key}
        if [ -n "$value" ]; then
            extra_cmdline+=" extra.$key='$value'"
        fi
    done

    # 指定最终安装系统的 mirrorlist，链接有&，在grub中是特殊字符，所以要加引号
    if [ -n "$finalos_mirrorlist" ]; then
        extra_cmdline+=" extra.mirrorlist='$finalos_mirrorlist'"
    elif [ -n "$nextos_mirrorlist" ]; then
        extra_cmdline+=" extra.mirrorlist='$nextos_mirrorlist'"
    fi
}

build_cmdline() {
    # nextos
    build_nextos_cmdline

    # finalos
    # trans 需要 finalos_distro 识别是安装 alpine 还是其他系统
    if [ "$distro" = alpine ]; then
        finalos_distro=alpine
    fi
    if [ -n "$finalos_distro" ]; then
        build_finalos_cmdline
    fi

    # extra
    build_extra_cmdline

    cmdline="$nextos_cmdline $finalos_cmdline $extra_cmdline"
}

get_entry_name() {
    printf 'reinstall ('
    printf '%s' "$distro"
    [ -n "$releasever" ] && printf ' %s' "$releasever"
    [ "$distro" = alpine ] && [ "$hold" = 1 ] && printf ' Live OS'
    printf ')'
}

del_empty_lines() {
    sed '/^[[:space:]]*$/d'
}

is_os_in_btrfs() {
    mount | grep -qw 'on / type btrfs'
}

is_alpine_live() {
    [ "$distro" = alpine ] && [ "$hold" = 1 ]
}

get_cmd_path() {
    # arch 云镜像不带 which
    # command -v 包括脚本里面的方法
    # ash 无效
    type -f -p $1
}




# 脚本入口
if [ "$(uname -o)" = Cygwin ] || [ "$(uname -o)" = Msys ]; then
    error_and_exit "Not support MS-Windows"
fi

# 检查 root
if [ "$EUID" -ne 0 ]; then
    error_and_exit "Please run as root."
fi

# 整理参数
if ! opts=$(getopt -n $0 -o "" --long ci,debug,hold:,sleep:,iso:,image-name:,img:,lang: -- "$@"); then
    usage_and_exit
fi

eval set -- "$opts"
# shellcheck disable=SC2034
while true; do
    case "$1" in
    --debug)
        set -x
        shift
        ;;
    --ci)
        cloud_image=1
        shift
        ;;
    --)
        shift
        break
        ;;
    *)
        echo "Unexpected option: $1."
        usage_and_exit
        ;;
    esac
done

# 检查目标系统名
verify_os_name "$@"

# 检查必须的参数
:
# 不支持容器虚拟化
:
# 不支持安全启动
:
# 必备组件
:

# /tmp 挂载在内存的话，可能不够空间
tmp=/reinstall-tmp
mkdir -p "$tmp"

# ubuntu 强制添加 --ci 参数
cloud_image=1
# 检查内存
:

# 检查硬件架构
basearch=$(uname -m)
basearch=x86_64
basearch_alt=amd64

# 设置国内代理
if [ -n "$github_proxy" ] && [[ "$confhome" = http*://raw.githubusercontent.com/* ]] && is_in_china; then
    confhome=${confhome/http:\/\//https:\/\/}
    confhome=${confhome/https:\/\/raw.githubusercontent.com/$github_proxy}
fi

# ubuntu 需要二步安装
alpine_ver_for_trans=3.19
setos finalos $distro $releasever
setos nextos alpine $alpine_ver_for_trans

# 删除之前的条目
:
# 有的机器开启了 kexec，例如腾讯云轻量 debian，要禁用
:
# 下载 nextos 内核
info download vmlnuz and initrd
curl -Lo /reinstall-vmlinuz $nextos_vmlinuz
curl -Lo /reinstall-initrd $nextos_initrd

# 修改 alpine initrd
if [ "$nextos_distro" = alpine ]; then
    mod_initrd
fi

# 将内核/netboot.xyz.lkrn 放到正确的位置
:
# grub
info 'create grub config'
grub_cfg=$(grep -o '[^ ]*grub.cfg' "$(get_cmd_path update-grub)" | head -1)
grub=grub
$grub-mkconfig -o $grub_cfg
target_cfg=$(dirname $grub_cfg)/custom.cfg
dir=/
vmlinuz=${dir}reinstall-vmlinuz
initrd=${dir}reinstall-initrd

# 生成 linux initrd 命令
find_main_disk
build_cmdline
linux_cmd="linux$efi $vmlinuz $cmdline"
initrd_cmd="initrd$efi $initrd"

# 生成 grub 配置
echo $target_cfg
del_empty_lines <<EOF | tee $target_cfg
set timeout=5
menuentry "$(get_entry_name)" {
    insmod lvm
    $(is_os_in_btrfs && echo 'set btrfs_relative_path=n')
    insmod all_video
    search --no-floppy --file --set=root $vmlinuz
    $linux_cmd
    $initrd_cmd
}
EOF

# 设置重启引导项
$grub-reboot "$(get_entry_name)"

info 'info'
echo "$distro $releasever"
username="root"
echo "Username: $username"
echo "Password: 123@@@"
echo "Reboot to start the installation."

exit 0