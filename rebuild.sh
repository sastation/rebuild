#!/bin/bash
#!/bin/bash
# shellcheck disable=SC2086
# shellcheck disable=SC2317
# shellcheck disable=SC2154

set -eE
confhome=https://raw.githubusercontent.com/sastation/rebuild/main
# mirror="https://mirror.sjtu.edu.cn"


to_upper() {
    tr '[:lower:]' '[:upper:]'
}

to_lower() {
    tr '[:upper:]' '[:lower:]'
}

info() {
    echo_color_text '\e[32m' "***** $* *****"
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

usage_and_exit() {
    cat <<EOF
Usage: rebuild.sh debian   10|11|12
                  ubuntu   20.04|22.04
EOF
    exit 1
}

get_cmd_path() {
    # arch 云镜像不带 which
    # command -v 包括脚本里面的方法
    # ash 无效
    type -f -p $1
}

is_have_cmd() {
    get_cmd_path $1 >/dev/null 2>&1
}

install_pkg() {
    cmd_to_pkg() {
        unset USE
        case $cmd in
            lsmem | lsblk | findmnt) pkg="util-linux" ;;
            unsquashfs) pkg="squashfs-tools" ;;
            nslookup | dig) pkg="dnsutils" ;;
            *) pkg=$cmd ;;
        esac
    }

    for cmd in "$@"; do
        if ! is_have_cmd $cmd; then
            cmd_to_pkg
            [ -z "$apt_updated" ] && apt update && apt_updated=1
     		DEBIAN_FRONTEND=noninteractive apt install -y $pkg
        fi
    done
}

error_and_exit() {
    error "$@"
    exit 1
}

is_in_container() {
    chars=$(grep "cpuset:/" /proc/1/cgroup | wc -m)
    if [ $chars -gt 11 ]; then true; else false; fi
}

verify_os_name() {
    if [ -z "$*" ]; then
        usage_and_exit
    fi

    for os in \
        'debian   10|11|12' \
        'ubuntu   20.04|22.04'
    do
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

curl() {
    # 添加 -f, --fail，不然 404 退出码也为0；
    # 防止证书问题，添加 --insecure
    command curl --insecure --connect-timeout 5 --retry 2 --retry-delay 1 -f "$@"
}

is_in_china() {
    if [ -z $_is_in_china ]; then
        curl -L http://www.cloudflare.com/cdn-cgi/trace |
            grep -qx 'loc=CN' && _is_in_china=true ||
            _is_in_china=false
    fi
    $_is_in_china
}

is_use_cloud_image() {
    [ -n "$cloud_image" ] && [ "$cloud_image" = 1 ]
}

is_virt() {
    if [ -z "$_is_virt" ]; then
        # aws t4g debian 11,
        #   - systemd-detect-virt: 为 none，即使装了dmidecode
        #   - virt-what, 未装 deidecode时结果为空，装了deidecode后结果为aws
        # 所以综合两个命令的结果来判断
        if is_have_cmd systemd-detect-virt && systemd-detect-virt -v; then
            _is_virt=true
        fi
        if [ -z "$_is_virt" ]; then
            # debian 安装 virt-what 不会自动安装 dmidecode，因此结果有误
            install_pkg dmidecode virt-what
            # virt-what 返回值始终是0，所以用是否有输出作为判断
            if [ -n "$(virt-what)" ]; then
                _is_virt=true
            fi
        fi

        if [ -z "$_is_virt" ]; then
            _is_virt=false
        fi
        echo "VM: $_is_virt"
    fi
    $_is_virt
}

setos() {
    local step=$1
    local distro=$2
    local releasever=$3
    info set $step $distro $releasever

    setos_alpine() {
        flavour=lts
        if is_virt; then
            # alpine aarch64 3.18 才有 virt 直连链接
            if [ "$basearch" == aarch64 ]; then
                install_pkg bc
                (($(echo "$releasever >= 3.18" | bc))) && flavour=virt
            else
                flavour=virt
            fi
        fi

        # 不要用https 因为甲骨文云arm initramfs阶段不会从硬件同步时钟，导致访问https出错
        if is_in_china; then
            mirror=http://mirrors.tuna.tsinghua.edu.cn/alpine/v$releasever
        else
            mirror=http://dl-cdn.alpinelinux.org/alpine/v$releasever
        fi
        eval ${step}_vmlinuz=$mirror/releases/$basearch/netboot/vmlinuz-$flavour
        eval ${step}_initrd=$mirror/releases/$basearch/netboot/initramfs-$flavour
        eval ${step}_repo=$mirror/main
        eval ${step}_modloop=$mirror/releases/$basearch/netboot/modloop-$flavour
    }

    setos_debian() {
        case "$releasever" in
        10) codename=buster ;;
        11) codename=bullseye ;;
        12) codename=bookworm ;;
        esac

        if is_use_cloud_image; then
            # cloud image
            if is_in_china; then
                ci_mirror=https://mirror.nju.edu.cn/debian-cdimage
            else
                ci_mirror=https://cdimage.debian.org/images
            fi

            is_virt && ci_type=genericcloud || ci_type=generic
            # 甲骨文 debian 10 amd64 genericcloud vnc 没有显示
            [ "$releasever" -eq 10 ] && [ "$basearch_alt" = amd64 ] && ci_type=generic
            eval ${step}_img=$ci_mirror/cloud/$codename/latest/debian-$releasever-$ci_type-$basearch_alt.qcow2
        else
            # 传统安装
            if is_in_china; then
                # 部分国内机无法访问 ftp.cn.debian.org
                deb_hostname=mirrors.tuna.tsinghua.edu.cn
            else
                deb_hostname=deb.debian.org
            fi

            mirror=http://$deb_hostname/debian/dists/$codename/main/installer-$basearch_alt/current/images/netboot/debian-installer/$basearch_alt
            eval ${step}_vmlinuz=$mirror/linux
            eval ${step}_initrd=$mirror/initrd.gz
            eval ${step}_ks=$confhome/debian.cfg

            is_virt && flavour=-cloud || flavour=
            # 甲骨文 debian 10 amd64 cloud 内核 vnc 没有显示
            [ "$releasever" -eq 10 ] && [ "$basearch_alt" = amd64 ] && flavour=
            # shellcheck disable=SC2034
            kernel=linux-image$flavour-$basearch_alt

        fi
    }

    setos_ubuntu() {
        if is_use_cloud_image; then
            # cloud image
            if is_in_china; then
                ci_mirror=https://mirror.nju.edu.cn/ubuntu-cloud-images
            else
                ci_mirror=https://cloud-images.ubuntu.com
            fi
            eval ${step}_img=$ci_mirror/releases/$releasever/release/ubuntu-$releasever-server-cloudimg-$basearch_alt.img
        else
            # 传统安装
            if is_in_china; then
                case "$basearch" in
                "x86_64") mirror=https://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/$releasever ;;
                "aarch64") mirror=https://mirrors.tuna.tsinghua.edu.cn/ubuntu-cdimage/releases/$releasever/release ;;
                esac
            else
                case "$basearch" in
                "x86_64") mirror=https://releases.ubuntu.com/$releasever ;;
                "aarch64") mirror=https://cdimage.ubuntu.com/releases/$releasever/release ;;
                esac
            fi

            # iso
            filename=$(curl -L $mirror | grep -oP "ubuntu-$releasever.*?-live-server-$basearch_alt.iso" | head -1)
            iso=$mirror/$filename
            eval ${step}_iso=$iso

            # ks
            eval ${step}_ks=$confhome/ubuntu.yaml
        fi
    }

    eval ${step}_distro=$distro
    setos_$distro
}

test_url(){
    url=$1
    info test $url

    status=$(curl -s -m 5 -IL $url | grep 200)
    if [ "$status" == "" ]; then
        false
    else
        true
    fi
}

is_efi() {
    [ -d /sys/firmware/efi ]
}

get_maybe_efi_dirs_in_linux() {
    mount | awk '$5=="vfat" {print $3}' | grep -E '/boot|/efi'
}

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
    for key in confhome hold cloud_image kernel deb_hostname; do
        value=${!key}
        if [ -n "$value" ]; then
            extra_cmdline+=" extra.$key='$value'"
        fi
    done

    # 指定最终安装系统的 mirrorlist，链接有&，在grub中是特殊字符，需加引号
    if [ -n "$finalos_mirrorlist" ]; then
        extra_cmdline+=" extra.mirrorlist='$finalos_mirrorlist'"
    elif [ -n "$nextos_mirrorlist" ]; then
        extra_cmdline+=" extra.mirrorlist='$nextos_mirrorlist'"
    fi
}

# shellcheck disable=SC2154
build_cmdline() {
    if [ -n "$finalos_cmdline" ]; then
        # 有 finalos_cmdline 表示需要两步安装
        # 两步安装需要修改 alpine initrd
        mod_alpine_initrd

        # 可添加 pkgs=xxx,yyy 启动时自动安装
        # apkovl=http://xxx.com/apkovl.tar.gz 可用，arm https未测但应该不行
        # apkovl=sda2:ext4:/apkovl.tar.gz 官方有写但不生效
        cmdline="alpine_repo=$nextos_repo modloop=$nextos_modloop $extra_cmdline $finalos_cmdline"
    else
        if [ $distro = debian ]; then
            cmdline="lowmem=+1 lowmem/low=1 auto=true priority=critical url=$nextos_ks $extra_cmdline"
            echo $cmdline
        else
            # redhat
            cmdline="root=live:$nextos_squashfs inst.ks=$nextos_ks $extra_cmdline"
        fi
    fi
}

mod_alpine_initrd() {
    # 修改 alpine 启动时运行的脚本
    info mod alpine initrd
    install_pkg gzip cpio

    # 解压
    # 先删除临时文件，避免之前运行中断有残留文件
    tmp_dir=/tmp/reinstall
    mkdir_clear $tmp_dir
    cd $tmp_dir
    zcat /reinstall-initrd | cpio -idm

    # 预先下载脚本
    curl -Lo $tmp_dir/trans.start $confhome/trans.sh
    curl -Lo $tmp_dir/alpine-network.sh $confhome/alpine-network.sh

    # virt 内核添加 ipv6 模块
    if virt_dir=$(ls -d $tmp_dir/lib/modules/*-virt 2>/dev/null); then
        ipv6_dir=$virt_dir/kernel/net/ipv6
        mkdir -p $ipv6_dir
        modloop_file=/tmp/modloop_file
        modloop_dir=/tmp/modloop_dir
        curl -Lo $modloop_file $nextos_modloop
        if is_in_windows; then
            # cygwin 没有 unsquashfs
            7z e $modloop_file ipv6.ko -r -y -o$ipv6_dir
        else
            install_pkg unsquashfs
            mkdir_clear $modloop_dir
            unsquashfs -f -d $modloop_dir $modloop_file 'modules/*/kernel/net/ipv6/ipv6.ko'
            find $modloop_dir -name ipv6.ko -exec cp {} $ipv6_dir/ \;
        fi
    fi

    # hack 1 添加 ipv6 模块
    insert_into_file init after 'configure_ip\(\)' <<EOF
        depmod
        modprobe ipv6
EOF

    # hack 2
    # udhcpc 添加 -n 参数，请求dhcp失败后退出
    # 使用同样参数运行 udhcpc6
    # TODO: digitalocean -i eth1?
    # shellcheck disable=SC2016
    orig_cmd="$(grep '$MOCK udhcpc' init)"
    mod_cmd4="$orig_cmd -n || true"
    mod_cmd6="${mod_cmd4//udhcpc/udhcpc6}"
    sed -i "/\$MOCK udhcpc/c$mod_cmd4 \n $mod_cmd6" init

    # hack 3 /usr/share/udhcpc/default.script
    # 脚本被调用的顺序
    # udhcpc:  deconfig
    # udhcpc:  bound
    # udhcpc6: deconfig
    # udhcpc6: bound
    # shellcheck disable=SC2154
    udhcpc() {
        if [ "$1" = deconfig ]; then
            return
        fi
        if [ "$1" = bound ] && [ -n "$ipv6" ]; then
            ip -6 addr add "$ipv6" dev "$interface"
            ip link set dev "$interface" up
            return
        fi
    }

    get_function_content udhcpc |
        insert_into_file usr/share/udhcpc/default.script after 'deconfig\|renew\|bound'

    # 允许设置 ipv4 onlink 网关
    sed -Ei 's,(0\.0\.0\.0\/0),"\1 onlink",' usr/share/udhcpc/default.script

    # hack 4 网络配置
    collect_netconf
    is_in_china && is_in_china=true || is_in_china=false
    insert_into_file init after 'MAC_ADDRESS=' <<EOF
        source /alpine-network.sh \
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
    # wget: bad header line: 
    insert_into_file init before '^exec (/bin/busybox )?switch_root' <<EOF
        # echo "wget --no-check-certificate -O- $confhome/trans.sh | /bin/ash" >\$sysroot/etc/local.d/trans.start
        # wget --no-check-certificate -O \$sysroot/etc/local.d/trans.start $confhome/trans.sh
        cp /trans.start \$sysroot/etc/local.d/trans.start
        chmod a+x \$sysroot/etc/local.d/trans.start
        ln -s /etc/init.d/local \$sysroot/etc/runlevels/default/
EOF

    # 重建
    # 注意要用 cpio -H newc 不要用 cpio -c ，不同版本的 -c 作用不一样，很坑
    # -c    Use the old portable (ASCII) archive format
    # -c    Identical to "-H newc", use the new (SVR4)
    #       portable format.If you wish the old portable
    #       (ASCII) archive format, use "-H odc" instead.
    find . | cpio -o -H newc | gzip -1 >/reinstall-initrd
    cd -
}


#主入口
# 检查 root
if [ "$EUID" -ne 0 ]; then
    info "Please run as root."
    #exit 1
fi

# 整理参数
if ! opts=$(getopt -n $0 -o "" --long debug,ci,cloud-image -- "$@"); then
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
    --ci | --cloud-image)
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

# 不支持容器虚拟化
if is_in_container; then error_and_exit "Not Supported OS in Container."; fi

# 检查目标系统名
verify_os_name "$@"

# 检查必须的参数，不需要
#verify_os_args

# 安装必备组件
install_pkg curl

# 检查硬件架构
# x86强制使用x64
basearch=$(uname -m)
[ $basearch = i686 ] && basearch=x86_64
case "$basearch" in
"x86_64") basearch_alt=amd64 ;;
"aarch64") basearch_alt=arm64 ;;
esac

# 若在国内设置代理
if [[ "$confhome" == http*://raw.githubusercontent.com/* ]] &&
    is_in_china; then
    confhome=https://ghps.cc/$confhome
    info "inCHINA"
fi


# 以下目标系统不需要进入中转系统/alpine
# debian
if ! is_use_cloud_image && [ "$distro" = "debian" ]; then
    setos nextos $distro $releasever
else
    # alpine作为中间系统时，使用 3.18
    alpine_releasever=3.18
    setos finalos $distro $releasever
    setos nextos alpine $alpine_releasever
fi

# 测试URL
if is_use_cloud_image; then
    if ! test_url $finalos_img; then error_and_exit "$finaos_img"; fi
elif [ -n "$finalos_img" ]; then
    if ! test_url $finalos_img; then error_and_exit "$finalos_img"; fi
elif [ -n "$finalos_iso" ]; then
    if ! test_url $finalos_iso; then error_and_exit "$finalos_iso"; fi
fi

# 删除之前的条目, bios 无论什么情况都用到 grub，所以不用处理
if is_efi; then # is_efi
    maybe_efi_dirs=$(get_maybe_efi_dirs_in_linux)
    find $maybe_efi_dirs /boot -type f -name 'custom.cfg' -exec rm -f {} \;
    install_pkg efibootmgr
    efibootmgr | grep -q 'BootNext:' && efibootmgr --quiet --delete-bootnext
    efibootmgr | grep 'reinstall.*' | grep -oE '[0-9]{4}' |
        xargs -I {} efibootmgr --quiet --bootnum {} --delete-bootnum
else # is_use_grub
    if is_have_cmd grub2-mkconfig; then
        grub=grub2
    elif is_have_cmd grub-mkconfig; then
        grub=grub
    else
        error_and_exit "grub not found"
    fi
fi

# 下载 内核
# 下载 nextos 内核
info download vmlnuz and initrd
echo $nextos_vmlinuz
curl -Lo /reinstall-vmlinuz $nextos_vmlinuz

echo $nextos_initrd
curl -Lo /reinstall-initrd $nextos_initrd

build_finalos_cmdline
build_extra_cmdline
build_cmdline

#exit 0

info 'create grub config'
# linux grub

if is_have_cmd update-grub; then
    grub_cfg=$(grep -o '[^ ]*grub.cfg' "$(get_cmd_path update-grub)")
else
    # 找出主配置文件（含有menuentry|blscfg）
    # 如果是efi，先搜索efi目录
    # arch云镜像efi分区挂载在/efi
    if is_efi; then
        efi_dir=$(get_maybe_efi_dirs_in_linux)
    fi
    grub_cfg=$(
        find $efi_dir /boot/grub* \
            -type f -name grub.cfg \
            -exec grep -E -l 'menuentry|blscfg' {} \;
    )

    if [ "$(wc -l <<<"$grub_cfg")" -gt 1 ]; then
        error_and_exit 'find multi grub.cfg files.'
    fi
fi

# 有些机子例如hython debian的grub.cfg少了40_custom 41_custom
# 所以先重新生成 grub.cfg
$grub-mkconfig -o $grub_cfg

# 在x86 efi机器上，不同版本的 grub 可能用 linux 或 linuxefi 加载内核
# 通过检测原有的条目有没有 linuxefi 字样就知道当前 grub 用哪一种
if [ -d /boot/loader/entries/ ]; then
    entries="/boot/loader/entries/"
fi
if grep -q -r -E '^[[:blank:]]*linuxefi[[:blank:]]' $grub_cfg $entries; then
    efi=efi
fi

# 生成 custom.cfg (linux)
custom_cfg=$(dirname $grub_cfg)/custom.cfg
echo $custom_cfg

linux_cmd="linux$efi /reinstall-vmlinuz $(echo_tmp_ttys) $cmdline"
initrd_cmd="initrd$efi /reinstall-initrd"

cat <<EOF | tee $custom_cfg
set timeout=5
menuentry "$(get_entry_name)" {
    insmod all_video
    insmod lvm
    insmod xfs
    search --no-floppy --file --set=root /reinstall-vmlinuz
    $linux_cmd
    $initrd_cmd
}
EOF

# if is_os_in_btrfs && is_os_in_subvol; then
#     cp_to_btrfs_root /reinstall-vmlinuz
#     is_have_initrd && cp_to_btrfs_root /reinstall-initrd
# fi

# 有的机器开启了 kexec，例如腾讯云轻量 debian，要禁用
if [ -f /etc/default/kexec ]; then
    sed -i 's/LOAD_KEXEC=true/LOAD_KEXEC=false/' /etc/default/kexec
fi

$grub-reboot "$(get_entry_name)"

if is_use_cloud_image; then
    info 'cloud image mode'
else
    info 'installer mode'
fi

exit 0