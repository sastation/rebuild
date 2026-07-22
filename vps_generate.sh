#!/bin/bash
# vps_generate.sh — 从配置源生成单文件部署脚本
#
# 数据流:
#   vps_config.sh (common + 多 profile, 私有)
#        │ 读取/注入
#        ▼
#   vps_deploy.sh (单文件, 内嵌全部 profile, 私有)
#
# 用法:
#   ./vps_generate.sh            # 交互选择：录入配置源 或 直接从已有配置源生成
#   ./vps_generate.sh generate   # 直接从已有 vps_config.sh 生成 vps_deploy.sh
#   ./vps_generate.sh collect    # 交互录入并写入 vps_config.sh

CONFIG_SRC="vps_config.sh"
TEMPLATE="vps_init.sh"
DEPLOY="vps_deploy.sh"

# ============================================================
# 辅助函数
# ============================================================

read_val() {
    local var="$1" desc="$2" default="$3"
    local input
    printf "  %-28s [%s]: " "${desc}" "${default}"
    read -r input
    if [[ -n "${input}" ]]; then
        eval "${var}=\"${input}\""
    fi
}

read_val_nospace() {
    local var="$1" desc="$2" default="$3"
    local input
    while true; do
        printf "  %-28s [%s]: " "${desc}" "${default}"
        read -r input
        if [[ -z "${input}" ]]; then
            break
        fi
        if [[ "${input}" != *" "* ]]; then
            eval "${var}=\"${input}\""
            break
        else
            echo "  ERROR: 不能包含空格，请重新输入"
        fi
    done
}

read_array() {
    local var="$1" desc="$2"
    local items=() input i=1
    echo "  ${desc}（每行一个，空行结束）:"
    while true; do
        printf "    [%d]: " "${i}"
        read -r input
        if [[ -z "${input}" ]]; then
            break
        fi
        items+=("${input}")
        i=$((i + 1))
    done
    local str="${var}=("
    for item in "${items[@]}"; do
        str+=" \"${item}\""
    done
    str+=" )"
    eval "${str}"
}

emit_scalar() {
    # 若变量非空则输出 "    NAME=\"value\"" 到目标文件
    local name="$1" value="$2" out="$3"
    [[ -n "${value}" ]] && echo "    ${name}=\"${value}\"" >> "${out}"
}

emit_array() {
    # 输出数组赋值（缩进 4 空格），无元素则跳过
    local name="$1" out="$2"; shift 2
    local items=("$@")
    [[ ${#items[@]} -eq 0 ]] && return
    {
        echo "    ${name}=("
        for item in "${items[@]}"; do
            echo "        \"${item}\""
        done
        echo "    )"
    } >> "${out}"
}

# ============================================================
# 交互录入 → 写入 vps_config.sh
# ============================================================

collect_common() {
    echo ""
    echo "== 录入 common 公共层（直接回车跳过） =="
    GIT_NAME=""; GIT_EMAIL=""; TIMEZONE=""
    DNS_PRIMARY=""; DNS_SECONDARY=""
    SSH_AUTHORIZED_KEYS=(); TRUSTED_IPS=()
    read_val TIMEZONE "时区" "Asia/Shanghai"
    read_val DNS_PRIMARY "DNS 主" "1.1.1.1"
    read_val DNS_SECONDARY "DNS 备" "8.8.4.4"
    read_val GIT_NAME "Git 用户名" ""
    read_val GIT_EMAIL "Git 邮箱" ""
    read_array SSH_AUTHORIZED_KEYS "SSH 公钥"
    read_array TRUSTED_IPS "fail2ban 信任 IP"
}

collect_profile() {
    # 录入单个 profile，结果存入以 profile 名前缀的临时变量
    local pname="$1"
    echo ""
    echo "== 录入 profile: ${pname}（直接回车跳过） =="
    P_AREA="VPS"; P_ADMIN_USER=""; P_SSH_PORT=""; P_DOMAIN=""
    P_PROXY_HTTP=""; P_DNS_PRIMARY=""; P_DNS_SECONDARY=""
    read_val P_AREA "环境类型 (VPS/Family)" "VPS"
    read_val_nospace P_ADMIN_USER "管理员用户名" ""
    read_val P_SSH_PORT "SSH 端口" ""
    read_val P_DOMAIN "DNS 搜索域" ""
    if [[ "${P_AREA}" = "Family" ]]; then
        read_val P_PROXY_HTTP "局域网代理地址" ""
        read_val P_DNS_PRIMARY "内网 DNS 主（覆盖 common）" ""
        read_val P_DNS_SECONDARY "内网 DNS 备（覆盖 common）" ""
    fi
}

write_config_src() {
    # 写入 common
    cat > "${CONFIG_SRC}" << 'EOF'
#!/bin/bash
# ============================================================
# 私有配置源 — 由 vps_generate.sh 生成，请勿上传公共库
# ============================================================

EOF

    echo "PROFILES=(${PROFILE_NAMES[*]})" >> "${CONFIG_SRC}"
    echo "" >> "${CONFIG_SRC}"

    # common 函数
    echo "profile_common() {" >> "${CONFIG_SRC}"
    emit_scalar TIMEZONE "${TIMEZONE}" "${CONFIG_SRC}"
    emit_scalar DNS_PRIMARY "${DNS_PRIMARY}" "${CONFIG_SRC}"
    emit_scalar DNS_SECONDARY "${DNS_SECONDARY}" "${CONFIG_SRC}"
    emit_scalar GIT_NAME "${GIT_NAME}" "${CONFIG_SRC}"
    emit_scalar GIT_EMAIL "${GIT_EMAIL}" "${CONFIG_SRC}"
    emit_array SSH_AUTHORIZED_KEYS "${CONFIG_SRC}" "${SSH_AUTHORIZED_KEYS[@]}"
    emit_array TRUSTED_IPS "${CONFIG_SRC}" "${TRUSTED_IPS[@]}"
    echo "    :" >> "${CONFIG_SRC}"
    echo "}" >> "${CONFIG_SRC}"
    echo "" >> "${CONFIG_SRC}"

    # 各 profile 函数
    local pname
    for pname in "${PROFILE_NAMES[@]}"; do
        eval "local area=\"\${AREA_${pname}}\""
        eval "local admin=\"\${ADMIN_USER_${pname}}\""
        eval "local port=\"\${SSH_PORT_${pname}}\""
        eval "local domain=\"\${DOMAIN_${pname}}\""
        eval "local proxy=\"\${PROXY_HTTP_${pname}}\""
        eval "local dns1=\"\${DNS_PRIMARY_${pname}}\""
        eval "local dns2=\"\${DNS_SECONDARY_${pname}}\""
        echo "profile_${pname}() {" >> "${CONFIG_SRC}"
        emit_scalar AREA "${area}" "${CONFIG_SRC}"
        emit_scalar ADMIN_USER "${admin}" "${CONFIG_SRC}"
        emit_scalar SSH_PORT "${port}" "${CONFIG_SRC}"
        emit_scalar DOMAIN "${domain}" "${CONFIG_SRC}"
        emit_scalar PROXY_HTTP "${proxy}" "${CONFIG_SRC}"
        emit_scalar DNS_PRIMARY "${dns1}" "${CONFIG_SRC}"
        emit_scalar DNS_SECONDARY "${dns2}" "${CONFIG_SRC}"
        echo "    :" >> "${CONFIG_SRC}"
        echo "}" >> "${CONFIG_SRC}"
        echo "" >> "${CONFIG_SRC}"
    done

    echo "  已生成配置源: ${CONFIG_SRC}"
}

collect_values() {
    PROFILE_NAMES=()
    collect_common

    echo ""
    echo "== 录入 profile（可添加多个） =="
    while true; do
        local pname
        printf "  新 profile 名称（留空结束）: "
        read -r pname
        [[ -z "${pname}" ]] && break
        if [[ "${pname}" == *" "* || "${pname}" = "common" ]]; then
            echo "  ERROR: 名称非法（不能含空格或为 common）"
            continue
        fi
        collect_profile "${pname}"
        PROFILE_NAMES+=("${pname}")
        eval "AREA_${pname}=\"\${P_AREA}\""
        eval "ADMIN_USER_${pname}=\"\${P_ADMIN_USER}\""
        eval "SSH_PORT_${pname}=\"\${P_SSH_PORT}\""
        eval "DOMAIN_${pname}=\"\${P_DOMAIN}\""
        eval "PROXY_HTTP_${pname}=\"\${P_PROXY_HTTP}\""
        eval "DNS_PRIMARY_${pname}=\"\${P_DNS_PRIMARY}\""
        eval "DNS_SECONDARY_${pname}=\"\${P_DNS_SECONDARY}\""
    done

    if [[ ${#PROFILE_NAMES[@]} -eq 0 ]]; then
        echo "  ERROR: 至少需要一个 profile"
        exit 1
    fi

    write_config_src
}

# ============================================================
# 从 vps_config.sh 注入模板 → 生成 vps_deploy.sh
# ============================================================

generate_deploy() {
    if [[ ! -f "${CONFIG_SRC}" ]]; then
        echo "  ERROR: 找不到 ${CONFIG_SRC}，请先录入配置。"
        exit 1
    fi
    if [[ ! -f "${TEMPLATE}" ]]; then
        echo "  ERROR: 找不到模板 ${TEMPLATE}"
        exit 1
    fi

    # shellcheck disable=SC1090
    source "${CONFIG_SRC}"

    if [[ ${#PROFILES[@]} -eq 0 ]]; then
        echo "  ERROR: ${CONFIG_SRC} 中未定义 PROFILES"
        exit 1
    fi

    cp "${TEMPLATE}" "${DEPLOY}"

    # 1. 替换 PROFILES 列表
    sed -i "s|__PROFILE_LIST__|${PROFILES[*]}|" "${DEPLOY}"

    # 2. 生成 common 函数体（含数组），替换 profile_common 中的占位
    local body_file
    body_file="$(mktemp)"
    {
        # 提取 profile_common 的函数体（去掉外层定义），直接内联展开
        # 通过重新调用 common 后 declare 收集较复杂，这里直接从源函数抽取赋值行
        declare -f profile_common | sed -e '1,2d' -e '$d'
    } > "${body_file}"

    # 用函数体替换 profile_common() { ... } 整块
    #   模板中 profile_common 为占位实现，需整体替换
    replace_func_block "profile_common" "${body_file}" "${DEPLOY}"
    rm -f "${body_file}"

    # 3. 生成各 profile 函数，替换 __PROFILE_FUNCS__ 标记行
    local funcs_file p
    funcs_file="$(mktemp)"
    for p in "${PROFILES[@]}"; do
        declare -f "profile_${p}" >> "${funcs_file}"
        echo "" >> "${funcs_file}"
    done
    sed -i "/^# __PROFILE_FUNCS__$/{
        r ${funcs_file}
        d
    }" "${DEPLOY}"
    rm -f "${funcs_file}"

    chmod +x "${DEPLOY}"
    echo ""
    echo "  已生成: ${DEPLOY}"
    echo "  单文件、内嵌全部 profile，无需外部文件即可运行。"
    echo "  用法: ./${DEPLOY} [--profile <name>]"
}

replace_func_block() {
    # 用给定的函数体文件替换目标脚本中已存在的同名函数整块定义
    local fname="$1" body_file="$2" target="$3"
    local tmp
    tmp="$(mktemp)"
    awk -v fname="${fname}" -v bodyfile="${body_file}" '
        $0 ~ "^"fname"\\(\\) \\{" {
            print fname"() {"
            while ((getline line < bodyfile) > 0) print line
            print "}"
            # 跳过原函数体直到匹配到单独的 }
            depth = 1
            while (depth > 0) {
                if ((getline l) <= 0) break
                if (l ~ /\{/) depth++
                if (l ~ /^\}/) depth--
            }
            next
        }
        { print }
    ' "${target}" > "${tmp}" && mv "${tmp}" "${target}"
}

# ============================================================
# Main
# ============================================================

echo "============================================"
echo "  VPS 部署脚本生成器"
echo "============================================"

MODE="${1:-}"
if [[ -z "${MODE}" ]]; then
    echo ""
    echo "  1) 从已有 ${CONFIG_SRC} 生成 ${DEPLOY}"
    echo "  2) 交互录入配置并写入 ${CONFIG_SRC}"
    echo ""
    printf "选择 [1]: "
    read -r m
    case "${m:-1}" in
        2) MODE="collect" ;;
        *) MODE="generate" ;;
    esac
fi

echo ""
echo "============================================"
case "${MODE}" in
    collect)
        collect_values
        echo ""
        printf "立即生成 ${DEPLOY}? (y/No) "
        read -r yn
        case "${yn}" in y|yes) generate_deploy ;; esac
        ;;
    generate)
        generate_deploy
        ;;
    *)
        echo "  未知模式: ${MODE}"
        exit 1
        ;;
esac
echo "============================================"
