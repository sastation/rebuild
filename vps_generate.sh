#!/bin/bash
# generate.sh — 生成个人配置
#
# 两种模式:
#   1) vps_init.env      — 独立配置文件，配合 vps_init.sh / vps_auth.sh 使用
#   2) vps_private.sh    — 完整独立脚本（含真实值），无需 env 文件

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
    # 将数组写入一个临时变量（通过 eval 的副作用存储）
    local str="${var}=("
    for item in "${items[@]}"; do
        str+=" \"${item}\""
    done
    str+=" )"
    eval "${str}"
}

array_to_lines() {
    local var="$1"
    # 读取数组并逐行输出
    eval "local items=(\"\${${var}[@]}\")"
    echo "${var}=("
    for item in "${items[@]}"; do
        echo "    \"${item}\""
    done
    echo ")"
}

# ============================================================
# 收集配置值
# ============================================================

collect_values() {
    echo ""
    echo "输入各配置项的值（直接回车跳过）:"
    echo ""

    read_val_nospace ADMIN_USER "管理员用户名" "__ADMIN_USER__"
    read_val SSH_PORT "SSH 端口" "__SSH_PORT__"
    read_val DOMAIN "DNS 搜索域" "__DOMAIN__"
    read_val PROXY_HTTP "局域网代理地址" "__PROXY_HTTP__"
    read_val DNS_FAMILY_PRIMARY "家庭 DNS 主" "__DNS_FAMILY_PRIMARY__"
    read_val DNS_FAMILY_SECONDARY "家庭 DNS 备" "__DNS_FAMILY_SECONDARY__"
    read_val GIT_NAME "Git 用户名" "__GIT_NAME__"
    read_val GIT_EMAIL "Git 邮箱" "__GIT_EMAIL__"
    read_array SSH_AUTHORIZED_KEYS "SSH 公钥"
    read_array TRUSTED_IPS "Google Auth 信任 IP"
}

# ============================================================
# 生成 vps_init.env
# ============================================================

generate_env() {
    local output="vps_init.env"

    cat > "${output}" << 'EOF'
# ============================================================
# 个人配置 — 由 generate.sh 自动生成
# ============================================================

EOF

    if [[ -n "${ADMIN_USER}" ]]; then
        echo "ADMIN_USER=\"${ADMIN_USER}\"" >> "${output}"
    fi

    {
        echo ""
        echo "# --- SSH ---"
    } >> "${output}"

    [[ -n "${SSH_PORT}" ]] && echo "SSH_PORT=\"${SSH_PORT}\"" >> "${output}"

    {
        echo ""
        echo "# --- 家庭网络（Family 环境） ---"
    } >> "${output}"

    [[ -n "${DOMAIN}" ]] && echo "DOMAIN=\"${DOMAIN}\"" >> "${output}"
    [[ -n "${PROXY_HTTP}" ]] && echo "PROXY_HTTP=\"${PROXY_HTTP}\"" >> "${output}"
    [[ -n "${DNS_FAMILY_PRIMARY}" ]] && echo "DNS_FAMILY_PRIMARY=\"${DNS_FAMILY_PRIMARY}\"" >> "${output}"
    [[ -n "${DNS_FAMILY_SECONDARY}" ]] && echo "DNS_FAMILY_SECONDARY=\"${DNS_FAMILY_SECONDARY}\"" >> "${output}"

    {
        echo ""
        echo "# --- Git 配置 ---"
    } >> "${output}"

    [[ -n "${GIT_NAME}" ]] && echo "GIT_NAME=\"${GIT_NAME}\"" >> "${output}"
    [[ -n "${GIT_EMAIL}" ]] && echo "GIT_EMAIL=\"${GIT_EMAIL}\"" >> "${output}"

    echo "" >> "${output}"
    echo "# --- SSH 公钥 ---" >> "${output}"
    if [[ ${#SSH_AUTHORIZED_KEYS[@]} -gt 0 ]]; then
        array_to_lines SSH_AUTHORIZED_KEYS >> "${output}"
    fi

    echo "" >> "${output}"
    echo "# --- Google Authenticator 信任 IP ---" >> "${output}"
    if [[ ${#TRUSTED_IPS[@]} -gt 0 ]]; then
        array_to_lines TRUSTED_IPS >> "${output}"
    fi

    echo ""
    echo "  已生成: ${output}"
    echo "  将此文件与 vps_init.sh / vps_auth.sh 放在同目录即可。"
}

# ============================================================
# 生成 vps_private.sh
# ============================================================

generate_private_sh() {
    local src="vps_init.sh"
    local dst="vps_private.sh"

    if [[ ! -f "${src}" ]]; then
        echo "  ERROR: 找不到 ${src}"
        return 1
    fi

    # 1. 复制模板
    cp "${src}" "${dst}"

    # 2. 删除 "Load personal config override" 区块（含验证）
    sed -i '/^# Load personal config override/,/^# Runtime variables/{
        /^# Load personal config override/d
        /^# Runtime variables/!d
    }' "${dst}"

    # 3. 替换简单标量占位符（使用 | 作为 sed 定界符）
    [[ -n "${ADMIN_USER}" ]]            && sed -i "s|__ADMIN_USER__|${ADMIN_USER}|g" "${dst}"
    [[ -n "${SSH_PORT}" ]]              && sed -i "s|__SSH_PORT__|${SSH_PORT}|g" "${dst}"
    [[ -n "${DOMAIN}" ]]                && sed -i "s|__DOMAIN__|${DOMAIN}|g" "${dst}"
    [[ -n "${PROXY_HTTP}" ]]            && sed -i "s|__PROXY_HTTP__|${PROXY_HTTP}|g" "${dst}"
    [[ -n "${DNS_FAMILY_PRIMARY}" ]]    && sed -i "s|__DNS_FAMILY_PRIMARY__|${DNS_FAMILY_PRIMARY}|g" "${dst}"
    [[ -n "${DNS_FAMILY_SECONDARY}" ]]  && sed -i "s|__DNS_FAMILY_SECONDARY__|${DNS_FAMILY_SECONDARY}|g" "${dst}"
    [[ -n "${GIT_NAME}" ]]              && sed -i "s|__GIT_NAME__|${GIT_NAME}|g" "${dst}"
    [[ -n "${GIT_EMAIL}" ]]             && sed -i "s|__GIT_EMAIL__|${GIT_EMAIL}|g" "${dst}"

    # 4. 替换 SSH_AUTHORIZED_KEYS 数组区块
    local tmpf tmp_keys
    tmpf="$(mktemp)"
    tmp_keys="$(mktemp)"

    # 用 awk 将占位数组替换为唯一标记行
    # __SSH_KEY_1__ 在数组元素中，需 peek 下一行来判断
    awk '
        /^SSH_AUTHORIZED_KEYS=\(/ {
            line = $0
            getline next_line
            if (next_line ~ /__SSH_KEY_1__/) {
                print "__SSH_KEYS_BLOCK__"
                while (getline && !/^\)/) {}
                next
            } else {
                print line
                print next_line
                next
            }
        }
        { print }
    ' "${dst}" > "${tmpf}" && mv "${tmpf}" "${dst}"

    # 生成真实数组内容
    {
        echo "SSH_AUTHORIZED_KEYS=("
        if [[ ${#SSH_AUTHORIZED_KEYS[@]} -gt 0 ]]; then
            for key in "${SSH_AUTHORIZED_KEYS[@]}"; do
                echo "    \"${key}\""
            done
        fi
        echo ")"
    } > "${tmp_keys}"

    # 用 sed 的 r + d 替换标记行：读取文件内容，删除标记行
    sed -i '/^__SSH_KEYS_BLOCK__$/{
        r '"${tmp_keys}"'
        d
    }' "${dst}"

    rm -f "${tmpf}" "${tmp_keys}"

    # 5. 修改文件头注释
    sed -i 's/Configuration — edit these values or create vps_init.env/Configuration — personal standalone script/' "${dst}"

    chmod +x "${dst}"

    echo ""
    echo "  已生成: ${dst}"
    echo "  独立脚本，无需 vps_init.env 即可运行。"
}

# ============================================================
# Main
# ============================================================

echo "============================================"
echo "  VPS Init 配置生成器"
echo "============================================"
echo ""
echo "生成模式:"
echo "  1) vps_init.env      — 交互式输入，生成独立配置文件"
echo "  2) vps_private.sh    — 从已有 vps_init.env 生成完整独立脚本"
echo ""
printf "选择 [1]: "
read mode
mode="${mode:-1}"

echo ""
echo "============================================"

case "${mode}" in
    2)
        # 从 vps_init.env 读取配置 → 生成独立脚本
        if [[ ! -f "vps_init.env" ]]; then
            echo "  ERROR: 找不到 vps_init.env"
            echo "  请先用模式 1 生成 vps_init.env"
            exit 1
        fi
        source vps_init.env
        generate_private_sh
        ;;
    *)
        # 交互式输入 → 生成 vps_init.env
        ADMIN_USER=""
        DOMAIN=""
        PROXY_HTTP=""
        DNS_FAMILY_PRIMARY=""
        DNS_FAMILY_SECONDARY=""
        GIT_NAME=""
        GIT_EMAIL=""
        SSH_AUTHORIZED_KEYS=()
        TRUSTED_IPS=()

        collect_values
        generate_env
        ;;
esac
echo "============================================"
