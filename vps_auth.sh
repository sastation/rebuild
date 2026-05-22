#!/bin/bash
set -euo pipefail

# ============================================================
# Configuration — edit these values before running
# ============================================================

# Google Authenticator 免验证 IP（access_vps.conf）
TRUSTED_IPS=(
    "__TRUSTED_IP_1__"
    "__TRUSTED_IP_2__"
    "__TRUSTED_IP_3__"
)

# ============================================================
# Load personal config override
# ============================================================
VPS_ENV="$(dirname "$0")/vps_init.env"
if [[ -f "${VPS_ENV}" ]]; then
    source "${VPS_ENV}"
fi

# ============================================================
# Functions
# ============================================================

GoogleAuth() {
    # 安装及配置 google-authenticator
    echo "=> Setup Google authenticator"
    read -rsp $'Press enter to continue...\n'

    apt update
    apt -y install libpam-google-authenticator
    apt -y install qrencode

    FS="/etc/pam.d/sshd"
    sed -i '3i\# white-ip list' "${FS}"
    sed -i '4i\auth [success=1 default=ignore] pam_access.so accessfile=/etc/security/access_vps.conf' "${FS}"
    sed -i '5i\# google authenticator plug' "${FS}"
    sed -i '6i\auth required pam_google_authenticator.so nullok' "${FS}"
    sed -i '7i\ ' "${FS}"

    SSHD_CONFIG="/etc/ssh/sshd_config"
    DROPIN_DIR="/etc/ssh/sshd_config.d"
    DROPIN_FILE="${DROPIN_DIR}/90-vps-auth.conf"

    mkdir -p "${DROPIN_DIR}"
    echo "ChallengeResponseAuthentication yes" > "${DROPIN_FILE}"

    # 确保 sshd_config 包含 Include 指令（追加到末尾）
    if ! grep -qF "Include ${DROPIN_DIR}/*.conf" "${SSHD_CONFIG}" 2>/dev/null; then
        {
            echo ""
            echo "Include ${DROPIN_DIR}/*.conf"
        } >> "${SSHD_CONFIG}"
    fi

    cat > /etc/security/access_vps.conf << EOF
# skip one-time password if logging in from the trusted network
EOF
    for ip in "${TRUSTED_IPS[@]}"; do
        echo "+ : ALL : ${ip}" >> /etc/security/access_vps.conf
    done
    echo "- : ALL : ALL" >> /etc/security/access_vps.conf
}

GoogleAuth_Local() {
    # 对当前用户的 google_authenticator 环境进行配置
    google-authenticator

    cd ~
    FS=".google_authenticator"
    chmod 600 "${FS}"
    for code in 64802810 64802811 64802812 64802813 64802814 64802815 64802816 64802817 64802818 64802819; do
        echo "${code}" >> "${FS}"
    done
    chmod 400 "${FS}"
}

# ============================================================
# Main
# ============================================================
if [[ "${BASH_SOURCE[0]}" = "${0}" ]]; then
    echo "=== Google Auth Setup ==="
    echo "1) System-wide setup (GoogleAuth)"
    echo "2) Local user setup (GoogleAuth_Local)"
    read -p "Choice: " opt
    case "${opt}" in
        1) GoogleAuth ;;
        2) GoogleAuth_Local ;;
        *) echo "Invalid choice." ;;
    esac
fi
