#!/usr/bin/env bash
# ==============================================================================
# LAN Network Manager (CLI Only) - Antigravity
# Tach biet 100% mang LAN (enp2s0) va WLAN/4G bang Linux Network Namespace
# ==============================================================================

set -o pipefail

NS_NAME="lan_ns"
ETH_DEV="enp2s0"

# ------------------------------------------------------------------------------
# Logging Helpers
# ------------------------------------------------------------------------------
log_info()  { echo -e "\033[1;34m[*] $*\033[0m" >&2; }
log_ok()    { echo -e "\033[1;32m[+] $*\033[0m" >&2; }
log_warn()  { echo -e "\033[1;33m[!] $*\033[0m" >&2; }
log_error() { echo -e "\033[1;31m[-] $*\033[0m" >&2; }

# ------------------------------------------------------------------------------
# Environment & Graphics Preservation for Root Execution
# ------------------------------------------------------------------------------
SAVED_DISPLAY="${ORIG_DISPLAY:-${DISPLAY:-:0}}"
SAVED_USER="${ORIG_USER:-${SUDO_USER:-$USER}}"
[ "$SAVED_USER" = "root" ] && SAVED_USER="undertaker"
SAVED_HOME=$(getent passwd "$SAVED_USER" 2>/dev/null | cut -d: -f6)
[ -z "$SAVED_HOME" ] && SAVED_HOME="/home/$SAVED_USER"

SAVED_XAUTH="${ORIG_XAUTH:-${XAUTHORITY:-$SAVED_HOME/.Xauthority}}"
if [ ! -f "$SAVED_XAUTH" ]; then
    FOUND_XAUTH=$(ls -t /run/user/*/xauth* 2>/dev/null | head -n 1)
    [ -n "$FOUND_XAUTH" ] && SAVED_XAUTH="$FOUND_XAUTH"
fi

SAVED_WAYLAND="${ORIG_WAYLAND:-${WAYLAND_DISPLAY:-wayland-0}}"
SAVED_XDG_RUNTIME="${ORIG_XDG_RUNTIME:-${XDG_RUNTIME_DIR:-/run/user/$(id -u "$SAVED_USER" 2>/dev/null || echo 1000)}}"

REAL_USER="$SAVED_USER"
REAL_HOME="$SAVED_HOME"

# ------------------------------------------------------------------------------
# Root Escalation with Error Handling
# ------------------------------------------------------------------------------
ensure_root() {
    if [ "$EUID" -ne 0 ]; then
        if ! command -v sudo >/dev/null 2>&1; then
            log_error "Chuong trinh yeu cau quyen root nhung 'sudo' khong ton tai."
            exit 1
        fi
        local script_path
        script_path=$(realpath "$0" 2>/dev/null || echo "$0")
        exec sudo ORIG_DISPLAY="$SAVED_DISPLAY" \
                  ORIG_XAUTH="$SAVED_XAUTH" \
                  ORIG_USER="$SAVED_USER" \
                  ORIG_WAYLAND="$SAVED_WAYLAND" \
                  ORIG_XDG_RUNTIME="$SAVED_XDG_RUNTIME" \
                  "$script_path" "$@" || {
            log_error "That bai khi lay quyen root qua sudo. Vui long kiem tra mat khau."
            exit 1
        }
    fi
}

# ------------------------------------------------------------------------------
# Interface & Hardware Verification
# ------------------------------------------------------------------------------
check_interface_exists() {
    # Kiem tra card co tren host khong
    if ip link show "$ETH_DEV" >/dev/null 2>&1; then
        return 0
    fi
    # Kiem tra card da duoc chuyen vao namespace chua
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        if ip netns exec "$NS_NAME" ip link show "$ETH_DEV" >/dev/null 2>&1; then
            return 0
        fi
    fi

    log_error "Khong tim thay card mang '$ETH_DEV' tren he thong hoac trong namespace '$NS_NAME'."
    echo -e "\033[1;33m[GỢI Ý] Danh sach card mang vat ly hien co tren may:\033[0m" >&2
    ip -br link 2>/dev/null | grep -v "lo" >&2 || echo "  (Khong phat hien card mang nao)" >&2
    return 1
}

check_carrier_status() {
    local carrier="0"
    if [ -f "/sys/class/net/$ETH_DEV/carrier" ]; then
        carrier=$(cat "/sys/class/net/$ETH_DEV/carrier" 2>/dev/null || echo "0")
    elif ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        carrier=$(ip netns exec "$NS_NAME" cat "/sys/class/net/$ETH_DEV/carrier" 2>/dev/null || echo "0")
    fi

    if [ "$carrier" != "1" ]; then
        log_warn "Card '$ETH_DEV' hien o trang thai NO-CARRIER (chua cam day LAN hoac router chua bat)."
    fi
}

# ------------------------------------------------------------------------------
# DNS Isolation Setup
# ------------------------------------------------------------------------------
setup_dns() {
    local ns_dir="/etc/netns/$NS_NAME"
    if ! mkdir -p "$ns_dir" 2>/dev/null; then
        log_warn "Khong the tao thu muc $ns_dir (co the do loi quyen root)."
        return 1
    fi

    cat << 'EOF' > "$ns_dir/resolv.conf" 2>/dev/null
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 192.168.1.1
nameserver 9.9.9.9
EOF
    if [ $? -ne 0 ]; then
        log_warn "Khong the ghi file $ns_dir/resolv.conf"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# 1. Initialize Network Namespace
# ------------------------------------------------------------------------------
init_netns() {
    check_interface_exists || return 1
    setup_dns

    # Kiem tra neu namespace da khoi tao hoan chinh va co IP
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        if ip netns exec "$NS_NAME" ip link show "$ETH_DEV" >/dev/null 2>&1; then
            ip netns exec "$NS_NAME" ip link set lo up 2>/dev/null || true
            ip netns exec "$NS_NAME" ip link set "$ETH_DEV" up 2>/dev/null || true
            ip netns exec "$NS_NAME" sysctl -w net.ipv4.ping_group_range="0 2147483647" >/dev/null 2>&1 || true
            local cur_ip
            cur_ip=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
            if [ -n "$cur_ip" ]; then
                if ! ip netns exec "$NS_NAME" ip route show default 2>/dev/null | grep -q "default"; then
                    ip netns exec "$NS_NAME" ip route add default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
                fi
                log_ok "Namespace '$NS_NAME' da san sang (IP: $cur_ip)."
                return 0
            fi
        fi
    fi

    log_info "Dang thiet lap Network Namespace '$NS_NAME' cho card $ETH_DEV..."
    check_carrier_status

    local HOST_IP=""
    local HOST_GW=""

    # Luu thong tin IP/GW neu card dang o host
    if ip link show "$ETH_DEV" >/dev/null 2>&1; then
        HOST_IP=$(ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
        HOST_GW=$(ip route show dev "$ETH_DEV" 2>/dev/null | grep default | awk '{print $3}')

        # Ngat NetworkManager de tranh tranh chap
        if command -v nmcli >/dev/null 2>&1; then
            nmcli device disconnect "$ETH_DEV" >/dev/null 2>&1 || true
            nmcli device set "$ETH_DEV" managed no >/dev/null 2>&1 || true
        fi
        ip link set dev "$ETH_DEV" down 2>/dev/null || true
    fi

    # Tao namespace neu chua co
    if ! ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        if ! ip netns add "$NS_NAME" 2>/dev/null; then
            log_error "Khong the tao network namespace '$NS_NAME'."
            return 1
        fi
    fi
    setup_dns

    # Di chuyen card mang vao namespace
    if ip link show "$ETH_DEV" >/dev/null 2>&1; then
        if ! ip link set "$ETH_DEV" netns "$NS_NAME" 2>/dev/null; then
            log_error "Khong the di chuyen card $ETH_DEV vao namespace $NS_NAME."
            return 1
        fi
    fi

    # Bat loopback va card LAN
    ip netns exec "$NS_NAME" ip link set lo up 2>/dev/null || true
    ip netns exec "$NS_NAME" ip link set "$ETH_DEV" up 2>/dev/null || true
    ip netns exec "$NS_NAME" sysctl -w net.ipv4.ping_group_range="0 2147483647" >/dev/null 2>&1 || true

    # Tai su dung IP/GW cu neu co
    if [ -n "$HOST_IP" ]; then
        ip netns exec "$NS_NAME" ip addr replace "$HOST_IP" dev "$ETH_DEV" 2>/dev/null || true
        [ -n "$HOST_GW" ] && ip netns exec "$NS_NAME" ip route replace default via "$HOST_GW" dev "$ETH_DEV" 2>/dev/null || true
    fi

    # Xin IP qua DHCP
    log_info "Dang xin IP dong (DHCP) cho $ETH_DEV..."
    if command -v dhcpcd >/dev/null 2>&1; then
        ip netns exec "$NS_NAME" dhcpcd -C resolv.conf -4 -b "$ETH_DEV" >/dev/null 2>&1 || true
    elif command -v dhclient >/dev/null 2>&1; then
        ip netns exec "$NS_NAME" dhclient -4 -nw "$ETH_DEV" >/dev/null 2>&1 || true
    fi

    # Cho nhan IP toi da 3 giay
    local IP_INFO=""
    for _ in {1..6}; do
        IP_INFO=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
        [ -n "$IP_INFO" ] && break
        sleep 0.5
    done

    # Fallback IP du phong neu DHCP chua tra ve
    if [ -z "$IP_INFO" ]; then
        log_warn "Router chua cap DHCP, tu dong gan IP du phong 192.168.1.13/24..."
        ip netns exec "$NS_NAME" ip addr replace 192.168.1.13/24 dev "$ETH_DEV" 2>/dev/null || true
        ip netns exec "$NS_NAME" ip route replace default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
        IP_INFO="192.168.1.13/24"
    fi

    # Dam bao co Default Gateway
    if ! ip netns exec "$NS_NAME" ip route show default 2>/dev/null | grep -q "default"; then
        ip netns exec "$NS_NAME" ip route add default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
    fi

    log_ok "Khoi tao mang LAN thanh cong! IP: $IP_INFO"
    return 0
}

# ------------------------------------------------------------------------------
# 2. Run Single Command (Exec) Inside LAN Namespace
# ------------------------------------------------------------------------------
exec_command() {
    local as_root=0
    if [ "$1" = "--root" ] || [ "$1" = "-r" ]; then
        as_root=1
        shift
    fi

    if [ $# -eq 0 ]; then
        local cmd
        cmd="$(basename "$0")"
        log_error "Thieu cau lenh can thuc thi."
        echo -e "\033[1;33mCu phap:\033[0m sudo $cmd run [--root] <command> [args...]" >&2
        echo "Vi du:   sudo $cmd run nc -lvnp 4444" >&2
        echo "         sudo $cmd run nc 192.168.1.50 80" >&2
        echo "         sudo $cmd run curl -s https://api.ipify.org" >&2
        echo "         sudo $cmd run --root nc -lvnp 80" >&2
        return 1
    fi

    init_netns || {
        log_error "Khong the khoi tao namespace de thuc thi lenh."
        return 1
    }

    if [ "$as_root" -eq 1 ]; then
        exec ip netns exec "$NS_NAME" "$@"
    else
        exec ip netns exec "$NS_NAME" sudo -u "$REAL_USER" -H \
            DISPLAY="$SAVED_DISPLAY" \
            XAUTHORITY="$SAVED_XAUTH" \
            WAYLAND_DISPLAY="$SAVED_WAYLAND" \
            XDG_RUNTIME_DIR="$SAVED_XDG_RUNTIME" \
            "$@"
    fi
}

# ------------------------------------------------------------------------------
# 3. Open Interactive LAN Terminal
# ------------------------------------------------------------------------------
open_terminal() {
    init_netns || {
        log_error "Khong the khoi tao namespace de mo Terminal."
        return 1
    }

    # Cap quyen X11 neu co DISPLAY
    if [ -n "$SAVED_DISPLAY" ] && command -v xhost >/dev/null 2>&1; then
        xhost +SI:localuser:"$REAL_USER" >/dev/null 2>&1 || xhost +local: >/dev/null 2>&1 || true
    fi

    # Neu co tham so --new / -n / --gui thi mo mot cua so Terminal GUI moi tren Desktop
    if [ "$1" = "--new" ] || [ "$1" = "-n" ] || [ "$1" = "--gui" ]; then
        local TERM_BIN=""
        for t in x-terminal-emulator konsole gnome-terminal xfce4-terminal mate-terminal qterminal alacritty kitty xterm; do
            if command -v "$t" >/dev/null 2>&1; then
                TERM_BIN="$t"
                break
            fi
        done

        if [ -n "$TERM_BIN" ]; then
            log_ok "Dang mo cua so Terminal moi ($TERM_BIN) ket noi mang LAN..."
            ip netns exec "$NS_NAME" sudo -u "$REAL_USER" -H \
                DISPLAY="$SAVED_DISPLAY" \
                XAUTHORITY="$SAVED_XAUTH" \
                WAYLAND_DISPLAY="$SAVED_WAYLAND" \
                XDG_RUNTIME_DIR="$SAVED_XDG_RUNTIME" \
                "$TERM_BIN" >/dev/null 2>&1 &
            log_ok "Cua so Terminal LAN da duoc mo thanh cong!"
            return 0
        else
            log_warn "Khong tim thay trinh gia lap terminal GUI (konsole/xterm), chuyen sang mo trong terminal hien tai..."
        fi
    fi

    log_ok "Dang vao Terminal mang LAN ($ETH_DEV)..."
    ip netns exec "$NS_NAME" sudo -u "$REAL_USER" -H \
        bash -c "
            export DISPLAY='$SAVED_DISPLAY'
            export XAUTHORITY='$SAVED_XAUTH'
            export WAYLAND_DISPLAY='$SAVED_WAYLAND'
            export XDG_RUNTIME_DIR='$SAVED_XDG_RUNTIME'
            PROMPT_COMMAND='PS1=\"\[\033[1;32m\][LAN-NETNS:\u@\h \W]\$ \[\033[0m\]\"; unset PROMPT_COMMAND'
            echo -e '\033[1;32m=============================================================\033[0m'
            echo -e '\033[1;32m   TERMINAL MANG LAN ($ETH_DEV) - NAMESPACE: $NS_NAME         \033[0m'
            echo -e '\033[1;36m   - Moi ket noi (curl, ping, ssh...) deu di qua mang LAN.     \033[0m'
            echo -e '\033[1;33m   - Go \"exit\" de thoat khoi namespace.                       \033[0m'
            echo -e '\033[1;32m=============================================================\033[0m\n'
            exec bash -i
        "
}

# ------------------------------------------------------------------------------
# 4. Open Chromium Inside LAN Namespace
# ------------------------------------------------------------------------------
open_chromium() {
    if ! command -v chromium >/dev/null 2>&1 && ! command -v google-chrome >/dev/null 2>&1; then
        log_error "Khong tim thay Chromium hoac Google Chrome tren may."
        log_info "Co the cai dat bang: sudo apt install chromium"
        return 1
    fi

    local BROWSER_BIN="chromium"
    ! command -v chromium >/dev/null 2>&1 && BROWSER_BIN="google-chrome"

    init_netns || {
        log_error "Khong the khoi tao namespace de mo trinh duyet."
        return 1
    }

    if [ -n "$SAVED_DISPLAY" ] && command -v xhost >/dev/null 2>&1; then
        xhost +SI:localuser:"$REAL_USER" >/dev/null 2>&1 || xhost +local: >/dev/null 2>&1 || true
    fi

    local LAN_USER_DATA="$REAL_HOME/.config/chromium-lan"
    mkdir -p "$LAN_USER_DATA" 2>/dev/null || true
    chown -R "$REAL_USER:$REAL_USER" "$LAN_USER_DATA" 2>/dev/null || true
    rm -f "$LAN_USER_DATA/Singleton"* 2>/dev/null || true

    local TARGET_URL="${1:-https://whatismyip.com}"

    log_ok "Dang khoi dong $BROWSER_BIN mang LAN ($ETH_DEV)..."
    echo -e "\033[1;34m    -> Profile: $LAN_USER_DATA\033[0m"
    echo -e "\033[1;34m    -> DoH DNS: Cloudflare Secure DNS\033[0m"

    ip netns exec "$NS_NAME" sudo -u "$REAL_USER" -H \
        DISPLAY="$SAVED_DISPLAY" \
        XAUTHORITY="$SAVED_XAUTH" \
        WAYLAND_DISPLAY="$SAVED_WAYLAND" \
        XDG_RUNTIME_DIR="$SAVED_XDG_RUNTIME" \
        "$BROWSER_BIN" \
        --user-data-dir="$LAN_USER_DATA" \
        --class=chromium-lan \
        --no-first-run \
        --no-default-browser-check \
        --enable-features=DnsOverHttps \
        --dns-over-https-mode=secure \
        --dns-over-https-templates="https://chrome.cloudflare-dns.com/dns-query" \
        "$TARGET_URL" >/tmp/lan_chromium.log 2>&1 &

    log_ok "$BROWSER_BIN LAN da khoi dong thanh cong!"
}

# ------------------------------------------------------------------------------
# 5. Connection Diagnostics & Diagnostics
# ------------------------------------------------------------------------------
test_connection() {
    init_netns || {
        log_error "Namespace chua san sang, khong the kiem tra ket noi."
        return 1
    }

    echo -e "\n\033[1;36m================ KIEM TRA KET NOI LAN ================\033[0m"

    # 1. Kiem tra IP
    local LAN_IP
    LAN_IP=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
    if [ -z "$LAN_IP" ]; then
        echo -e "\033[1;31m[-] [1] IP card LAN: CHUA CO IP!\033[0m (Vui long kiem tra day cap mang)"
        return 1
    fi
    echo -e "\033[1;32m[+] [1] IP card LAN: $LAN_IP\033[0m"

    # 2. Kiem tra Gateway
    local GW
    GW=$(ip netns exec "$NS_NAME" ip route show default 2>/dev/null | awk '{print $3}')
    if [ -z "$GW" ]; then
        echo -e "\033[1;33m[!] [2] Tu dong gan Gateway 192.168.1.1 cho LAN...\033[0m"
        ip netns exec "$NS_NAME" ip route add default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
        GW="192.168.1.1"
    fi
    echo -e "\033[1;32m[+] [2] Gateway LAN: $GW\033[0m"

    # 3. Ping Gateway LAN
    echo -n "[*] [3] Ping Gateway ($GW)... "
    if ip netns exec "$NS_NAME" ping -c 2 -W 2 "$GW" >/dev/null 2>&1; then
        echo -e "\033[1;32mTHANH CONG (Noi bo LAN thong)\033[0m"
    else
        echo -e "\033[1;31mTHAT BAI (Khong ping duoc Router LAN)\033[0m"
    fi

    # 4. Ping Internet IP truc tiep (8.8.8.8)
    echo -n "[*] [4] Ping Internet truc tiep (8.8.8.8)... "
    if ip netns exec "$NS_NAME" ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo -e "\033[1;32mTHANH CONG (Internet LAN thong)\033[0m"
    else
        echo -e "\033[1;31mTHAT BAI (Router LAN chua thong Internet ra ngoai)\033[0m"
    fi

    # 5. Kiem tra phan giai DNS
    echo -n "[*] [5] Phan giai DNS (google.com)... "
    if ip netns exec "$NS_NAME" ping -c 1 -W 3 google.com >/dev/null 2>&1; then
        echo -e "\033[1;32mTHANH CONG (DNS hoat dong tot)\033[0m"
    else
        echo -e "\033[1;31mTHAT BAI (Loi DNS hoac bi chan)\033[0m"
    fi

    # 6. Lay Public IP
    echo -n "[*] [6] Lay Public IP qua card LAN... "
    local PUB_IP
    PUB_IP=$(ip netns exec "$NS_NAME" curl -s --max-time 4 https://api.ipify.org 2>/dev/null || true)
    if [ -n "$PUB_IP" ]; then
        echo -e "\033[1;32mTHANH CONG -> Public IP: $PUB_IP\033[0m"
    else
        echo -e "\033[1;33mKhong lay duoc Public IP (timeout hoac chua co ket noi ngoai)\033[0m"
    fi

    echo -e "\033[1;36m======================================================\033[0m\n"
}

# ------------------------------------------------------------------------------
# 6. Compare Network Status (Host vs LAN)
# ------------------------------------------------------------------------------
status_network() {
    echo -e "\n\033[1;36m================ TRANG THAI MANG SO SANH ================\033[0m"

    # Tu dong xac dinh card mang mac dinh cua Host
    local HOST_DEFAULT_DEV
    HOST_DEFAULT_DEV=$(ip route show default 2>/dev/null | head -n 1 | awk '{print $5}')
    [ -z "$HOST_DEFAULT_DEV" ] && HOST_DEFAULT_DEV="wlo1"

    echo -e "\033[1;33m[1] MANG MAC DINH CUA MAY (Host - App thuong):\033[0m"
    ip -4 -br a show dev "$HOST_DEFAULT_DEV" 2>/dev/null || ip -4 -br a 2>/dev/null | grep -v "lo"
    echo -n "    Default Gateway Host: "
    ip route show default 2>/dev/null | awk '{print $3}' || echo "Chua co default route"
    local HOST_PUB
    HOST_PUB=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || true)
    [ -n "$HOST_PUB" ] && echo -e "    Public IP Host:       \033[1;32m$HOST_PUB\033[0m"

    echo -e "\n\033[1;33m[2] MANG LAN TACH BIET (Namespace '$NS_NAME'):\033[0m"
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        ip netns exec "$NS_NAME" ip -4 -br a show dev "$ETH_DEV" 2>/dev/null || echo "    Card $ETH_DEV chua co IP trong namespace."
        echo -n "    Default Gateway LAN:  "
        ip netns exec "$NS_NAME" ip route show default 2>/dev/null | awk '{print $3}' || echo "Chua nhan duoc gateway"
        local LAN_PUB
        LAN_PUB=$(ip netns exec "$NS_NAME" curl -s --max-time 3 https://api.ipify.org 2>/dev/null || true)
        [ -n "$LAN_PUB" ] && echo -e "    Public IP LAN:        \033[1;32m$LAN_PUB\033[0m"
    else
        echo "    Namespace '$NS_NAME' chua duoc khoi tao (Card $ETH_DEV dang o host hoac chua bat)."
    fi
    echo -e "\033[1;36m=========================================================\033[0m\n"
}

# ------------------------------------------------------------------------------
# 7. Renew DHCP Inside LAN Namespace
# ------------------------------------------------------------------------------
renew_dhcp() {
    if ! ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        log_error "Namespace '$NS_NAME' chua duoc khoi tao. Hay chay '$0 init' truoc."
        return 1
    fi

    log_info "Dang lam moi dia chi IP qua DHCP cho $ETH_DEV..."
    setup_dns

    if command -v dhcpcd >/dev/null 2>&1; then
        ip netns exec "$NS_NAME" dhcpcd -k "$ETH_DEV" 2>/dev/null || true
        sleep 0.5
        ip netns exec "$NS_NAME" dhcpcd -C resolv.conf -4 -b "$ETH_DEV" 2>/dev/null || true
    elif command -v dhclient >/dev/null 2>&1; then
        ip netns exec "$NS_NAME" dhclient -r "$ETH_DEV" 2>/dev/null || true
        sleep 0.5
        ip netns exec "$NS_NAME" dhclient -4 -nw "$ETH_DEV" 2>/dev/null || true
    fi

    sleep 1
    test_connection
}

# ------------------------------------------------------------------------------
# 8. Stop and Revert to Host
# ------------------------------------------------------------------------------
stop_netns() {
    log_info "Dang dong ung dung va khoi phuc card $ETH_DEV ve he thong chinh..."

    # 1. Tat cac ung dung dang mo trong namespace
    pkill -f "chromium-lan" 2>/dev/null || true
    rm -f "$REAL_HOME/.config/chromium-lan/Singleton"* 2>/dev/null || true

    # 2. Dung DHCP va tra card ve host namespace 1
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        if command -v dhcpcd >/dev/null 2>&1; then
            ip netns exec "$NS_NAME" dhcpcd -k "$ETH_DEV" >/dev/null 2>&1 || true
        elif command -v dhclient >/dev/null 2>&1; then
            ip netns exec "$NS_NAME" dhclient -r "$ETH_DEV" >/dev/null 2>&1 || true
        fi
        ip netns exec "$NS_NAME" ip link set "$ETH_DEV" netns 1 2>/dev/null || true
        ip netns del "$NS_NAME" 2>/dev/null || true
    fi

    # 3. Kich hoat lai card tren may chinh cho NetworkManager
    ip link set "$ETH_DEV" up 2>/dev/null || true
    if command -v nmcli >/dev/null 2>&1; then
        nmcli device set "$ETH_DEV" managed yes 2>/dev/null || true
        nmcli device connect "$ETH_DEV" 2>/dev/null || true
    fi

    log_ok "Da khoi phuc card $ETH_DEV ve he thong chinh thanh cong!"
}

# ------------------------------------------------------------------------------
# 9. Install and Uninstall CLI
# ------------------------------------------------------------------------------
install_cli() {
    local src_path
    src_path=$(realpath "$0" 2>/dev/null || echo "$0")
    local target_bin="/usr/local/bin/lan"

    log_info "Dang cai dat LAN CLI vao $target_bin..."
    install -m 755 "$src_path" "$target_bin"
    [ -d "$REAL_HOME/.local/bin" ] && ln -sf "$target_bin" "$REAL_HOME/.local/bin/lan" 2>/dev/null || true

    log_ok "Cai dat thanh cong! Gio day ban co the dung 'sudo lan term' hoac 'sudo lan browser' o moi noi."
}

uninstall_cli() {
    log_info "Dang go bo LAN CLI khoi he thong..."
    rm -f "/usr/local/bin/lan" "$REAL_HOME/.local/bin/lan" 2>/dev/null || true
    log_ok "Da go bo thanh cong LAN CLI!"
}

# ------------------------------------------------------------------------------
# CLI Help / Usage
# ------------------------------------------------------------------------------
show_help() {
    local cmd
    cmd="$(basename "$0")"

    echo -e "\033[1;36m================================================================================\033[0m"
    echo -e "\033[1;36m LAN Network Manager - Antigravity\033[0m"
    echo -e " Co lap 100% Terminal & Browser vao mang LAN ($ETH_DEV)"
    echo -e "\033[1;36m================================================================================\033[0m\n"
    echo -e "\033[1;33mCAC CHUC NANG CHINH:\033[0m"
    echo -e "  \033[1;32msudo $cmd term\033[0m             -> Mo Terminal ket noi mang LAN"
    echo -e "  \033[1;32msudo $cmd browser\033[0m          -> Mo Trinh duyet Chromium ket noi mang LAN"
    echo -e "  \033[1;32msudo $cmd run <cmd...>\033[0m    -> Chay nhanh 1 lenh qua mang LAN (vd: run nc ...)\n"
    echo -e "\033[1;33mDUNG & HOAN TRA:\033[0m"
    echo -e "  \033[1;31msudo $cmd stop\033[0m             -> Dong ung dung va khoi phuc card mang ve binh thuong\n"
    echo -e "\033[1;33mCAC LENH TIEN ICH KHAC (Tuy chon):\033[0m"
    echo "  sudo $cmd term --new       -> Bat mot cua so Terminal GUI moi tren Desktop"
    echo "  sudo $cmd run nc ...       -> Chay netcat qua mang LAN (vd: run nc -lvnp 4444)"
    echo "  sudo $cmd run --root ...   -> Chay lenh voi quyen root (vd: run --root tcpdump ...)"
    echo "  sudo $cmd browser [url]    -> Mo trinh duyet voi URL tuy chon"
    echo "  sudo $cmd status           -> Xem so sanh IP giua mang Host va mang LAN"
    echo "  sudo $cmd test             -> Kiem tra chan doan ket noi mang LAN (Ping, DNS, IP)"
    echo "  sudo $cmd install          -> Cai dat 'lan' thanh lenh toan cuc he thong"
    echo "  $cmd --help                -> Hien thi huong dan nay (khong can sudo)"
    echo ""
}

# ------------------------------------------------------------------------------
# MAIN ENTRYPOINT
# ------------------------------------------------------------------------------
COMMAND="${1:-help}"

# Kiem tra tinh hop le cua lenh truoc khi yeu cau quyen root
case "$COMMAND" in
    help|-h|--help)
        show_help
        exit 0
        ;;
    up|init|start|down|stop|revert|restart|exec|run|term|terminal|shell|chrome|chromium|browser|test|check|ping|status|info|renew|dhcp|install|uninstall)
        # Lenh hop le -> tiep tuc xu ly
        ;;
    *)
        log_error "Lenh khong hop le: '$COMMAND'"
        echo ""
        show_help
        exit 1
        ;;
esac

# Cac lenh quan ly namespace can quyen root
ensure_root "$@"

shift 2>/dev/null || true

case "$COMMAND" in
    up|init|start)
        init_netns
        ;;
    down|stop|revert)
        stop_netns
        ;;
    restart)
        stop_netns
        sleep 1
        init_netns
        ;;
    exec|run)
        exec_command "$@"
        ;;
    term|terminal|shell)
        open_terminal "$@"
        ;;
    chrome|chromium|browser)
        open_chromium "$@"
        ;;
    test|check|ping)
        test_connection
        ;;
    status|info)
        status_network
        ;;
    renew|dhcp)
        renew_dhcp
        ;;
    install)
        install_cli
        ;;
    uninstall)
        uninstall_cli
        ;;
esac
