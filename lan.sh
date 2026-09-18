#!/usr/bin/env bash
# ==============================================================================
# LAN Network Manager (CLI) - Antigravity
# Tách biệt mạng LAN bằng Linux Network Namespace
# ==============================================================================
set -o pipefail

NS_NAME="lan_ns"
ETH_DEV="${ETH_DEV:-enp2s0}"

# --- Logging Helpers ---
log_ok()    { echo -e "\033[1;32m[+]\033[0m $*" >&2; }
log_warn()  { echo -e "\033[1;33m[!]\033[0m $*" >&2; }
log_error() { echo -e "\033[1;31m[-]\033[0m $*" >&2; }

# --- Environment & Display Preservation ---
SAVED_DISPLAY="${ORIG_DISPLAY:-${DISPLAY:-:0}}"
SAVED_USER="${ORIG_USER:-${SUDO_USER:-$USER}}"
[ "$SAVED_USER" = "root" ] && SAVED_USER="undertaker"
SAVED_HOME=$(getent passwd "$SAVED_USER" 2>/dev/null | cut -d: -f6)
[ -z "$SAVED_HOME" ] && SAVED_HOME="/home/$SAVED_USER"

SAVED_XAUTH="${ORIG_XAUTH:-${XAUTHORITY:-$SAVED_HOME/.Xauthority}}"
[ ! -f "$SAVED_XAUTH" ] && SAVED_XAUTH=$(ls -t /run/user/*/xauth* 2>/dev/null | head -n 1)

SAVED_WAYLAND="${ORIG_WAYLAND:-${WAYLAND_DISPLAY:-wayland-0}}"
SAVED_XDG="${ORIG_XDG_RUNTIME:-${XDG_RUNTIME_DIR:-/run/user/$(id -u "$SAVED_USER" 2>/dev/null || echo 1000)}}"

# --- Escalation ---
ensure_root() {
    if [ "$EUID" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || { log_error "Yêu cầu 'sudo' để chạy lệnh."; exit 1; }
        exec sudo ORIG_DISPLAY="$SAVED_DISPLAY" \
                  ORIG_XAUTH="$SAVED_XAUTH" \
                  ORIG_USER="$SAVED_USER" \
                  ORIG_WAYLAND="$SAVED_WAYLAND" \
                  ORIG_XDG_RUNTIME="$SAVED_XDG" \
                  "$(realpath "$0" 2>/dev/null || echo "$0")" "$@"
    fi
}

detect_interface() {
    # 1. Kiểm tra card cấu hình sẵn trên Host hoặc trong Namespace
    if ip link show "$ETH_DEV" >/dev/null 2>&1; then
        return 0
    fi
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        if ip netns exec "$NS_NAME" ip link show "$ETH_DEV" >/dev/null 2>&1; then
            return 0
        fi
    fi

    # 2. Chờ tối đa 1.5s phòng trường hợp driver Realtek/PHY đang reset khi vừa cắm dây
    for _ in 1 2 3; do
        sleep 0.5
        if ip link show "$ETH_DEV" >/dev/null 2>&1; then
            return 0
        fi
    done

    # 3. Tự động quét card Ethernet vật lý trên Host (en*, eth*)
    local auto_dev=""
    for dev_path in /sys/class/net/*; do
        local dname; dname=$(basename "$dev_path")
        [ "$dname" = "lo" ] && continue
        [ -d "$dev_path/wireless" ] && continue
        if [ -d "$dev_path/device" ]; then
            auto_dev="$dname"
            break
        fi
    done

    if [ -n "$auto_dev" ]; then
        log_warn "Tự động nhận diện card LAN: $auto_dev"
        ETH_DEV="$auto_dev"
        return 0
    fi

    # 4. Kiểm tra xem có card nào trong namespace chưa
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        local ns_dev
        ns_dev=$(ip netns exec "$NS_NAME" ip -br link show 2>/dev/null | grep -v "^lo" | awk '{print $1}' | head -n 1)
        if [ -n "$ns_dev" ]; then
            ETH_DEV="$ns_dev"
            return 0
        fi
    fi

    log_error "Không tìm thấy card mạng LAN '$ETH_DEV'."
    echo -e "Danh sách card mạng hiện có trên máy:" >&2
    ip -br link show 2>/dev/null >&2
    return 1
}

setup_dns() {
    mkdir -p "/etc/netns/$NS_NAME" 2>/dev/null || return 1
    cat << 'EOF' > "/etc/netns/$NS_NAME/resolv.conf"
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 192.168.1.1
EOF
}

# --- 1. Init Namespace ---
init_netns() {
    detect_interface || return 1
    setup_dns

    # Đã cấu hình và có IP sẵn trong namespace?
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        if ip netns exec "$NS_NAME" ip link show "$ETH_DEV" >/dev/null 2>&1; then
            local cur_ip
            cur_ip=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
            [ -n "$cur_ip" ] && return 0
        fi
    fi

    local HOST_IP="" HOST_GW=""
    if ip link show "$ETH_DEV" >/dev/null 2>&1; then
        HOST_IP=$(ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
        HOST_GW=$(ip route show dev "$ETH_DEV" 2>/dev/null | grep default | awk '{print $3}')
        if command -v nmcli >/dev/null 2>&1; then
            nmcli dev disconnect "$ETH_DEV" >/dev/null 2>&1 || true
            nmcli dev set "$ETH_DEV" managed no >/dev/null 2>&1 || true
        fi
        ip link set dev "$ETH_DEV" down 2>/dev/null || true
    fi

    ip netns list 2>/dev/null | grep -qw "$NS_NAME" || ip netns add "$NS_NAME"
    ip link show "$ETH_DEV" >/dev/null 2>&1 && ip link set "$ETH_DEV" netns "$NS_NAME"

    ip netns exec "$NS_NAME" ip link set lo up 2>/dev/null || true
    ip netns exec "$NS_NAME" ip link set "$ETH_DEV" up 2>/dev/null || true
    ip netns exec "$NS_NAME" sysctl -w net.ipv4.ping_group_range="0 2147483647" >/dev/null 2>&1 || true

    if [ -n "$HOST_IP" ]; then
        ip netns exec "$NS_NAME" ip addr replace "$HOST_IP" dev "$ETH_DEV" 2>/dev/null || true
        [ -n "$HOST_GW" ] && ip netns exec "$NS_NAME" ip route replace default via "$HOST_GW" dev "$ETH_DEV" 2>/dev/null || true
    fi

    if command -v dhcpcd >/dev/null 2>&1; then
        ip netns exec "$NS_NAME" dhcpcd -C resolv.conf -4 -b "$ETH_DEV" >/dev/null 2>&1 || true
    elif command -v dhclient >/dev/null 2>&1; then
        ip netns exec "$NS_NAME" dhclient -4 -nw "$ETH_DEV" >/dev/null 2>&1 || true
    fi

    local ip_info=""
    for _ in {1..6}; do
        ip_info=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
        [ -n "$ip_info" ] && break
        sleep 0.5
    done

    if [ -z "$ip_info" ]; then
        ip netns exec "$NS_NAME" ip addr replace 192.168.1.13/24 dev "$ETH_DEV" 2>/dev/null || true
        ip netns exec "$NS_NAME" ip route replace default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
        ip_info="192.168.1.13/24 (dự phòng)"
    fi

    ip netns exec "$NS_NAME" ip route show default 2>/dev/null | grep -q default || \
        ip netns exec "$NS_NAME" ip route add default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true

    log_ok "Đã kích hoạt mạng LAN ($ETH_DEV) -> IP: $ip_info"
}

# --- 2. Run Command ---
exec_command() {
    local as_root=0
    [ "$1" = "--root" ] || [ "$1" = "-r" ] && { as_root=1; shift; }

    [ $# -eq 0 ] && {
        echo "Cú pháp: lan run [--root] <command> [args...]" >&2
        echo "Ví dụ:   lan run nc -lvnp 4444" >&2
        return 1
    }

    init_netns >/dev/null || return 1

    if [ "$as_root" -eq 1 ]; then
        exec ip netns exec "$NS_NAME" "$@"
    else
        exec ip netns exec "$NS_NAME" sudo -u "$SAVED_USER" -H \
            DISPLAY="$SAVED_DISPLAY" \
            XAUTHORITY="$SAVED_XAUTH" \
            WAYLAND_DISPLAY="$SAVED_WAYLAND" \
            XDG_RUNTIME_DIR="$SAVED_XDG" \
            "$@"
    fi
}

# --- 3. Open Terminal ---
open_terminal() {
    init_netns || return 1
    [ -n "$SAVED_DISPLAY" ] && command -v xhost >/dev/null 2>&1 && xhost +local: >/dev/null 2>&1 || true

    if [ "$1" = "--new" ] || [ "$1" = "-n" ]; then
        local term_bin=""
        for t in konsole x-terminal-emulator gnome-terminal xfce4-terminal kitty alacritty xterm; do
            command -v "$t" >/dev/null 2>&1 && { term_bin="$t"; break; }
        done
        if [ -n "$term_bin" ]; then
            log_ok "Đã mở cửa sổ Terminal LAN ($term_bin)"
            ip netns exec "$NS_NAME" sudo -u "$SAVED_USER" -H \
                DISPLAY="$SAVED_DISPLAY" \
                XAUTHORITY="$SAVED_XAUTH" \
                WAYLAND_DISPLAY="$SAVED_WAYLAND" \
                XDG_RUNTIME_DIR="$SAVED_XDG" \
                "$term_bin" >/dev/null 2>&1 &
            return 0
        fi
    fi

    echo -e "\033[1;32m[+] Vào Terminal LAN ($ETH_DEV). Gõ 'exit' để thoát.\033[0m"
    ip netns exec "$NS_NAME" sudo -u "$SAVED_USER" -H bash -c "
        export DISPLAY='$SAVED_DISPLAY' XAUTHORITY='$SAVED_XAUTH'
        export WAYLAND_DISPLAY='$SAVED_WAYLAND' XDG_RUNTIME_DIR='$SAVED_XDG'
        export PROMPT_COMMAND='case \"\$PS1\" in *\"[LAN]\"*) ;; *) PS1=\"\[\033[1;32m\][LAN] \[\033[0m\]\$PS1\" ;; esac'
        exec bash -i
    "
}

# --- 4. Open Browser ---
open_chromium() {
    local browser="chromium"
    command -v chromium >/dev/null 2>&1 || browser="google-chrome"
    command -v "$browser" >/dev/null 2>&1 || { log_error "Không tìm thấy Chromium hoặc Chrome."; return 1; }

    init_netns || return 1
    [ -n "$SAVED_DISPLAY" ] && command -v xhost >/dev/null 2>&1 && xhost +local: >/dev/null 2>&1 || true

    local udata="$SAVED_HOME/.config/chromium-lan"
    mkdir -p "$udata" 2>/dev/null && chown -R "$SAVED_USER:$SAVED_USER" "$udata" 2>/dev/null || true
    rm -f "$udata/Singleton"* 2>/dev/null || true

    local url="${1:-https://whatismyip.com}"
    log_ok "Đã mở $browser LAN ($url)"

    ip netns exec "$NS_NAME" sudo -u "$SAVED_USER" -H \
        DISPLAY="$SAVED_DISPLAY" \
        XAUTHORITY="$SAVED_XAUTH" \
        WAYLAND_DISPLAY="$SAVED_WAYLAND" \
        XDG_RUNTIME_DIR="$SAVED_XDG" \
        "$browser" \
        --user-data-dir="$udata" \
        --class=chromium-lan \
        --no-first-run \
        --no-default-browser-check \
        --enable-features=DnsOverHttps \
        --dns-over-https-mode=secure \
        --dns-over-https-templates="https://chrome.cloudflare-dns.com/dns-query" \
        "$url" >/dev/null 2>&1 &
}

# --- 5. Stop ---
stop_netns() {
    pkill -f "chromium-lan" 2>/dev/null || true
    rm -f "$SAVED_HOME/.config/chromium-lan/Singleton"* 2>/dev/null || true

    detect_interface >/dev/null 2>&1 || true

    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        command -v dhcpcd >/dev/null 2>&1 && ip netns exec "$NS_NAME" dhcpcd -k "$ETH_DEV" >/dev/null 2>&1 || true
        command -v dhclient >/dev/null 2>&1 && ip netns exec "$NS_NAME" dhclient -r "$ETH_DEV" >/dev/null 2>&1 || true
        ip netns exec "$NS_NAME" ip link set "$ETH_DEV" netns 1 2>/dev/null || true
        ip netns del "$NS_NAME" 2>/dev/null || true
    fi

    ip link set "$ETH_DEV" up 2>/dev/null || true
    if command -v nmcli >/dev/null 2>&1; then
        nmcli dev set "$ETH_DEV" managed yes 2>/dev/null || true
        nmcli dev connect "$ETH_DEV" 2>/dev/null || true
    fi
    log_ok "Đã khôi phục $ETH_DEV về hệ thống chính."
}

# --- 6. Diagnostics & Status ---
status_network() {
    local hdev
    hdev=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
    [ -z "$hdev" ] && hdev="wlo1"
    local hip
    hip=$(ip -4 -br a show dev "$hdev" 2>/dev/null | awk '{print $3}')

    echo -e "\033[1;34m[Host]\033[0m Card: ${hdev:-none} | IP: ${hip:-none}"

    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        local lip
        lip=$(ip netns exec "$NS_NAME" ip -4 -br a show dev "$ETH_DEV" 2>/dev/null | awk '{print $3}')
        echo -e "\033[1;32m[LAN ]\033[0m Card: $ETH_DEV | IP: ${lip:-chưa có IP} (trong $NS_NAME)"
    else
        echo -e "\033[1;33m[LAN ]\033[0m Card: $ETH_DEV đang ở Host ($NS_NAME chưa bật)"
    fi
}

test_connection() {
    init_netns || return 1
    local ip gw
    ip=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
    gw=$(ip netns exec "$NS_NAME" ip route show default 2>/dev/null | awk '{print $3}')
    [ -z "$gw" ] && gw="192.168.1.1"

    echo "IP LAN:       ${ip:-Chưa có}"
    echo "Gateway:      $gw"
    echo -n "Ping Router:  "; ip netns exec "$NS_NAME" ping -c 1 -W 2 "$gw" >/dev/null 2>&1 && echo "OK" || echo "FAIL"
    echo -n "Ping Internet:"; ip netns exec "$NS_NAME" ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo "OK" || echo "FAIL"
    echo -n "Phân giải DNS:"; ip netns exec "$NS_NAME" ping -c 1 -W 2 google.com >/dev/null 2>&1 && echo "OK" || echo "FAIL"
    local pub; pub=$(ip netns exec "$NS_NAME" curl -s --max-time 3 https://api.ipify.org 2>/dev/null || true)
    echo "Public IP:    ${pub:-Không lấy được}"
}

# --- 7. Install / Uninstall ---
install_cli() {
    local src; src=$(realpath "$0" 2>/dev/null || echo "$0")
    install -m 755 "$src" "/usr/local/bin/lan"
    [ -d "$SAVED_HOME/.local/bin" ] && ln -sf "/usr/local/bin/lan" "$SAVED_HOME/.local/bin/lan" 2>/dev/null || true
    log_ok "Đã cài đặt 'lan' vào /usr/local/bin/lan"
}

uninstall_cli() {
    rm -f "/usr/local/bin/lan" "$SAVED_HOME/.local/bin/lan" 2>/dev/null || true
    log_ok "Đã gỡ bỏ 'lan' khỏi hệ thống."
}

# --- CLI Help ---
show_help() {
    local cmd; cmd="$(basename "$0")"
    cat << EOF
LAN CLI - Cô lập Terminal & Browser vào mạng LAN ($ETH_DEV)

Cú pháp:
  $cmd <lệnh> [tùy chọn]

Lệnh chính:
  term [--new]         Mở Terminal mạng LAN (--new: mở cửa sổ mới)
  browser [url]        Mở Chromium mạng LAN
  run [--root] <cmd>   Chạy lệnh qua mạng LAN (vd: $cmd run nc ...)
  stop                 Khôi phục card mạng về máy chính

Khác:
  status               Xem IP Host vs LAN
  test                 Kiểm tra kết nối mạng LAN
  install / uninstall  Cài đặt / gỡ bỏ lệnh 'lan' toàn cục
  -h, --help           Hiển thị trợ giúp này
EOF
}

# --- Main Entrypoint ---
COMMAND="${1:-help}"

case "$COMMAND" in
    help|-h|--help)
        show_help
        exit 0
        ;;
    up|init|start|down|stop|revert|restart|exec|run|term|terminal|shell|chrome|chromium|browser|test|check|ping|status|info|install|uninstall)
        ;;
    *)
        log_error "Lệnh không hợp lệ: '$COMMAND'"
        echo ""
        show_help
        exit 1
        ;;
esac

ensure_root "$@"
shift 2>/dev/null || true

case "$COMMAND" in
    up|init|start)           init_netns ;;
    down|stop|revert)        stop_netns ;;
    restart)                 stop_netns; sleep 1; init_netns ;;
    exec|run)                exec_command "$@" ;;
    term|terminal|shell)     open_terminal "$@" ;;
    chrome|chromium|browser) open_chromium "$@" ;;
    test|check|ping)         test_connection ;;
    status|info)             status_network ;;
    install)                 install_cli ;;
    uninstall)               uninstall_cli ;;
esac
