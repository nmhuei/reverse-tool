#!/usr/bin/env bash
# ==============================================================================
# LAN Network Manager - Antigravity
# Tách biệt 100% mạng LAN (enp2s0) và WLAN/4G (wlo1) bằng Network Namespace
# ==============================================================================

NS_NAME="lan_ns"
ETH_DEV="enp2s0"

# Lưu lại các biến môi trường đồ họa và user trước khi sudo
SAVED_DISPLAY="${ORIG_DISPLAY:-${DISPLAY:-:0}}"
SAVED_USER="${ORIG_USER:-${SUDO_USER:-$USER}}"
[ "$SAVED_USER" = "root" ] && SAVED_USER="undertaker"
SAVED_HOME=$(getent passwd "$SAVED_USER" | cut -d: -f6)
SAVED_XAUTH="${ORIG_XAUTH:-${XAUTHORITY:-$SAVED_HOME/.Xauthority}}"
if [ ! -f "$SAVED_XAUTH" ]; then
    FOUND_XAUTH=$(ls -t /run/user/1000/xauth* 2>/dev/null | head -n 1)
    [ -n "$FOUND_XAUTH" ] && SAVED_XAUTH="$FOUND_XAUTH"
fi
SAVED_WAYLAND="${ORIG_WAYLAND:-${WAYLAND_DISPLAY:-wayland-0}}"
SAVED_XDG_RUNTIME="${ORIG_XDG_RUNTIME:-${XDG_RUNTIME_DIR:-/run/user/1000}}"

REAL_USER="$SAVED_USER"
REAL_HOME="$SAVED_HOME"

# Yêu cầu quyền root và truyền lại các biến môi trường
ensure_root() {
    if [ "$EUID" -ne 0 ]; then
        exec sudo ORIG_DISPLAY="$SAVED_DISPLAY" \
                  ORIG_XAUTH="$SAVED_XAUTH" \
                  ORIG_USER="$SAVED_USER" \
                  ORIG_WAYLAND="$SAVED_WAYLAND" \
                  ORIG_XDG_RUNTIME="$SAVED_XDG_RUNTIME" \
                  "$0" "$@"
    fi
}

# Cập nhật file cấu hình DNS riêng biệt cho namespace LAN
setup_dns() {
    mkdir -p "/etc/netns/$NS_NAME"
    cat << 'EOF' > "/etc/netns/$NS_NAME/resolv.conf"
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 192.168.1.1
nameserver 9.9.9.9
EOF
}

# 1. Khởi tạo Network Namespace cho card LAN
init_netns() {
    setup_dns

    # Trường hợp 1: Card đã nằm trong namespace và đã có IP
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        if ip netns exec "$NS_NAME" ip link show "$ETH_DEV" >/dev/null 2>&1; then
            ip netns exec "$NS_NAME" ip link set lo up 2>/dev/null || true
            ip netns exec "$NS_NAME" ip link set "$ETH_DEV" up 2>/dev/null || true
            local cur_ip
            cur_ip=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
            if [ -n "$cur_ip" ]; then
                if ! ip netns exec "$NS_NAME" ip route show default 2>/dev/null | grep -q "default"; then
                    ip netns exec "$NS_NAME" ip route add default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
                fi
                return 0
            fi
        fi
    fi

    echo -e "\033[1;34m[*] Dang thiet lap Network Namespace '$NS_NAME' cho card $ETH_DEV...\033[0m"

    # Trường hợp 2: Kiểm tra xem card có bị kẹt bởi tiến trình cũ không
    if ! ip link show "$ETH_DEV" >/dev/null 2>&1 && ! (ip netns list 2>/dev/null | grep -qw "$NS_NAME" && ip netns exec "$NS_NAME" ip link show "$ETH_DEV" >/dev/null 2>&1); then
        echo -e "\033[1;33m[*] Don dep tien trinh cu dang giu card LAN...\033[0m"
        pkill -f "chromium-lan" 2>/dev/null || true
        sleep 0.5
    fi

    local HOST_IP=""
    local HOST_GW=""

    # Nếu card đang ở ngoài máy chính (host)
    if ip link show "$ETH_DEV" >/dev/null 2>&1; then
        HOST_IP=$(ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
        HOST_GW=$(ip route show dev "$ETH_DEV" 2>/dev/null | grep default | awk '{print $3}')

        # Yêu cầu NetworkManager ngừng can thiệp vào card LAN
        nmcli device disconnect "$ETH_DEV" >/dev/null 2>&1 || true
        nmcli device set "$ETH_DEV" managed no >/dev/null 2>&1 || true
        ip link set dev "$ETH_DEV" down 2>/dev/null || true
    fi

    # Tạo namespace nếu chưa tồn tại
    ip netns add "$NS_NAME" 2>/dev/null || true
    setup_dns

    # Đưa card vào namespace
    if ip link show "$ETH_DEV" >/dev/null 2>&1; then
        ip link set "$ETH_DEV" netns "$NS_NAME" 2>/dev/null || true
    fi

    # Kích hoạt loopback và card LAN trong namespace
    ip netns exec "$NS_NAME" ip link set lo up 2>/dev/null || true
    ip netns exec "$NS_NAME" ip link set "$ETH_DEV" up 2>/dev/null || true

    # Nếu trước đó đã có IP/Gateway trên host, khôi phục ngay lập tức để không mất thời gian chờ
    if [ -n "$HOST_IP" ]; then
        ip netns exec "$NS_NAME" ip addr replace "$HOST_IP" dev "$ETH_DEV" 2>/dev/null || true
        [ -n "$HOST_GW" ] && ip netns exec "$NS_NAME" ip route replace default via "$HOST_GW" dev "$ETH_DEV" 2>/dev/null || true
    fi

    # Chạy dhcpcd ngầm (-C resolv.conf để không ghi đè DNS độc lập)
    echo -e "\033[1;34m[*] Dang xin IP dong (DHCP) cho $ETH_DEV...\033[0m"
    ip netns exec "$NS_NAME" dhcpcd -C resolv.conf -4 -b "$ETH_DEV" >/dev/null 2>&1 || true

    # Chờ nhận IP
    local IP_INFO=""
    for i in {1..6}; do
        IP_INFO=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
        [ -n "$IP_INFO" ] && break
        sleep 0.5
    done

    # Nếu router chưa trả DHCP kịp thời, gán IP dự phòng để thông mạng ngay
    if [ -z "$IP_INFO" ]; then
        ip netns exec "$NS_NAME" ip addr replace 192.168.1.13/24 dev "$ETH_DEV" 2>/dev/null || true
        ip netns exec "$NS_NAME" ip route replace default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
        IP_INFO="192.168.1.13/24"
    fi

    # Đảm bảo default gateway tồn tại
    if ! ip netns exec "$NS_NAME" ip route show default 2>/dev/null | grep -q "default"; then
        ip netns exec "$NS_NAME" ip route add default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
    fi

    echo -e "\033[1;32m[+] Khoi tao mang LAN thanh cong!\033[0m"
    echo -e "\033[1;32m    -> IP LAN nhan duoc: $IP_INFO\033[0m"
}

# 2. Mở Terminal LAN độc lập
open_terminal() {
    init_netns
    setup_dns

    # Cấp quyền X11
    xhost +SI:localuser:"$REAL_USER" >/dev/null 2>&1 || xhost +local: >/dev/null 2>&1 || true

    echo -e "\033[1;32m[+] Dang vao Terminal mang LAN ($ETH_DEV)...\033[0m"
    echo -e "\033[1;36m    -> DISPLAY: $SAVED_DISPLAY\033[0m"

    ip netns exec "$NS_NAME" sudo -u "$REAL_USER" -H \
        bash -c "
            export DISPLAY='$SAVED_DISPLAY'
            export XAUTHORITY='$SAVED_XAUTH'
            export WAYLAND_DISPLAY='$SAVED_WAYLAND'
            export XDG_RUNTIME_DIR='$SAVED_XDG_RUNTIME'
            PROMPT_COMMAND='PS1=\"\[\033[1;32m\][LAN-NETNS:\u@\h \W]\$ \[\033[0m\]\"; unset PROMPT_COMMAND'
            echo -e '\033[1;32m=============================================================\033[0m'
            echo -e '\033[1;32m   BAN DANG O TRONG TERMINAL MANG LAN ($ETH_DEV)            \033[0m'
            echo -e '\033[1;36m   - Moi ket noi (curl, ping, chromium...) deu di qua LAN.    \033[0m'
            echo -e '\033[1;33m   - Go \"exit\" de thoat va quay lai Menu chinh.              \033[0m'
            echo -e '\033[1;32m=============================================================\033[0m\n'
            exec bash -i
        "
}

# 3. Mở Chromium LAN độc lập (Hoàn toàn miễn nhiễm khi đổi mạng Wi-Fi/4G trên máy)
open_chromium() {
    init_netns
    setup_dns

    # Cấp quyền kết nối X11
    xhost +SI:localuser:"$REAL_USER" >/dev/null 2>&1 || xhost +local: >/dev/null 2>&1 || true

    local LAN_USER_DATA="$REAL_HOME/.config/chromium-lan"
    mkdir -p "$LAN_USER_DATA" 2>/dev/null || true
    chown -R "$REAL_USER:$REAL_USER" "$LAN_USER_DATA" 2>/dev/null || true

    # Xóa file lock cũ để tránh bị trỏ nhầm vào tiến trình Chromium cũ bị kẹt
    rm -f "$LAN_USER_DATA/Singleton"* 2>/dev/null || true

    local TARGET_URL="${1:-https://whatismyip.com}"

    echo -e "\033[1;32m[+] Dang khoi dong Chromium mang LAN ($ETH_DEV)...\033[0m"
    echo -e "\033[1;34m    -> Profile rieng: $LAN_USER_DATA\033[0m"
    echo -e "\033[1;34m    -> Chế độ DNS: DoH Cloudflare (Chống đơ/mất mạng khi máy đổi Wi-Fi/4G)\033[0m"

    ip netns exec "$NS_NAME" sudo -u "$REAL_USER" -H \
        DISPLAY="$SAVED_DISPLAY" \
        XAUTHORITY="$SAVED_XAUTH" \
        WAYLAND_DISPLAY="$SAVED_WAYLAND" \
        XDG_RUNTIME_DIR="$SAVED_XDG_RUNTIME" \
        chromium \
        --user-data-dir="$LAN_USER_DATA" \
        --class=chromium-lan \
        --no-first-run \
        --no-default-browser-check \
        --enable-features=DnsOverHttps \
        --dns-over-https-mode=secure \
        --dns-over-https-templates="https://chrome.cloudflare-dns.com/dns-query" \
        "$TARGET_URL" >/tmp/lan_chromium.log 2>&1 &

    echo -e "\033[1;32m[+] Chromium LAN da khoi dong thanh cong!\033[0m"
    echo -e "\033[1;30m    (Neu muon dong Chromium LAN, chon muc so 6 trong Menu)\033[0m"
}

# 4. Kiểm tra chẩn đoán kết nối mạng LAN
test_connection() {
    init_netns
    setup_dns
    echo -e "\n\033[1;36m================ KIEM TRA KET NOI LAN ================\033[0m"

    # 1. Kiểm tra IP của enp2s0
    local LAN_IP
    LAN_IP=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
    if [ -z "$LAN_IP" ]; then
        echo -e "\033[1;31m[!] Card $ETH_DEV CHUA CO DIA CHI IP!\033[0m (Kiem tra xem da cam day LAN chua)"
        return 1
    fi
    echo -e "\033[1;32m[1] IP card LAN: $LAN_IP (OK)\033[0m"

    # 2. Kiểm tra Gateway
    local GW
    GW=$(ip netns exec "$NS_NAME" ip route show default 2>/dev/null | awk '{print $3}')
    if [ -z "$GW" ]; then
        echo -e "\033[1;33m[!] Tu dong gan Gateway 192.168.1.1 cho LAN...\033[0m"
        ip netns exec "$NS_NAME" ip route add default via 192.168.1.1 dev "$ETH_DEV" 2>/dev/null || true
        GW="192.168.1.1"
    fi
    echo -e "\033[1;32m[2] Gateway LAN: $GW\033[0m"

    # 3. Ping thử Gateway (Router mạng LAN)
    echo -n "[3] Ping thu Gateway ($GW)... "
    if ip netns exec "$NS_NAME" ping -c 2 -W 2 "$GW" >/dev/null 2>&1; then
        echo -e "\033[1;32mTHANH CONG (Noi bo LAN thong)\033[0m"
    else
        echo -e "\033[1;31mTHAT BAI (Khong ping duoc router LAN!)\033[0m"
    fi

    # 4. Ping thử Internet trực tiếp qua IP (8.8.8.8)
    echo -n "[4] Ping thu Internet IP (8.8.8.8)... "
    if ip netns exec "$NS_NAME" ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo -e "\033[1;32mTHANH CONG (Internet LAN thong)\033[0m"
    else
        echo -e "\033[1;31mTHAT BAI (Router LAN chua co Internet ra ngoai!)\033[0m"
    fi

    # 5. Kiểm tra phân giải tên miền (DNS)
    echo -n "[5] Phan giai ten mien DNS (google.com)... "
    if ip netns exec "$NS_NAME" ping -c 1 -W 3 google.com >/dev/null 2>&1; then
        echo -e "\033[1;32mTHANH CONG (DNS hoat dong tot)\033[0m"
    else
        echo -e "\033[1;31mTHAT BAI (Loi DNS hoac bi chan)\033[0m"
    fi

    # 6. Lấy Public IP qua card LAN
    echo -n "[6] Lay Public IP qua card LAN... "
    local PUB_IP
    PUB_IP=$(ip netns exec "$NS_NAME" curl -s --max-time 4 https://api.ipify.org 2>/dev/null || true)
    if [ -n "$PUB_IP" ]; then
        echo -e "\033[1;32mTHANH CONG -> Public IP LAN: $PUB_IP\033[0m"
    else
        echo -e "\033[1;33mKhong lay duoc Public IP (curl timeout hoac chua thong web)\033[0m"
    fi

    echo -e "\033[1;36m======================================================\033[0m\n"
}

# 5. Xem trạng thái mạng so sánh giữa Host (WLAN/4G) và LAN
status_network() {
    echo -e "\n\033[1;36m================ TRANG THAI MANG SO SANH ================\033[0m"
    echo -e "\033[1;33m[1] MANG MAC DINH CUA MAY (WLAN / 4G Hotspot - App binh thuong):\033[0m"
    ip -4 -br a show dev wlo1 2>/dev/null || ip -4 -br a
    echo -n "Default Gateway Host: "
    ip route show default 2>/dev/null | awk '{print $3}' || echo "Chua co default route"
    local HOST_PUB
    HOST_PUB=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || true)
    [ -n "$HOST_PUB" ] && echo -e "Public IP Host:       \033[1;32m$HOST_PUB\033[0m"

    echo -e "\n\033[1;33m[2] MANG LAN TACH BIET (Namespace '$NS_NAME' - Chromium / Terminal LAN):\033[0m"
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        ip netns exec "$NS_NAME" ip -4 -br a 2>/dev/null
        echo -n "Default Gateway LAN:  "
        ip netns exec "$NS_NAME" ip route show default 2>/dev/null | awk '{print $3}' || echo "Chua nhan duoc gateway"
        local LAN_PUB
        LAN_PUB=$(ip netns exec "$NS_NAME" curl -s --max-time 3 https://api.ipify.org 2>/dev/null || true)
        [ -n "$LAN_PUB" ] && echo -e "Public IP LAN:        \033[1;32m$LAN_PUB\033[0m"
    else
        echo "Mang LAN namespace chua duoc bat."
    fi
    echo -e "\033[1;36m=========================================================\033[0m\n"
}

# 6. Dừng và khôi phục card LAN về hệ thống chính
stop_netns() {
    echo -e "\033[1;33m[*] Dang dong ung dung va khoi phuc card $ETH_DEV ve lai he thong chinh...\033[0m"

    # 1. Tắt Chromium LAN nếu đang mở
    pkill -f "chromium-lan" 2>/dev/null || true
    rm -f "$REAL_HOME/.config/chromium-lan/Singleton"* 2>/dev/null || true

    # 2. Dừng DHCP và đưa card về host
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        ip netns exec "$NS_NAME" dhcpcd -k "$ETH_DEV" >/dev/null 2>&1 || true
        ip netns exec "$NS_NAME" ip link set "$ETH_DEV" netns 1 2>/dev/null || true
        ip netns del "$NS_NAME" 2>/dev/null || true
    fi

    # 3. Kích hoạt lại card trên máy chính cho NetworkManager quản lý
    ip link set "$ETH_DEV" up 2>/dev/null || true
    nmcli device set "$ETH_DEV" managed yes 2>/dev/null || true
    nmcli device connect "$ETH_DEV" 2>/dev/null || true

    echo -e "\033[1;32m[+] Da khoi phuc hoan toan ve trang thai binh thuong!\033[0m"
}

# Menu điều khiển tương tác
menu() {
    init_netns
    while true; do
        echo -e "\n\033[1;35m--- BAN DIEU KHIEN MANG LAN ($ETH_DEV) ---\033[0m"
        echo "1) Mo Terminal dung mang LAN"
        echo "2) Mo Chromium dung mang LAN"
        echo "3) Kiem tra ket noi Internet LAN (Ping, DNS & Public IP)"
        echo "4) Xem IP va trang thai mang so sanh (WLAN vs LAN)"
        echo "5) Lam moi IP LAN (Renew DHCP)"
        echo "6) Tat & Khoi phuc card LAN ve binh thuong"
        echo "0) Thoat menu"
        echo -n "Chon [0-6]: "
        read -r choice
        case "$choice" in
            1) open_terminal ;;
            2) open_chromium ;;
            3) test_connection ;;
            4) status_network ;;
            5)
               echo -e "\033[1;34m[*] Dang lam moi IP qua DHCP cho $ETH_DEV...\033[0m"
               setup_dns
               ip netns exec "$NS_NAME" dhcpcd -k "$ETH_DEV" 2>/dev/null || true
               sleep 0.5
               ip netns exec "$NS_NAME" dhcpcd -C resolv.conf -4 -b "$ETH_DEV" 2>/dev/null || true
               sleep 1
               test_connection
               ;;
            6) stop_netns; break ;;
            0) break ;;
            *) echo "Lua chon khong hop le!" ;;
        esac
    done
}

# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================
ensure_root "$@"

case "$1" in
    term|terminal)
        open_terminal
        ;;
    chrome|chromium)
        shift
        open_chromium "$@"
        ;;
    test|ping|check)
        test_connection
        ;;
    status)
        status_network
        ;;
    init|up|start)
        init_netns
        ;;
    stop|down|revert)
        stop_netns
        ;;
    *)
        menu
        ;;
esac
