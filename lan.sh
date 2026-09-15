#!/usr/bin/env bash
# ==============================================================================
# LAN Network Manager - Antigravity
# Tách biệt 100% mạng LAN (eth0) và WLAN (wlan0) bằng Network Namespace
# ==============================================================================

NS_NAME="lan_ns"
ETH_DEV="eth0"

# Lưu lại các biến môi trường đồ họa (X11) của user trước khi sudo
SAVED_DISPLAY="${ORIG_DISPLAY:-${DISPLAY:-:0.0}}"
SAVED_USER="${ORIG_USER:-${SUDO_USER:-$USER}}"
[ "$SAVED_USER" = "root" ] && SAVED_USER="dell"
SAVED_HOME=$(getent passwd "$SAVED_USER" | cut -d: -f6)
SAVED_XAUTH="${ORIG_XAUTH:-${XAUTHORITY:-$SAVED_HOME/.Xauthority}}"

REAL_USER="$SAVED_USER"
REAL_HOME="$SAVED_HOME"

# Yêu cầu quyền root và truyền lại biến DISPLAY/XAUTHORITY
ensure_root() {
    if [ "$EUID" -ne 0 ]; then
        exec sudo ORIG_DISPLAY="$SAVED_DISPLAY" ORIG_XAUTH="$SAVED_XAUTH" ORIG_USER="$SAVED_USER" "$0" "$@"
    fi
}

# Cập nhật DNS cho namespace (bắt buộc dùng DNS công cộng để không bị rò sang DNS của Wi-Fi)
setup_dns() {
    mkdir -p "/etc/netns/$NS_NAME"
    cat << 'EOF' > "/etc/netns/$NS_NAME/resolv.conf"
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF
}

# 1. Khởi tạo Network Namespace cho LAN
init_netns() {
    # Luôn đảm bảo file DNS của netns có đầy đủ nameserver
    setup_dns

    # Kiểm tra xem eth0 đã ở trong namespace chưa
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME" && ip netns exec "$NS_NAME" ip link show "$ETH_DEV" >/dev/null 2>&1; then
        return 0
    fi

    echo -e "\033[1;34m[*] Dang thiet lap Network Namespace '$NS_NAME' cho card $ETH_DEV...\033[0m"
    
    # Tạo namespace nếu chưa có
    ip netns add "$NS_NAME" 2>/dev/null || true
    setup_dns

    # Đưa card eth0 vào namespace (nếu nó vẫn ở ngoài host)
    if ip link show "$ETH_DEV" >/dev/null 2>&1; then
        ip link set "$ETH_DEV" netns "$NS_NAME"
    fi

    # Kích hoạt loopback và card eth0
    ip netns exec "$NS_NAME" ip link set lo up
    ip netns exec "$NS_NAME" ip link set "$ETH_DEV" up

    # Khởi chạy dhcpcd ngầm (-C resolv.conf để KHÔNG ghi đè DNS đã cấu hình)
    echo -e "\033[1;34m[*] Dang xin IP dong (DHCP) cho $ETH_DEV...\033[0m"
    ip netns exec "$NS_NAME" dhcpcd -C resolv.conf -4 -b "$ETH_DEV" >/dev/null 2>&1 || true

    # Chờ tối đa 3 giây để nhận IP
    for i in {1..6}; do
        IP_INFO=$(ip netns exec "$NS_NAME" ip -4 -br a show "$ETH_DEV" 2>/dev/null | awk '{print $3}')
        if [ -n "$IP_INFO" ]; then
            break
        fi
        sleep 0.5
    done

    echo -e "\033[1;32m[+] Khoi tao mang LAN thanh cong!\033[0m"
    if [ -n "$IP_INFO" ]; then
        echo -e "\033[1;32m    -> IP LAN nhan duoc: $IP_INFO\033[0m"
    else
        echo -e "\033[1;33m    -> Chua nhan duoc IP (kiem tra lai xem da cam day LAN chua).\033[0m"
    fi
}

# 2. Mở Terminal LAN (có đầy đủ môi trường X11 để mở app đồ họa như Chromium)
open_terminal() {
    init_netns
    setup_dns
    
    # Cấp quyền X11
    xhost +SI:localuser:"$REAL_USER" >/dev/null 2>&1 || xhost +local: >/dev/null 2>&1 || true

    echo -e "\033[1;32m[+] Dang vao Terminal mang LAN ($ETH_DEV)...\033[0m"
    echo -e "\033[1;36m    -> DISPLAY: $SAVED_DISPLAY\033[0m"
    echo -e "\033[1;30m    (Tat ca lenh va app do hoa nhu 'chromium' trong day se di 100% qua LAN. Go 'exit' de thoat)\033[0m\n"
    
    # Mở shell với biến DISPLAY và XAUTHORITY đầy đủ
    ip netns exec "$NS_NAME" sudo -u "$REAL_USER" -H \
        env DISPLAY="$SAVED_DISPLAY" XAUTHORITY="$SAVED_XAUTH" \
        bash -c "export DISPLAY='$SAVED_DISPLAY'; export XAUTHORITY='$SAVED_XAUTH'; exec bash -i"
}

# 3. Mở Chromium LAN
open_chromium() {
    init_netns
    setup_dns
    
    # Cấp quyền kết nối X11
    xhost +SI:localuser:"$REAL_USER" >/dev/null 2>&1 || xhost +local: >/dev/null 2>&1 || true

    echo -e "\033[1;32m[+] Dang khoi dong Chromium chay qua mang LAN ($ETH_DEV)...\033[0m"
    ip netns exec "$NS_NAME" sudo -u "$REAL_USER" -H \
        DISPLAY="$SAVED_DISPLAY" \
        XAUTHORITY="$SAVED_XAUTH" \
        chromium "$@" >/dev/null 2>&1 &
    echo -e "\033[1;32m[+] Chromium da duoc mo o che do chay ngam!\033[0m"
}

# 4. Kiểm tra chẩn đoán kết nối mạng LAN
test_connection() {
    init_netns
    setup_dns
    echo -e "\n\033[1;36m================ KIEM TRA KET NOI LAN ================\033[0m"
    
    # 1. Kiểm tra IP của eth0
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
        echo -e "\033[1;31m[!] CHUA CO DEFAULT GATEWAY cho LAN!\033[0m"
        return 1
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
    echo -e "\033[1;36m======================================================\033[0m\n"
}

# 5. Xem trạng thái mạng
status_network() {
    echo -e "\n\033[1;36m================ TRANG THAI MANG ================\033[0m"
    echo -e "\033[1;33m[1] MANG MAC DINH CUA MAY (WLAN - Tat ca app thuong):\033[0m"
    ip -4 -br a show dev wlan0 2>/dev/null || ip -4 -br a
    echo "Default Gateway:"
    ip route show default 2>/dev/null || echo "Chua co default route"

    echo -e "\n\033[1;33m[2] MANG LAN TACH BIET (Namespace '$NS_NAME'):\033[0m"
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        ip netns exec "$NS_NAME" ip -4 -br a 2>/dev/null
        echo "Default Gateway LAN:"
        ip netns exec "$NS_NAME" ip route show default 2>/dev/null || echo "Chua nhan duoc gateway"
    else
        echo "Mang LAN namespace chua duoc bat."
    fi
    echo -e "\033[1;36m=================================================\033[0m\n"
}

# 6. Dừng và khôi phục về trạng thái bình thường
stop_netns() {
    echo -e "\033[1;33m[*] Dang khoi phuc card $ETH_DEV ve lai he thong chinh...\033[0m"
    if ip netns list 2>/dev/null | grep -qw "$NS_NAME"; then
        # Dừng dhcpcd trong namespace
        ip netns exec "$NS_NAME" dhcpcd -k "$ETH_DEV" >/dev/null 2>&1 || true
        # Đưa card eth0 về namespace chính (init netns 1)
        ip netns exec "$NS_NAME" ip link set "$ETH_DEV" netns 1 2>/dev/null || true
        # Xóa namespace
        ip netns del "$NS_NAME" 2>/dev/null || true
    fi
    # Kích hoạt lại card trên máy chính
    ip link set "$ETH_DEV" up 2>/dev/null || true
    systemctl restart NetworkManager 2>/dev/null || true
    echo -e "\033[1;32m[+] Da khoi phuc hoan toan ve trang thai binh thuong!\033[0m"
}

# Menu tương tác khi chạy không có tham số
menu() {
    init_netns
    while true; do
        echo -e "\n\033[1;35m--- BAN DIEU KHIEN MANG LAN ($ETH_DEV) ---\033[0m"
        echo "1) Mo Terminal dung mang LAN"
        echo "2) Mo Chromium dung mang LAN"
        echo "3) Kiem tra ket noi Internet LAN (Ping test & DNS test)"
        echo "4) Xem IP va trang thai mang (WLAN vs LAN)"
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
               echo "[*] Dang lam moi IP qua DHCP..."
               setup_dns
               ip netns exec "$NS_NAME" dhcpcd -C resolv.conf -n "$ETH_DEV" 2>/dev/null || true
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
