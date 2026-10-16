#!/bin/sh
set -e

echo "Installing LAN-Orangutan traffic plugin for OpenWrt uapi..."

# 1. Install nlbwmon if missing
if ! command -v nlbw >/dev/null 2>&1; then
    echo "Installing nlbwmon..."
    if command -v apk >/dev/null 2>&1; then
        apk add nlbwmon
    elif command -v opkg >/dev/null 2>&1; then
        opkg update && opkg install nlbwmon
    fi
fi

# 2. Ensure nlbwmon is enabled and running
/etc/init.d/nlbwmon enable
/etc/init.d/nlbwmon start

# 3. Install traffic.hosts.uc
mkdir -p /usr/share/uapi/resources
if command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -qO /usr/share/uapi/resources/traffic.hosts.uc \
        "https://raw.githubusercontent.com/spoutin/LAN-Orangutan/main/scripts/openwrt/traffic.hosts.uc"
else
    curl -sSL -o /usr/share/uapi/resources/traffic.hosts.uc \
        "https://raw.githubusercontent.com/spoutin/LAN-Orangutan/main/scripts/openwrt/traffic.hosts.uc"
fi
chmod 644 /usr/share/uapi/resources/traffic.hosts.uc

# 4. Register in main.uc if not already present
if [ -f /usr/share/uapi/main.uc ]; then
    if ! grep -q '"traffic:hosts"' /usr/share/uapi/main.uc; then
        sed -i '/const RESOURCES = {/a \	"traffic:hosts": handler.make_collection(load_resource("traffic:hosts")),' /usr/share/uapi/main.uc
    fi
    /etc/init.d/uhttpd restart
fi

echo "Successfully installed! Endpoint is live at /api/v3/traffic/hosts"
