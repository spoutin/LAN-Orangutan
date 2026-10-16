#!/bin/sh
set -e

echo "Uninstalling LAN-Orangutan traffic plugin..."

rm -f /usr/share/uapi/resources/traffic.hosts.uc

if [ -f /usr/share/uapi/main.uc ]; then
    sed -i '/"traffic:hosts"/d' /usr/share/uapi/main.uc
    /etc/init.d/uhttpd restart
fi

echo "Successfully uninstalled."
