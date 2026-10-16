#!/bin/sh
set -eu

# build-ipk.sh -- Package uapi-traffic-hosts into an OpenWrt .ipk package

VERSION="${1:-1.0.0-1}"
DEST_DIR="${2:-dist}"
PKG_NAME="uapi-traffic-hosts"
ARCH="all"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_PLUGIN="${SCRIPT_DIR}/traffic.hosts.uc"

if [ ! -f "${SRC_PLUGIN}" ]; then
    echo "Error: ${SRC_PLUGIN} not found" >&2
    exit 1
fi

mkdir -p "${DEST_DIR}"
DEST_DIR="$(cd "${DEST_DIR}" && pwd)"
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'ipk_build')"
trap 'rm -rf "${TMP_DIR}"' EXIT INT TERM

# 1. Prepare data directory (files to install on router)
DATA_DIR="${TMP_DIR}/data"
mkdir -p "${DATA_DIR}/usr/share/uapi/resources"
cp "${SRC_PLUGIN}" "${DATA_DIR}/usr/share/uapi/resources/traffic.hosts.uc"
chmod 644 "${DATA_DIR}/usr/share/uapi/resources/traffic.hosts.uc"

# Pack data.tar.gz
(
    cd "${DATA_DIR}"
    tar -czf "${TMP_DIR}/data.tar.gz" .
)

# 2. Prepare control directory
CONTROL_DIR="${TMP_DIR}/control"
mkdir -p "${CONTROL_DIR}"

INSTALLED_SIZE=$(du -sk "${DATA_DIR}" | cut -f1)

cat << EOF > "${CONTROL_DIR}/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Depends: uapi, nlbwmon
Section: net
Architecture: ${ARCH}
Maintainer: LAN-Orangutan
Installed-Size: ${INSTALLED_SIZE}
Description: OpenWrt uapi traffic plugin for LAN-Orangutan bandwidth telemetry
EOF

cat << 'EOF' > "${CONTROL_DIR}/postinst"
#!/bin/sh
if [ -f /usr/share/uapi/main.uc ]; then
    if ! grep -q '"traffic:hosts"' /usr/share/uapi/main.uc; then
        sed -i '/const RESOURCES = {/a \	"traffic:hosts": handler.make_collection(load_resource("traffic:hosts")),' /usr/share/uapi/main.uc
    fi
    /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${CONTROL_DIR}/postinst"

cat << 'EOF' > "${CONTROL_DIR}/prerm"
#!/bin/sh
if [ -f /usr/share/uapi/main.uc ]; then
    sed -i '/"traffic:hosts"/d' /usr/share/uapi/main.uc
    /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${CONTROL_DIR}/prerm"

# Pack control.tar.gz
(
    cd "${CONTROL_DIR}"
    tar -czf "${TMP_DIR}/control.tar.gz" .
)

# 3. Create debian-binary
echo "2.0" > "${TMP_DIR}/debian-binary"

# 4. Assemble final .ipk archive (tar.gz containing debian-binary, data.tar.gz, control.tar.gz)
OUTPUT_FILE="${DEST_DIR}/${PKG_NAME}_${VERSION}_${ARCH}.ipk"
(
    cd "${TMP_DIR}"
    tar -czf "${OUTPUT_FILE}" ./debian-binary ./data.tar.gz ./control.tar.gz
)

echo "Successfully built OpenWrt package: ${OUTPUT_FILE}"
