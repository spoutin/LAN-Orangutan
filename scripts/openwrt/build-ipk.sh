#!/bin/sh
set -eu

# Prevent macOS BSD tar from injecting ._* AppleDouble files
export COPYFILE_DISABLE=1

# build-ipk.sh -- Package uapi-traffic-hosts into OpenWrt .ipk and signed .apk packages

RAW_VERSION="${1:-1.0.0}"
DEST_DIR="${2:-dist}"
PKG_NAME="uapi-traffic-hosts"
ARCH="all"

# Normalize version numbers
CLEAN_VER="$(echo "$RAW_VERSION" | sed 's/^v//; s/-.*//')"
IPK_VER="${CLEAN_VER}-1"
APK_VER="${CLEAN_VER}-r1"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_PLUGIN="${SCRIPT_DIR}/traffic.hosts.uc"
KEY_PRIV="${SCRIPT_DIR}/keys/orangutan.rsa"
KEY_PUB="${SCRIPT_DIR}/keys/orangutan.rsa.pub"

if [ ! -f "${SRC_PLUGIN}" ]; then
    echo "Error: ${SRC_PLUGIN} not found" >&2
    exit 1
fi

mkdir -p "${DEST_DIR}"
DEST_DIR="$(cd "${DEST_DIR}" && pwd)"
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'pkg_build')"
trap 'rm -rf "${TMP_DIR}"' EXIT INT TERM

# 1. Prepare payload filesystem
DATA_DIR="${TMP_DIR}/payload"
mkdir -p "${DATA_DIR}/usr/share/uapi/resources"
cp "${SRC_PLUGIN}" "${DATA_DIR}/usr/share/uapi/resources/traffic.hosts.uc"
chmod 644 "${DATA_DIR}/usr/share/uapi/resources/traffic.hosts.uc"

INSTALLED_SIZE=$(du -sk "${DATA_DIR}" | cut -f1)
BUILD_DATE=$(date +%s 2>/dev/null || date -u +%s)

# --- 2. Build .ipk package (for OpenWrt opkg) ---
IPK_DIR="${TMP_DIR}/ipk"
mkdir -p "${IPK_DIR}"
( cd "${DATA_DIR}" && tar -czf "${IPK_DIR}/data.tar.gz" . )

mkdir -p "${IPK_DIR}/control"
cat << EOF > "${IPK_DIR}/control/control"
Package: ${PKG_NAME}
Version: ${IPK_VER}
Depends: uapi, nlbwmon
Section: net
Architecture: ${ARCH}
Maintainer: LAN-Orangutan
Installed-Size: ${INSTALLED_SIZE}
Description: OpenWrt uapi traffic plugin for LAN-Orangutan bandwidth telemetry
EOF

cat << 'EOF' > "${IPK_DIR}/control/postinst"
#!/bin/sh
if [ -f /usr/share/uapi/main.uc ]; then
    if ! grep -q '"traffic:hosts"' /usr/share/uapi/main.uc; then
        sed -i '/const RESOURCES = {/a \	"traffic:hosts": handler.make_collection(load_resource("traffic:hosts")),' /usr/share/uapi/main.uc
    fi
    /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${IPK_DIR}/control/postinst"

cat << 'EOF' > "${IPK_DIR}/control/prerm"
#!/bin/sh
if [ -f /usr/share/uapi/main.uc ]; then
    sed -i '/"traffic:hosts"/d' /usr/share/uapi/main.uc
    /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${IPK_DIR}/control/prerm"

( cd "${IPK_DIR}/control" && tar -czf "${IPK_DIR}/control.tar.gz" . )
echo "2.0" > "${IPK_DIR}/debian-binary"

OUTPUT_IPK="${DEST_DIR}/${PKG_NAME}_${IPK_VER}_${ARCH}.ipk"
( cd "${IPK_DIR}" && tar -czf "${OUTPUT_IPK}" ./debian-binary ./data.tar.gz ./control.tar.gz )
echo "Built OpenWrt .ipk: ${OUTPUT_IPK}"

# --- 3. Build .apk package (for modern OpenWrt apk-tools 3 / APKv3 ADB format) ---
# OpenWrt 24.10+ / 25.12+ uses apk-tools 3 (APKv3 / ADB format).
# Packages are built using `apk mkpkg` and signed with `--sign-key`.

OUTPUT_APK="${DEST_DIR}/${PKG_NAME}-${APK_VER}.apk"
OUTPUT_APK_NOARCH="${DEST_DIR}/${PKG_NAME}_${CLEAN_VER}_noarch.apk"
OUTPUT_APK_ALL="${DEST_DIR}/${PKG_NAME}_${CLEAN_VER}_all.apk"

# Lifecycle scripts for apk package
cat << 'EOF' > "${TMP_DIR}/post-install"
#!/bin/sh
if [ -f /usr/share/uapi/main.uc ]; then
    if ! grep -q '"traffic:hosts"' /usr/share/uapi/main.uc; then
        sed -i '/const RESOURCES = {/a \	"traffic:hosts": handler.make_collection(load_resource("traffic:hosts")),' /usr/share/uapi/main.uc
    fi
    /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${TMP_DIR}/post-install"

cat << 'EOF' > "${TMP_DIR}/pre-deinstall"
#!/bin/sh
if [ -f /usr/share/uapi/main.uc ]; then
    sed -i '/"traffic:hosts"/d' /usr/share/uapi/main.uc
    /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${TMP_DIR}/pre-deinstall"

BUILD_APK_SUCCESS=0

if command -v apk >/dev/null 2>&1 && apk mkpkg --help >/dev/null 2>&1; then
    echo "Building APKv3 using host apk mkpkg..."
    SIGN_ARGS=""
    if [ -f "${KEY_PRIV}" ]; then
        SIGN_ARGS="--sign-key ${KEY_PRIV}"
    fi

    # shellcheck disable=SC2086
    apk ${SIGN_ARGS} mkpkg \
        --info "name:${PKG_NAME}" \
        --info "version:${APK_VER}" \
        --info "description:OpenWrt uapi traffic plugin for LAN-Orangutan bandwidth telemetry" \
        --info "arch:noarch" \
        --info "origin:${PKG_NAME}" \
        --info "url:https://github.com/spoutin/LAN-Orangutan" \
        --info "maintainer:LAN-Orangutan" \
        --info "depends:uapi nlbwmon" \
        --script "post-install:${TMP_DIR}/post-install" \
        --script "pre-deinstall:${TMP_DIR}/pre-deinstall" \
        --files "${DATA_DIR}" \
        --output "${OUTPUT_APK}"

    if [ -f "${KEY_PUB}" ]; then
        VERIFY_KEY_DIR="${TMP_DIR}/verify-keys"
        mkdir -p "${VERIFY_KEY_DIR}"
        cp "${KEY_PUB}" "${VERIFY_KEY_DIR}/"
        apk --keys-dir "${VERIFY_KEY_DIR}" verify "${OUTPUT_APK}"
    fi
    BUILD_APK_SUCCESS=1

elif command -v docker >/dev/null 2>&1; then
    echo "Building APKv3 using Docker (alpine:edge apk mkpkg)..."
    docker run --rm \
        -v "${TMP_DIR}:/tmp/pkg:rw" \
        -v "${SCRIPT_DIR}/keys:/keys:ro" \
        alpine:edge sh -eu -c '
            apk add --no-cache apk-tools-static >/dev/null 2>&1 || apk add --no-cache apk-tools >/dev/null 2>&1
            APK_BIN="apk"
            if command -v apk.static >/dev/null 2>&1; then
                APK_BIN="apk.static"
            fi
            SIGN_ARGS=""
            if [ -f /keys/orangutan.rsa ]; then
                SIGN_ARGS="--sign-key /keys/orangutan.rsa"
            fi

            ${APK_BIN} ${SIGN_ARGS} mkpkg \
                --info "name:'"${PKG_NAME}"'" \
                --info "version:'"${APK_VER}"'" \
                --info "description:OpenWrt uapi traffic plugin for LAN-Orangutan bandwidth telemetry" \
                --info "arch:noarch" \
                --info "origin:'"${PKG_NAME}"'" \
                --info "url:https://github.com/spoutin/LAN-Orangutan" \
                --info "maintainer:LAN-Orangutan" \
                --info "depends:uapi nlbwmon" \
                --script "post-install:/tmp/pkg/post-install" \
                --script "pre-deinstall:/tmp/pkg/pre-deinstall" \
                --files /tmp/pkg/payload \
                --output "/tmp/pkg/'"${PKG_NAME}-${APK_VER}.apk"'"

            if [ -f /keys/orangutan.rsa.pub ]; then
                mkdir -p /tmp/verify-keys
                cp /keys/orangutan.rsa.pub /tmp/verify-keys/
                echo "Verifying built APK signature against orangutan.rsa.pub..."
                ${APK_BIN} --keys-dir /tmp/verify-keys verify "/tmp/pkg/'"${PKG_NAME}-${APK_VER}.apk"'"
            fi
            chmod 644 "/tmp/pkg/'"${PKG_NAME}-${APK_VER}.apk"'"
        '

    cp "${TMP_DIR}/${PKG_NAME}-${APK_VER}.apk" "${OUTPUT_APK}"
    BUILD_APK_SUCCESS=1
else
    echo "Warning: Neither 'apk mkpkg' nor 'docker' is available. APKv3 build skipped." >&2
fi

if [ "${BUILD_APK_SUCCESS}" -eq 1 ]; then
    cp "${OUTPUT_APK}" "${OUTPUT_APK_NOARCH}"
    cp "${OUTPUT_APK}" "${OUTPUT_APK_ALL}"
    if [ -f "${KEY_PUB}" ]; then
        cp "${KEY_PUB}" "${DEST_DIR}/$(basename "${KEY_PUB}")"
    fi
    echo "Built OpenWrt APKv3: ${OUTPUT_APK} (and ${OUTPUT_APK_NOARCH}, ${OUTPUT_APK_ALL})"
fi
