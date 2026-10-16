# OpenWrt Traffic & Bandwidth Monitoring

LAN-Orangutan integrates with OpenWrt to track WAN and per-device traffic volume using `nlbwmon` (Netlink Bandwidth Monitor) and the router's native `uapi` REST service.

---

## 1. Prerequisites on OpenWrt

1. **Install and start `nlbwmon`**:
   ```sh
   opkg update
   opkg install nlbwmon
   /etc/init.d/nlbwmon enable
   /etc/init.d/nlbwmon start
   ```
2. Verify `nlbw` runs:
   ```sh
   nlbw -c json
   ```

---

## 2. Install the `uapi` Plugin on OpenWrt

### Method A: One-Command Installer (Recommended)

Run this single command via SSH on your OpenWrt router:

```sh
curl -sSL https://raw.githubusercontent.com/spoutin/LAN-Orangutan/main/scripts/openwrt/install.sh | sh
```
*(Or if curl isn't installed: `uclient-fetch -qO - https://raw.githubusercontent.com/spoutin/LAN-Orangutan/main/scripts/openwrt/install.sh | sh`)*

This script automatically:
1. Installs and starts `nlbwmon` if not already running.
2. Installs `/usr/share/uapi/resources/traffic.hosts.uc`.
3. Registers `"traffic:hosts"` into `/usr/share/uapi/main.uc`.
4. Restarts `uhttpd` so the API is live immediately.

To uninstall at any time:
```sh
curl -sSL https://raw.githubusercontent.com/spoutin/LAN-Orangutan/main/scripts/openwrt/uninstall.sh | sh
```

---

### Method B: Install via LuCI Web GUI (.apk or .ipk package)

1. *(Optional one-time setup for LuCI)*: To allow LuCI to install signed `.apk` packages without untrusted signature warnings, trust the Orangutan release public key:
   ```sh
   uclient-fetch -qO /etc/apk/keys/orangutan.rsa.pub \
     "https://github.com/spoutin/LAN-Orangutan/releases/download/<version>/orangutan.rsa.pub"
   ```
2. Download the package matching your OpenWrt package manager from [GitHub Releases](https://github.com/spoutin/LAN-Orangutan/releases):
   - **For modern OpenWrt (`apk`-based, 24.10+ / 25.x):** download `uapi-traffic-hosts-<version>-r1.apk` (or `uapi-traffic-hosts_<version>_noarch.apk` / `_all.apk`).
   - **For legacy OpenWrt (`opkg`-based, 23.x / 22.x):** download `uapi-traffic-hosts_<version>-1_all.ipk`.
3. In your OpenWrt LuCI web interface, navigate to **System → Software**.
4. Click the **Upload Package...** button.
5. Select the downloaded file from your computer and click **Upload**.
6. Click **Install**.
   The package installs `/usr/share/uapi/resources/traffic.hosts.uc`, registers `"traffic:hosts"` into `/usr/share/uapi/main.uc`, and restarts `uhttpd` automatically.

---

### Method C: Manual Script Copy

If you prefer copying the script manually via SSH:
   Copy `scripts/openwrt/traffic.hosts.uc` to `/usr/share/uapi/resources/traffic.hosts.uc` on the router.

   Or create it directly on the router via SSH:
   ```sh
   cat << 'EOF' > /usr/share/uapi/resources/traffic.hosts.uc
   let fs = require('fs');

   function get_traffic() {
   	let p = fs.popen("/usr/sbin/nlbw -c json", "r");
   	if (!p) return [];
   	let raw = p.read("all") ?? "";
   	p.close();
   	let parsed = json(raw);
   	if (!parsed || type(parsed.data) != "array" || type(parsed.columns) != "array") return [];

   	let col_map = {};
   	for (let i = 0; i < length(parsed.columns); i++) {
   		col_map[parsed.columns[i]] = i;
   	}
   	let ip_idx = col_map["ip"] ?? -1;
   	let mac_idx = col_map["mac"] ?? -1;
   	let rx_idx = col_map["rx_bytes"] ?? -1;
   	let tx_idx = col_map["tx_bytes"] ?? -1;
   	let conns_idx = col_map["conns"] ?? -1;
   	let proto_idx = col_map["proto"] ?? -1;
   	let port_idx = col_map["port"] ?? -1;
   	let layer7_idx = col_map["layer7"] ?? -1;

   	let items = [];
   	for (let row in parsed.data) {
   		let ip = (ip_idx >= 0) ? row[ip_idx] : null;
   		let mac = (mac_idx >= 0) ? row[mac_idx] : null;
   		if (!ip && !mac) continue;
   		push(items, {
   			id: (mac ? mac : ip) + (proto_idx >= 0 ? ":" + row[proto_idx] : "") + (port_idx >= 0 ? ":" + row[port_idx] : ""),
   			ip: ip,
   			mac: mac,
   			rx_bytes: (rx_idx >= 0) ? int(row[rx_idx]) : 0,
   			tx_bytes: (tx_idx >= 0) ? int(row[tx_idx]) : 0,
   			conns: (conns_idx >= 0) ? int(row[conns_idx]) : 0,
   			proto: (proto_idx >= 0) ? row[proto_idx] : null,
   			port: (port_idx >= 0) ? int(row[port_idx]) : 0,
   			layer7: (layer7_idx >= 0) ? row[layer7_idx] : null,
   		});
   	}
   	return items;
   }

   return {
   	package: "traffic",
   	type: "hosts",
   	id_field: "id",
   	list_fn: function(conn, query) { return get_traffic(); },
   	schema_properties: {
   		id: { type: "string" },
   		ip: { type: "string" },
   		mac: { type: "string" },
   		rx_bytes: { type: "integer" },
   		tx_bytes: { type: "integer" },
   	},
   };
   EOF
   ```

2. **Register the resource in `/usr/share/uapi/main.uc`**:
   Inside `/usr/share/uapi/main.uc`, add the following line inside `const RESOURCES = { ... };`:
   ```ucode
   	"traffic:hosts": handler.make_collection(load_resource("traffic:hosts")),
   ```

3. **Reload `uhttpd`**:
   ```sh
   /etc/init.d/uhttpd restart
   ```

4. **Test with your API token**:
   ```sh
   curl -k -H "Authorization: Bearer <your-token>" "https://<router-ip>/api/v3/traffic/hosts"
   ```

---

## 3. Configure LAN-Orangutan

In `config.ini`:

```ini
[openwrt]
enable = true
url = https://10.5.5.1
api_token = <your-uapi-token>
traffic_monitoring = true
networks = 10.5.5.0/24
```

LAN-Orangutan will periodically query `/api/v3/traffic/hosts` every 60 seconds, compute rate deltas, and display real-time WAN download/upload speeds and byte totals for all devices on configured OpenWrt subnets.
