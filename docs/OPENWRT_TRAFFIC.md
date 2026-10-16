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

If your OpenWrt router runs `uapi` (the native REST API):

1. **Copy the plugin script**:
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
