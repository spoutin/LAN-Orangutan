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
