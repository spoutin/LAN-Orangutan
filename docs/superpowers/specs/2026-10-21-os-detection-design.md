# Operating System and Version Detection Design

## Intent and Why

LAN Orangutan currently discovers devices, their vendors (via MAC OUI), open ports, and open services, but does not identify the target operating system or version. Operators looking at network inventory need to know what operating system and release (e.g., Ubuntu 22.04, Windows 11, FreeBSD, macOS) each host is running to assess security postures, plan updates, and quickly spot unexpected or unmanaged systems on the LAN.

Determining the OS and version during discovery requires balancing speed, permission boundaries, and accuracy. Fast subnet discovery sweeps cannot reliably determine an OS version. By integrating dual-mode OS detection—combining active TCP/IP stack fingerprinting (`nmap -O`) and service banner extraction (`nmap -sV`) into Stage 2 deep scans—LAN Orangutan can accurately discover operating systems and versions without slowing down regular discovery or failing in unprivileged environments.

---

## Goals

1. **Dual-Method Detection:** Identify OS family, OS name, and OS version during deep scans by combining active TCP/IP stack fingerprinting (`nmap -O`) and service banner heuristics (`-sV`).
2. **Graceful Degradation:** If root/sudo or `CAP_NET_RAW` privileges are unavailable (such as unprivileged Docker containers or SSH remote gateways without sudo), the scanner must automatically fall back to banner-based detection instead of failing the deep scan.
3. **Persistent Data Model:** Persist `os`, `os_version`, and `os_family` on the `devices` table via SQLite schema migrations, and expose them through the device REST APIs.
4. **Rich Visual Presentation:**
   - **Main Devices Table:** Add a sortable "OS" column that displays an OS family icon (Linux, Windows, Apple, Android, BSD, etc.) followed by the version string. If no icon is available for an OS, fall back cleanly to text. If unprobed or undetected, show an unobtrusive dash (`—`).
   - **Sidebar Drawer:** Add an `OS:` row under device hardware specifications (Vendor, MAC Address) displaying the full OS name and version.
   - **Device Detail Modal:** Display detected operating system details in the read-only technical specs panel.
   - **Searchability:** Allow filtering and searching by OS name or version in the main dashboard search bar.

---

## Non-Goals

- **OS Detection on Regular Scans:** Regular scans (Stage 1 / controller inventory refreshes) will not attempt OS or version detection. They remain lightweight to preserve network performance and avoid high connection states.
- **Active Agent Installation:** Discovery is strictly agentless over the network. No software, SNMP credentials, or SSH logins are required on target endpoints.
- **100% Identification Guarantee:** Firewalled or hardened devices that drop all probes or filter all ports may only report partial or unknown OS data; the system must gracefully represent unknown OS states.

---

## Anti-Goals

- **Scan Failures Due to Missing Privileges:** Deep scans must never fail because `nmap -O` was denied due to missing raw socket permissions. Unprivileged runs must still complete port and service scans normally with banner-derived OS detection.
- **Table Clutter:** The OS column in the main table must remain legible and clean; verbose raw Nmap fingerprint strings must not be dumped into table cells.

---

## Constraints

- **Execution Privileges:** Nmap TCP/IP stack fingerprinting (`-O`) requires raw socket access (`CAP_NET_RAW`, root UID 0, or `sudo`).
- **Remote Gateway Execution:** When deep scans run through remote SSH gateways (`internal/remotescan`), the remote runner may or may not have `sudo` configured in `remotescan.yaml`.
- **Database Migrations:** Schema changes must follow the sequential numbered migration system in `internal/storage/migrations/`.
- **UI Styling & Assets:** The UI must maintain consistency with LAN Orangutan's existing dark/light CSS themes and SVG icon aesthetics.

---

## Technical Design & Architecture

### 1. Scanner & Detection Pipeline (`internal/scanner`)

#### A. Nmap Probing Strategy & Privilege Handling

Deep scan execution currently runs:
`nmap -sV -Pn -p <ports> <timing> -n --max-retries 2 --host-timeout 180s -oX - <ip>`

We will enhance the deep scan arguments:
- When privileged (local root / `CAP_NET_RAW` or remote runner configured with `sudo: true`), append `-O --osscan-limit --osscan-guess`.
  - `--osscan-limit`: Skips OS detection against targets where not at least 1 open and 1 closed TCP port were found, preventing wasted timeouts on completely filtered devices.
  - `--osscan-guess`: Guesses more aggressively when an exact match isn't certain.
- **Privilege Awareness & Caching (Builder Call):**
  - To prevent doubling scan times on unprivileged environments by retrying every host, the scanner checks raw socket capability:
    - For local scans: check `os.Geteuid() == 0` or probe ICMP socket creation. If privileged, run with `-O`. If the first execution fails because root privileges are required, cache `privileged = false` and continue with unprivileged flags.
    - For remote scans: `RemoteRunner` provides `CanRunPrivileged(target string) bool` (backed by the SSH runner's `sudo` setting). If `sudo` is false, omit `-O` upfront.
- If executing unprivileged, omit `-O` and rely on service banners (`-sV`).

#### B. Nmap XML Parsing & OS Resolution

In `parsePortScanResult` (and related XML models):
1. **Parse `<os>` block:**
   - Look for `<osmatch name="..." accuracy="...">`.
   - Look for `<osclass type="..." vendor="..." osfamily="..." osgen="...">`.
2. **Parse `<service>` banner hints:**
   - Check `ostype` attribute on discovered services (e.g. `ostype="Linux"`, `ostype="Windows"`).
   - Inspect service banner details:
     - SSH banner: `OpenSSH 8.9p1 Ubuntu 3ubuntu0.10` -> OS: `Ubuntu`, Version: `22.04` (Jammy), Family: `Linux`.
     - SMB / NetBIOS / RDP banners: Windows build numbers and server editions.
     - Web server banners: `Server: Apache/2.4.41 (Ubuntu)`, `nginx (Debian)`.
3. **Consolidation Logic:**
   - Combine results:
     - If `-O` provided a generic kernel (e.g., `Linux 5.4 - 5.10`) and a service banner provided a specific distro (e.g., `Ubuntu 22.04.4 LTS`), merge them into:
       - `OS`: "Ubuntu Linux"
       - `OSVersion`: "22.04"
       - `OSFamily`: "Linux"
     - If only `-O` matched (e.g. `Windows 11`, `Apple iOS 16`), extract `OS`: "Windows 11", `OSVersion`: "11", `OSFamily`: "Windows".
     - If neither provided high confidence, record the highest-confidence match or leave empty.

### 2. Data Storage & API Models

#### A. SQLite Migration
Add migration `00016_add_os_detection.sql`:
```sql
ALTER TABLE devices ADD COLUMN os TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN os_version TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN os_family TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN custom_os TEXT NOT NULL DEFAULT '';
```

#### B. Types (`internal/types/types.go`)
Extend `types.Device`:
```go
type Device struct {
    ...
    OS        string `json:"os,omitempty"`
    OSVersion string `json:"os_version,omitempty"`
    OSFamily  string `json:"os_family,omitempty"`
    CustomOS  string `json:"custom_os,omitempty"`
}
```

#### C. Storage Updates (`internal/storage/storage.go`)
- Update `GetDevice`, `GetDevices`, `GetAllDevices`, and `UpdateDevice` to read and write the `os`, `os_version`, `os_family`, and `custom_os` columns.
- Update `UpdateDeviceFields` to accept `custom_os` so operators can override the operating system from the UI.
- Ensure deep scan enrichment updates `os`, `os_version`, and `os_family` while leaving `custom_os` untouched. Display logic uses `CustomOS` when non-empty, falling back to `OS`.

#### D. API Updates
- The `/api/devices` and `/api/devices/{ip}` endpoints automatically serialize these fields via `types.Device`.
- `PUT /api/devices/{ip}` handles updating `custom_os` from the edit form.
- When updating or deep scanning a device, the returned payload includes the latest OS and custom OS metadata.

---

### 3. Frontend & User Interface

#### A. Main Devices Table (`internal/web/templates/index.html`)
- **Header:** Add a sortable column `<th class="col-os" data-sort="os" onclick="sortTable('os')">OS <span class="sort-icon">↕</span></th>` positioned between `Vendor` and `Last Seen`.
- **Row Rendering:**
  - Display `device.custom_os` if set; otherwise display the detected OS.
  - Render an OS icon (Linux, Windows, Apple, Android, BSD) if `OSFamily` or the effective OS matches a recognized family.
  - Render the version/name string adjacent to the icon (e.g., `[Linux Icon] Ubuntu 22.04` or `[Windows Icon] 11`).
  - If no icon is available for an esoteric OS, render the plain text name.
  - If empty, render an unobtrusive dash `—`.
- **Search & Sorting:**
  - Update `sortTable('os')` in `app.js` to sort by effective OS name and version.
  - Update table filter/search logic to match on `device.os`, `device.os_version`, and `device.custom_os`.

#### B. Sidebar Drawer
- In `sidebar-spec-list`:
  - Add an `OS:` entry below `Vendor` and `MAC Address`:
    ```html
    <li>
        <span class="spec-label">OS:</span>
        <span class="spec-val" id="sb-os">—</span>
    </li>
    ```
  - In `app.js`, populate `sb-os` with the effective OS name and version (with an override indicator if `custom_os` is set), or `—` if not scanned.

#### C. Device Detail Modal
- In `index.html` within the left spec list:
  - Add `<li><span class="spec-label">Operating System:</span> <span class="spec-val" id="detail-os"></span></li>` (showing detected OS, version, and family).
- In the right-hand edit form:
  - Add an input field for **Custom OS** (`edit-custom-os`) alongside `edit-custom-hostname` and `edit-custom-type`.
  - In `app.js`, wire saving and loading for `custom_os`.

#### D. OS Icons
- Use clean, accessible inline SVGs (or CSS-styled SVG symbols) for primary operating system families:
  - **Linux:** Tux penguin silhouette
  - **Windows:** 4-pane grid
  - **Apple:** Apple logo silhouette (macOS / iOS)
  - **Android:** Android bug silhouette
  - **BSD:** FreeBSD beastie / daemon trident silhouette
  - **Other / Network OS:** Generic terminal / chip icon fallback when text alone isn't preferred

---

## What's Left to the Builder

- The exact dictionary / regex mappings for extracting specific distro versions from SSH (`OpenSSH...`), HTTP Server headers, and SMB banners.
- Tuning the SVG icon paths and sizing (`14px` by `14px`) to match the existing icon design system.
- Unit test fixtures containing sample Nmap XML with `-O` and `-sV` tags for testing parsing across Linux, Windows, macOS, and unprivileged scans.
