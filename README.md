# reverse-tool

A **Policy-Routing Orchestrator with Daemon** for Linux network segmentation and lab routing in Rust.

`reverse-tool` does not attempt to guess whether an application is an "exploit" or "normal" process. Instead, it deterministically evaluates each connection's **destination**, network topology, user policies, and interface health states. The Linux kernel's Routing Policy Database (RPDB) then automatically steers traffic through the appropriate interface (WAN/LAN/VPN).

---

## Key Principles & Architecture

1. **Never Hijack Default Internet Route**:
   - Table `52000` (custom isolated routing table)
   - RPDB priority `12000` (placed ahead of `main` table `32766`)
   - Table `52000` **never** contains a default route (`0.0.0.0/0`).
   - Normal Internet traffic falls through cleanly to the host's `main` table (Wi-Fi/WAN).
2. **Three Operating Modes**:
   - `auto`: Discovers connected subnets of LAN interfaces and routes them via isolated tables.
   - `manual`: Only routes user-specified targets and subnets.
   - `hybrid` (default): Deterministic precedence order:
     ```text
     Manual exact IP target
             ↓
     Manual exact domain
             ↓
     Manual CIDR
             ↓
     Manual domain suffix (*.lab, ~lab)
             ↓
     Auto-discovered LAN subnets
             ↓
     Default WAN
     ```
3. **Failover with Safety Drop**:
   - Monitored paths follow a hysteresis state machine (`UNKNOWN` -> `HEALTHY` -> `DEGRADED` -> `DOWN` -> `RECOVERING` -> `HEALTHY`).
   - If preferred and fallback lab interfaces fail, the target is **DROPPED** (`DROP`). Lab traffic is **never leaked to the public Internet/WAN**!
4. **Split DNS**:
   - Integrates with NetworkManager (routing domains `~domain`) and `systemd-resolved` per-link routing domains without dirtying `/etc/resolv.conf`.

---

## Workspace Structure

```text
reverse-tool/
├── Cargo.toml
├── config/
│   └── example.toml             # Configuration template
├── systemd/
│   └── reversed.service         # Least-privilege systemd service (CAP_NET_ADMIN)
├── crates/
│   ├── reverse-core/            # Pure models, classifier, policy engine, planner, health SM
│   ├── reverse-linux/           # Linux adapters: Netlink, SO_BINDTODEVICE probe, Split-DNS
│   └── reverse-app/             # Reconciler, state management, Unix socket RPC, CLI commands
└── src/bin/
    ├── reverse-tool.rs          # User CLI
    └── reversed.rs              # Background Daemon
```

---

## Build & Test

```bash
# Build binaries
cargo build --release

# Run unit and integration tests
cargo test --workspace

# Run lint and format checks
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

---

## Usage Guide

### 1. Run Diagnostics (`doctor`)

```bash
reverse-tool doctor
```

Checks Netlink access, capabilities (`CAP_NET_ADMIN`), table availability, default gateway, and DNS backends.

### 2. Discover Network Topology (`scan`)

```bash
reverse-tool scan
```

Scans network interfaces and categorizes roles: `WAN`, `LAN`, `VPN`, `Virtual` (Docker/veth/bridges), and `Loopback`.

### 3. Auto-Detect LAN Subnets & Servers (`autoconfig`)

```bash
# Detect connected LAN subnets and server IPs
reverse-tool autoconfig

# Detect and save directly to configuration file
reverse-tool autoconfig --save

# Detect, save, and immediately apply routing policy
sudo reverse-tool autoconfig --save --apply
```

Automatically inspects connected LAN interfaces, calculates clean network CIDR subnets (e.g. `192.168.56.0/24`), detects gateways, and queries ARP neighbor tables to discover local server IPs.

### 4. Trace Routing Decision (`explain`)

```bash
# Trace a lab IP
reverse-tool -c config/example.toml explain 192.168.56.20

# Trace a lab domain
reverse-tool -c config/example.toml explain victim.malware.lab

# Trace normal Internet traffic
reverse-tool -c config/example.toml explain google.com
```

### 4. Apply Policy (`apply`)

```bash
# Dry-run mode: View diff without modifying kernel routing tables or rules
reverse-tool -c config/example.toml apply --dry-run

# Live apply (requires CAP_NET_ADMIN or root)
sudo reverse-tool -c config/example.toml apply
```

### 5. Running the Background Daemon (`reversed`)

```bash
# Run daemon directly
sudo ./target/release/reversed -c config/example.toml

# Or install systemd service:
sudo cp target/release/reversed /usr/local/bin/
sudo cp target/release/reverse-tool /usr/local/bin/
sudo cp config/example.toml /etc/reverse-tool/config.toml
sudo cp systemd/reversed.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now reversed
```

### 6. Clean Teardown (`reset`)

```bash
sudo reverse-tool reset
```

Removes all custom routes in table `52000` and RPDB priority rule `12000`, cleanly restoring host routing.
