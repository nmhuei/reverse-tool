use crate::error::LinuxError;
use ipnet::IpNet;
use reverse_core::{Interface, InterfaceRole, Route, RouteType, RpdbRule};
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

#[derive(Default)]
pub struct NetlinkController;

impl NetlinkController {
    pub fn new() -> Self {
        Self
    }

    /// Read all network interfaces from sysfs and procfs
    pub fn get_interfaces(&self) -> Result<Vec<Interface>, LinuxError> {
        let mut interfaces = Vec::new();

        let net_dir = fs::read_dir("/sys/class/net")?;
        for entry in net_dir {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();

            // Read interface index
            let ifindex_path = entry.path().join("ifindex");
            let index = if let Ok(content) = fs::read_to_string(&ifindex_path) {
                content.trim().parse::<u32>().unwrap_or(0)
            } else {
                0
            };

            // Read operstate and flags
            let operstate_path = entry.path().join("operstate");
            let operstate = fs::read_to_string(&operstate_path)
                .unwrap_or_default()
                .trim()
                .to_string();
            let is_up = operstate == "up" || operstate == "unknown";

            // Read carrier
            let carrier_path = entry.path().join("carrier");
            let has_carrier = if let Ok(carrier) = fs::read_to_string(&carrier_path) {
                carrier.trim() == "1"
            } else {
                is_up
            };

            let is_loopback = name == "lo";

            // Read MTU
            let mtu_path = entry.path().join("mtu");
            let mtu = if let Ok(mtu_str) = fs::read_to_string(&mtu_path) {
                mtu_str.trim().parse::<u32>().unwrap_or(1500)
            } else {
                1500
            };

            // Read MAC address
            let addr_path = entry.path().join("address");
            let mac = fs::read_to_string(&addr_path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "00:00:00:00:00:00");

            // Query IP addresses for this interface using ip command
            let ip_addrs = self.get_interface_ips(&name)?;

            interfaces.push(Interface {
                index,
                name,
                is_up,
                has_carrier,
                is_loopback,
                mtu,
                mac,
                ip_addrs,
                gateway: None,
                role: InterfaceRole::Unknown,
            });
        }

        interfaces.sort_by_key(|i| i.index);
        Ok(interfaces)
    }

    /// Query IP addresses for a specific interface
    pub fn get_interface_ips(&self, iface_name: &str) -> Result<Vec<IpNet>, LinuxError> {
        let mut ips = Vec::new();

        let output = Command::new("ip")
            .args(["-br", "addr", "show", "dev", iface_name])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    for addr_str in &parts[2..] {
                        if let Ok(net) = IpNet::from_str(addr_str) {
                            ips.push(net);
                        }
                    }
                }
            }
        }

        Ok(ips)
    }

    /// Identify the default WAN interface from host routing table
    pub fn get_default_wan_interface(&self) -> Result<Option<String>, LinuxError> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(dev_idx) = parts.iter().position(|&r| r == "dev") {
                    if let Some(dev_name) = parts.get(dev_idx + 1) {
                        return Ok(Some(dev_name.to_string()));
                    }
                }
            }
        }

        Ok(None)
    }

    /// True when the main route table has a usable default route on `iface`.
    pub fn has_default_route_on_interface(&self, iface: &str) -> Result<bool, LinuxError> {
        let output = Command::new("ip")
            .args(["route", "show", "default", "dev", iface])
            .output()?;
        Ok(output.status.success() && has_default_route(&String::from_utf8_lossy(&output.stdout)))
    }

    /// Removes rogue default routes on a target LAN interface from table main,
    /// ensuring LAN can never hijack general Internet (WLAN) traffic.
    pub fn remove_default_routes_on_interface(&self, iface_name: &str) -> Result<(), LinuxError> {
        let output = Command::new("ip")
            .args(["route", "show", "default", "dev", iface_name])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if !line.trim().is_empty() {
                    let delete = Command::new("ip")
                        .args(["route", "del", "default", "dev", iface_name])
                        .output();
                    let delete = delete?;
                    if !delete.status.success() {
                        return Err(command_failure(
                            "ip",
                            &["route", "del", "default", "dev", iface_name],
                            &delete,
                        ));
                    }
                    tracing::info!(
                        "Removed rogue default route on LAN interface {}: {}",
                        iface_name,
                        line.trim()
                    );
                }
            }
        }

        Ok(())
    }

    /// Prioritizes the WAN interface in table main by installing metric 50 routes
    /// (metric 50 has higher priority in Linux than wired Ethernet metric 100).
    pub fn prioritize_wan_interface(&self, wan_iface: &str) -> Result<(), LinuxError> {
        let output = Command::new("ip")
            .args(["route", "show", "dev", wan_iface])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                // If already metric 50, skip
                if parts.contains(&"metric") {
                    if let Some(pos) = parts.iter().position(|&p| p == "metric") {
                        if parts.get(pos + 1) == Some(&"50") {
                            continue;
                        }
                    }
                }

                // Default route: default via <gw> dev <wan_iface>
                if parts[0] == "default" {
                    if let Some(gw_idx) = parts.iter().position(|&p| p == "via") {
                        if let Some(gw) = parts.get(gw_idx + 1) {
                            let replace = Command::new("ip")
                                .args([
                                    "route", "replace", "default", "via", gw, "dev", wan_iface,
                                    "metric", "50",
                                ])
                                .output();
                            let replace = replace?;
                            if !replace.status.success() {
                                return Err(command_failure(
                                    "ip",
                                    &[
                                        "route", "replace", "default", "via", gw, "dev", wan_iface,
                                        "metric", "50",
                                    ],
                                    &replace,
                                ));
                            }
                            tracing::info!(
                                "Prioritized WAN default route on {} with metric 50",
                                wan_iface
                            );
                        }
                    }
                } else if parts[0].contains('/') {
                    // Subnet route: e.g. 192.168.1.0/24
                    let cidr = parts[0];
                    let replace = Command::new("ip")
                        .args(["route", "replace", cidr, "dev", wan_iface, "metric", "50"])
                        .output();
                    let replace = replace?;
                    if !replace.status.success() {
                        return Err(command_failure(
                            "ip",
                            &["route", "replace", cidr, "dev", wan_iface, "metric", "50"],
                            &replace,
                        ));
                    }
                    tracing::info!(
                        "Prioritized WAN subnet route {} on {} with metric 50",
                        cidr,
                        wan_iface
                    );
                }
            }
        }

        Ok(())
    }

    /// Restores original WAN routing by removing temporary metric 50 routes.
    pub fn restore_wan_interface(&self, wan_iface: &str) -> Result<(), LinuxError> {
        let output = Command::new("ip")
            .args(["route", "show", "dev", wan_iface])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.contains(&"metric") {
                    if let Some(pos) = parts.iter().position(|&p| p == "metric") {
                        if parts.get(pos + 1) == Some(&"50") {
                            let dest = parts[0];
                            let _ = Command::new("ip")
                                .args(["route", "del", dest, "dev", wan_iface, "metric", "50"])
                                .output();
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Allocate an unused routing table within the reserved range 52000-52099
    pub fn allocate_table(&self, start: u32, end: u32) -> Result<u32, LinuxError> {
        let mut used_tables = HashSet::new();

        // Check tables in use via ip rule
        let rule_output = Command::new("ip").args(["rule", "show"]).output()?;
        if rule_output.status.success() {
            let stdout = String::from_utf8_lossy(&rule_output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&r| r == "lookup") {
                    if let Some(tbl) = parts.get(pos + 1) {
                        if let Ok(num) = tbl.parse::<u32>() {
                            used_tables.insert(num);
                        }
                    }
                }
            }
        }

        // Check tables with routes
        for table in start..=end {
            if used_tables.contains(&table) {
                continue;
            }

            let route_output = Command::new("ip")
                .args(["route", "show", "table", &table.to_string()])
                .output()?;

            let is_free = if route_output.status.success() {
                route_output.stdout.is_empty()
            } else {
                let stderr = String::from_utf8_lossy(&route_output.stderr);
                stderr.contains("FIB table does not exist")
            };

            if is_free {
                return Ok(table);
            }
        }

        Err(LinuxError::Netlink(format!(
            "No free routing table available in range {}-{}",
            start, end
        )))
    }

    /// Get all routes in a specific table
    pub fn get_table_routes(&self, table: u32) -> Result<Vec<Route>, LinuxError> {
        let mut routes = Vec::new();

        let output = Command::new("ip")
            .args(["route", "show", "table", &table.to_string()])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                // Identify route type and destination
                let (dest_str, route_type) = if parts[0] == "unreachable" && parts.len() > 1 {
                    (parts[1], RouteType::Unreachable)
                } else if parts[0] == "blackhole" && parts.len() > 1 {
                    (parts[1], RouteType::Blackhole)
                } else {
                    (parts[0], RouteType::Unicast)
                };

                let dest = if let Ok(net) = IpNet::from_str(dest_str) {
                    net
                } else if let Ok(ip) = IpAddr::from_str(dest_str) {
                    let p = match ip {
                        IpAddr::V4(_) => 32,
                        IpAddr::V6(_) => 128,
                    };
                    IpNet::new(ip, p).map_err(|e| LinuxError::Netlink(e.to_string()))?
                } else {
                    continue;
                };

                let mut out_iface = String::new();
                let mut gateway = None;
                let mut metric = None;

                for (i, &word) in parts.iter().enumerate() {
                    if word == "dev" && i + 1 < parts.len() {
                        out_iface = parts[i + 1].to_string();
                    } else if word == "via" && i + 1 < parts.len() {
                        gateway = IpAddr::from_str(parts[i + 1]).ok();
                    } else if word == "metric" && i + 1 < parts.len() {
                        metric = parts[i + 1].parse::<u32>().ok();
                    }
                }

                if !out_iface.is_empty() || route_type != RouteType::Unicast {
                    routes.push(Route {
                        destination: dest,
                        output_interface: out_iface,
                        gateway,
                        table,
                        metric,
                        route_type,
                    });
                }
            }
        }

        Ok(routes)
    }

    /// Get all RPDB rules matching our priority/table
    pub fn get_rpdb_rules(&self) -> Result<Vec<RpdbRule>, LinuxError> {
        let mut rules = Vec::new();

        let output = Command::new("ip").args(["rule", "show"]).output()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let prio_str = parts[0].trim_end_matches(':');
                    if let Ok(priority) = prio_str.parse::<u32>() {
                        if let Some(pos) = parts.iter().position(|&r| r == "lookup") {
                            if let Some(tbl) = parts.get(pos + 1) {
                                if let Ok(table) = tbl.parse::<u32>() {
                                    rules.push(RpdbRule { priority, table });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(rules)
    }

    /// Ensure an RPDB rule exists: `ip rule add pref <prio> lookup <table>`
    pub fn ensure_rpdb_rule(&self, priority: u32, table: u32) -> Result<(), LinuxError> {
        let existing = self.get_rpdb_rules()?;
        if existing
            .iter()
            .any(|r| r.priority == priority && r.table == table)
        {
            return Ok(());
        }

        let output = Command::new("ip")
            .args([
                "rule",
                "add",
                "pref",
                &priority.to_string(),
                "lookup",
                &table.to_string(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(LinuxError::Netlink(format!(
                "Failed to add RPDB rule: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Remove RPDB rule: `ip rule del pref <prio> lookup <table>`
    pub fn remove_rpdb_rule(&self, priority: u32, table: u32) -> Result<(), LinuxError> {
        let existing = self.get_rpdb_rules()?;
        if !existing
            .iter()
            .any(|r| r.priority == priority && r.table == table)
        {
            return Ok(());
        }

        let output = Command::new("ip")
            .args([
                "rule",
                "del",
                "pref",
                &priority.to_string(),
                "lookup",
                &table.to_string(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(LinuxError::Netlink(format!(
                "Failed to remove RPDB rule: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Add a route to custom table
    pub fn add_route(&self, route: &Route) -> Result<(), LinuxError> {
        // Validation check
        if route.destination.prefix_len() == 0 {
            return Err(LinuxError::Netlink(
                "Safety violation: Attempted to add default route (0.0.0.0/0) to isolated table"
                    .into(),
            ));
        }

        let args = if route.route_type == RouteType::Unreachable {
            vec![
                "route".to_string(),
                "replace".to_string(),
                "unreachable".to_string(),
                route.destination.trunc().to_string(),
                "table".to_string(),
                route.table.to_string(),
            ]
        } else if route.route_type == RouteType::Blackhole {
            vec![
                "route".to_string(),
                "replace".to_string(),
                "blackhole".to_string(),
                route.destination.trunc().to_string(),
                "table".to_string(),
                route.table.to_string(),
            ]
        } else {
            let mut a = vec![
                "route".to_string(),
                "replace".to_string(), // use replace for idempotence
                route.destination.trunc().to_string(),
                "dev".to_string(),
                route.output_interface.clone(),
                "table".to_string(),
                route.table.to_string(),
            ];

            if let Some(gw) = route.gateway {
                a.push("via".to_string());
                a.push(gw.to_string());
            }

            if let Some(metric) = route.metric {
                a.push("metric".to_string());
                a.push(metric.to_string());
            }
            a
        };

        let output = Command::new("ip").args(&args).output()?;
        if !output.status.success() {
            return Err(LinuxError::Netlink(format!(
                "Failed to add route {}: {}",
                route.destination,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Delete a route from custom table
    pub fn delete_route(&self, route: &Route) -> Result<(), LinuxError> {
        let dest_str = route.destination.trunc().to_string();
        let table_str = route.table.to_string();
        let args = if route.route_type == RouteType::Unreachable {
            vec![
                "route",
                "del",
                "unreachable",
                &dest_str,
                "table",
                &table_str,
            ]
        } else if route.route_type == RouteType::Blackhole {
            vec!["route", "del", "blackhole", &dest_str, "table", &table_str]
        } else if !route.output_interface.is_empty() {
            vec![
                "route",
                "del",
                &dest_str,
                "dev",
                &route.output_interface,
                "table",
                &table_str,
            ]
        } else {
            vec!["route", "del", &dest_str, "table", &table_str]
        };

        let output = Command::new("ip").args(&args).output()?;
        // Ignore "No such process" if already deleted
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("No such process") && !stderr.contains("Cannot find") {
                return Err(LinuxError::Netlink(format!(
                    "Failed to delete route {}: {}",
                    route.destination, stderr
                )));
            }
        }

        Ok(())
    }

    /// Flush all routes in a specific routing table
    pub fn flush_table(&self, table: u32) -> Result<(), LinuxError> {
        let output = Command::new("ip")
            .args(["route", "flush", "table", &table.to_string()])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Flushing table {} returned: {}", table, stderr);
        }
        Ok(())
    }

    /// Query default or peer gateway on an interface
    pub fn get_interface_gateway(&self, iface: &str) -> Option<IpAddr> {
        let output = Command::new("ip")
            .args(["route", "show", "dev", iface])
            .output()
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&p| p == "via") {
                    if let Some(gw_str) = parts.get(pos + 1) {
                        if let Ok(gw) = IpAddr::from_str(gw_str) {
                            return Some(gw);
                        }
                    }
                }
            }
        }
        None
    }

    /// Query an IPv6 default gateway on an interface.
    ///
    /// `get_interface_gateway` intentionally uses the IPv4 route table.  Keep
    /// IPv6 discovery separate so callers never accidentally install an IPv4
    /// gateway on an IPv6 route (or vice versa).
    pub fn get_interface_gateway_v6(&self, iface: &str) -> Option<IpAddr> {
        let output = Command::new("ip")
            .args(["-6", "route", "show", "default", "dev", iface])
            .output()
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&p| p == "via") {
                    if let Some(gw_str) = parts.get(pos + 1) {
                        if let Ok(gw) = gw_str.parse::<IpAddr>() {
                            if gw.is_ipv6() {
                                return Some(gw);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Read active neighbor IPs on an interface from ARP cache and ip neigh
    pub fn get_interface_neighbors(&self, iface: &str) -> Vec<IpAddr> {
        let mut neighbors = HashSet::new();

        // 1. Check /proc/net/arp
        if let Ok(content) = fs::read_to_string("/proc/net/arp") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let ip_str = parts[0];
                    let flags = parts[2];
                    let dev = parts[5];

                    if dev == iface && flags != "0x0" {
                        if let Ok(ip) = IpAddr::from_str(ip_str) {
                            neighbors.insert(ip);
                        }
                    }
                }
            }
        }

        // 2. Check ip neigh show dev <iface>
        if let Ok(output) = Command::new("ip")
            .args(["neigh", "show", "dev", iface])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(first) = parts.first() {
                        if let Ok(ip) = IpAddr::from_str(first) {
                            neighbors.insert(ip);
                        }
                    }
                }
            }
        }

        let mut list: Vec<IpAddr> = neighbors.into_iter().collect();
        list.sort();
        list
    }
}

fn command_failure(binary: &str, args: &[&str], output: &std::process::Output) -> LinuxError {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    LinuxError::Netlink(format!(
        "{} {} exited {}{}",
        binary,
        args.join(" "),
        output.status,
        if stderr.is_empty() {
            String::new()
        } else {
            format!(": {}", stderr)
        }
    ))
}

fn has_default_route(output: &str) -> bool {
    output
        .lines()
        .any(|line| line.split_whitespace().next() == Some("default"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_route_parser_requires_default_entry() {
        assert!(has_default_route(
            "default via 192.0.2.1 dev wlan0 metric 50\n"
        ));
        assert!(!has_default_route("192.0.2.0/24 dev wlan0 proto kernel\n"));
    }

    #[test]
    fn test_read_interfaces() {
        let controller = NetlinkController::new();
        let ifaces = controller.get_interfaces().unwrap();
        assert!(!ifaces.is_empty());
        assert!(ifaces.iter().any(|i| i.name == "lo"));
    }
}
