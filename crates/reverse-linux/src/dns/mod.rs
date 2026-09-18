pub mod disabled;
pub mod networkmanager;
pub mod resolved;

use crate::error::LinuxError;
use std::net::IpAddr;
use std::process::Command;

pub trait DnsBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    fn apply_split_domains(
        &mut self,
        iface: &str,
        domains: &[String],
        dns_servers: &[IpAddr],
    ) -> Result<(), LinuxError>;
    fn rollback(&mut self, iface: &str) -> Result<(), LinuxError>;
}

fn preferred_backend_name(
    resolved_available: bool,
    network_manager_available: bool,
) -> &'static str {
    if resolved_available {
        "systemd-resolved"
    } else if network_manager_available {
        "NetworkManager"
    } else {
        "Disabled"
    }
}

/// Parse address-first output such as `getent ahosts`, preserving order while
/// removing duplicate A/AAAA answers.
pub fn parse_system_lookup_output(output: &str) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    for line in output.lines() {
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        if let Ok(address) = first.parse::<IpAddr>() {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    addresses
}

/// Resolve a hostname through the host resolver after split-DNS has assigned
/// the domain to the LAN link. Callers must use this only for allowlisted LAN
/// domains and must fail closed if no answers are available.
pub fn resolve_via_system_lookup(domain: &str) -> Result<Vec<IpAddr>, LinuxError> {
    let output = Command::new("getent").args(["ahosts", domain]).output()?;
    if !output.status.success() {
        return Err(LinuxError::Dns(format!(
            "system lookup failed for {}: {}",
            domain,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let addresses = parse_system_lookup_output(&String::from_utf8_lossy(&output.stdout));
    if addresses.is_empty() {
        return Err(LinuxError::Dns(format!(
            "system lookup returned no A/AAAA addresses for {}",
            domain
        )));
    }
    Ok(addresses)
}

pub fn detect_best_dns_backend() -> Box<dyn DnsBackend> {
    let resolved = resolved::ResolvedDnsBackend::new();
    let network_manager = networkmanager::NetworkManagerDnsBackend::new();
    match preferred_backend_name(resolved.is_available(), network_manager.is_available()) {
        "systemd-resolved" => Box::new(resolved),
        "NetworkManager" => Box::new(network_manager),
        _ => Box::new(disabled::DisabledDnsBackend::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networkmanager_is_selected_when_resolved_is_unavailable() {
        assert_eq!(preferred_backend_name(false, true), "NetworkManager");
        assert_eq!(preferred_backend_name(true, true), "systemd-resolved");
        assert_eq!(preferred_backend_name(false, false), "Disabled");
    }

    #[test]
    fn parses_unique_addresses_from_system_lookup_output() {
        let addresses = parse_system_lookup_output(
            "10.0.0.77 STREAM server.lab\n10.0.0.77 DGRAM\n2001:db8::77 STREAM server.lab\ninvalid STREAM server.lab\n",
        );
        assert_eq!(
            addresses,
            vec![
                "10.0.0.77".parse::<IpAddr>().unwrap(),
                "2001:db8::77".parse::<IpAddr>().unwrap(),
            ]
        );
    }
}
