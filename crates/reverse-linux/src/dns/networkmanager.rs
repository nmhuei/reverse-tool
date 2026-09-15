use super::DnsBackend;
use crate::error::LinuxError;
use std::net::IpAddr;
use std::process::Command;

#[derive(Default)]
pub struct NetworkManagerDnsBackend;

impl NetworkManagerDnsBackend {
    pub fn new() -> Self {
        Self
    }
}

impl DnsBackend for NetworkManagerDnsBackend {
    fn name(&self) -> &'static str {
        "NetworkManager"
    }

    fn is_available(&self) -> bool {
        if let Ok(output) = Command::new("nmcli").arg("general").arg("status").output() {
            output.status.success()
        } else {
            false
        }
    }

    fn apply_split_domains(
        &mut self,
        iface: &str,
        domains: &[String],
        dns_servers: &[IpAddr],
    ) -> Result<(), LinuxError> {
        if domains.is_empty() {
            return Ok(());
        }

        // Format search domains with `~` prefix for split DNS routing in NetworkManager
        let search_domains: Vec<String> = domains
            .iter()
            .map(|d| {
                let trimmed = d.trim();
                if trimmed.starts_with('~') {
                    trimmed.to_string()
                } else if let Some(s) = trimmed.strip_prefix('.') {
                    format!("~{}", s)
                } else if let Some(s) = trimmed.strip_prefix("*.") {
                    format!("~{}", s)
                } else {
                    format!("~{}", trimmed)
                }
            })
            .collect();

        let dns_str: Vec<String> = dns_servers.iter().map(|ip| ip.to_string()).collect();

        let mut cmd = Command::new("nmcli");
        cmd.args(["device", "modify", iface]);

        if !dns_str.is_empty() {
            cmd.args(["ipv4.dns", &dns_str.join(" ")]);
        }
        cmd.args(["ipv4.dns-search", &search_domains.join(" ")]);

        let output = cmd.output()?;
        if !output.status.success() {
            return Err(LinuxError::Dns(format!(
                "NetworkManager failed to apply split DNS: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    fn rollback(&mut self, iface: &str) -> Result<(), LinuxError> {
        let output = Command::new("nmcli")
            .args(["device", "modify", iface, "ipv4.dns-search", ""])
            .output()?;

        if !output.status.success() {
            tracing::warn!(
                "Failed to rollback NM DNS for {}: {}",
                iface,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}
