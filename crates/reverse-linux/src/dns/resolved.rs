use super::DnsBackend;
use crate::error::LinuxError;
use std::net::IpAddr;
use std::process::Command;

#[derive(Default)]
pub struct ResolvedDnsBackend;

impl ResolvedDnsBackend {
    pub fn new() -> Self {
        Self
    }
}

impl DnsBackend for ResolvedDnsBackend {
    fn name(&self) -> &'static str {
        "systemd-resolved"
    }

    fn is_available(&self) -> bool {
        if let Ok(output) = Command::new("resolvectl").arg("status").output() {
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

        // Format search domains with `~` prefix for split DNS routing in systemd-resolved
        let routing_domains: Vec<String> = domains
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

        // 1. Set routing domains
        let mut domain_cmd = Command::new("resolvectl");
        domain_cmd.args(["domain", iface]);
        domain_cmd.args(&routing_domains);

        let out = domain_cmd.output()?;
        if !out.status.success() {
            return Err(LinuxError::Dns(format!(
                "resolvectl domain failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }

        // 2. Set DNS servers if provided
        if !dns_servers.is_empty() {
            let mut dns_cmd = Command::new("resolvectl");
            dns_cmd.args(["dns", iface]);
            for server in dns_servers {
                dns_cmd.arg(server.to_string());
            }

            let out = dns_cmd.output()?;
            if !out.status.success() {
                return Err(LinuxError::Dns(format!(
                    "resolvectl dns failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
        }

        Ok(())
    }

    fn rollback(&mut self, iface: &str) -> Result<(), LinuxError> {
        let _ = Command::new("resolvectl")
            .args(["domain", iface, ""])
            .output();
        let _ = Command::new("resolvectl").args(["dns", iface, ""]).output();
        Ok(())
    }
}
