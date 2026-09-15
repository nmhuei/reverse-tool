pub mod disabled;
pub mod networkmanager;
pub mod resolved;

use crate::error::LinuxError;
use std::net::IpAddr;

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

pub fn detect_best_dns_backend() -> Box<dyn DnsBackend> {
    let nm = networkmanager::NetworkManagerDnsBackend::new();
    if nm.is_available() {
        return Box::new(nm);
    }

    let resolved = resolved::ResolvedDnsBackend::new();
    if resolved.is_available() {
        return Box::new(resolved);
    }

    Box::new(disabled::DisabledDnsBackend::new())
}
