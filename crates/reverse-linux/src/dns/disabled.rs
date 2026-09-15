use super::DnsBackend;
use crate::error::LinuxError;
use std::net::IpAddr;

#[derive(Default)]
pub struct DisabledDnsBackend;

impl DisabledDnsBackend {
    pub fn new() -> Self {
        Self
    }
}

impl DnsBackend for DisabledDnsBackend {
    fn name(&self) -> &'static str {
        "Disabled"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn apply_split_domains(
        &mut self,
        _iface: &str,
        _domains: &[String],
        _dns_servers: &[IpAddr],
    ) -> Result<(), LinuxError> {
        // No-op
        Ok(())
    }

    fn rollback(&mut self, _iface: &str) -> Result<(), LinuxError> {
        // No-op
        Ok(())
    }
}
