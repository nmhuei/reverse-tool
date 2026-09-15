use crate::error::LinuxError;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub struct CapabilityChecker;

impl CapabilityChecker {
    pub const CAP_NET_ADMIN_BIT: u64 = 1 << 12;

    pub fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    pub fn get_effective_caps() -> Result<u64, LinuxError> {
        let file = File::open("/proc/self/status")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if let Some(caps_hex) = line.strip_prefix("CapEff:\t") {
                let val = u64::from_str_radix(caps_hex.trim(), 16).map_err(|e| {
                    LinuxError::Capability(format!("Failed to parse CapEff hex: {}", e))
                })?;
                return Ok(val);
            }
        }

        Err(LinuxError::Capability(
            "CapEff line not found in /proc/self/status".into(),
        ))
    }

    pub fn has_cap_net_admin() -> bool {
        if Self::is_root() {
            return true;
        }

        match Self::get_effective_caps() {
            Ok(caps) => (caps & Self::CAP_NET_ADMIN_BIT) != 0,
            Err(_) => false,
        }
    }

    pub fn check_net_admin() -> Result<(), LinuxError> {
        if Self::has_cap_net_admin() {
            Ok(())
        } else {
            Err(LinuxError::Capability(
                "Process lacks CAP_NET_ADMIN or root privileges to modify network tables".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_caps_runs_without_panic() {
        let caps = CapabilityChecker::get_effective_caps();
        assert!(caps.is_ok());
    }
}
