use crate::error::LinuxError;
use std::process::Command;

pub struct FirewallController;

impl FirewallController {
    /// Applies a strict egress firewall whitelist on the specified LAN interface.
    /// Only explicitly allowed target IPs/CIDRs can leave this interface.
    /// All other packets attempting to exit via this interface are DROPPED.
    pub fn apply_egress_whitelist(
        interface: &str,
        allowed_targets: &[String],
    ) -> Result<(), LinuxError> {
        let chain_name = format!("RT_EGRESS_{}", interface.replace(['.', '-'], "_"));

        // 1. Create or flush dedicated chain
        let _ = Command::new("iptables").args(["-N", &chain_name]).output();
        let _ = Command::new("iptables").args(["-F", &chain_name]).output();

        // 2. Allow established & related connections
        let _ = Command::new("iptables")
            .args([
                "-A",
                &chain_name,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ])
            .output();

        // 3. Allow DHCP client requests so interface can maintain IP
        let _ = Command::new("iptables")
            .args([
                "-A",
                &chain_name,
                "-p",
                "udp",
                "--dport",
                "67:68",
                "--sport",
                "67:68",
                "-j",
                "ACCEPT",
            ])
            .output();

        // 4. Whitelist explicitly allowed target IPs/CIDRs
        for target in allowed_targets {
            let trimmed = target.trim();
            if !trimmed.is_empty() {
                let _ = Command::new("iptables")
                    .args(["-A", &chain_name, "-d", trimmed, "-j", "ACCEPT"])
                    .output();
            }
        }

        // 5. Strictly DROP all other egress traffic on this LAN interface
        let _ = Command::new("iptables")
            .args(["-A", &chain_name, "-j", "DROP"])
            .output();

        // 6. Ensure chain is hooked into the OUTPUT table
        let check = Command::new("iptables")
            .args(["-C", "OUTPUT", "-o", interface, "-j", &chain_name])
            .output();

        if check.is_err() || !check.unwrap().status.success() {
            let _ = Command::new("iptables")
                .args(["-I", "OUTPUT", "-o", interface, "-j", &chain_name])
                .output();
        }

        tracing::info!(
            "Enforced strict egress whitelist on {}: {} target(s) allowed, all other LAN egress DROPPED",
            interface,
            allowed_targets.len()
        );

        Ok(())
    }

    /// Removes the egress whitelist filter for a specific interface
    pub fn remove_egress_whitelist(interface: &str) -> Result<(), LinuxError> {
        let chain_name = format!("RT_EGRESS_{}", interface.replace(['.', '-'], "_"));

        while Command::new("iptables")
            .args(["-D", "OUTPUT", "-o", interface, "-j", &chain_name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {}

        let _ = Command::new("iptables").args(["-F", &chain_name]).output();
        let _ = Command::new("iptables").args(["-X", &chain_name]).output();

        Ok(())
    }

    /// Cleans up all RT_EGRESS chains on reset
    pub fn cleanup_all() -> Result<(), LinuxError> {
        if let Ok(output) = Command::new("iptables-save").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.starts_with(":RT_EGRESS_") {
                    let chain = line
                        .trim_start_matches(':')
                        .split_whitespace()
                        .next()
                        .unwrap_or("");
                    if !chain.is_empty() {
                        let _ = Command::new("sh")
                            .arg("-c")
                            .arg(format!(
                                "iptables -S OUTPUT 2>/dev/null | grep '{}' | sed 's/^-A/iptables -D/' | sh 2>/dev/null",
                                chain
                            ))
                            .output();
                        let _ = Command::new("iptables").args(["-F", chain]).output();
                        let _ = Command::new("iptables").args(["-X", chain]).output();
                    }
                }
            }
        }
        Ok(())
    }
}
