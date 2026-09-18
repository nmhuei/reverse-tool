use crate::error::LinuxError;
use ipnet::IpNet;
use std::process::{Command, Output};

pub struct FirewallController;

impl FirewallController {
    /// Applies a strict egress firewall whitelist on the specified LAN interface.
    /// Only explicitly allowed target IPs/CIDRs can leave this interface.
    /// All other packets attempting to exit via this interface are DROPPED.
    pub fn apply_egress_whitelist(
        interface: &str,
        allowed_targets: &[(String, Option<u16>)],
    ) -> Result<(), LinuxError> {
        Self::apply_egress_policy(interface, allowed_targets, &[])
    }

    /// Applies an interface-scoped egress policy. Blacklisted destinations are
    /// dropped before conntrack ACCEPT rules so existing sessions cannot bypass
    /// the deny list. IPv4 and IPv6 are programmed independently.
    pub fn apply_egress_policy(
        interface: &str,
        allowed_targets: &[(String, Option<u16>)],
        blocked_targets: &[IpNet],
    ) -> Result<(), LinuxError> {
        apply_family(
            "iptables",
            interface,
            allowed_targets,
            blocked_targets,
            false,
        )?;
        apply_family(
            "ip6tables",
            interface,
            allowed_targets,
            blocked_targets,
            true,
        )?;
        // If IPv6 programming fails, the IPv4 generation intentionally stays
        // installed: removing it after a partial dual-stack update would turn
        // an error into a LAN leak.
        Ok(())
    }

    /// Returns the blacklist rule order for deterministic, unprivileged tests.
    pub fn blacklist_rule_plan(blocked_targets: &[IpNet]) -> Vec<(bool, String)> {
        blocked_targets
            .iter()
            .map(|net| (net.addr().is_ipv6(), format!("-d {} -j DROP", net)))
            .collect()
    }

    /// Produces deterministic destination allow rules. A `None` port is an
    /// all-port authorization for that configured LAN destination; DNS
    /// resolvers are represented explicitly with `Some(53)`.
    pub fn lan_allow_rule_plan(allowed_targets: &[(String, Option<u16>)]) -> Vec<(bool, String)> {
        let mut rules = Vec::new();
        for (target, port) in allowed_targets {
            let target = target.trim();
            let Ok(network) = target.parse::<IpNet>() else {
                continue;
            };
            let ipv6 = network.addr().is_ipv6();
            match port {
                Some(port) => {
                    for protocol in ["udp", "tcp"] {
                        rules.push((
                            ipv6,
                            format!("-d {} -p {} --dport {} -j ACCEPT", target, protocol, port),
                        ));
                    }
                }
                None => rules.push((ipv6, format!("-d {} -j ACCEPT", target))),
            }
        }
        rules
    }

    /// Removes the egress whitelist filter for a specific interface
    pub fn remove_egress_whitelist(interface: &str) -> Result<(), LinuxError> {
        remove_family("iptables", interface);
        remove_family("ip6tables", interface);
        Ok(())
    }

    /// Cleans up all RT_EGRESS chains on reset
    pub fn cleanup_all() -> Result<(), LinuxError> {
        cleanup_family("iptables");
        cleanup_family("ip6tables");
        Ok(())
    }
}

fn apply_family(
    binary: &str,
    interface: &str,
    allowed_targets: &[(String, Option<u16>)],
    blocked_targets: &[IpNet],
    ipv6: bool,
) -> Result<(), LinuxError> {
    let base_chain = chain_name(interface, "");
    let chain_a = chain_name(interface, "_A");
    let chain_b = chain_name(interface, "_B");
    let output_rules = command_ok(binary, &["-S", "OUTPUT"])?;
    let output_rules = String::from_utf8_lossy(&output_rules.stdout);

    // Populate an inactive generation first.  The OUTPUT jump is installed
    // only after every rule has succeeded, avoiding the old fail-open window
    // where a hooked chain was flushed in place.
    let chain_name = if output_has_hook(&output_rules, interface, &chain_a) {
        chain_b.clone()
    } else {
        chain_a.clone()
    };
    ensure_empty_chain(binary, &chain_name)?;

    // Blacklist must be evaluated before established/related.
    for net in blocked_targets
        .iter()
        .filter(|net| net.addr().is_ipv6() == ipv6)
    {
        command_ok(
            binary,
            &["-A", &chain_name, "-d", &net.to_string(), "-j", "DROP"],
        )?;
    }

    // 2. Allow established & related connections
    command_ok(
        binary,
        &[
            "-A",
            &chain_name,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )?;

    // 3. Allow DHCP client requests so interface can maintain IP
    command_ok(
        binary,
        &[
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
        ],
    )?;

    // 5. Allow ICMP for network diagnostics and path MTU discovery
    let icmp_proto = if ipv6 { "icmpv6" } else { "icmp" };
    command_ok(
        binary,
        &["-A", &chain_name, "-p", icmp_proto, "-j", "ACCEPT"],
    )?;

    // 4. Whitelist explicitly configured LAN destinations. Ordinary target
    // IPs are all-port; only configured LAN DNS servers carry a port-53 rule.
    for (is_v6, rule) in FirewallController::lan_allow_rule_plan(allowed_targets) {
        if is_v6 != ipv6 {
            continue;
        }
        let mut args = vec!["-A", chain_name.as_str()];
        args.extend(rule.split_whitespace());
        command_ok(binary, &args)?;
    }

    // 5. Strictly DROP all other egress traffic on this LAN interface
    command_ok(binary, &["-A", &chain_name, "-j", "DROP"])?;

    // 6. Ensure chain is hooked into the OUTPUT table
    let check = Command::new(binary)
        .args(["-C", "OUTPUT", "-o", interface, "-j", &chain_name])
        .output()
        .map_err(LinuxError::Io)?;

    if !check.status.success() {
        command_ok(
            binary,
            &["-I", "OUTPUT", "-o", interface, "-j", &chain_name],
        )?;
    }

    // The new generation now has first-match precedence.  Remove all old
    // generations (including the legacy pre-transactional chain) only after
    // the new DROP rule is live.
    for old_chain in [&base_chain, &chain_a, &chain_b] {
        if old_chain != &chain_name {
            remove_output_hooks(binary, interface, old_chain)?;
        }
    }

    Ok(())
}

fn remove_family(binary: &str, interface: &str) {
    for suffix in ["", "_A", "_B"] {
        let chain = chain_name(interface, suffix);
        let _ = remove_output_hooks(binary, interface, &chain);
        let _ = Command::new(binary).args(["-F", &chain]).output();
        let _ = Command::new(binary).args(["-X", &chain]).output();
    }
}

fn cleanup_family(binary: &str) {
    let save_binary = format!("{}-save", binary);
    if let Ok(output) = Command::new(save_binary).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.starts_with(":RT_EGRESS_") {
                let chain = line
                    .trim_start_matches(':')
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                if !chain.is_empty() {
                    // Discover the actual hooked interface instead of
                    // assuming eth0/wlan0.  Names are intentionally parsed
                    // only from our RT_EGRESS chain prefix.
                    if let Ok(output) = command_ok(binary, &["-S", "OUTPUT"]) {
                        let rules = String::from_utf8_lossy(&output.stdout);
                        for interface in output_interfaces_for_chain(&rules, chain) {
                            let _ = remove_output_hooks(binary, &interface, chain);
                        }
                    }
                    let _ = Command::new(binary).args(["-F", chain]).output();
                    let _ = Command::new(binary).args(["-X", chain]).output();
                }
            }
        }
    }
}

fn chain_name(interface: &str, suffix: &str) -> String {
    // iptables chain names are limited to 29 bytes. Linux interface names
    // are capped at 15 bytes, so this retains the complete interface name.
    format!("RT_EGRESS_{}{}", interface.replace(['.', '-'], "_"), suffix)
}

fn command_ok(binary: &str, args: &[&str]) -> Result<Output, LinuxError> {
    let output = Command::new(binary).args(args).output()?;
    if output.status.success() {
        return Ok(output);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(LinuxError::Capability(format!(
        "{} {} exited {}{}",
        binary,
        args.join(" "),
        output.status,
        if stderr.is_empty() {
            String::new()
        } else {
            format!(": {}", stderr)
        }
    )))
}

fn ensure_empty_chain(binary: &str, chain: &str) -> Result<(), LinuxError> {
    let create = Command::new(binary).args(["-N", chain]).output()?;
    if !create.status.success() {
        // A non-zero `-N` normally means the generation exists. The required
        // flush below distinguishes that benign case from an unusable binary.
    }
    command_ok(binary, &["-F", chain])?;
    Ok(())
}

fn output_has_hook(rules: &str, interface: &str, chain: &str) -> bool {
    rules.lines().any(|line| {
        line.split_whitespace().collect::<Vec<_>>()
            == ["-A", "OUTPUT", "-o", interface, "-j", chain]
    })
}

fn output_interfaces_for_chain(rules: &str, chain: &str) -> Vec<String> {
    rules
        .lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            (parts.len() == 6
                && parts[0] == "-A"
                && parts[1] == "OUTPUT"
                && parts[2] == "-o"
                && parts[4] == "-j"
                && parts[5] == chain)
                .then(|| parts[3].to_string())
        })
        .collect()
}

fn remove_output_hooks(binary: &str, interface: &str, chain: &str) -> Result<(), LinuxError> {
    loop {
        let output = command_ok(binary, &["-S", "OUTPUT"])?;
        let rules = String::from_utf8_lossy(&output.stdout);
        if !output_has_hook(&rules, interface, chain) {
            return Ok(());
        }
        command_ok(binary, &["-D", "OUTPUT", "-o", interface, "-j", chain])?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blacklist_rule_plan_preserves_ipv4_and_ipv6_families() {
        let entries = vec![
            "203.0.113.10/32".parse::<IpNet>().unwrap(),
            "2001:db8::10/128".parse::<IpNet>().unwrap(),
        ];
        let plan = FirewallController::blacklist_rule_plan(&entries);
        assert_eq!(plan[0], (false, "-d 203.0.113.10/32 -j DROP".into()));
        assert_eq!(plan[1], (true, "-d 2001:db8::10/128 -j DROP".into()));
    }

    #[test]
    fn lan_ip_allow_plan_is_all_port_but_dns_server_is_port_53_only() {
        let entries = vec![
            ("10.0.0.1/32".into(), None),
            ("10.0.0.53/32".into(), Some(53)),
        ];
        let plan = FirewallController::lan_allow_rule_plan(&entries);

        assert!(plan.contains(&(false, "-d 10.0.0.1/32 -j ACCEPT".into())));
        assert!(!plan
            .iter()
            .any(|(_, rule)| { rule.contains("10.0.0.1/32") && rule.contains("--dport") }));
        assert!(plan.contains(&(false, "-d 10.0.0.53/32 -p udp --dport 53 -j ACCEPT".into())));
        assert!(plan.contains(&(false, "-d 10.0.0.53/32 -p tcp --dport 53 -j ACCEPT".into())));
    }

    #[test]
    fn firewall_command_failure_is_returned_to_the_caller() {
        let error = command_ok("false", &[]).unwrap_err().to_string();
        assert!(error.contains("false"));
        assert!(error.contains("exited"));
    }
}
