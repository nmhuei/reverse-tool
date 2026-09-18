use crate::state::{RuntimeState, StateManager};
use reverse_core::{DesiredState, RoutePlanner, StateDiff};
use reverse_linux::{LinuxError, NetlinkController};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileReport {
    pub diff: StateDiff,
    pub dry_run: bool,
    pub applied: bool,
    pub verified: bool,
    pub rolled_back: bool,
    pub error: Option<String>,
}

pub struct Reconciler {
    netlink: NetlinkController,
    state_manager: StateManager,
}

impl Reconciler {
    pub fn new(state_manager: StateManager) -> Self {
        Self {
            netlink: NetlinkController::new(),
            state_manager,
        }
    }

    pub fn plan(&self, desired: &DesiredState) -> Result<StateDiff, LinuxError> {
        let runtime_state = self.state_manager.load()?;
        let actual = self.state_manager.to_actual_state(&runtime_state);
        let diff = RoutePlanner::plan_diff(&actual, desired)?;
        Ok(diff)
    }

    pub fn reconcile(
        &self,
        desired: &DesiredState,
        dry_run: bool,
    ) -> Result<ReconcileReport, LinuxError> {
        let mut runtime_state = self.state_manager.load()?;
        let actual = self.state_manager.to_actual_state(&runtime_state);

        let diff = RoutePlanner::plan_diff(&actual, desired)?;

        let mut firewall_interfaces = desired.lan_interfaces.clone();
        firewall_interfaces.extend(
            desired
                .firewall_whitelist
                .iter()
                .map(|(iface, _, _)| iface.clone()),
        );
        firewall_interfaces.sort();
        firewall_interfaces.dedup();

        let firewall_changed = runtime_state.firewall_whitelist != desired.firewall_whitelist
            || runtime_state.firewall_blacklist != desired.blacklist
            || runtime_state.firewall_interfaces != firewall_interfaces;

        if dry_run || (diff.is_empty() && !firewall_changed) {
            return Ok(ReconcileReport {
                diff,
                dry_run,
                applied: false,
                verified: true,
                rolled_back: false,
                error: None,
            });
        }

        // Do this before any route/rule mutation. The policy makes WLAN the
        // normal path, so applying it while the configured WLAN has no
        // default route could strand the host offline.
        if let Some(wan) = desired.wan_interface.as_deref() {
            if !self.netlink.has_default_route_on_interface(wan)? {
                return Err(LinuxError::Netlink(format!(
                    "Refusing apply: configured WLAN interface {} has no default route",
                    wan
                )));
            }
        }

        // Install the interface DROP guard before adding any LAN route or
        // RPDB rule. If this fails, no routing state has changed; if a later
        // route operation fails, the guard deliberately remains in place
        // (fail-closed) rather than briefly exposing LAN egress.
        self.apply_firewall(desired, &firewall_interfaces)?;

        // 1. Ensure desired RPDB rules exist first so table is queried
        for rule in &diff.rules_to_add {
            self.netlink.ensure_rpdb_rule(rule.priority, rule.table)?;
        }

        // 2. Add or replace desired routes in isolated table
        for route in &diff.routes_to_add {
            if let Err(e) = self.netlink.add_route(route) {
                // Rollback on failure!
                tracing::error!(
                    "Failed to add route {}: {}. Triggering rollback!",
                    route.destination,
                    e
                );
                let _ = self.rollback(&diff, &runtime_state);
                return Ok(ReconcileReport {
                    diff,
                    dry_run: false,
                    applied: false,
                    verified: false,
                    rolled_back: true,
                    error: Some(format!("Apply error, rolled back: {}", e)),
                });
            }
        }

        // 3. Remove obsolete routes from isolated table
        for route in &diff.routes_to_remove {
            let _ = self.netlink.delete_route(route);
        }

        // 4. Remove obsolete RPDB rules after routes are safely adjusted
        for rule in &diff.rules_to_remove {
            let _ = self.netlink.remove_rpdb_rule(rule.priority, rule.table);
        }

        // 5. Prioritize configured WAN interface with metric 50 and purge rogue LAN default routes
        let configured_wan = desired.wan_interface.clone();
        let default_wan =
            configured_wan.or_else(|| self.netlink.get_default_wan_interface().unwrap_or(None));
        if let Some(ref wan) = default_wan {
            if let Err(error) = self.netlink.prioritize_wan_interface(wan) {
                let _ = self.rollback(&diff, &runtime_state);
                return Ok(failed_report(
                    diff,
                    format!(
                        "failed to prioritize WLAN route; policy kept fail-closed: {}",
                        error
                    ),
                ));
            }
        }
        for route in &desired.routes {
            if !route.output_interface.is_empty()
                && Some(&route.output_interface) != default_wan.as_ref()
            {
                if let Err(error) = self
                    .netlink
                    .remove_default_routes_on_interface(&route.output_interface)
                {
                    let _ = self.rollback(&diff, &runtime_state);
                    return Ok(failed_report(
                        diff,
                        format!(
                            "failed to remove LAN default route; policy kept fail-closed: {}",
                            error
                        ),
                    ));
                }
            }
        }

        // 6. Verification step: verify routes are actually present in table
        let current_routes = self
            .netlink
            .get_table_routes(runtime_state.allocated_table)?;
        let mut verify_failed = false;
        for desired_route in &desired.routes {
            if !current_routes.iter().any(|r| {
                r.destination.trunc() == desired_route.destination.trunc()
                    && r.route_type == desired_route.route_type
            }) {
                verify_failed = true;
                break;
            }
        }

        if verify_failed {
            tracing::error!(
                "Verification failed: desired routes not found in kernel table! Rolling back."
            );
            let _ = self.rollback(&diff, &runtime_state);
            return Ok(ReconcileReport {
                diff,
                dry_run: false,
                applied: true,
                verified: false,
                rolled_back: true,
                error: Some("Kernel verification failed: routes not observed in table".into()),
            });
        }

        // 6. Commit state
        runtime_state.routes_owned = desired.routes.clone();
        runtime_state.rules_owned = desired.rules.clone();
        runtime_state.firewall_whitelist = desired.firewall_whitelist.clone();
        runtime_state.firewall_blacklist = desired.blacklist.clone();
        runtime_state.firewall_interfaces = firewall_interfaces;
        if let Some(first_rule) = desired.rules.first() {
            runtime_state.allocated_table = first_rule.table;
            runtime_state.rule_priority = first_rule.priority;
        }
        runtime_state.generation += 1;
        runtime_state.last_reconcile_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.state_manager.save(&runtime_state)?;

        Ok(ReconcileReport {
            diff,
            dry_run: false,
            applied: true,
            verified: true,
            rolled_back: false,
            error: None,
        })
    }

    fn apply_firewall(
        &self,
        desired: &DesiredState,
        firewall_interfaces: &[String],
    ) -> Result<(), LinuxError> {
        // Only explicitly configured LAN destinations are allowed out each
        // LAN interface; all other egress is dropped by FirewallController.
        let mut iface_targets: std::collections::HashMap<String, Vec<(String, Option<u16>)>> =
            std::collections::HashMap::new();

        if !desired.firewall_whitelist.is_empty() {
            for (iface, cidr, port) in &desired.firewall_whitelist {
                iface_targets
                    .entry(iface.clone())
                    .or_default()
                    .push((cidr.clone(), *port));
            }
        } else {
            for r in &desired.routes {
                iface_targets
                    .entry(r.output_interface.clone())
                    .or_default()
                    .push((r.destination.to_string(), None));
            }
        }

        for iface in firewall_interfaces {
            let targets = iface_targets.remove(iface).unwrap_or_default();
            reverse_linux::FirewallController::apply_egress_policy(
                iface,
                &targets,
                &desired.blacklist,
            )?;
        }
        Ok(())
    }

    pub fn rollback(&self, diff: &StateDiff, old_state: &RuntimeState) -> Result<(), LinuxError> {
        // Remove newly added routes
        for route in &diff.routes_to_add {
            let _ = self.netlink.delete_route(route);
        }

        // Re-add old routes
        for route in &old_state.routes_owned {
            let _ = self.netlink.add_route(route);
        }

        Ok(())
    }

    pub fn reset(&self) -> Result<(), LinuxError> {
        // 1. Always clean up any strict egress firewall whitelist chains created by us
        let _ = reverse_linux::FirewallController::cleanup_all();

        // 2. If recorded state exists, delete explicitly owned routes and rules
        if self.state_manager.exists() {
            if let Ok(state) = self.state_manager.load() {
                for route in &state.routes_owned {
                    let _ = self.netlink.delete_route(route);
                }
                for rule in &state.rules_owned {
                    let _ = self.netlink.remove_rpdb_rule(rule.priority, rule.table);
                }
                let _ = self
                    .netlink
                    .remove_rpdb_rule(state.rule_priority, state.allocated_table);
            }
            let _ = self.state_manager.clear();
        }

        // 3. Unconditional crash-recovery scan: Always remove rule 12000 and flush table 52000!
        // This guarantees that even if daemon crashed before state.json was written,
        // no orphaned rules or routes remain in the kernel.
        let _ = self.netlink.remove_rpdb_rule(12000, 52000);
        let _ = self.netlink.flush_table(52000);

        // 4. Restore original WAN metrics in table main
        if let Ok(Some(wan)) = self.netlink.get_default_wan_interface() {
            let _ = self.netlink.restore_wan_interface(&wan);
        }
        let _ = self.netlink.restore_wan_interface("wlan0");
        let _ = self.netlink.restore_wan_interface("wlan1");

        Ok(())
    }
}

fn failed_report(diff: StateDiff, error: String) -> ReconcileReport {
    ReconcileReport {
        diff,
        dry_run: false,
        applied: false,
        verified: false,
        rolled_back: true,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_reset_without_state_file_does_not_error() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp); // ensures file does not exist

        let sm = StateManager::with_path(path);
        let reconciler = Reconciler::new(sm);
        assert!(reconciler.reset().is_ok());
    }
}
