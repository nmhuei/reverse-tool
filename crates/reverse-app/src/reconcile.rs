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

        let firewall_changed = runtime_state.firewall_whitelist != desired.firewall_whitelist;

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

        // 1. Remove obsolete RPDB rules
        for rule in &diff.rules_to_remove {
            let _ = self.netlink.remove_rpdb_rule(rule.priority, rule.table);
        }

        // 2. Ensure desired RPDB rules exist
        for rule in &diff.rules_to_add {
            self.netlink.ensure_rpdb_rule(rule.priority, rule.table)?;
        }

        // 3. Purge rogue default routes on target LAN interfaces in table main
        for route in &desired.routes {
            let _ = self
                .netlink
                .remove_default_routes_on_interface(&route.output_interface);
        }

        // 4. Remove obsolete routes from isolated table
        for route in &diff.routes_to_remove {
            self.netlink.delete_route(route)?;
        }

        // 3. Add desired routes
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

        // 4. Verification step: verify routes are actually present in table
        let current_routes = self
            .netlink
            .get_table_routes(runtime_state.allocated_table)?;
        let mut verify_failed = false;
        for desired_route in &desired.routes {
            if !current_routes
                .iter()
                .any(|r| r.destination == desired_route.destination)
            {
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

        // 5. Apply strict egress firewall whitelist on each target interface
        // Enforces: ONLY configured target IPs and ports are allowed out through LAN; everything else is DROPPED.
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

        for (iface, targets) in iface_targets {
            let _ = reverse_linux::FirewallController::apply_egress_whitelist(&iface, &targets);
        }

        // 6. Commit state
        runtime_state.routes_owned = desired.routes.clone();
        runtime_state.rules_owned = desired.rules.clone();
        runtime_state.firewall_whitelist = desired.firewall_whitelist.clone();
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
        // Always clean up any strict egress firewall whitelist chains created by us
        let _ = reverse_linux::FirewallController::cleanup_all();

        // Only delete kernel routes/rules if we have a recorded owned state file
        if !self.state_manager.exists() {
            return Ok(());
        }

        let state = self.state_manager.load()?;

        // Delete specifically the routes owned by us
        for route in &state.routes_owned {
            let _ = self.netlink.delete_route(route);
        }

        // Delete RPDB rules owned by us
        for rule in &state.rules_owned {
            let _ = self.netlink.remove_rpdb_rule(rule.priority, rule.table);
        }
        let _ = self
            .netlink
            .remove_rpdb_rule(state.rule_priority, state.allocated_table);

        // Clear state file
        self.state_manager.clear()?;
        Ok(())
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
