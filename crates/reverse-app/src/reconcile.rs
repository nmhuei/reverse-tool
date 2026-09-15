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

        if dry_run || diff.is_empty() {
            return Ok(ReconcileReport {
                diff,
                dry_run,
                applied: false,
                verified: true,
                rolled_back: false,
                error: None,
            });
        }

        // Apply changes:
        // 1. Ensure RPDB rule exists
        for rule in &diff.rules_to_add {
            self.netlink.ensure_rpdb_rule(rule.priority, rule.table)?;
        }

        // 2. Remove obsolete routes from isolated table
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

        // 5. Commit state
        runtime_state.routes_owned = desired.routes.clone();
        runtime_state.rules_owned = desired.rules.clone();
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
        let state = self.state_manager.load()?;

        // Delete all routes owned by us in the allocated table
        let routes = self.netlink.get_table_routes(state.allocated_table)?;
        for route in routes {
            let _ = self.netlink.delete_route(&route);
        }

        // Delete RPDB rule
        let _ = self
            .netlink
            .remove_rpdb_rule(state.rule_priority, state.allocated_table);

        // Clear state file
        self.state_manager.clear()?;
        Ok(())
    }
}
