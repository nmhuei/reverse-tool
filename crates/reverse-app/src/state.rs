use reverse_core::{ActualState, Route, RpdbRule};
use reverse_linux::LinuxError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeState {
    pub allocated_table: u32,
    pub rule_priority: u32,
    pub routes_owned: Vec<Route>,
    pub rules_owned: Vec<RpdbRule>,
    #[serde(default)]
    pub firewall_whitelist: Vec<(String, String, Option<u16>)>,
    pub generation: u64,
    pub last_reconcile_epoch: u64,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            allocated_table: 52000,
            rule_priority: 12000,
            routes_owned: vec![],
            rules_owned: vec![],
            firewall_whitelist: vec![],
            generation: 1,
            last_reconcile_epoch: 0,
        }
    }
}

pub struct StateManager {
    path: PathBuf,
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StateManager {
    pub fn new() -> Self {
        // Preferred: /run/reverse-tool/state.json, fallback: /tmp/reverse-tool/state.json
        let path = if Path::new("/run").exists() && unsafe { libc::geteuid() == 0 } {
            PathBuf::from("/run/reverse-tool/state.json")
        } else {
            PathBuf::from("/tmp/reverse-tool/state.json")
        };

        Self { path }
    }

    pub fn with_path<P: Into<PathBuf>>(path: P) -> Self {
        Self { path: path.into() }
    }

    pub fn state_file_path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn load(&self) -> Result<RuntimeState, LinuxError> {
        if !self.path.exists() {
            return Ok(RuntimeState::default());
        }

        let content = fs::read_to_string(&self.path)?;
        serde_json::from_str(&content)
            .map_err(|e| LinuxError::Core(reverse_core::CoreError::Serialization(e.to_string())))
    }

    pub fn save(&self, state: &RuntimeState) -> Result<(), LinuxError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(state)
            .map_err(|e| LinuxError::Core(reverse_core::CoreError::Serialization(e.to_string())))?;
        fs::write(&self.path, json)?;
        Ok(())
    }

    pub fn to_actual_state(&self, state: &RuntimeState) -> ActualState {
        ActualState {
            routes: state.routes_owned.clone(),
            rules: state.rules_owned.clone(),
            allocated_table: state.allocated_table,
            rule_priority: state.rule_priority,
        }
    }

    pub fn clear(&self) -> Result<(), LinuxError> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_state_save_and_load() {
        let tmp = NamedTempFile::new().unwrap();
        let manager = StateManager::with_path(tmp.path());

        let state = RuntimeState {
            allocated_table: 52005,
            generation: 42,
            ..Default::default()
        };

        manager.save(&state).unwrap();

        let loaded = manager.load().unwrap();
        assert_eq!(loaded.allocated_table, 52005);
        assert_eq!(loaded.generation, 42);
    }
}
