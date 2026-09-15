use crate::reconcile::ReconcileReport;
use reverse_core::{Decision, Interface, Route, TargetConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    Ping,
    Status,
    Scan,
    Explain {
        target: String,
    },
    Apply {
        dry_run: bool,
        config_toml: Option<String>,
    },
    Reset,
    AddTarget(TargetConfig),
    RemoveTarget {
        name_or_cidr: String,
    },
    ListTargets,
    Reload,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub daemon_running: bool,
    pub pid: u32,
    pub allocated_table: u32,
    pub rule_priority: u32,
    pub active_routes: Vec<Route>,
    pub interface_count: usize,
    pub default_wan: Option<String>,
    pub last_reconcile_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub interfaces: Vec<Interface>,
    pub default_wan: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    Ok(String),
    Status(StatusReport),
    Scan(ScanReport),
    Explain(Decision),
    Apply(ReconcileReport),
    Targets(Vec<TargetConfig>),
    Error(String),
}

pub fn default_socket_path() -> PathBuf {
    if Path::new("/run").exists() && unsafe { libc::geteuid() == 0 } {
        PathBuf::from("/run/reverse-tool/reversed.sock")
    } else {
        PathBuf::from("/tmp/reverse-tool/reversed.sock")
    }
}

pub fn default_pid_path() -> PathBuf {
    if Path::new("/run").exists() && unsafe { libc::geteuid() == 0 } {
        PathBuf::from("/run/reverse-tool/reversed.pid")
    } else {
        PathBuf::from("/tmp/reverse-tool/reversed.pid")
    }
}

pub fn default_log_path() -> PathBuf {
    if Path::new("/var/log").exists() && unsafe { libc::geteuid() == 0 } {
        PathBuf::from("/var/log/reversed.log")
    } else if Path::new("/run").exists() && unsafe { libc::geteuid() == 0 } {
        PathBuf::from("/run/reverse-tool/reversed.log")
    } else {
        PathBuf::from("/tmp/reverse-tool/reversed.log")
    }
}
