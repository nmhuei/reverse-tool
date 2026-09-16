use crate::reconcile::Reconciler;
use crate::rpc::{default_socket_path, DaemonRequest, DaemonResponse, ScanReport, StatusReport};
use crate::state::StateManager;
use reverse_core::{
    Config, HealthConfig, HealthStateMachine, InterfaceClassifier, PathHealth, PolicyEngine,
    RoutePlanner,
};
use reverse_linux::{detect_best_dns_backend, CapabilityChecker, NetlinkController, PathProber};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

pub struct DaemonState {
    pub config: Config,
    pub health_map: HashMap<String, PathHealth>,
    pub health_sm: HealthStateMachine,
    pub default_wan: Option<String>,
}

pub struct ReversedDaemon {
    socket_path: PathBuf,
    state: Arc<Mutex<DaemonState>>,
}

impl ReversedDaemon {
    pub fn new(config: Config, custom_socket: Option<PathBuf>) -> Self {
        let socket_path = custom_socket.unwrap_or_else(default_socket_path);
        let netlink = NetlinkController::new();

        let explicit_wan = config.wan.interfaces.first().filter(|w| *w != "auto").cloned();
        let default_wan = explicit_wan.or_else(|| netlink.get_default_wan_interface().unwrap_or(None));

        let daemon_state = DaemonState {
            config,
            health_map: HashMap::new(),
            health_sm: HealthStateMachine::new(HealthConfig::default()),
            default_wan,
        };

        Self {
            socket_path,
            state: Arc::new(Mutex::new(daemon_state)),
        }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        // Check privileges
        if let Err(e) = CapabilityChecker::check_net_admin() {
            tracing::warn!("Starting daemon with warnings: {}", e);
        }

        // Clean existing socket
        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }
        if let Some(parent) = self.socket_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        tracing::info!("reversed daemon listening on {:?}", self.socket_path);

        // Write PID file
        let pid_path = crate::rpc::default_pid_path();
        if let Some(parent) = pid_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&pid_path, std::process::id().to_string());

        // Spawn background health probe loop
        let state_probe = Arc::clone(&self.state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            loop {
                interval.tick().await;
                let mut state = state_probe.lock().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Collect candidate interfaces from config
                let mut ifaces_to_probe = Vec::new();
                for net in &state.config.networks {
                    for iface in &net.interfaces {
                        ifaces_to_probe.push(iface.clone());
                    }
                }
                for target in &state.config.targets {
                    for iface in &target.via {
                        ifaces_to_probe.push(iface.clone());
                    }
                }

                ifaces_to_probe.sort();
                ifaces_to_probe.dedup();

                let health_sm = state.health_sm.clone();
                for iface in ifaces_to_probe {
                    let ok = PathProber::probe_interface(&iface, None).unwrap_or(false);
                    let entry = state
                        .health_map
                        .entry(iface.clone())
                        .or_insert_with(PathHealth::default);

                    if ok {
                        health_sm.record_success(entry, now);
                    } else {
                        health_sm.record_failure(entry, now);
                    }
                }
            }
        });

        // Accept loop
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = Arc::clone(&self.state);
                    let state_mgr = StateManager::new();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, state, state_mgr).await {
                            tracing::error!("Client handling error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Listener accept error: {}", e);
                    sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    async fn handle_client(
        stream: UnixStream,
        state: Arc<Mutex<DaemonState>>,
        state_mgr: StateManager,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        while let Some(line) = lines.next_line().await? {
            let req: DaemonRequest = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    let resp = DaemonResponse::Error(format!("Invalid request JSON: {}", e));
                    let resp_str = serde_json::to_string(&resp)? + "\n";
                    writer.write_all(resp_str.as_bytes()).await?;
                    continue;
                }
            };

            let resp = match req {
                DaemonRequest::Ping => DaemonResponse::Ok("pong".into()),
                DaemonRequest::Status => {
                    let s = state.lock().await;
                    let rt_state = state_mgr.load().unwrap_or_default();
                    let netlink = NetlinkController::new();
                    let ifaces = netlink.get_interfaces().unwrap_or_default();

                    DaemonResponse::Status(StatusReport {
                        daemon_running: true,
                        pid: std::process::id(),
                        allocated_table: rt_state.allocated_table,
                        rule_priority: rt_state.rule_priority,
                        active_routes: rt_state.routes_owned,
                        interface_count: ifaces.len(),
                        default_wan: s.default_wan.clone(),
                        last_reconcile_epoch: rt_state.last_reconcile_epoch,
                    })
                }
                DaemonRequest::Scan => {
                    let netlink = NetlinkController::new();
                    let mut ifaces = netlink.get_interfaces().unwrap_or_default();
                    let wan = netlink.get_default_wan_interface().unwrap_or(None);

                    for iface in &mut ifaces {
                        iface.role = InterfaceClassifier::classify(iface, wan.as_deref(), &[]);
                    }

                    DaemonResponse::Scan(ScanReport {
                        interfaces: ifaces,
                        default_wan: wan,
                    })
                }
                DaemonRequest::Explain { target } => {
                    let s = state.lock().await;
                    let netlink = NetlinkController::new();
                    let mut ifaces = netlink.get_interfaces().unwrap_or_default();
                    for iface in &mut ifaces {
                        iface.role =
                            InterfaceClassifier::classify(iface, s.default_wan.as_deref(), &[]);
                    }

                    let engine =
                        PolicyEngine::from_config(&s.config, &ifaces, s.default_wan.clone());
                    let decision = engine.decide(&target, &s.health_map, &s.health_sm);
                    DaemonResponse::Explain(decision)
                }
                DaemonRequest::Apply {
                    dry_run,
                    config_toml,
                } => {
                    let mut s = state.lock().await;
                    if let Some(toml_content) = config_toml {
                        if let Ok(new_cfg) = Config::from_toml_str(&toml_content) {
                            s.config = new_cfg;
                        }
                    }

                    let netlink = NetlinkController::new();
                    let mut ifaces = netlink.get_interfaces().unwrap_or_default();
                    for iface in &mut ifaces {
                        iface.role = InterfaceClassifier::classify(
                            iface,
                            s.default_wan.as_deref(),
                            &s.config.wan.interfaces,
                        );
                    }

                    // Automatically detect LAN subnets & servers if in auto/hybrid mode
                    if s.config.mode != reverse_core::OperatingMode::Manual {
                        let mut gateways = HashMap::new();
                        let mut neighbors = HashMap::new();
                        for iface in &ifaces {
                            if iface.role == reverse_core::InterfaceRole::Lan {
                                if let Some(gw) = netlink.get_interface_gateway(&iface.name) {
                                    gateways.insert(iface.name.clone(), gw);
                                }
                                let neighs = netlink.get_interface_neighbors(&iface.name);
                                if !neighs.is_empty() {
                                    neighbors.insert(iface.name.clone(), neighs);
                                }
                            }
                        }
                        let detected =
                            reverse_core::LanDetector::detect(&ifaces, &gateways, &neighbors);
                        reverse_core::LanDetector::merge_into_config(&mut s.config, detected);
                    }

                    let engine =
                        PolicyEngine::from_config(&s.config, &ifaces, s.default_wan.clone());
                    let desired_routes =
                        engine.generate_desired_routes(&s.health_map, &s.health_sm);

                    // Collect split DNS domains
                    let mut split_dns = Vec::new();
                    for net in &s.config.networks {
                        if let Some(dns_ip) = net.dns.first() {
                            for dom in &net.domains {
                                split_dns.push((dom.clone(), *dns_ip));
                            }
                        }
                    }

                    let desired = RoutePlanner::generate_desired_state(
                        s.config.defaults.table_id,
                        s.config.defaults.rule_priority,
                        desired_routes,
                        split_dns.clone(),
                    );

                    let reconciler = Reconciler::new(StateManager::new());
                    let report = reconciler.reconcile(&desired, dry_run);

                    // Apply DNS if not dry run and succeeded
                    if !dry_run {
                        if let Ok(ref rep) = report {
                            if rep.applied {
                                let mut dns = detect_best_dns_backend();
                                for net in &s.config.networks {
                                    if let Some(iface) = net.interfaces.first() {
                                        let _ =
                                            dns.apply_split_domains(iface, &net.domains, &net.dns);
                                    }
                                }
                            }
                        }
                    }

                    match report {
                        Ok(rep) => DaemonResponse::Apply(rep),
                        Err(e) => DaemonResponse::Error(e.to_string()),
                    }
                }
                DaemonRequest::Reset => {
                    let reconciler = Reconciler::new(StateManager::new());
                    match reconciler.reset() {
                        Ok(()) => DaemonResponse::Ok("Routing tables and rules cleared".into()),
                        Err(e) => DaemonResponse::Error(e.to_string()),
                    }
                }
                DaemonRequest::AddTarget(target) => {
                    let mut s = state.lock().await;
                    s.config.targets.retain(|t| t.cidr != target.cidr);
                    s.config.targets.push(target);
                    DaemonResponse::Ok("Target added to active policy".into())
                }
                DaemonRequest::RemoveTarget { name_or_cidr } => {
                    let mut s = state.lock().await;
                    s.config
                        .targets
                        .retain(|t| t.name != name_or_cidr && t.cidr != name_or_cidr);
                    DaemonResponse::Ok("Target removed from active policy".into())
                }
                DaemonRequest::ListTargets => {
                    let s = state.lock().await;
                    DaemonResponse::Targets(s.config.targets.clone())
                }
                DaemonRequest::Reload => DaemonResponse::Ok("Daemon reloaded".into()),
                DaemonRequest::Shutdown => {
                    let resp = DaemonResponse::Ok("Daemon stopping".into());
                    let resp_str = serde_json::to_string(&resp)? + "\n";
                    writer.write_all(resp_str.as_bytes()).await?;
                    let _ = writer.flush().await;
                    tokio::spawn(async {
                        sleep(Duration::from_millis(100)).await;
                        std::process::exit(0);
                    });
                    return Ok(());
                }
            };

            let resp_str = serde_json::to_string(&resp)? + "\n";
            writer.write_all(resp_str.as_bytes()).await?;
        }

        Ok(())
    }
}
