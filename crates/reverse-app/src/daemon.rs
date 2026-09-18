use crate::reconcile::Reconciler;
use crate::rpc::{default_socket_path, DaemonRequest, DaemonResponse, ScanReport, StatusReport};
use crate::state::StateManager;
use reverse_core::{
    Config, HealthConfig, HealthStateMachine, InterfaceClassifier, PathHealth, PolicyEngine,
    RoutePlanner,
};
use reverse_linux::{
    detect_best_dns_backend, resolve_via_system_lookup, CapabilityChecker, NetlinkController,
    PathProber,
};
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

        let explicit_wan = config
            .wan
            .interfaces
            .first()
            .filter(|w| *w != "auto")
            .cloned();
        let default_wan =
            explicit_wan.or_else(|| netlink.get_default_wan_interface().unwrap_or(None));

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

        // 1. Reset any stale policy routes or firewall rules from prior crashes if state file exists
        let state_mgr = StateManager::new();
        if state_mgr.exists() {
            tracing::info!(
                "Found leftover state file from prior run; resetting stale routes and rules..."
            );
            let startup_reconciler = Reconciler::new(state_mgr);
            if let Err(e) = startup_reconciler.reset() {
                tracing::warn!("Startup reset notice: {}", e);
            }
        }

        // Clean existing socket
        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }
        if let Some(parent) = self.socket_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.socket_path, fs::Permissions::from_mode(0o666));
        }
        tracing::info!("reversed daemon listening on {:?}", self.socket_path);

        // Write PID file
        let pid_path = crate::rpc::default_pid_path();
        if let Some(parent) = pid_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&pid_path, std::process::id().to_string());

        // Automatically activate policy on startup so running `reversed` immediately takes effect
        {
            let mut s = self.state.lock().await;
            match Self::execute_apply(&mut s, false) {
                Ok(rep) => {
                    tracing::info!(
                        "Startup policy active: {} routes, {} target(s) whitelisted",
                        rep.diff.routes_to_add.len(),
                        s.config.targets.len()
                    );
                }
                Err(e) => {
                    tracing::warn!("Startup policy activation notice: {}", e);
                }
            }
        }

        // Channel to signal shutdown from RPC (e.g. DaemonRequest::Shutdown)
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

        // Spawn background health probe loop
        let state_probe = Arc::clone(&self.state);
        let probe_handle = tokio::spawn(async move {
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

                let mut state_changed = false;
                let health_sm = state.health_sm.clone();
                for iface in ifaces_to_probe {
                    let ok = PathProber::probe_interface(&iface, None).unwrap_or(false);
                    let entry = state
                        .health_map
                        .entry(iface.clone())
                        .or_insert_with(PathHealth::default);

                    let was_available = health_sm.is_available(entry);
                    if ok {
                        health_sm.record_success(entry, now);
                    } else {
                        health_sm.record_failure(entry, now);
                    }
                    let is_now_available = health_sm.is_available(entry);
                    if was_available != is_now_available {
                        tracing::warn!(
                            "Interface {} availability changed (was: {}, now: {})",
                            iface,
                            was_available,
                            is_now_available
                        );
                        state_changed = true;
                    }
                }

                if state_changed {
                    tracing::info!(
                        "Health state changed, triggering dynamic failover reconciliation..."
                    );
                    if let Err(e) = Self::execute_apply(&mut state, false) {
                        tracing::error!("Dynamic failover reconciliation error: {}", e);
                    }
                } else {
                    // Continuous guard against NetworkManager re-adding rogue default routes on LAN
                    let netlink = NetlinkController::new();
                    let wan = state
                        .default_wan
                        .clone()
                        .or_else(|| state.config.wan.interfaces.first().cloned());
                    if let Some(wan_iface) = wan {
                        for target in &state.config.targets {
                            for iface in &target.via {
                                if iface != &wan_iface {
                                    let _ = netlink.remove_default_routes_on_interface(iface);
                                }
                            }
                        }
                    }
                }
            }
        });

        #[cfg(unix)]
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

        // Accept loop with signal listening
        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _)) => {
                            let state = Arc::clone(&self.state);
                            let state_mgr = StateManager::new();
                            let s_tx = shutdown_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_client(stream, state, state_mgr, s_tx).await {
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
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
                    break;
                }
                _ = async {
                    #[cfg(unix)]
                    {
                        sigterm.recv().await
                    }
                    #[cfg(not(unix))]
                    {
                        std::future::pending::<Option<()>>().await
                    }
                } => {
                    tracing::info!("Received SIGTERM, initiating graceful shutdown...");
                    break;
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Received RPC Shutdown request, initiating graceful shutdown...");
                    break;
                }
            }
        }

        // Immediately abort background health task so it cannot race with cleanup!
        probe_handle.abort();

        // Ephemeral lifecycle guarantee: Clean up all custom routing tables, rules, and iptables chains!
        tracing::info!(
            "Restoring system routing and firewall before exit (ephemeral lifecycle)..."
        );
        let cleanup_reconciler = Reconciler::new(StateManager::new());
        if let Err(e) = cleanup_reconciler.reset() {
            tracing::error!("Error cleaning up during shutdown: {}", e);
        }

        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }
        let pid_path = crate::rpc::default_pid_path();
        if pid_path.exists() {
            let _ = fs::remove_file(&pid_path);
        }

        tracing::info!("reversed daemon successfully stopped and cleaned up.");
        Ok(())
    }

    async fn handle_client(
        stream: UnixStream,
        state: Arc<Mutex<DaemonState>>,
        state_mgr: StateManager,
        shutdown_tx: tokio::sync::mpsc::Sender<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Enforce local privilege boundary: Query peer credentials via SO_PEERCRED
        let peer_cred = stream.peer_cred().ok();
        let peer_uid = peer_cred.as_ref().map(|c| c.uid());
        let is_root = peer_uid == Some(0);
        let is_owner = peer_uid == Some(unsafe { libc::getuid() });
        let is_authorized = is_root || is_owner;

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

            // Gate administrative / state-mutating RPC commands
            match &req {
                DaemonRequest::Apply { .. }
                | DaemonRequest::Reset
                | DaemonRequest::AddTarget(_)
                | DaemonRequest::RemoveTarget { .. }
                | DaemonRequest::Shutdown
                    if !is_authorized =>
                {
                    let resp = DaemonResponse::Error(
                        "Permission denied: State-mutating commands (apply, reset, shutdown, target add/remove) require root (sudo).".into(),
                    );
                    let resp_str = serde_json::to_string(&resp)? + "\n";
                    writer.write_all(resp_str.as_bytes()).await?;
                    continue;
                }
                _ => {}
            }

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

                    match Self::execute_apply(&mut s, dry_run) {
                        Ok(rep) => DaemonResponse::Apply(rep),
                        Err(e) => DaemonResponse::Error(e),
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
                    let resp = DaemonResponse::Ok("Daemon stopping and resetting state".into());
                    let resp_str = serde_json::to_string(&resp)? + "\n";
                    let _ = writer.write_all(resp_str.as_bytes()).await;
                    let _ = writer.flush().await;
                    let _ = shutdown_tx.send(()).await;
                    return Ok(());
                }
            };

            let resp_str = serde_json::to_string(&resp)? + "\n";
            writer.write_all(resp_str.as_bytes()).await?;
        }

        Ok(())
    }

    pub fn execute_apply(
        s: &mut DaemonState,
        dry_run: bool,
    ) -> Result<crate::reconcile::ReconcileReport, String> {
        s.config
            .validate_strict_lan_policy()
            .map_err(|error| format!("configuration rejected: {}", error))?;
        let mut dns_backend = detect_best_dns_backend();
        let needs_lan_dns = s
            .config
            .lan_domains
            .iter()
            .any(|domain| s.config.resolve_local_domain(domain).is_none());
        if !dry_run
            && needs_lan_dns
            && (s.config.lan_interfaces.is_empty()
                || s.config.lan_dns_servers.is_empty()
                || dns_backend.name() == "Disabled")
        {
            return Err(
                "LAN_DOMAINS require LAN_INTERFACE, LAN_DNS_SERVER, and an available split-DNS backend"
                    .into(),
            );
        }

        let netlink = NetlinkController::new();
        let mut ifaces = netlink.get_interfaces().map_err(|e| e.to_string())?;
        for iface in &mut ifaces {
            iface.gateway = netlink.get_interface_gateway(&iface.name);
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
            let detected = reverse_core::LanDetector::detect(&ifaces, &gateways, &neighbors);
            reverse_core::LanDetector::merge_into_config(&mut s.config, detected);
        }

        let mut engine = PolicyEngine::from_config(&s.config, &ifaces, s.default_wan.clone());
        let wan_v6_gateway = s
            .default_wan
            .as_deref()
            .and_then(|wan| netlink.get_interface_gateway_v6(wan));
        engine.set_wan_ipv6_gateway(wan_v6_gateway);
        let desired_routes = engine.generate_desired_routes(&s.health_map, &s.health_sm);

        // Collect split DNS domains
        let mut split_dns = Vec::new();
        for net in &s.config.networks {
            if let Some(dns_ip) = net.dns.first() {
                for dom in &net.domains {
                    split_dns.push((dom.clone(), *dns_ip));
                }
            }
        }

        let mut desired = RoutePlanner::generate_desired_state(
            s.config.defaults.table_id,
            s.config.defaults.rule_priority,
            desired_routes,
            split_dns,
        );
        desired.wan_interface = s
            .default_wan
            .clone()
            .or_else(|| s.config.wan.interfaces.first().cloned());
        desired.lan_interfaces = s.config.lan_interfaces.clone();
        desired.blacklist = s.config.blacklist.clone();

        for target in &s.config.targets {
            for iface in &target.via {
                desired
                    .firewall_whitelist
                    .push((iface.clone(), target.cidr.to_string(), None));
            }
        }
        // A raw port-53 allow rule is not domain-aware: any process could
        // send arbitrary QNAMEs to the LAN resolver. Dynamic LAN DNS is
        // rejected by strict validation until it is mediated by a dedicated
        // restricted resolver proxy.
        for domain in &s.config.lan_domains {
            if let Some(addresses) = s.config.resolve_local_domain(domain) {
                for iface in &s.config.lan_interfaces {
                    for address in addresses {
                        let prefix = if address.is_ipv4() { 32 } else { 128 };
                        desired.firewall_whitelist.push((
                            iface.clone(),
                            format!("{}/{}", address, prefix),
                            None,
                        ));
                    }
                }
            }
        }

        let reconciler = Reconciler::new(StateManager::new());
        let report = reconciler
            .reconcile(&desired, dry_run)
            .map_err(|e| e.to_string())?;

        // Apply DNS if not dry run and succeeded. LAN domains are installed
        // on the LAN link only; other domains retain the normal WLAN resolver.
        if !dry_run && report.applied {
            for net in &s.config.networks {
                if let Some(iface) = net.interfaces.first() {
                    let _ = dns_backend.apply_split_domains(iface, &net.domains, &net.dns);
                }
            }

            if needs_lan_dns {
                let lan_iface = s.config.lan_interfaces.first().ok_or_else(|| {
                    "LAN_DOMAINS are configured without a LAN_INTERFACE".to_string()
                })?;
                dns_backend
                    .apply_split_domains(
                        lan_iface,
                        &s.config.lan_domains,
                        &s.config.lan_dns_servers,
                    )
                    .map_err(|error| format!("failed to configure LAN split DNS: {}", error))?;

                let mut answers_changed = false;
                for domain in s.config.lan_domains.clone() {
                    let addresses = resolve_via_system_lookup(&domain).map_err(|error| {
                        format!("LAN DNS lookup failed for {}: {}", domain, error)
                    })?;
                    if s.config.resolve_local_domain(&domain) != Some(addresses.as_slice()) {
                        s.config.local_dns.insert(domain, addresses);
                        answers_changed = true;
                    }
                }

                // The first reconciliation admitted only configured IPs and
                // the DNS server. Reconcile once more when DNS answers change
                // so exact result IPs become LAN routes/firewall entries.
                if answers_changed {
                    return Self::execute_apply(s, false);
                }
            }
        }

        Ok(report)
    }
}
