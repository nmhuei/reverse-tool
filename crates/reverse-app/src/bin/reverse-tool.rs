use clap::{Parser, Subcommand};
use reverse_app::client::DaemonClient;
use reverse_app::commands::{
    autoconfig::handle_autoconfig, handle_apply, handle_doctor, handle_explain, handle_reset,
    handle_scan, handle_status, handle_target_add, handle_target_list,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "reverse-tool")]
#[command(about = "Policy-routing orchestrator for network segmentation and lab routing", long_about = None)]
struct Cli {
    /// Custom path to reversed Unix domain socket
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    /// Path to config TOML file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan network interfaces and detect topology roles
    Scan,

    /// Show current daemon and policy routing status
    Status,

    /// Explain the deterministic routing decision for a destination IP or domain
    Explain {
        /// Target IP (e.g. 192.168.56.20) or domain (e.g. victim.lab)
        target: String,
    },

    /// Apply routing policy to isolated table 52000
    Apply {
        /// Show diff without modifying kernel routing tables or rules
        #[arg(long)]
        dry_run: bool,
    },

    /// Reset and remove all custom routes and RPDB rules
    Reset,

    /// Run system diagnostic checks for Netlink, capabilities, and DNS
    Doctor,

    /// Capture outbound connect metadata for an agent command (no payloads)
    Capture {
        /// Agent label stored in the report
        #[arg(long)]
        label: String,
        /// Maximum runtime in seconds
        #[arg(long, default_value_t = 20)]
        duration: u64,
        /// JSON report output path
        #[arg(long)]
        output: Option<PathBuf>,
        /// Optional file to append validated /32 or /128 entries to
        #[arg(long)]
        promote_blacklist: Option<PathBuf>,
        /// Agent executable and arguments, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Automatically detect LAN subnets and server IPs and configure policies
    #[command(alias = "auto")]
    Autoconfig {
        /// Save detected LAN subnets and targets to config file
        #[arg(short, long)]
        save: bool,

        /// Apply detected configuration immediately to isolated table 52000
        #[arg(short, long)]
        apply: bool,
    },

    /// Manage policy targets dynamically
    Target {
        #[command(subcommand)]
        sub: TargetSubcommands,
    },

    /// Stop running reversed background daemon (shortcut for `daemon stop`)
    Stop,

    /// Manage reversed daemon
    Daemon {
        #[command(subcommand)]
        sub: DaemonSubcommands,
    },
}

#[derive(Subcommand)]
enum TargetSubcommands {
    /// Add a new target rule
    Add {
        name: String,
        cidr: String,
        #[arg(short, long, required = true, num_args = 1..)]
        via: Vec<String>,
        #[arg(short, long, default_value = "drop")]
        fallback: String,
    },
    /// List configured targets
    List,
    /// Remove a target rule
    Remove { name_or_cidr: String },
}

#[derive(Subcommand)]
enum DaemonSubcommands {
    /// Start reversed daemon in background and detach from terminal
    Start {
        /// Optional path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Stop running reversed background daemon
    Stop,
    /// Restart reversed background daemon
    Restart {
        /// Optional path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Check daemon process status and PID
    Status,
    /// Reload daemon policy configuration
    Reload,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = DaemonClient::new(cli.socket);

    match cli.command {
        Commands::Scan => handle_scan(&client).await,
        Commands::Status => handle_status(&client).await,
        Commands::Explain { target } => {
            handle_explain(&client, &target, cli.config.as_deref()).await;
        }
        Commands::Apply { dry_run } => {
            if let Err(error) = handle_apply(&client, dry_run, cli.config.as_deref()).await {
                eprintln!("\x1b[1;31mApply failed: {}\x1b[0m", error);
                std::process::exit(1);
            }
        }
        Commands::Reset => handle_reset(&client).await,
        Commands::Doctor => handle_doctor().await,
        Commands::Capture {
            label,
            duration,
            output,
            promote_blacklist,
            command,
        } => {
            if let Err(err) = reverse_app::commands::capture::handle_capture(
                &label,
                duration,
                output.as_deref(),
                promote_blacklist.as_deref(),
                command,
            )
            .await
            {
                eprintln!("capture failed: {}", err);
                std::process::exit(1);
            }
        }
        Commands::Autoconfig { save, apply } => {
            handle_autoconfig(&client, save, apply, cli.config.as_deref()).await;
        }
        Commands::Stop => {
            reverse_app::commands::daemon::handle_daemon_stop(&client).await;
        }
        Commands::Target { sub } => match sub {
            TargetSubcommands::Add {
                name,
                cidr,
                via,
                fallback,
            } => {
                handle_target_add(&client, &name, &cidr, via, &fallback).await;
            }
            TargetSubcommands::List => {
                handle_target_list(&client).await;
            }
            TargetSubcommands::Remove { name_or_cidr } => {
                if client.is_alive().await {
                    let _ = client
                        .send(&reverse_app::rpc::DaemonRequest::RemoveTarget { name_or_cidr })
                        .await;
                    println!("\x1b[1;32m[+] Target removed\x1b[0m");
                }
            }
        },
        Commands::Daemon { sub } => match sub {
            DaemonSubcommands::Start { config } => {
                let cfg = config.as_deref().or(cli.config.as_deref());
                reverse_app::commands::daemon::handle_daemon_start(&client, cfg).await;
            }
            DaemonSubcommands::Stop => {
                reverse_app::commands::daemon::handle_daemon_stop(&client).await;
            }
            DaemonSubcommands::Restart { config } => {
                let cfg = config.as_deref().or(cli.config.as_deref());
                reverse_app::commands::daemon::handle_daemon_restart(&client, cfg).await;
            }
            DaemonSubcommands::Status => {
                reverse_app::commands::daemon::handle_daemon_status(&client).await;
            }
            DaemonSubcommands::Reload => {
                if client.is_alive().await {
                    let _ = client.send(&reverse_app::rpc::DaemonRequest::Reload).await;
                    println!("\x1b[1;32m[+] Daemon reloaded\x1b[0m");
                } else {
                    println!("\x1b[1;31m[!] Daemon is not running\x1b[0m");
                }
            }
        },
    }
}
