use clap::Parser;
use reverse_app::daemon::ReversedDaemon;
use reverse_core::Config;
use std::fs;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "reversed")]
#[command(about = "reverse-tool background policy routing daemon")]
struct Cli {
    /// Path to config TOML file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Custom Unix socket path
    #[arg(short, long)]
    socket: Option<PathBuf>,

    /// Detach and run as background daemon (survives terminal close)
    #[arg(short, long)]
    daemon: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.daemon {
        let log_path = reverse_app::rpc::default_log_path();
        if let Some(parent) = log_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            use std::os::fd::AsRawFd;
            let fd = file.as_raw_fd();
            unsafe {
                libc::dup2(fd, libc::STDOUT_FILENO);
                libc::dup2(fd, libc::STDERR_FILENO);
            }
        }

        let ret = unsafe { libc::daemon(1, 1) };
        if ret != 0 {
            eprintln!(
                "Failed to daemonize process: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Load config
    let mut config = if let Some(ref path) = cli.config {
        let content = fs::read_to_string(path)?;
        Config::from_toml_str(&content)?
    } else if Path::new("/etc/reverse-tool/config.toml").exists() {
        let content = fs::read_to_string("/etc/reverse-tool/config.toml")?;
        Config::from_toml_str(&content)?
    } else if Path::new("config/example.toml").exists() {
        let content = fs::read_to_string("config/example.toml")?;
        Config::from_toml_str(&content)?
    } else {
        Config::default()
    };

    // Automatically merge .env if present
    if Path::new(".env").exists() {
        config.merge_env_file(".env");
    } else if Path::new("/etc/reverse-tool/.env").exists() {
        config.merge_env_file("/etc/reverse-tool/.env");
    }

    let daemon = ReversedDaemon::new(config, cli.socket);
    daemon.run().await?;

    Ok(())
}
