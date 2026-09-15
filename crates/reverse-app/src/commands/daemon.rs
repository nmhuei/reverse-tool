use crate::client::DaemonClient;
use crate::rpc::{default_log_path, default_pid_path, DaemonRequest, DaemonResponse};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

pub async fn handle_daemon_start(client: &DaemonClient, config_path: Option<&Path>) {
    if client.is_alive().await {
        println!("\x1b[1;33m[!] reversed daemon is already running.\x1b[0m");
        return;
    }

    println!("\x1b[1;34m[*] Starting reversed daemon in background...\x1b[0m");

    // Find reversed binary: check current directory target/debug/reversed or target/release/reversed or PATH
    let binary_path = find_reversed_binary();

    let mut cmd = Command::new(&binary_path);
    cmd.arg("--daemon");

    if let Some(cfg) = config_path {
        cmd.arg("-c").arg(cfg);
    }

    match cmd.spawn() {
        Ok(_) => {
            // Wait for daemon to initialize and socket to become active
            let mut started = false;
            for _ in 0..10 {
                sleep(Duration::from_millis(200)).await;
                if client.is_alive().await {
                    started = true;
                    break;
                }
            }

            if started {
                let pid = read_pid().unwrap_or(0);
                let log_path = default_log_path();
                println!(
                    "\x1b[1;32m[+] reversed daemon started successfully in background!\x1b[0m"
                );
                if pid > 0 {
                    println!("    PID:  \x1b[1m{}\x1b[0m", pid);
                }
                println!("    Logs: \x1b[1m{:?}\x1b[0m", log_path);
                println!("    \x1b[1;36m-> You can safely close this terminal now; the daemon will keep running.\x1b[0m\n");
            } else {
                eprintln!("\x1b[1;31m[!] Daemon spawned but socket did not respond within 2 seconds.\x1b[0m");
                eprintln!("    Check log file at {:?}", default_log_path());
            }
        }
        Err(e) => {
            eprintln!("\x1b[1;31mFailed to start reversed: {}\x1b[0m", e);
            eprintln!("Ensure 'reversed' binary is built or in your PATH.");
        }
    }
}

pub async fn handle_daemon_stop(client: &DaemonClient) {
    if client.is_alive().await {
        println!("\x1b[1;34m[*] Stopping reversed daemon...\x1b[0m");
        let _ = client.send(&DaemonRequest::Shutdown).await;
        sleep(Duration::from_millis(300)).await;
    }

    // Also verify by PID
    if let Some(pid) = read_pid() {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }

    let pid_path = default_pid_path();
    if pid_path.exists() {
        let _ = fs::remove_file(pid_path);
    }

    println!("\x1b[1;32m[+] reversed daemon stopped successfully.\x1b[0m\n");
}

pub async fn handle_daemon_restart(client: &DaemonClient, config_path: Option<&Path>) {
    handle_daemon_stop(client).await;
    sleep(Duration::from_millis(500)).await;
    handle_daemon_start(client, config_path).await;
}

pub async fn handle_daemon_status(client: &DaemonClient) {
    if client.is_alive().await {
        if let Ok(DaemonResponse::Status(s)) = client.send(&DaemonRequest::Status).await {
            println!("\n=== reversed Daemon Status ===");
            println!("Status:          \x1b[1;32mRUNNING (Background)\x1b[0m");
            println!("PID:             {}", s.pid);
            println!("Log File:        {:?}", default_log_path());
            println!("Allocated Table: {}", s.allocated_table);
            println!("Rule Priority:   {}", s.rule_priority);
            println!("Active Routes:   {}", s.active_routes.len());
            println!();
            return;
        }
    }

    let pid = read_pid();
    if let Some(p) = pid {
        // Check if process exists in /proc
        if Path::new(&format!("/proc/{}", p)).exists() {
            println!("\n=== reversed Daemon Status ===");
            println!(
                "Status:   \x1b[1;33mRUNNING (PID: {}) but socket unresponsive\x1b[0m",
                p
            );
            println!("Log File: {:?}", default_log_path());
            println!();
            return;
        }
    }

    println!("\n=== reversed Daemon Status ===");
    println!("Status:   \x1b[1;31mSTOPPED\x1b[0m");
    println!("Log File: {:?}", default_log_path());
    println!();
}

fn read_pid() -> Option<u32> {
    let pid_path = default_pid_path();
    if let Ok(content) = fs::read_to_string(pid_path) {
        content.trim().parse::<u32>().ok()
    } else {
        None
    }
}

fn find_reversed_binary() -> PathBuf {
    // 1. Current exe sibling
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let candidate = parent.join("reversed");
            if candidate.exists() {
                return candidate;
            }
        }
    }

    // 2. Target debug or release
    let candidates = [
        PathBuf::from("target/debug/reversed"),
        PathBuf::from("target/release/reversed"),
        PathBuf::from("/usr/local/bin/reversed"),
    ];

    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }

    // Fallback to reversed in PATH
    PathBuf::from("reversed")
}
