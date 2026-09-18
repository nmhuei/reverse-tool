use ipnet::IpNet;
use serde::Serialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapturedEndpoint {
    pub label: String,
    pub pid: Option<u32>,
    pub ip: IpAddr,
    pub port: u16,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureReport {
    pub label: String,
    pub timed_out: bool,
    pub endpoints: Vec<CapturedEndpoint>,
}

pub async fn handle_capture(
    label: &str,
    duration_secs: u64,
    output: Option<&Path>,
    promote_blacklist: Option<&Path>,
    command: Vec<String>,
) -> Result<PathBuf, String> {
    if command.is_empty() {
        return Err("capture requires a command after `--`".into());
    }
    if duration_secs == 0 {
        return Err("capture duration must be greater than zero".into());
    }

    let trace_path = std::env::temp_dir().join(format!(
        "reverse-tool-capture-{}-{}.strace",
        sanitize_label(label),
        std::process::id()
    ));
    let mut child = Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=connect", "-o"])
        .arg(&trace_path)
        .arg("--")
        .arg(&command[0])
        .args(&command[1..])
        .spawn()
        .map_err(|e| format!("unable to start strace: {}", e))?;

    let timed_out = timeout(Duration::from_secs(duration_secs), child.wait())
        .await
        .is_err();
    if timed_out {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    let trace = tokio::fs::read_to_string(&trace_path)
        .await
        .map_err(|e| format!("unable to read capture trace: {}", e))?;
    let now = epoch_secs();
    let mut endpoints = parse_connect_trace(label, &trace, now);
    endpoints.sort_by_key(|e| (e.ip, e.port, e.pid));
    endpoints.dedup_by_key(|e| (e.ip, e.port, e.pid));

    let report = CaptureReport {
        label: label.to_string(),
        timed_out,
        endpoints,
    };
    let report_path = output.map(Path::to_path_buf).unwrap_or_else(|| {
        std::env::temp_dir().join(format!(
            "reverse-tool-{}-capture.json",
            sanitize_label(label)
        ))
    });
    let json = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    tokio::fs::write(&report_path, json)
        .await
        .map_err(|e| format!("unable to write capture report: {}", e))?;

    if let Some(path) = promote_blacklist {
        promote(&report, path).await?;
    }
    let _ = tokio::fs::remove_file(trace_path).await;
    println!(
        "captured {} endpoint(s) -> {}",
        report.endpoints.len(),
        report_path.display()
    );
    Ok(report_path)
}

fn parse_connect_trace(label: &str, trace: &str, timestamp_secs: u64) -> Vec<CapturedEndpoint> {
    trace
        .lines()
        .filter_map(|line| {
            let ip = extract_quoted_after(line, "inet_addr(\"")
                .or_else(|| extract_quoted_after(line, "inet_pton(AF_INET6, \""))?
                .parse::<IpAddr>()
                .ok()?;
            let port = extract_port(line)?;
            let pid = line
                .strip_prefix("[pid ")
                .and_then(|s| s.split(']').next())
                .and_then(|s| s.parse::<u32>().ok());
            Some(CapturedEndpoint {
                label: label.to_string(),
                pid,
                ip,
                port,
                timestamp_secs,
            })
        })
        .collect()
}

fn extract_quoted_after(line: &str, marker: &str) -> Option<String> {
    let rest = line.split_once(marker)?.1;
    Some(rest.split_once('"')?.0.to_string())
}

fn extract_port(line: &str) -> Option<u16> {
    let marker = "htons(";
    let rest = line.split_once(marker)?.1;
    rest.split_once(')')?.0.parse().ok()
}

async fn promote(report: &CaptureReport, path: &Path) -> Result<(), String> {
    let mut existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    for endpoint in &report.endpoints {
        let prefix = if endpoint.ip.is_ipv4() { 32 } else { 128 };
        let net = IpNet::new(endpoint.ip, prefix).map_err(|e| e.to_string())?;
        let line = format!("{}\n", net);
        if !existing
            .lines()
            .any(|entry| entry.trim() == net.to_string())
        {
            existing.push_str(&line);
        }
    }
    tokio::fs::write(path, existing)
        .await
        .map_err(|e| format!("unable to promote blacklist: {}", e))
}

fn sanitize_label(label: &str) -> String {
    let safe: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "agent".into()
    } else {
        safe
    }
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_connect_metadata_only() {
        let trace = r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = 0
[pid 42] connect(4, {sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet_pton(AF_INET6, "2001:db8::10")}, 28) = 0
sendto(3, "Authorization: Bearer secret", 30, 0, NULL, 0) = 30"#;
        let parsed = parse_connect_trace("codex", trace, 10);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].ip, "203.0.113.10".parse::<IpAddr>().unwrap());
        assert_eq!(parsed[1].ip, "2001:db8::10".parse::<IpAddr>().unwrap());
        assert!(parsed.iter().all(|e| e.port == 443));
    }
}
