use crate::rpc::{default_socket_path, DaemonRequest, DaemonResponse};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    pub fn new(custom_socket: Option<PathBuf>) -> Self {
        Self {
            socket_path: custom_socket.unwrap_or_else(default_socket_path),
        }
    }

    pub async fn is_alive(&self) -> bool {
        match self.send(&DaemonRequest::Ping).await {
            Ok(DaemonResponse::Ok(s)) => s == "pong",
            _ => false,
        }
    }

    pub async fn send(
        &self,
        req: &DaemonRequest,
    ) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (reader, mut writer) = stream.into_split();

        let req_json = serde_json::to_string(req)? + "\n";
        writer.write_all(req_json.as_bytes()).await?;

        let mut lines = BufReader::new(reader).lines();
        if let Some(line) = lines.next_line().await? {
            let resp: DaemonResponse = serde_json::from_str(&line)?;
            Ok(resp)
        } else {
            Err("No response received from daemon".into())
        }
    }
}
