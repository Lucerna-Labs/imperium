//! Bounded local control request used by operator actions that own host state.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_COMMAND_BYTES: usize = 512;
const MAX_RESPONSE_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct ControlReply {
    pub status: String,
    pub message: String,
    pub mesh_data_path_blocked: Option<bool>,
    pub host_guard_installed: Option<bool>,
    pub host_guard_mode: Option<String>,
    pub host_egress_blocked: Option<bool>,
}

impl ControlReply {
    pub fn ok(&self) -> bool {
        self.status == "ok"
    }
}

pub(crate) async fn request(endpoint: &str, command: &str) -> Result<ControlReply, String> {
    if endpoint.is_empty()
        || command.is_empty()
        || command.len() > MAX_COMMAND_BYTES
        || command
            .bytes()
            .any(|byte| matches!(byte, b'\n' | b'\r' | 0))
    {
        return Err("invalid local control request".into());
    }
    tokio::time::timeout(REQUEST_TIMEOUT, request_inner(endpoint, command))
        .await
        .map_err(|_| "local control request timed out".to_string())?
}

async fn request_inner(endpoint: &str, command: &str) -> Result<ControlReply, String> {
    let mut stream = UnixStream::connect(endpoint)
        .await
        .map_err(|error| format!("local control unavailable: {error}"))?;
    stream
        .write_all(command.as_bytes())
        .await
        .map_err(|error| format!("control request write failed: {error}"))?;
    stream
        .write_all(b"\n")
        .await
        .map_err(|error| format!("control request write failed: {error}"))?;

    let mut response = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("control reply read failed: {error}"))?;
        if count == 0 {
            return Err("control socket closed before its reply".into());
        }
        let line_end = chunk[..count].iter().position(|byte| *byte == b'\n');
        let used = line_end.unwrap_or(count);
        if response.len() + used > MAX_RESPONSE_BYTES {
            return Err("control reply exceeds the size limit".into());
        }
        response.extend_from_slice(&chunk[..used]);
        if line_end.is_some() {
            break;
        }
    }
    let value: serde_json::Value = serde_json::from_slice(&response)
        .map_err(|error| format!("control reply is invalid JSON: {error}"))?;
    let status = value["status"]
        .as_str()
        .ok_or_else(|| "control reply has no status".to_string())?;
    let message = value["message"]
        .as_str()
        .ok_or_else(|| "control reply has no message".to_string())?;
    Ok(ControlReply {
        status: status.to_string(),
        message: message.to_string(),
        mesh_data_path_blocked: value["mesh_data_path_blocked"].as_bool(),
        host_guard_installed: value["host_guard_installed"].as_bool(),
        host_guard_mode: value["host_guard_mode"].as_str().map(str::to_string),
        host_egress_blocked: value["host_egress_blocked"].as_bool(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn sends_one_command_and_reads_authoritative_host_flags() {
        let path = std::env::temp_dir().join(format!(
            "imperium-gui-control-{}.sock",
            uuid::Uuid::new_v4()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut input = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                input.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            assert_eq!(input, b"vpn killswitch engage gui confirmation\n");
            stream.write_all(b"{\"status\":\"ok\",\"message\":\"host egress blocked\",\"mesh_data_path_blocked\":true,\"host_guard_installed\":true,\"host_guard_mode\":\"engaged\",\"host_egress_blocked\":true}\n").await.unwrap();
        });
        let reply = request(
            path.to_str().unwrap(),
            "vpn killswitch engage gui confirmation",
        )
        .await
        .unwrap();
        assert!(reply.ok());
        assert_eq!(reply.host_egress_blocked, Some(true));
        assert_eq!(reply.mesh_data_path_blocked, Some(true));
        server.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn rejects_command_injection_before_connecting() {
        assert!(
            request("/nonexistent", "vpn killswitch arm\nvpn killswitch disarm")
                .await
                .is_err()
        );
    }
}
