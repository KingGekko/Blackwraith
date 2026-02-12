// Service fingerprinting – Banner grabbing and version detection

use crate::error::Result;
use crate::core::proxy::ProxyManager;
use serde::{Serialize, Deserialize};
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncReadExt;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceResult {
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub banner: String,
    pub version: Option<String>,
}

/// Attempt banner grabbing on discovered open ports
pub async fn fingerprint_services(target: IpAddr, proxy: &ProxyManager) -> Result<ServiceResult> {
    let mut result = ServiceResult::default();

    // Common service ports to fingerprint
    let ports = [22, 80, 443, 21, 25, 3306, 5432, 8080];

    for &port in &ports {
        if let Ok(service) = grab_banner(target, port, proxy).await {
            result.services.push(service);
        }
    }

    Ok(result)
}

async fn grab_banner(target: IpAddr, port: u16, proxy: &ProxyManager) -> Result<ServiceInfo> {
    let timeout_dur = std::time::Duration::from_secs(2);
    let addr = SocketAddr::new(target, port);
    
    // Use proxy.connect
    let mut stream = tokio::time::timeout(timeout_dur, proxy.connect(addr))
        .await
        .map_err(|_| crate::error::BlackWraithError::Network("timeout".into()))??;

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(timeout_dur, stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);

    let banner = String::from_utf8_lossy(&buf[..n]).to_string();

    Ok(ServiceInfo {
        port,
        protocol: guess_protocol(port),
        banner: banner.trim().to_string(),
        version: None,
    })
}

fn guess_protocol(port: u16) -> String {
    match port {
        21 => "ftp",
        22 => "ssh",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        8080 => "http-proxy",
        _ => "unknown",
    }
    .to_string()
}
