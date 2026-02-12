// SYN scanning – Layer 3/4 port discovery

use crate::error::Result;
use crate::core::proxy::ProxyManager;
use serde::{Serialize, Deserialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SynResult {
    pub open_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
}

/// Perform TCP connect scan (SYN scan requires raw sockets)
pub async fn syn_scan(target: IpAddr, proxy: &ProxyManager) -> Result<SynResult> {
    let mut result = SynResult::default();

    // Scan common ports using TCP connect as fallback
    let common_ports: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
    ];

    for port in common_ports {
        let addr = SocketAddr::new(target, port);
        // Use proxy.connect
        match tokio::time::timeout(
            Duration::from_millis(1500),
            proxy.connect(addr),
        )
        .await
        {
            Ok(Ok(_)) => result.open_ports.push(port),
            Ok(Err(_)) => {} // connection failed
            Err(_) => result.filtered_ports.push(port), // timeout
        }
    }

    Ok(result)
}
