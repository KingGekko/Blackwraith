// SYN scanning – Layer 3/4 port discovery

use crate::error::Result;
use crate::core::proxy::ProxyManager;
use serde::{Serialize, Deserialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use futures::stream::{FuturesUnordered, StreamExt};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SynResult {
    pub open_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
}

/// Perform TCP connect scan (SYN scan requires raw sockets)
pub async fn syn_scan(target: IpAddr, proxy: &ProxyManager, timeout: Duration) -> Result<SynResult> {
    let mut result = SynResult::default();

    // Scan common ports using TCP connect as fallback
    let common_ports: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
        464, 593, 636, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000
    ];

    let mut tasks = FuturesUnordered::new();

    for port in common_ports {
        let addr = SocketAddr::new(target, port);
        let p = proxy.clone();
        tasks.push(tokio::spawn(async move {
            match tokio::time::timeout(timeout, p.connect(addr)).await {
                Ok(Ok(_)) => (port, true),
                _ => (port, false),
            }
        }));
    }

    while let Some(task_res) = tasks.next().await {
        if let Ok((port, open)) = task_res {
            if open {
                result.open_ports.push(port);
            } else {
                // In HTB, if it's not open, it's often filtered by a gateway
                result.filtered_ports.push(port);
            }
        }
    }

    result.open_ports.sort_unstable();
    result.filtered_ports.sort_unstable();

    Ok(result)
}
