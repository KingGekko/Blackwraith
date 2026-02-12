// DNS resolution and DNS record harvesting

use crate::error::Result;
use serde::{Serialize, Deserialize};
use std::net::{IpAddr, ToSocketAddrs};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DnsResult {
    pub resolved_ips: Vec<String>,
    pub reverse_dns: Vec<String>,
    pub subdomains: Vec<String>,
}

/// Resolve a hostname or IP string into a list of IP addresses
pub async fn resolve(target: &str) -> Result<Vec<IpAddr>> {
    // First try to parse as an IP address directly
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    // Otherwise perform DNS resolution
    let target_owned = target.to_string();
    let ips = tokio::task::spawn_blocking(move || {
        let addr = format!("{}:0", target_owned);
        addr.to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect::<Vec<_>>())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();

    if ips.is_empty() {
        Err(crate::error::BlackWraithError::Dns(format!(
            "Could not resolve: {}",
            target
        )))
    } else {
        Ok(ips)
    }
}

/// Harvest DNS information for a domain
pub async fn dns_harvest(domain: &str) -> Result<DnsResult> {
    let mut result = DnsResult::default();

    // Resolve the base domain
    if let Ok(ips) = resolve(domain).await {
        result.resolved_ips = ips.iter().map(|ip| ip.to_string()).collect();
    }

    // Common subdomain enumeration (stub – would use wordlist in production)
    let prefixes = ["www", "mail", "ftp", "admin", "api", "dev", "staging"];
    for prefix in &prefixes {
        let sub = format!("{}.{}", prefix, domain);
        if let Ok(ips) = resolve(&sub).await {
            if !ips.is_empty() {
                result.subdomains.push(sub);
            }
        }
    }

    Ok(result)
}
