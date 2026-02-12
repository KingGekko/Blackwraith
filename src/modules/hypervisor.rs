// Hypervisor type inference and MMIO/PMIO attack surface enumeration
// Based on 2025–2026 VM escape research (Bayet & Pujos)

use crate::error::Result;
use crate::core::proxy::ProxyManager;
use serde::{Serialize, Deserialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum HypervisorType {
    VMwareESXi,
    KVM,
    VirtualBox,
    HyperV,
    Xen,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HypervisorReport {
    pub hv_type: HypervisorType,
    pub confidence: f32,
    pub mmio_regions: Vec<MMIORange>,
    pub pmio_ports: Vec<u16>,
    pub vulnerable_device_models: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MMIORange {
    pub start: u64,
    pub end: u64,
    pub device: String,
}

pub async fn detect_hypervisor(target: IpAddr, proxy: &ProxyManager) -> Result<HypervisorReport> {
    // 1. TCP/IP stack fingerprinting
    let tcp_quirks = tcp_stack_fingerprint(target, proxy).await?;
    let hv_type = match tcp_quirks {
        TcpQuirks::VmwareEthernet => HypervisorType::VMwareESXi,
        TcpQuirks::VirtioNet => HypervisorType::KVM,
        TcpQuirks::VirtualBoxNAT => HypervisorType::VirtualBox,
        TcpQuirks::HyperV => HypervisorType::HyperV,
        TcpQuirks::None => HypervisorType::Unknown,
    };

    // 2. If hypervisor, attempt PCI config space reads (if we have guest access)
    let mmio = if hv_type != HypervisorType::Unknown {
        probe_mmio_regions(target).await?
    } else {
        Vec::new()
    };

    Ok(HypervisorReport {
        hv_type,
        confidence: 0.85,
        mmio_regions: mmio,
        pmio_ports: vec![0xcf8, 0xcfc], // PCI config ports
        vulnerable_device_models: vec!["vmxnet3".into(), "e1000".into()],
    })
}

#[derive(Debug)]
enum TcpQuirks {
    VmwareEthernet,
    VirtioNet,
    VirtualBoxNAT,
    HyperV,
    None,
}

async fn tcp_stack_fingerprint(target: IpAddr, proxy: &ProxyManager) -> Result<TcpQuirks> {
    // Send SYN to an open port, analyze TCP options
    // Simplified: check if target has VMware tools open
    let timeout_dur = std::time::Duration::from_secs(2);
    let vmware_addr = SocketAddr::new(target, 902);
    if tokio::time::timeout(timeout_dur, proxy.connect(vmware_addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
    {
        // VMware ESXi hostd port
        return Ok(TcpQuirks::VmwareEthernet);
    }
    // KVM often has virtio-serial on 4444
    let kvm_addr = SocketAddr::new(target, 4444);
    if tokio::time::timeout(timeout_dur, proxy.connect(kvm_addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
    {
        return Ok(TcpQuirks::VirtioNet);
    }
    Ok(TcpQuirks::None)
}

async fn probe_mmio_regions(_target: IpAddr) -> Result<Vec<MMIORange>> {
    // This would require VM escape to read host physical memory
    // For reconnaissance, we infer from known device models
    Ok(vec![
        MMIORange { start: 0xf0000000, end: 0xf07fffff, device: "vmxnet3".into() },
        MMIORange { start: 0xf0800000, end: 0xf0ffffff, device: "e1000".into() },
    ])
}