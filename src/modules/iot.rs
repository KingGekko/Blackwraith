// Industrial & IoT protocol scanners
// Modbus, BACnet, MQTT, CoAP, Siemens S7, EtherNet/IP

use crate::error::Result;
use crate::core::proxy::ProxyManager;
use serde::{Serialize, Deserialize};
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct IoTReport {
    pub modbus_devices: Vec<String>,
    pub bacnet_devices: Vec<String>,
    pub mqtt_brokers: Vec<String>,
    pub coap_servers: Vec<String>,
    pub s7_plcs: Vec<String>,
}

pub async fn scan_iot_network(target: IpAddr, proxy: &ProxyManager) -> Result<IoTReport> {
    let mut report = IoTReport {
        modbus_devices: Vec::new(),
        bacnet_devices: Vec::new(),
        mqtt_brokers: Vec::new(),
        coap_servers: Vec::new(),
        s7_plcs: Vec::new(),
    };

    // Modbus TCP on 502
    if is_port_open(target, 502, proxy).await {
        report.modbus_devices.push(target.to_string());
    }

    // BACnet/IP on 47808 (UDP) - Skip if proxied
    if !proxy.is_active() {
        if probe_bacnet(target).await.is_ok() {
            report.bacnet_devices.push(target.to_string());
        }
    }

    // MQTT on 1883 (TCP)
    if is_port_open(target, 1883, proxy).await {
        report.mqtt_brokers.push(SocketAddr::new(target, 1883).to_string());
    }

    // CoAP on 5683 (UDP) - Skip if proxied
    if !proxy.is_active() {
        if probe_coap(target).await.is_ok() {
            report.coap_servers.push(SocketAddr::new(target, 5683).to_string());
        }
    }

    // Siemens S7 on 102
    if is_port_open(target, 102, proxy).await {
        report.s7_plcs.push(target.to_string());
    }

    Ok(report)
}

async fn is_port_open(target: IpAddr, port: u16, proxy: &ProxyManager) -> bool {
    timeout(
        Duration::from_secs(2),
        proxy.connect(SocketAddr::new(target, port)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

async fn probe_bacnet(target: IpAddr) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect((target, 47808)).await?;
    // BACnet Who-Is broadcast
    let who_is = vec![0x81, 0x0a, 0x00, 0x00, 0x00, 0x08, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x00, 0x10];
    socket.send(&who_is).await?;
    let mut buf = [0; 1024];
    timeout(Duration::from_secs(2), socket.recv(&mut buf)).await??;
    Ok(())
}

async fn probe_coap(target: IpAddr) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect((target, 5683)).await?;
    // CoAP ping
    let ping = vec![0x40, 0x00, 0x00, 0x00];
    socket.send(&ping).await?;
    let mut buf = [0; 1024];
    timeout(Duration::from_secs(2), socket.recv(&mut buf)).await??;
    Ok(())
}