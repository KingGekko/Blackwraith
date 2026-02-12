// BlackWraith 2.0 – Module declarations
// Each module is feature-gated to keep the default binary minimal

pub mod arp;
pub mod syn;
pub mod service;
pub mod dns;

#[cfg(feature = "l1_rf")]
pub mod l1_rf;

#[cfg(feature = "l7_web")]
pub mod l7_web;

#[cfg(feature = "l7_ai")]
pub mod l7_ai;

#[cfg(feature = "l7_cloud")]
pub mod l7_cloud;

#[cfg(feature = "hypervisor")]
pub mod hypervisor;

#[cfg(feature = "iot")]
pub mod iot;

pub mod evasion;
pub mod exfiltration;

pub mod adversarial;

/// Unified output type for all scan modules
pub enum ModuleOutput {
    Arp(arp::ArpResult),
    Syn(syn::SynResult),
    Dns(dns::DnsResult),
    Service(service::ServiceResult),
    #[cfg(feature = "l1_rf")]
    Rf(l1_rf::RFTransmitterFingerprint),
    #[cfg(feature = "hypervisor")]
    Hypervisor(hypervisor::HypervisorReport),
    #[cfg(feature = "iot")]
    Iot(iot::IoTReport),
    #[cfg(feature = "l7_cloud")]
    Cloud(l7_cloud::CloudAssets),
    #[cfg(feature = "l7_ai")]
    Ai(l7_ai::AIInfrastructureReport),
    #[cfg(feature = "l7_web")]
    Web(l7_web::WebVulnerabilityReport),
    BreachEvasion(adversarial::breach_evasion::BreachEvasionReport),
    ExploitDev(adversarial::exploit_development::ExploitDevelopmentReport),
    WebExpert(adversarial::web_expert::WebExpertReport),
    Extreme(adversarial::extreme_exploitation::ExtremeExploitationReport),
    Evasion(evasion::EvasionCapabilities),
    None,
}
