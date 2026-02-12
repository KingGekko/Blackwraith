use serde::{Serialize, Deserialize};
use crate::modules::*;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ScanReport {
    pub target: String,
    pub timestamp: String,
    pub techniques: Vec<Technique>,
    pub campaign_attribution: Vec<String>,
    pub manifold_curvature: Option<f64>,
    // Module outputs
    pub arp: Option<arp::ArpResult>,
    pub syn: Option<syn::SynResult>,
    pub dns: Option<dns::DnsResult>,
    pub service: Option<service::ServiceResult>,
    #[cfg(feature = "l1_rf")]
    pub rf: Option<l1_rf::RFTransmitterFingerprint>,
    #[cfg(feature = "hypervisor")]
    pub hypervisor: Option<hypervisor::HypervisorReport>,
    #[cfg(feature = "iot")]
    pub iot: Option<iot::IoTReport>,
    #[cfg(feature = "l7_cloud")]
    pub cloud: Option<l7_cloud::CloudAssets>,
    #[cfg(feature = "l7_ai")]
    pub ai: Option<l7_ai::AIInfrastructureReport>,
    #[cfg(feature = "l7_web")]
    pub web: Option<l7_web::WebVulnerabilityReport>,
    pub breach_evasion: Option<adversarial::breach_evasion::BreachEvasionReport>,
    pub exploit_dev: Option<adversarial::exploit_development::ExploitDevelopmentReport>,
    pub web_expert: Option<adversarial::web_expert::WebExpertReport>,
    pub extreme: Option<adversarial::extreme_exploitation::ExtremeExploitationReport>,
    pub evasion: Option<evasion::EvasionCapabilities>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Technique {
    pub technique_id: String,
    pub technique_name: String,
    pub confidence: f32,
    pub evidence: serde_json::Value,
}

impl ScanReport {
    pub fn new() -> Self {
        Self {
            target: String::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            techniques: Vec::new(),
            campaign_attribution: Vec::new(),
            manifold_curvature: None,
            arp: None,
            syn: None,
            dns: None,
            service: None,
            #[cfg(feature = "l1_rf")]
            rf: None,
            #[cfg(feature = "hypervisor")]
            hypervisor: None,
            #[cfg(feature = "iot")]
            iot: None,
            #[cfg(feature = "l7_cloud")]
            cloud: None,
            #[cfg(feature = "l7_ai")]
            ai: None,
            #[cfg(feature = "l7_web")]
            web: None,
            breach_evasion: None,
            exploit_dev: None,
            web_expert: None,
            extreme: None,
            evasion: None,
        }
    }

    pub fn merge(&mut self, output: ModuleOutput) {
        match output {
            ModuleOutput::Arp(o) => self.arp = Some(o),
            ModuleOutput::Syn(o) => self.syn = Some(o),
            ModuleOutput::Dns(o) => self.dns = Some(o),
            ModuleOutput::Service(o) => self.service = Some(o),
            #[cfg(feature = "l1_rf")]
            ModuleOutput::Rf(o) => self.rf = Some(o),
            #[cfg(feature = "hypervisor")]
            ModuleOutput::Hypervisor(o) => self.hypervisor = Some(o),
            #[cfg(feature = "iot")]
            ModuleOutput::Iot(o) => self.iot = Some(o),
            #[cfg(feature = "l7_cloud")]
            ModuleOutput::Cloud(o) => self.cloud = Some(o),
            #[cfg(feature = "l7_ai")]
            ModuleOutput::Ai(o) => self.ai = Some(o),
            #[cfg(feature = "l7_web")]
            ModuleOutput::Web(o) => self.web = Some(o),
            ModuleOutput::BreachEvasion(o) => self.breach_evasion = Some(o),
            ModuleOutput::ExploitDev(o) => self.exploit_dev = Some(o),
            ModuleOutput::WebExpert(o) => self.web_expert = Some(o),
            ModuleOutput::Extreme(o) => self.extreme = Some(o),
            ModuleOutput::Evasion(o) => self.evasion = Some(o),
            ModuleOutput::None => (),
        }
    }
}