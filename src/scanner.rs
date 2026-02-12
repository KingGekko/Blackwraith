// Orchestrates all scanning modules with concurrency control and manifold state

use crate::core::manifold::VulnerabilityManifold;
use crate::core::policy::PolicyNetwork;
use crate::error::{Result, BlackWraithError};
use crate::modules::*;
use crate::output::ScanReport;
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use crate::core::proxy::ProxyManager;
use tokio::sync::Semaphore;

pub struct ScannerEngine {
    // Core state
    manifold: VulnerabilityManifold,
    policy: PolicyNetwork,

    // Concurrency
    semaphore: Arc<Semaphore>,

    // Module flags
    // Module flags
    modules: Vec<Module>,
    rf_interface: Option<String>,
    bezier_res: usize,
    proxy_manager: ProxyManager,
    predict_chains: bool,

    // Output
    output_path: Option<PathBuf>,
    report: ScanReport,
}

#[derive(PartialEq, Clone, Copy)]
enum Module {
    // Layer 1–7 basic
    Arp, Syn, Service, Dns,
    // Advanced modules
    #[cfg(feature = "l1_rf")]
    Rf,
    #[cfg(feature = "hypervisor")]
    Hypervisor,
    #[cfg(feature = "iot")]
    Iot,
    #[cfg(feature = "l7_cloud")]
    Cloud,
    #[cfg(feature = "l7_ai")]
    Ai,
    #[cfg(feature = "l7_web")]
    WebFull,
    // Adversarial pathways
    BreachEvasion, ExploitDevelopment, WebExpert, ExtremeExploitation,
    // Evasion
    Evasion,
}

impl ScannerEngine {
    pub fn new(concurrency: usize) -> Self {
        Self {
            manifold: VulnerabilityManifold::new(),
            policy: PolicyNetwork::new(),
            semaphore: Arc::new(Semaphore::new(concurrency)),
            modules: Vec::new(),
            rf_interface: None,
            bezier_res: 16,
            proxy_manager: ProxyManager::new(None),
            predict_chains: false,
            output_path: None,
            report: ScanReport::new(),
        }
    }

    // --- Module enabling ---
    pub fn enable_all_basic(&mut self) {
        self.modules.extend(vec![Module::Arp, Module::Syn, Module::Service, Module::Dns]);
    }

    #[cfg(feature = "l1_rf")]
    pub fn enable_rf(&mut self) { self.modules.push(Module::Rf); }
    #[cfg(not(feature = "l1_rf"))]
    pub fn enable_rf(&mut self) {
        eprintln!("[!] RF module not compiled – enable 'l1_rf' feature");
    }

    #[cfg(feature = "hypervisor")]
    pub fn enable_hypervisor(&mut self) { self.modules.push(Module::Hypervisor); }
    #[cfg(not(feature = "hypervisor"))]
    pub fn enable_hypervisor(&mut self) {
        eprintln!("[!] Hypervisor module not compiled – enable 'hypervisor' feature");
    }

    #[cfg(feature = "iot")]
    pub fn enable_iot(&mut self) { self.modules.push(Module::Iot); }
    #[cfg(not(feature = "iot"))]
    pub fn enable_iot(&mut self) {
        eprintln!("[!] IoT module not compiled – enable 'iot' feature");
    }

    #[cfg(feature = "l7_cloud")]
    pub fn enable_cloud(&mut self) { self.modules.push(Module::Cloud); }
    #[cfg(not(feature = "l7_cloud"))]
    pub fn enable_cloud(&mut self) {
        eprintln!("[!] Cloud module not compiled – enable 'l7_cloud' feature");
    }

    #[cfg(feature = "l7_ai")]
    pub fn enable_ai(&mut self) { self.modules.push(Module::Ai); }
    #[cfg(not(feature = "l7_ai"))]
    pub fn enable_ai(&mut self) {
        eprintln!("[!] AI module not compiled – enable 'l7_ai' feature");
    }

    pub fn enable_web(&mut self) { /* basic web checks */ }

    #[cfg(feature = "l7_web")]
    pub fn enable_web_full(&mut self) { self.modules.push(Module::WebFull); }
    #[cfg(not(feature = "l7_web"))]
    pub fn enable_web_full(&mut self) {
        eprintln!("[!] Web module not compiled – enable 'l7_web' feature");
    }

    pub fn enable_breach_evasion(&mut self) { self.modules.push(Module::BreachEvasion); }
    pub fn enable_exploit_development(&mut self) { self.modules.push(Module::ExploitDevelopment); }
    pub fn enable_web_expert(&mut self) { self.modules.push(Module::WebExpert); }
    pub fn enable_extreme_exploitation(&mut self) { self.modules.push(Module::ExtremeExploitation); }
    pub fn enable_evasion(&mut self) { self.modules.push(Module::Evasion); }

    // --- Configuration ---
    pub fn set_output(&mut self, path: Option<PathBuf>) { self.output_path = path; }
    pub fn set_rf_interface(&mut self, iface: String) { self.rf_interface = Some(iface); }
    pub fn set_bezier_resolution(&mut self, res: usize) { self.bezier_res = res; }
    pub fn set_proxy(&mut self, proxy_url: String) { self.proxy_manager = ProxyManager::new(Some(proxy_url)); }
    pub fn set_predict_chains(&mut self, enabled: bool) { self.predict_chains = enabled; }

    // --- Scan entry points ---
    pub async fn scan_target(&mut self, target: &str) -> Result<()> {
        // Resolve target to IP(s)
        let ips = crate::modules::dns::resolve(target).await?;
        for ip in ips {
            self.scan_ip(ip).await?;
        }
        Ok(())
    }

    pub async fn scan_ip(&mut self, target: IpAddr) -> Result<()> {
        eprintln!("  \x1b[36m⟐\x1b[0m  Scanning \x1b[1;37m{}\x1b[0m ...", target);
        let mut tasks = FuturesUnordered::new();

        for &module in &self.modules {
            let permit = self.semaphore.clone().acquire_owned().await?;
            let ip = target;
            let rf_iface = self.rf_interface.clone();
            let bezier_res = self.bezier_res;

            let proxy = self.proxy_manager.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                match module {
                    Module::Arp => arp::arp_scan(ip).await.map(|o| ModuleOutput::Arp(o)),
                    Module::Syn => syn::syn_scan(ip, &proxy).await.map(|o| ModuleOutput::Syn(o)),
                    Module::Service => service::fingerprint_services(ip, &proxy).await.map(|o| ModuleOutput::Service(o)),
                    Module::Dns => dns::dns_harvest(&ip.to_string()).await.map(|o| ModuleOutput::Dns(o)),
                    #[cfg(feature = "l1_rf")]
                    Module::Rf => {
                        if let Some(iface) = rf_iface {
                            l1_rf::scan_rf_fingerprint(&iface, bezier_res).await.map(|o| ModuleOutput::Rf(o))
                        } else {
                            Err(BlackWraithError::Rf("No interface specified".into()))
                        }
                    }
                    #[cfg(feature = "hypervisor")]
                    Module::Hypervisor => hypervisor::detect_hypervisor(ip, &proxy).await.map(|o| ModuleOutput::Hypervisor(o)),
                    #[cfg(feature = "iot")]
                    Module::Iot => iot::scan_iot_network(ip, &proxy).await.map(|o| ModuleOutput::Iot(o)),
                    #[cfg(feature = "l7_cloud")]
                    Module::Cloud => l7_cloud::enumerate_cloud(&ip.to_string(), &proxy).await.map(|o| ModuleOutput::Cloud(o)),
                    #[cfg(feature = "l7_ai")]
                    Module::Ai => l7_ai::scan_ai_infrastructure(ip, &proxy).await.map(|o| ModuleOutput::Ai(o)),
                    #[cfg(feature = "l7_web")]
                    Module::WebFull => l7_web::full_web_assessment(&format!("http://{}", ip), &proxy).await.map(|o| ModuleOutput::Web(o)),
                    Module::BreachEvasion => adversarial::breach_evasion::assess(ip, &proxy).await.map(|o| ModuleOutput::BreachEvasion(o)),
                    Module::ExploitDevelopment => adversarial::exploit_development::assess(ip, &proxy).await.map(|o| ModuleOutput::ExploitDev(o)),
                    Module::WebExpert => adversarial::web_expert::assess(&format!("http://{}", ip), &proxy).await.map(|o| ModuleOutput::WebExpert(o)),
                    Module::ExtremeExploitation => adversarial::extreme_exploitation::assess(ip, &proxy).await.map(|o| ModuleOutput::Extreme(o)),
                    Module::Evasion => evasion::check_evasion_capabilities(ip, &proxy).await.map(|o| ModuleOutput::Evasion(o)),
                }
            }));
        }

        while let Some(result) = tasks.next().await {
            match result {
                Ok(Ok(output)) => self.report.merge(output),
                Ok(Err(e)) => eprintln!("  \x1b[31m✗\x1b[0m  Module error: {}", e),
                Err(e) => eprintln!("  \x1b[31m✗\x1b[0m  Task panic: {}", e),
            }
        }

        // Update manifold with new findings
        self.manifold.update(&self.report);
        Ok(())
    }

    #[cfg(feature = "l7_web")]
    pub async fn scan_url(&mut self, url: &str) -> Result<()> {
        let output = l7_web::full_web_assessment(url, &self.proxy_manager).await?;
        self.report.merge(ModuleOutput::Web(output));
        Ok(())
    }

    #[cfg(not(feature = "l7_web"))]
    pub async fn scan_url(&mut self, _url: &str) -> Result<()> {
        eprintln!("[!] Web module not compiled – enable 'l7_web' feature");
        Ok(())
    }

    #[cfg(feature = "l1_rf")]
    pub async fn scan_rf(&mut self) -> Result<()> {
        if let Some(iface) = &self.rf_interface {
            let output = l1_rf::scan_rf_fingerprint(iface, self.bezier_res).await?;
            self.report.merge(ModuleOutput::Rf(output));
            Ok(())
        } else {
            Err(BlackWraithError::Rf("No interface".into()))
        }
    }

    #[cfg(not(feature = "l1_rf"))]
    pub async fn scan_rf(&mut self) -> Result<()> {
        eprintln!("[!] RF module not compiled – enable 'l1_rf' feature");
        Ok(())
    }

    pub async fn finalize(&mut self) -> Result<()> {
        // Compute exploitability geodesics
        let curvature = self.manifold.compute_curvature();
        self.report.manifold_curvature = Some(curvature);

        // Generate ATT&CK chains
        if self.predict_chains {
            let chains = self.policy.suggest_chains(&self.report);
            self.report.campaign_attribution = chains;
        }

        let json = serde_json::to_string_pretty(&self.report)?;
        if let Some(path) = &self.output_path {
            tokio::fs::write(path, json).await?;
        } else {
            println!("{}", json);
        }
        Ok(())
    }
}