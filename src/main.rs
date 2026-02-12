// BlackWraith 2.0 – Apotheosis Entry Point
// Coloured output, startup banner, ethical warnings, progress feedback

mod core;
mod error;
mod modules;
mod output;
mod scanner;

use clap::{Parser, Subcommand};
use error::Result;
use scanner::ScannerEngine;
use std::path::PathBuf;

const BANNER: &str = r#"
 ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
 ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
 ██████╔╝██║     ███████║██║     █████╔╝ ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
 ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
 ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
"#;

const DISCLAIMER: &str = "\x1b[33m⚠  AUTHORISED USE ONLY — Use exclusively on systems you own or have written permission to test.\x1b[0m";

fn print_banner() {
    eprintln!("\x1b[36m{}\x1b[0m", BANNER);
    eprintln!("  \x1b[1;37mv2.0 Apotheosis\x1b[0m  \x1b[90m│  Memory-safe async reconnaissance engine\x1b[0m");
    eprintln!("  \x1b[90m─────────────────┴────────────────────────────────────────\x1b[0m");
    eprintln!();
    eprintln!("  {}", DISCLAIMER);
    eprintln!();
}

fn status(icon: &str, msg: &str) {
    eprintln!("  \x1b[36m{}\x1b[0m  {}", icon, msg);
}

fn success(msg: &str) {
    eprintln!("  \x1b[32m✓\x1b[0m  {}", msg);
}

fn warn(msg: &str) {
    eprintln!("  \x1b[33m⚠\x1b[0m  \x1b[33m{}\x1b[0m", msg);
}

#[derive(Parser)]
#[command(
    author = "KingGekko",
    version,
    about = "BlackWraith 2.0: Apotheosis – Advanced Security Scanner",
    long_about = "A fast, modern security scanner for authorized testing. Use responsibly on systems you own."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output file (JSON)
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,

    /// Concurrent task limit
    #[arg(long, default_value_t = 100, global = true)]
    concurrency: usize,

    /// Less output, no banner
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Show more details during scan
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Use a proxy (e.g., socks5://127.0.0.1:9050)
    #[arg(long, global = true)]
    proxy: Option<String>,

    /// Timeout for network operations in milliseconds
    #[arg(long, global = true, default_value_t = 3000)]
    timeout: u64,

    /// Predict attack chains (slow, uses AI)
    #[arg(long, global = true)]
    predict_chains: bool,

    /// Enable AI Orchestration (Apotheosis Mode)
    #[arg(long, global = true)]
    auto: bool,

    /// Ollama API URL (default: http://localhost:11434)
    #[arg(long, global = true, default_value = "http://localhost:11434")]
    ollama: String,

    /// AI Model for reasoning (default: llama3)
    #[arg(long, global = true, default_value = "llama3")]
    model: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Standard network scan (ports, services, cloud, AI)
    Full {
        /// Target IP or domain (e.g., 10.10.10.1)
        target: String,

        /// Scan for radio signals (requires special hardware + monitor mode)
        #[arg(long)]
        rf: bool,

        /// Detect Virtual Machines / Hypervisors
        #[arg(long)]
        hypervisor: bool,

        /// Check for public cloud buckets (AWS/Azure/GCP)
        #[arg(long)]
        cloud: bool,

        /// Scan for AI/LLM servers and vulnerabilities
        #[arg(long)]
        ai: bool,

        /// Use stealthy techniques (slower, harder to detect)
        #[arg(long)]
        stealth: bool,
    },

    /// Scan a website for vulnerabilities
    Web {
        /// URL to scan (e.g., https://example.com)
        url: String,

        /// Run ALL checks (XSS, SQLi, etc.) - takes longer
        #[arg(long)]
        all: bool,
    },

    /// RF fingerprint collection
    Rf {
        /// Network interface in monitor mode
        #[arg(short, long)]
        interface: String,

        /// Bézier surface resolution (default: 16×16)
        #[arg(long, default_value_t = 16)]
        bezier_res: usize,
    },

    /// Advanced adversarial exploitation pathways
    Adversarial {
        /// Target IP
        target: String,

        /// Breach & Evasion — AMSI bypass, AppLocker escape, credential extraction
        #[arg(long)]
        breach_evasion: bool,

        /// Exploit Development — SEH overwrites, egg hunters, pool grooming
        #[arg(long)]
        exploit_dev: bool,

        /// Web Expert — Java deser, ViewState forgery, CSRF→RCE
        #[arg(long)]
        web_expert: bool,

        /// Extreme Exploitation — Kernel exploits, VMware escape, Secure Boot
        #[arg(long)]
        extreme: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.quiet {
        print_banner();
    }

    let mut engine = ScannerEngine::new(cli.concurrency);
    engine.set_output(cli.output);
    if let Some(proxy) = cli.proxy {
        engine.set_proxy(proxy);
    }
    engine.set_timeout(cli.timeout);
    engine.set_predict_chains(cli.predict_chains);

    let target = match &cli.command {
        Commands::Full { target, .. } => target.clone(),
        Commands::Web { url, .. } => url.clone(),
        Commands::Rf { .. } => "RF_INTERFACE".to_string(),
        Commands::Adversarial { target, .. } => target.clone(),
    };

    match cli.command {
        Commands::Full { target, rf, hypervisor, cloud, ai, stealth } => {
            status("⟐", &format!("Target: \x1b[1;37m{}\x1b[0m", target));
            status("◈", &format!("Concurrency: {} tasks", cli.concurrency));
            eprintln!();

            engine.enable_all_basic();

            let mut extras = Vec::new();
            if rf { engine.enable_rf(); extras.push("RF"); }
            if hypervisor { engine.enable_hypervisor(); extras.push("Hypervisor"); }
            if cloud { engine.enable_cloud(); extras.push("Cloud"); }
            if ai { engine.enable_ai(); extras.push("AI/MCP"); }
            if stealth { engine.enable_evasion(); extras.push("Stealth"); }

            status("▶", "Modules: ARP, SYN, Service, DNS");
            if !extras.is_empty() {
                status("▶", &format!("Extended: {}", extras.join(", ")));
            }
            eprintln!();

            engine.scan_target(&target).await?;
        }
        Commands::Web { url, all } => {
            status("⟐", &format!("Target: \x1b[1;37m{}\x1b[0m", url));
            status("▶", if all { "Mode: Full web assessment (all classes)" } else { "Mode: Basic web checks" });
            eprintln!();

            engine.enable_web();
            if all { engine.enable_web_full(); }
            engine.scan_url(&url).await?;
        }
        Commands::Rf { interface, bezier_res } => {
            status("⟐", &format!("Interface: \x1b[1;37m{}\x1b[0m", interface));
            status("◈", &format!("Bézier resolution: {}×{}", bezier_res, bezier_res));
            eprintln!();

            engine.set_rf_interface(interface);
            engine.set_bezier_resolution(bezier_res);
            engine.enable_rf();
            engine.scan_rf().await?;
        }
        Commands::Adversarial { target, breach_evasion, exploit_dev, web_expert, extreme } => {
            status("⟐", &format!("Target: \x1b[1;37m{}\x1b[0m", target));

            let mut pathways = Vec::new();
            if breach_evasion { engine.enable_breach_evasion(); pathways.push("BAE"); }
            if exploit_dev { engine.enable_exploit_development(); pathways.push("WED"); }
            if web_expert { engine.enable_web_expert(); pathways.push("WEX"); }
            if extreme { engine.enable_extreme_exploitation(); pathways.push("XEE"); }

            if pathways.is_empty() {
                warn("No adversarial pathways selected — use --breach-evasion, --exploit-dev, --web-expert, or --extreme");
                return Ok(());
            }

            status("▶", &format!("Pathways: {}", pathways.join(", ")));
            eprintln!();

            engine.scan_target(&target).await?;
        }
    }

    if cli.auto {
        status("🧠", "Engaging Apotheosis AI Orchestration...");
        let analyzer = crate::modules::ai_analysis::AIAnalyzer::new(cli.ollama, cli.model);
        let orchestrator = crate::core::orchestrator::Orchestrator::new(analyzer, engine.get_report());
        orchestrator.run_reasoning_loop(&target).await?;
    }

    if !cli.quiet {
        eprintln!();
        status("◈", "Finalising report...");
    }

    engine.finalize().await?;

    if !cli.quiet {
        success("Scan complete.");
        eprintln!();
    }

    Ok(())
}