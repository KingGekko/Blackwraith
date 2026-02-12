use crate::error::Result;
use crate::modules::ai_analysis::AIAnalyzer;
use crate::core::executor::ToolExecutor;
use crate::output::ScanReport;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Orchestrator {
    analyzer: AIAnalyzer,
    report: Arc<Mutex<ScanReport>>,
}

impl Orchestrator {
    pub fn new(analyzer: AIAnalyzer, report: Arc<Mutex<ScanReport>>) -> Self {
        Self { analyzer, report }
    }

    pub async fn run_reasoning_loop(&self, target: &str) -> Result<()> {
        let mut loop_count = 0;
        let max_loops = 5;

        while loop_count < max_loops {
            let current_json = {
                let report = self.report.lock().await;
                serde_json::to_string(&*report)?
            };

            let next_command = self.analyzer.get_next_command(&current_json).await?;
            if next_command.to_lowercase() == "none" || next_command.is_empty() {
                println!("\x1b[32m[AI Orchestration]\x1b[0m AI core finished - No further actions recommended.");
                break;
            }

            // Extract open ports for the <PORTS> placeholder
            let ports_str = {
                let report = self.report.lock().await;
                if let Some(syn) = &report.syn {
                    syn.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
                } else {
                    "80,443".to_string()
                }
            };

            // Sanitize command
            let sanitized_cmd = next_command
                .replace("<TARGET>", target)
                .replace("$TARGET", target)
                .replace("<PORTS>", &ports_str)
                .trim_matches('`')
                .trim_matches('"')
                .trim()
                .to_string();
            
            println!("\x1b[35m[AI Reasoning]\x1b[0m Executing: \x1b[1m{}\x1b[0m", sanitized_cmd);

            let output = ToolExecutor::execute(&sanitized_cmd).await?;
            let assessment = self.analyzer.assess_output(&output).await?;
            
            println!("\x1b[35m[AI Assessment]\x1b[0m {}", assessment);

            // Extract MITRE Techniques (T1234) from assessment
            let mut techniques = Vec::new();
            let re = regex::Regex::new(r"T\d{4}")?;
            for mat in re.find_iter(&assessment) {
                let tid = mat.as_str().to_string();
                techniques.push(crate::output::Technique {
                    technique_id: tid,
                    technique_name: "AI Identified Pathway".into(),
                    confidence: 0.8,
                    evidence: serde_json::Value::String(assessment.clone()),
                });
            }

            // Sync structural finding and techniques back to report
            {
                let mut report = self.report.lock().await;
                report.add_ai_finding(&sanitized_cmd, &assessment, techniques);
            }

            loop_count += 1;
        }

        Ok(())
    }
}
