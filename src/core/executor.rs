use std::process::Command;
use crate::error::Result;
use std::time::Duration;
use tokio::process::Command as TokioCommand;

pub struct ToolExecutor;

impl ToolExecutor {
    pub async fn execute(cmd_str: &str) -> Result<String> {
        let parts: Vec<&str> = cmd_str.split_whitespace().collect();
        if parts.is_empty() {
            return Err(crate::error::BlackWraithError::Internal("Empty command".to_string()));
        }

        let program = parts[0];
        let args = &parts[1..];

        let mut child = TokioCommand::new(program)
            .args(args)
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&child.stdout).to_string();
        let stderr = String::from_utf8_lossy(&child.stderr).to_string();

        Ok(format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr))
    }
}
