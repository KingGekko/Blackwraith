use crate::error::Result;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct OllamaResponse {
    response: String,
}

pub struct AIAnalyzer {
    url: String,
    model: String,
}

impl AIAnalyzer {
    pub fn new(url: String, model: String) -> Self {
        Self { url, model }
    }

    pub async fn get_next_command(&self, current_report: &str) -> Result<String> {
        let client = Client::new();

        let tool_knowledge = "
You are an expert security orchestrator with deep knowledge of ALL local-only Kali Linux tools.
Based on the provided scan results, recommend the SINGLE most effective command to run next.
Use <TARGET> as a placeholder for the target IP or domain and <PORTS> for discovered ports.

CRITICAL RULE: NEVER recommend tools that require external API keys or cloud credentials (e.g., Shodan, Censys). Use ONLY local-running binaries.

CORE SYNERGY RULES:
1. Trust findings from core modules (ARP, SYN, Service). If a port is marked open, do not try to re-discover it; instead, call a specialized tool (e.g., gobuster for 80, enum4linux for 445).
2. Use core results as a launchpad. Your job is to go beyond what a static scanner can do.
3. If core results are sparse, try local OSINT tools (`assetfinder`, `dnsrecon`) to widen the attack surface.

CATEGORIES & RECOMMENDED UTILITIES:
- Web Discovery: gobuster dir -u <TARGET> -w /usr/share/wordlists/dirb/common.txt, ffuf, nikto -h <TARGET>, feroxbuster -u <TARGET>, wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt --hc 404 <TARGET>/FUZZ
- Web Vuln: sqlmap -u <TARGET> --batch, commix -u <TARGET>, wpscan --url <TARGET>
- Network/SMB: enum4linux-ng <TARGET>, smbmap -H <TARGET>, smbclient -L //<TARGET>/, rpcdump.py <TARGET>, nmap -sC -sV -p<PORTS> <TARGET>
- SNMP/TFTP: snmp-check <TARGET>, onesixtyone <TARGET>, atftp <TARGET>
- Auth: hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET> <SERVICE>, crackmapexec smb <TARGET>, john <HASHFILE>, hashcat -m 0 <HASHFILE> /usr/share/wordlists/rockyou.txt
- OSINT/DNS: dnsrecon -d <TARGET>, assetfinder <TARGET>, sublist3r -d <TARGET> (local mode)
- DB: odat all -s <TARGET>, sqsh -S <TARGET> -U sa, mysql -h <TARGET>, psql -h <TARGET>
- Wireless/RF: wifite, reaver -i <IFACE> -b <BSSID>, aircrack-ng <FILE>
- IoT/Industrial: binwalk -e <FILE>, modbus-cli --tcp <TARGET> read_coils 0 10
- Cloud (Local Tools): cloud_enum -k <KEYWORD>, pacu --cmd 'run help', scoutsuite -p <PROVIDER>
- Post-Ex/AD: bloodhound-python -u <USER> -p <PASS> -d <DOMAIN> -c All, certipy find -u <USER>@<DOMAIN>, linpeas.sh
- Lateral Move: wmiexec.py <USER>:<PASS>@<TARGET>, smbexec.py <USER>:<PASS>@<TARGET>, psexec.py <USER>:<PASS>@<TARGET>
- Packet Eng: hping3 -S <TARGET> -p 80, scapy
- Forensics: volatility -f <IMAGE> --profile=<P> pslist, sleuthkit fls <IMAGE>
- Reverse Eng: radare2 <BIN>, gdb <BIN>, apktool d <APK>
- Sniff/Spoof: responder -I <IFACE>, bettercap -iface <IFACE>, ettercap -T -q -i <IFACE>
- Exploitation: searchsploit <SERVICE>, msfconsole -q -x 'use ...; set RHOSTS <TARGET>; run; exit'

FINAL RULES:
1. Reply ONLY with the command string. No explanations. Use <TARGET> and <PORTS>.
2. If mission complete, reply 'NONE'.
3. Prioritize precision over volume.
";

        let prompt = format!(
            "{}\n\nCURRENT SCAN RESULTS (JSON):\n{}",
            tool_knowledge,
            current_report
        );

        let req = OllamaRequest {
            model: self.model.clone(),
            prompt,
            stream: false,
        };

        let resp = client.post(format!("{}/api/generate", self.url))
            .json(&req)
            .timeout(Duration::from_secs(60))
            .send()
            .await?
            .json::<OllamaResponse>()
            .await?;

        Ok(resp.response.trim().to_string())
    }

    pub async fn assess_output(&self, output: &str) -> Result<String> {
        let client = Client::new();
        let prompt = format!(
            "Analyze this tool output. Does it reveal a significant vulnerability or an easy path for exploitation?
Summarize the risk in 1 sentence and INCLUDE the relevant MITRE ATT&CK technique ID (e.g., T1190, T1068, T1046) if applicable.

OUTPUT:
{}",
            output
        );

        let req = OllamaRequest {
            model: self.model.clone(),
            prompt,
            stream: false,
        };

        let resp = client.post(format!("{}/api/generate", self.url))
            .json(&req)
            .timeout(Duration::from_secs(30))
            .send()
            .await?
            .json::<OllamaResponse>()
            .await?;

        Ok(resp.response.trim().to_string())
    }
}
