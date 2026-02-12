<div align="center">

# BlackWraith 2.0

**Advanced Security Scanner**

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-f74c00?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Kali Ready](https://img.shields.io/badge/Kali-Ready-blue?style=for-the-badge&logo=kalilinux)](https://www.kali.org)

BlackWraith is a modern, high-speed security scanner designed for authorized penetration testing. It replaces legacy enumeration scripts with a faster, safer, and more powerful engine.

> [!IMPORTANT]
> **Use this tool responsibly.** Only scan systems you own or have permission to test.
</div>

---

## 🚀 Quick Usage

BlackWraith is a localized binary. Simply run it from your terminal.

### Basic Network Scan
Scan a target IP to see open ports and services:
```bash
./blackwraith full 10.10.10.15
```

### Web Vulnerability Scan
Check a website for vulnerabilities like XSS, SQLi, and more:
```bash
./blackwraith web https://example.com --all
```

### Anonymity (SOCKS5 Proxy)
Scan through Tor or an SSH tunnel for anonymity:
```bash
./blackwraith full 10.10.10.15 --proxy socks5://127.0.0.1:9050
```

---

## 📚 Command Reference

| Command | What it does | Example |
| :--- | :--- | :--- |
| `full` | Standard network scan | `./blackwraith full <IP>` |
| `web` | Web vulnerability scan | `./blackwraith web <URL>` |
| `--stealth` | Slower scan to avoid detection | `./blackwraith full <IP> --stealth` |
| `--cloud` | Check for public cloud buckets | `./blackwraith full <IP> --cloud` |
| `--ai` | Scan for AI/LLM servers | `./blackwraith full <IP> --ai` |
| `--predict-chains` | AI predicts attack paths (Slow) | `./blackwraith full <IP> --predict-chains` |

---

## ✨ Extra Features

<details>
<summary><b>View Research Capabilities</b></summary>

### 🌀 Temporal Vulnerability Manifolds
BlackWraith models the attack surface using Riemannian geometry. It calculates the "curvature" of the vulnerability landscape to predict how easily different exploits can be chained together.

### 📡 RF Fingerprinting
Identify hardware radio signatures using standard network cards (requires monitor mode). It uses Bézier surface fitting to distinguish between devices.

### 🤖 AI Infrastructure Attacks
Specialized modules to detect and audit Model Context Protocol (MCP) endpoints, looking for prompt injection and data exfiltration risks.

</details>

---

<div align="center">
<b>Research • Ethics • Security</b>
</div>