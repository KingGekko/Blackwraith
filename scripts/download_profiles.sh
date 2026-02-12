#!/bin/bash
# Download wordlists, RF fingerprint databases, APT playbooks

mkdir -p data/wordlists
mkdir -p data/rf_fingerprints
mkdir -p data/playbooks

# BlackWraith Web Exploitation Framework wordlists
curl -o data/wordlists/web_directories.txt https://raw.githubusercontent.com/blackwraith/wordlists/main/web_directories.txt
curl -o data/wordlists/ssti_payloads.txt https://raw.githubusercontent.com/blackwraith/wordlists/main/ssti.txt

echo "[+] Profiles downloaded."