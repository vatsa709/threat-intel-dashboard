# 🛡️ Threat Intelligence Dashboard

A Flask-based dashboard to collect and visualize cybersecurity threat intelligence.

## 📦 Features

- Collects live CVE, IOC, and threat actor data from:
  - NVD, ExploitDB, VirusTotal, AbuseIPDB, OTX, Shodan, RSS Feeds, GitHub
- SQLite database backend
- Dynamic dashboard with real-time metrics

## 🚀 How to Use

```bash
# Install dependencies
pip install -r requirements.txt

# Collect latest data
python3 threat_collector.py

# Start the dashboard
python3 app.py
