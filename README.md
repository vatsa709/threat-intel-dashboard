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

## 🔑 API Setup

This project relies on data from APIs such as VirusTotal, Shodan, AbuseIPDB, OTX, etc.

### Step 1: Create `config.json`

In the root of the project, create a file named `config.json`:

```json
{
    "api_keys": {
        "virustotal": "YOUR_VT_API_KEY",
        "otx": "YOUR_OTX_API_KEY", 
        "shodan": "YOUR_SHODAN_API_KEY",
        "abuseipdb": "YOUR_ABUSEIPDB_API_KEY"
    }
}


