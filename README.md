# 🛡️ Threat Intelligence Dashboard

**Collect and visualize critical vulnerabilities, IOCs & threat actors—every 3 days**

A Python‑based dashboard that automates the collection of threat intelligence from multiple public sources and presents it in an interactive web UI.

---

## 🎯 Motivation & Value

* **Why every 3 days?**
  Newly disclosed vulnerabilities are weaponized within 2–3 weeks, but many organizations lag on patching. By refreshing data every 72 hours, your security team gains early warning of new CVEs, IOCs, and threat reports—so you can triage and remediate faster.

* **Business Impact:**

  * Proactive vulnerability management
  * Consolidated threat actor insights
  * Centralized intelligence feeds for quick decision‑making

---

## ⭐ Key Features

* **Automated 3‑Day Collection** from:

  * **Vulnerabilities:** NVD CVE Database, ExploitDB
  * **Indicators of Compromise (IOCs):** AbuseIPDB, VirusTotal, Shodan, GitHub commits
  * **Threat Reports:** AlienVault OTX, security RSS feeds, MISP (simulated)

* **SQLite Backend**
  Three schematized tables: `vulnerabilities`, `iocs`, `threat_intel`.

* **Python API Endpoints**

  * `/api/dashboard-data` — metrics & aggregates
  * `/api/vulnerabilities` & `/api/iocs` — paginated detail endpoints

* **Interactive Dashboard (HTML + JavaScript)**

  * Critical Vulnerabilities
  * Indicators of Compromise
  * Active Threat Actors
  * Intelligence Sources
  * Automatic refresh button & connection status

* **Config‑Driven**
  Easily add/remove feeds, repos, or adjust collection parameters via `config.json`.

---

## 📁 Project Structure

```
threat-intel-dashboard/
├── app.py                  # Python web server & API
├── threat_collector.py     # Data collection engine
├── config_sample.json      # Template for user API keys & feeds
├── requirements.txt        # Python dependencies
├── templates/
│   └── dashboard.html      # Front‑end UI
├── static/                 # Static assets (CSS, JS, images)
├── .gitignore              # Excludes keys & DB
└── README.md               # This file
```

---

## ⚙️ Prerequisites

* **Python 3.8+**
* **pip**

---

## 🔧 Installation & Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/vatsa709/threat-intel-dashboard.git
   cd threat-intel-dashboard
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API keys & feeds**

   * Copy `config_sample.json` to `config.json` in the project root.
   * Open `config.json` and replace placeholders with your own API keys:

     ```json
     {
       "api_keys": {
         "virustotal": "YOUR_VT_API_KEY",
         "otx":        "YOUR_OTX_API_KEY",
         "shodan":     "YOUR_SHODAN_API_KEY",
         "abuseipdb":  "YOUR_ABUSEIPDB_API_KEY"
       }
     }
     ```
   * **Important:** `config.json` is excluded from version control—ensure it exists before running.

---

## 🚀 Usage

1. **Collect threat data**

   ```bash
   python3 threat_collector.py
   ```

   * Fetches last 3 days of data from all configured sources.
   * Inserts new, deduplicated records into `threat_intelligence.db`.

2. **Start the dashboard**

   ```bash
   python3 app.py
   ```

   * Launches a local web server at `http://localhost:5000`.

3. **View & Interact**

   * Open your browser to `http://localhost:5000`.
   * Click **Refresh Data** to manually re‑query the API.
   * Metrics and tables auto‑update based on the latest DB contents.

---

## 🛠️ Configuration Tips

* **Change collection window**
  In `threat_collector.py`, adjust:

  ```python
  start_date = end_date - timedelta(days=3)
  ```

  to `days=1` or `7` as needed.

* **Wipe old data**
  To collect fresh-only data, add a DB-cleanup step at the top of `collect_all_data()`:

  ```python
  conn.execute("DELETE FROM vulnerabilities")
  conn.execute("DELETE FROM iocs")
  conn.execute("DELETE FROM threat_intel")
  ```

* **Add new feeds or GitHub repos** via `config.json` without changing code.

---

## 📈 How It Works (High‑Level)

1. **Collector** runs (manually or via cron) and queries each source for the defined date range.
2. **Data Processing**:

   * Parses responses, extracts CVE details, IOCs, threat reports.
   * Deduplicates on unique keys (e.g., `cve_id`, `ioc_value`).
3. **Storage**: inserts new entries into SQLite tables.
4. **API**: `app.py` exposes endpoints to fetch aggregates and detailed records.
5. **Dashboard**: AJAX calls render cards, lists, and status indicators in the browser.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/FOO`)
3. Commit your changes (`git commit -m "Add feature FOO"`)
4. Push to your branch (`git push origin feature/FOO`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.

---

## Acknowledgments

* [NVD CVE](https://nvd.nist.gov/)
* [ExploitDB](https://www.exploit-db.com/)
* [VirusTotal](https://www.virustotal.com/)
* [AbuseIPDB](https://www.abuseipdb.com/)
* [AlienVault OTX](https://otx.alienvault.com/)
* [Shodan](https://www.shodan.io/)
* [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)
* [feedparser](https://github.com/kurtmckee/feedparser)

---
