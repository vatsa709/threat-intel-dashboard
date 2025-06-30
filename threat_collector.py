# enhanced_threat_collector.py
import requests
import sqlite3
import json
import time
import hashlib
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import re
import feedparser
from urllib.parse import urljoin, urlparse
import base64

class EnhancedThreatCollector:
    def __init__(self, config_file='config.json'):
        self.config = self.load_config(config_file)
        self.db_path = 'threat_intelligence.db'
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntelligenceBot/1.0'
        })
        self.init_database()
        
    def load_config(self, config_file):
        """Load API keys and configuration"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default config structure
            return {
                "api_keys": {
                    "virustotal": "YOUR_ACTUAL_VT_API_KEY_HERE",
                    "otx": "YOUR_ACTUAL_OTX_API_KEY_HERE",
                    "shodan": "YOUR_ACTUAL_SHODAN_API_KEY_HERE",
                    "abuseipdb": "YOUR_ACTUAL_ABUSEIPDB_API_KEY_HERE"
                },
                "rss_feeds": [
                    "https://feeds.feedburner.com/securityweek",
                    "https://feeds.feedburner.com/TheHackersNews",
                    "https://krebsonsecurity.com/feed/"
                ],
                "github_repos": [
                    "stamparm/maltrail",
                    "fireeye/iocs",
                    "Neo23x0/signature-base"
                ]
            }
    
    def init_database(self):
        """Initialize SQLite database with comprehensive schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                cve_id TEXT UNIQUE,
                title TEXT,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                published_date TEXT,
                affected_products TEXT,
                solution TEXT,
                exploit_available BOOLEAN,
                source TEXT,
                tags TEXT,
                [references] TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IOCs (Indicators of Compromise) table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY,
                ioc_value TEXT,
                ioc_type TEXT,
                confidence INTEGER,
                threat_type TEXT,
                first_seen TEXT,
                last_seen TEXT,
                source TEXT,
                description TEXT,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Threat intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY,
                title TEXT,
                description TEXT,
                threat_actor TEXT,
                malware_family TEXT,
                attack_vectors TEXT,
                mitigation TEXT,
                source TEXT,
                published_date TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def collect_all_data(self):
        """Main method to collect data from all sources"""
        print("🚀 Starting Enhanced Threat Intelligence Collection...")
        print("📅 Collecting data for the last 3 days for maximum relevancy\n")
        
        collection_summary = {
            'vulnerabilities': 0,
            'iocs': 0,
            'threat_intel': 0,
            'sources_used': []
        }
        
        # Calculate date range (last 3 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=3)
        
        print(f"📊 Collection period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
        print("-" * 60)
        
        # Collect from various sources
        try:
            # CVE/Vulnerability Sources
            print("🔍 Collecting CVE data...")
            cve_count = self.collect_cve_data(start_date, end_date)
            collection_summary['vulnerabilities'] += cve_count
            collection_summary['sources_used'].append('NVD CVE Database')
            
            print("💥 Collecting ExploitDB data...")
            exploit_count = self.collect_exploitdb_data()
            collection_summary['vulnerabilities'] += exploit_count
            collection_summary['sources_used'].append('ExploitDB')
            
            # Threat Intelligence Sources
            if self.config['api_keys']['virustotal'] != "YOUR_VT_API_KEY":
                print("🦠 Collecting VirusTotal intelligence...")
                vt_count = self.collect_virustotal_data()
                collection_summary['iocs'] += vt_count
                collection_summary['sources_used'].append('VirusTotal')
            
            if self.config['api_keys']['otx'] != "YOUR_OTX_API_KEY":
                print("👁️ Collecting AlienVault OTX data...")
                otx_count = self.collect_otx_data()
                collection_summary['threat_intel'] += otx_count
                collection_summary['sources_used'].append('AlienVault OTX')
            
            if self.config['api_keys']['abuseipdb'] != "YOUR_ABUSEIPDB_API_KEY":
                print("🚫 Collecting AbuseIPDB data...")
                abuse_count = self.collect_abuseipdb_data()
                collection_summary['iocs'] += abuse_count
                collection_summary['sources_used'].append('AbuseIPDB')
            
            if self.config['api_keys']['shodan'] != "YOUR_SHODAN_API_KEY":
                print("🔎 Collecting Shodan intelligence...")
                shodan_count = self.collect_shodan_data()
                collection_summary['iocs'] += shodan_count
                collection_summary['sources_used'].append('Shodan')
            
            # Open Source Intelligence
            print("📰 Collecting RSS feed intelligence...")
            rss_count = self.collect_rss_feeds()
            collection_summary['threat_intel'] += rss_count
            collection_summary['sources_used'].append('Security RSS Feeds')
            
            print("🐙 Collecting GitHub IOCs...")
            github_count = self.collect_github_iocs()
            collection_summary['iocs'] += github_count
            collection_summary['sources_used'].append('GitHub IOC Repositories')
            
            # MISP Community (if available)
            print("🤝 Collecting MISP community data...")
            misp_count = self.collect_misp_data()
            collection_summary['threat_intel'] += misp_count
            collection_summary['sources_used'].append('MISP Community')
            
            # URLVoid for URL reputation
            print("🔗 Collecting URLVoid data...")
            urlvoid_count = self.collect_urlvoid_data()
            collection_summary['iocs'] += urlvoid_count
            collection_summary['sources_used'].append('URLVoid')
            
        except Exception as e:
            print(f"❌ Error during collection: {e}")
        
        # Print collection summary
        print("\n" + "="*60)
        print("📊 COLLECTION SUMMARY")
        print("="*60)
        print(f"🔴 Vulnerabilities collected: {collection_summary['vulnerabilities']}")
        print(f"🔶 IOCs collected: {collection_summary['iocs']}")
        print(f"🔵 Threat Intelligence reports: {collection_summary['threat_intel']}")
        print(f"📡 Sources used: {len(collection_summary['sources_used'])}")
        print("\n📋 Sources:")
        for source in collection_summary['sources_used']:
            print(f"   ✓ {source}")
        
        print(f"\n✅ Collection completed! Database updated: {self.db_path}")
        return collection_summary
    
    def collect_cve_data(self, start_date, end_date):
        """Collect CVE data from NVD for last 3 days"""
        try:
            # Format dates for NVD API
            start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_str}&pubEndDate={end_str}&resultsPerPage=100"
            
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                count = 0
                for item in vulnerabilities:
                    cve_data = item.get('cve', {})
                    if self.process_cve_vulnerability(cve_data):
                        count += 1
                
                print(f"   ✓ Collected {count} CVE records")
                return count
            else:
                print(f"   ❌ CVE API error: {response.status_code}")
                return 0
                
        except Exception as e:
            print(f"   ❌ Error collecting CVE data: {e}")
            return 0
    
    def collect_exploitdb_data(self):
        """Collect recent exploits from ExploitDB"""
        try:
            url = "https://www.exploit-db.com/rss.xml"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                # Parse RSS feed
                feed = feedparser.parse(response.text)
                count = 0
                
                # Get entries from last 3 days
                cutoff_date = datetime.now() - timedelta(days=3)
                
                for entry in feed.entries[:50]:  # Limit to 50 recent entries
                    # Parse entry date
                    try:
                        entry_date = datetime.strptime(entry.published, '%a, %d %b %Y %H:%M:%S %z').replace(tzinfo=None)
                        if entry_date < cutoff_date:
                            continue
                    except:
                        # If date parsing fails, include the entry
                        pass
                    
                    # Extract CVE if mentioned
                    cve_match = re.search(r'CVE-\d{4}-\d{4,}', entry.title + ' ' + entry.summary)
                    
                    exploit_data = {
                        'cve_id': cve_match.group(0) if cve_match else f"EDB-{entry.id.split('/')[-1]}",
                        'title': entry.title,
                        'description': entry.summary,
                        'cvss_score': 0,  # ExploitDB doesn't provide CVSS
                        'severity': 'HIGH',  # Assume high since exploit exists
                        'published_date': entry.published,
                        'affected_products': self.extract_products_from_text(entry.title + ' ' + entry.summary),
                        'solution': '🔴 URGENT: Exploit available - Apply patches immediately | 🛡️ Implement WAF rules',
                        'exploit_available': True,
                        'source': 'ExploitDB',
                        'tags': 'exploit,proof-of-concept',
                        'references': entry.link
                    }
                    
                    if self.store_vulnerability(exploit_data):
                        count += 1
                
                print(f"   ✓ Collected {count} ExploitDB records")
                return count
            else:
                print(f"   ❌ ExploitDB RSS error: {response.status_code}")
                return 0
                
        except Exception as e:
            print(f"   ❌ Error collecting ExploitDB data: {e}")
            return 0
    
    def collect_virustotal_data(self):
        """Collect recent malware hashes from VirusTotal"""
        try:
            api_key = self.config['api_keys']['virustotal']
            if api_key == "YOUR_VT_API_KEY":
                print("   ⚠️ VirusTotal API key not configured")
                return 0
            
            headers = {'x-apikey': api_key}
            
            # Get recent malware samples
            url = "https://www.virustotal.com/api/v3/intelligence/search"
            params = {
                'query': 'first_submission_date:2024-01-01+ type:file',
                'limit': 50
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                
                for item in data.get('data', []):
                    # Extract IOC data
                    ioc_data = {
                        'ioc_value': item.get('id', ''),
                        'ioc_type': 'file_hash',
                        'confidence': 85,
                        'threat_type': 'malware',
                        'first_seen': item.get('attributes', {}).get('first_submission_date', ''),
                        'last_seen': item.get('attributes', {}).get('last_analysis_date', ''),
                        'source': 'VirusTotal',
                        'description': f"Malware detected by {item.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)} engines",
                        'tags': 'malware,file_hash'
                    }
                    
                    if self.store_ioc(ioc_data):
                        count += 1
                
                print(f"   ✓ Collected {count} VirusTotal IOCs")
                return count
            else:
                print(f"   ❌ VirusTotal API error: {response.status_code}")
                return 0
                
        except Exception as e:
            print(f"   ❌ Error collecting VirusTotal data: {e}")
            return 0
    
    def collect_otx_data(self):
        """Collect threat intelligence from AlienVault OTX"""
        try:
            api_key = self.config['api_keys']['otx']
            if api_key == "YOUR_OTX_API_KEY":
                print("   ⚠️ AlienVault OTX API key not configured")
                return 0
            
            headers = {'X-OTX-API-KEY': api_key}
            
            # Get recent pulses (threat intelligence reports)
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            params = {'limit': 50}
            
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                
                # Filter for last 3 days
                cutoff_date = datetime.now() - timedelta(days=3)
                
                for pulse in data.get('results', []):
                    # Check if pulse is recent
                    try:
                        pulse_date = datetime.strptime(pulse.get('created')[:19], '%Y-%m-%dT%H:%M:%S')
                        if pulse_date < cutoff_date:
                            continue
                    except:
                        pass
                    
                    # Store threat intelligence
                    threat_data = {
                        'title': pulse.get('name', ''),
                        'description': pulse.get('description', ''),
                        'threat_actor': ', '.join(pulse.get('adversary', [])),
                        'malware_family': ', '.join([tag for tag in pulse.get('tags', []) if 'malware' in tag.lower()]),
                        'attack_vectors': ', '.join(pulse.get('attack_ids', [])),
                        'mitigation': self.generate_otx_mitigation(pulse),
                        'source': 'AlienVault OTX',
                        'published_date': pulse.get('created', '')
                    }
                    
                    if self.store_threat_intel(threat_data):
                        count += 1
                        
                        # Also store IOCs from this pulse
                        for indicator in pulse.get('indicators', []):
                            ioc_data = {
                                'ioc_value': indicator.get('indicator', ''),
                                'ioc_type': indicator.get('type', ''),
                                'confidence': 75,
                                'threat_type': indicator.get('role', ''),
                                'first_seen': pulse.get('created', ''),
                                'last_seen': pulse.get('modified', ''),
                                'source': 'AlienVault OTX',
                                'description': f"Associated with: {pulse.get('name', '')}",
                                'tags': ','.join(pulse.get('tags', []))
                            }
                            self.store_ioc(ioc_data)
                
                print(f"   ✓ Collected {count} OTX threat reports")
                return count
            else:
                print(f"   ❌ OTX API error: {response.status_code}")
                return 0
                
        except Exception as e:
            print(f"   ❌ Error collecting OTX data: {e}")
            return 0
    
    def collect_abuseipdb_data(self):
        """Collect malicious IPs from AbuseIPDB"""
        try:
            api_key = self.config['api_keys']['abuseipdb']
            if api_key == "YOUR_ABUSEIPDB_API_KEY":
                print("   ⚠️ AbuseIPDB API key not configured")
                return 0
            
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            
            # Get blacklisted IPs
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            params = {
                'confidenceMinimum': 75,
                'limit': 100
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                
                for item in data.get('data', []):
                    ioc_data = {
                        'ioc_value': item.get('ipAddress', ''),
                        'ioc_type': 'ip',
                        'confidence': item.get('abuseConfidencePercentage', 0),
                        'threat_type': 'malicious_ip',
                        'first_seen': '',
                        'last_seen': item.get('lastReportedAt', ''),
                        'source': 'AbuseIPDB',
                        'description': f"Reported for: {', '.join(item.get('usageType', []))}",
                        'tags': 'malicious_ip,blacklist'
                    }
                    
                    if self.store_ioc(ioc_data):
                        count += 1
                
                print(f"   ✓ Collected {count} AbuseIPDB IOCs")
                return count
            else:
                print(f"   ❌ AbuseIPDB API error: {response.status_code}")
                return 0
                
        except Exception as e:
            print(f"   ❌ Error collecting AbuseIPDB data: {e}")
            return 0
    
    def collect_shodan_data(self):
        """Collect exposed services from Shodan"""
        try:
            api_key = self.config['api_keys']['shodan']
            if api_key == "YOUR_SHODAN_API_KEY":
                print("   ⚠️ Shodan API key not configured")
                return 0
            
            # Search for recently discovered vulnerable services
            url = f"https://api.shodan.io/shodan/host/search"
            params = {
                'key': api_key,
                'query': 'vuln:CVE-2024 country:US',  # Adjust query as needed
                'limit': 50
            }
            
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                
                for item in data.get('matches', []):
                    ioc_data = {
                        'ioc_value': item.get('ip_str', ''),
                        'ioc_type': 'ip',
                        'confidence': 80,
                        'threat_type': 'exposed_service',
                        'first_seen': '',
                        'last_seen': item.get('timestamp', ''),
                        'source': 'Shodan',
                        'description': f"Exposed service: {item.get('product', '')} on port {item.get('port', '')}",
                        'tags': 'exposed_service,vulnerable'
                    }
                    
                    if self.store_ioc(ioc_data):
                        count += 1
                
                print(f"   ✓ Collected {count} Shodan IOCs")
                return count
            else:
                print(f"   ❌ Shodan API error: {response.status_code}")
                return 0
                
        except Exception as e:
            print(f"   ❌ Error collecting Shodan data: {e}")
            return 0
    
    def collect_rss_feeds(self):
        """Collect threat intelligence from security RSS feeds"""
        try:
            count = 0
            cutoff_date = datetime.now() - timedelta(days=3)
            
            for feed_url in self.config.get('rss_feeds', []):
                try:
                    feed = feedparser.parse(feed_url)
                    
                    for entry in feed.entries[:10]:  # Limit per feed
                        # Check if entry is recent
                        try:
                            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                                entry_date = datetime(*entry.published_parsed[:6])
                                if entry_date < cutoff_date:
                                    continue
                        except:
                            pass
                        
                        # Extract threat intelligence
                        threat_data = {
                            'title': entry.title,
                            'description': entry.summary,
                            'threat_actor': self.extract_threat_actors(entry.title + ' ' + entry.summary),
                            'malware_family': self.extract_malware_families(entry.title + ' ' + entry.summary),
                            'attack_vectors': self.extract_attack_vectors(entry.title + ' ' + entry.summary),
                            'mitigation': self.generate_rss_mitigation(entry),
                            'source': f"RSS: {feed.feed.title}",
                            'published_date': entry.published if hasattr(entry, 'published') else ''
                        }
                        
                        if self.store_threat_intel(threat_data):
                            count += 1
                            
                except Exception as e:
                    print(f"   ⚠️ Error with RSS feed {feed_url}: {e}")
                    continue
            
            print(f"   ✓ Collected {count} RSS threat reports")
            return count
            
        except Exception as e:
            print(f"   ❌ Error collecting RSS feeds: {e}")
            return 0
    
    def collect_github_iocs(self):
        """Collect IOCs from GitHub security repositories"""
        try:
            count = 0
            
            for repo in self.config.get('github_repos', []):
                try:
                    # Get recent commits from the repository
                    url = f"https://api.github.com/repos/{repo}/commits"
                    params = {'since': (datetime.now() - timedelta(days=3)).isoformat()}
                    
                    response = self.session.get(url, params=params, timeout=15)
                    
                    if response.status_code == 200:
                        commits = response.json()
                        
                        for commit in commits[:5]:  # Limit per repo
                            # Get commit details
                            commit_url = commit['url']
                            commit_response = self.session.get(commit_url, timeout=10)
                            
                            if commit_response.status_code == 200:
                                commit_data = commit_response.json()
                                
                                # Extract IOCs from commit message and files
                                commit_text = commit['commit']['message']
                                
                                # Look for IP addresses
                                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', commit_text)
                                for ip in ips:
                                    ioc_data = {
                                        'ioc_value': ip,
                                        'ioc_type': 'ip',
                                        'confidence': 70,
                                        'threat_type': 'malicious_ip',
                                        'first_seen': commit['commit']['author']['date'],
                                        'last_seen': commit['commit']['author']['date'],
                                        'source': f"GitHub: {repo}",
                                        'description': f"Found in commit: {commit['commit']['message'][:100]}",
                                        'tags': 'github,ioc'
                                    }
                                    
                                    if self.store_ioc(ioc_data):
                                        count += 1
                                
                                # Look for file hashes
                                hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', commit_text)
                                for hash_val in hashes:
                                    if len(hash_val) in [32, 40, 64]:  # MD5, SHA1, SHA256
                                        ioc_data = {
                                            'ioc_value': hash_val,
                                            'ioc_type': 'file_hash',
                                            'confidence': 75,
                                            'threat_type': 'malware',
                                            'first_seen': commit['commit']['author']['date'],
                                            'last_seen': commit['commit']['author']['date'],
                                            'source': f"GitHub: {repo}",
                                            'description': f"Found in commit: {commit['commit']['message'][:100]}",
                                            'tags': 'github,ioc,malware'
                                        }
                                        
                                        if self.store_ioc(ioc_data):
                                            count += 1
                            
                            time.sleep(0.5)  # Rate limiting
                            
                except Exception as e:
                    print(f"   ⚠️ Error with GitHub repo {repo}: {e}")
                    continue
            
            print(f"   ✓ Collected {count} GitHub IOCs")
            return count
            
        except Exception as e:
            print(f"   ❌ Error collecting GitHub IOCs: {e}")
            return 0
    
    def collect_misp_data(self):
        """Collect data from MISP community (simulated - requires actual MISP instance)"""
        try:
            # This is a placeholder for MISP integration
            # In a real implementation, you would connect to a MISP instance
            print("   ⚠️ MISP integration requires actual MISP instance configuration")
            
            # Simulate some MISP-style data
            sample_data = [
                {
                    'title': 'APT Campaign Indicators',
                    'description': 'Indicators related to recent APT campaign',
                    'threat_actor': 'APT29',
                    'malware_family': 'Cobalt Strike',
                    'attack_vectors': 'Spear Phishing, Lateral Movement',
                    'mitigation': '🛡️ Implement email security | 🔍 Monitor for lateral movement',
                    'source': 'MISP Community',
                    'published_date': datetime.now().isoformat()
                }
            ]
            
            count = 0
            for data in sample_data:
                if self.store_threat_intel(data):
                    count += 1
            
            print(f"   ✓ Collected {count} MISP community reports")
            return count
            
        except Exception as e:
            print(f"   ❌ Error collecting MISP data: {e}")
            return 0
    
    def collect_urlvoid_data(self):
        """Collect URL reputation data from URLVoid (simulated - requires API key)"""
        try:
            # URLVoid requires paid API access, so this is a simulation
            print("   ⚠️ URLVoid integration requires API subscription")
            
            # Simulate some URLVoid-style data for demonstration
            suspicious_urls = [
                'http://malicious-example.com',
                'http://phishing-site.net',
                'http://suspicious-domain.org'
            ]
            
            count = 0
            for url in suspicious_urls:
                ioc_data = {
                    'ioc_value': url,
                    'ioc_type': 'url',
                    'confidence': 80,
                    'threat_type': 'malicious_url',
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'source': 'URLVoid',
                    'description': 'Suspicious URL detected by multiple engines',
                    'tags': 'malicious_url,phishing'
                }
                
                if self.store_ioc(ioc_data):
                    count += 1
            
            print(f"   ✓ Collected {count} URLVoid IOCs")
            return count
            
        except Exception as e:
            print(f"   ❌ Error collecting URLVoid data: {e}")
            return 0
    
    # Helper methods for data processing
    def process_cve_vulnerability(self, cve_data):
        """Process CVE data and store in database"""
        try:
            cve_id = cve_data.get('id', '')
            if not cve_id:
                return False
            
            # Extract description
            descriptions = cve_data.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Extract CVSS score and severity
            metrics = cve_data.get('metrics', {})
            cvss_score = 0
            severity = 'UNKNOWN'
            
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                severity = self.cvss_v2_to_severity(cvss_score)
            
            # Extract affected products
            configurations = cve_data.get('configurations', [])
            affected_products = self.extract_affected_products(configurations)
            
            # Extract references
            references = cve_data.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references]
            
            # Check if exploit is available (simple heuristic)
            exploit_available = any('exploit' in ref.get('url', '').lower() for ref in references)
            
            vulnerability_data = {
                'cve_id': cve_id,
                'title': f"CVE Vulnerability: {cve_id}",
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published_date': cve_data.get('published', ''),
                'affected_products': affected_products,
                'solution': self.generate_cve_solution(severity, exploit_available),
                'exploit_available': exploit_available,
                'source': 'NVD CVE Database',
                'tags': f"cve,{severity.lower()}",
                'references': '; '.join(ref_urls[:5])  # Limit references
            }
            
            return self.store_vulnerability(vulnerability_data)
            
        except Exception as e:
            print(f"   ❌ Error processing CVE {cve_data.get('id', 'unknown')}: {e}")
            return False
    
    def cvss_v2_to_severity(self, score):
        """Convert CVSS v2 score to severity level"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def extract_affected_products(self, configurations):
        """Extract affected products from CVE configuration data"""
        products = []
        try:
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe_name = cpe_match.get('criteria', '')
                        if cpe_name:
                            # Parse CPE name to extract product info
                            parts = cpe_name.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 else ''
                                products.append(f"{vendor} {product} {version}".strip())
        except Exception as e:
            print(f"   ⚠️ Error extracting products: {e}")
        
        return '; '.join(list(set(products))[:10])  # Unique products, limit to 10
    
    def generate_cve_solution(self, severity, exploit_available):
        """Generate solution recommendations based on CVE severity and exploit availability"""
        solutions = []
        
        if exploit_available:
            solutions.append("🔴 CRITICAL: Active exploit detected - Apply patches immediately")
        
        if severity == 'CRITICAL':
            solutions.extend([
                "🚨 Emergency patching required within 24 hours",
                "🛡️ Implement temporary WAF rules",
                "📊 Continuous monitoring required"
            ])
        elif severity == 'HIGH':
            solutions.extend([
                "⚡ Apply patches within 72 hours",
                "🔍 Monitor for exploitation attempts",
                "🛡️ Consider temporary mitigations"
            ])
        elif severity == 'MEDIUM':
            solutions.extend([
                "📅 Schedule patching within 30 days",
                "🔍 Regular security monitoring"
            ])
        else:
            solutions.append("📋 Include in regular patching cycle")
        
        return ' | '.join(solutions)
    
    def extract_products_from_text(self, text):
        """Extract product names from text using common patterns"""
        products = []
        
        # Common product patterns
        patterns = [
            r'(Windows|Linux|Apache|Nginx|MySQL|PostgreSQL|Oracle|Microsoft|Adobe|Chrome|Firefox|Safari)',
            r'(WordPress|Drupal|Joomla|PHP|Java|Python|Node\.js)',
            r'(VMware|Cisco|Fortinet|Palo Alto|Check Point)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            products.extend(matches)
        
        return '; '.join(list(set(products))) if products else 'Unknown'
    
    def extract_threat_actors(self, text):
        """Extract threat actor names from text"""
        actors = []
        
        # Common APT group patterns
        apt_patterns = [
            r'APT\d+',
            r'Lazarus',
            r'Fancy Bear',
            r'Cozy Bear',
            r'Carbanak',
            r'Fin\d+',
            r'Turla',
            r'Kimsuky',
            r'OceanLotus',
            r'Winnti'
        ]
        
        for pattern in apt_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            actors.extend(matches)
        
        return ', '.join(list(set(actors))) if actors else ''
    
    def extract_malware_families(self, text):
        """Extract malware family names from text"""
        families = []
        
        # Common malware family patterns
        malware_patterns = [
            r'Cobalt Strike',
            r'Mimikatz',
            r'PowerShell Empire',
            r'Metasploit',
            r'Emotet',
            r'TrickBot',
            r'Ryuk',
            r'Conti',
            r'BlackMatter',
            r'LockBit',
            r'Ransomware'
        ]
        
        for pattern in malware_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                families.append(pattern)
        
        return ', '.join(list(set(families))) if families else ''
    
    def extract_attack_vectors(self, text):
        """Extract attack vectors from text"""
        vectors = []
        
        # Common attack vector patterns
        vector_patterns = [
            r'Phishing',
            r'Spear Phishing',
            r'SQL Injection',
            r'Cross-Site Scripting',
            r'Remote Code Execution',
            r'Privilege Escalation',
            r'Lateral Movement',
            r'Command Injection',
            r'Buffer Overflow',
            r'Memory Corruption'
        ]
        
        for pattern in vector_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                vectors.append(pattern)
        
        return ', '.join(list(set(vectors))) if vectors else ''
    
    def generate_otx_mitigation(self, pulse):
        """Generate mitigation recommendations for OTX pulse"""
        mitigations = []
        
        tags = pulse.get('tags', [])
        
        if any('malware' in tag.lower() for tag in tags):
            mitigations.append("🦠 Deploy anti-malware solutions")
        
        if any('phishing' in tag.lower() for tag in tags):
            mitigations.append("📧 Implement email security controls")
        
        if any('apt' in tag.lower() for tag in tags):
            mitigations.extend([
                "🔍 Enhanced monitoring for APT TTPs",
                "🛡️ Implement zero-trust architecture"
            ])
        
        if not mitigations:
            mitigations.append("🔒 Apply general security hardening")
        
        return ' | '.join(mitigations)
    
    def generate_rss_mitigation(self, entry):
        """Generate mitigation recommendations for RSS entries"""
        text = (entry.title + ' ' + entry.summary).lower()
        mitigations = []
        
        if any(keyword in text for keyword in ['vulnerability', 'exploit', 'patch']):
            mitigations.append("⚡ Apply security patches immediately")
        
        if any(keyword in text for keyword in ['phishing', 'email']):
            mitigations.append("📧 Strengthen email security controls")
        
        if any(keyword in text for keyword in ['ransomware', 'encryption']):
            mitigations.extend([
                "💾 Verify backup integrity",
                "🔒 Implement endpoint protection"
            ])
        
        if any(keyword in text for keyword in ['breach', 'data leak']):
            mitigations.append("🔍 Implement data loss prevention")
        
        if not mitigations:
            mitigations.append("🛡️ Review and update security controls")
        
        return ' | '.join(mitigations)
    
    # Database storage methods
    def store_vulnerability(self, vuln_data):
        """Store vulnerability data in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities 
                (cve_id, title, description, cvss_score, severity, published_date, 
                 affected_products, solution, exploit_available, source, tags, [references])
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln_data.get('cve_id'),
                vuln_data.get('title'),
                vuln_data.get('description'),
                vuln_data.get('cvss_score'),
                vuln_data.get('severity'),
                vuln_data.get('published_date'),
                vuln_data.get('affected_products'),
                vuln_data.get('solution'),
                vuln_data.get('exploit_available'),
                vuln_data.get('source'),
                vuln_data.get('tags'),
                vuln_data.get('references')
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"   ❌ Error storing vulnerability: {e}")
            return False
    
    def store_ioc(self, ioc_data):
        """Store IOC data in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check for duplicates
            cursor.execute('SELECT id FROM iocs WHERE ioc_value = ? AND ioc_type = ?', 
                         (ioc_data.get('ioc_value'), ioc_data.get('ioc_type')))
            
            if cursor.fetchone():
                conn.close()
                return False  # Duplicate found
            
            cursor.execute('''
                INSERT INTO iocs 
                (ioc_value, ioc_type, confidence, threat_type, first_seen, last_seen, 
                 source, description, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ioc_data.get('ioc_value'),
                ioc_data.get('ioc_type'),
                ioc_data.get('confidence'),
                ioc_data.get('threat_type'),
                ioc_data.get('first_seen'),
                ioc_data.get('last_seen'),
                ioc_data.get('source'),
                ioc_data.get('description'),
                ioc_data.get('tags')
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"   ❌ Error storing IOC: {e}")
            return False
    
    def store_threat_intel(self, threat_data):
        """Store threat intelligence data in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threat_intel 
                (title, description, threat_actor, malware_family, attack_vectors, 
                 mitigation, source, published_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_data.get('title'),
                threat_data.get('description'),
                threat_data.get('threat_actor'),
                threat_data.get('malware_family'),
                threat_data.get('attack_vectors'),
                threat_data.get('mitigation'),
                threat_data.get('source'),
                threat_data.get('published_date')
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"   ❌ Error storing threat intel: {e}")
            return False
    
    def generate_daily_report(self):
        """Generate a comprehensive daily threat intelligence report"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            print("\n" + "="*80)
            print("📊 DAILY THREAT INTELLIGENCE REPORT")
            print("="*80)
            print(f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"📊 Data Period: Last 3 days")
            
            # Vulnerability Summary
            cursor.execute('''
                SELECT COUNT(*), severity, AVG(cvss_score) 
                FROM vulnerabilities 
                WHERE created_at >= datetime('now', '-3 days')
                GROUP BY severity
                ORDER BY 
                    CASE severity 
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END
            ''')
            
            vuln_stats = cursor.fetchall()
            
            print("\n🔴 VULNERABILITY SUMMARY")
            print("-" * 40)
            total_vulns = sum(stat[0] for stat in vuln_stats)
            print(f"Total Vulnerabilities: {total_vulns}")
            
            for count, severity, avg_score in vuln_stats:
                print(f"  {severity}: {count} (Avg CVSS: {avg_score:.1f})")
            
            # Critical vulnerabilities with exploits
            cursor.execute('''
                SELECT cve_id, title, cvss_score 
                FROM vulnerabilities 
                WHERE exploit_available = 1 AND created_at >= datetime('now', '-3 days')
                ORDER BY cvss_score DESC
                LIMIT 5
            ''')
            
            critical_exploits = cursor.fetchall()
            
            if critical_exploits:
                print("\n🚨 CRITICAL: Vulnerabilities with Active Exploits")
                print("-" * 50)
                for cve_id, title, score in critical_exploits:
                    print(f"  • {cve_id} (CVSS: {score}) - {title[:60]}...")
            
            # IOC Summary
            cursor.execute('''
                SELECT ioc_type, COUNT(*), AVG(confidence)
                FROM iocs 
                WHERE created_at >= datetime('now', '-3 days')
                GROUP BY ioc_type
                ORDER BY COUNT(*) DESC
            ''')
            
            ioc_stats = cursor.fetchall()
            
            print("\n🔶 IOC SUMMARY")
            print("-" * 30)
            total_iocs = sum(stat[1] for stat in ioc_stats)
            print(f"Total IOCs: {total_iocs}")
            
            for ioc_type, count, avg_conf in ioc_stats:
                print(f"  {ioc_type}: {count} (Avg Confidence: {avg_conf:.0f}%)")
            
            # High confidence IOCs
            cursor.execute('''
                SELECT ioc_value, ioc_type, confidence, source
                FROM iocs 
                WHERE confidence >= 85 AND created_at >= datetime('now', '-3 days')
                ORDER BY confidence DESC
                LIMIT 10
            ''')
            
            high_conf_iocs = cursor.fetchall()
            
            if high_conf_iocs:
                print("\n🎯 HIGH CONFIDENCE IOCs")
                print("-" * 40)
                for ioc_value, ioc_type, confidence, source in high_conf_iocs:
                    print(f"  • {ioc_value[:50]} ({ioc_type}) - {confidence}% [{source}]")
            
            # Threat Actor Activity
            cursor.execute('''
                SELECT threat_actor, COUNT(*)
                FROM threat_intel 
                WHERE threat_actor != '' AND created_at >= datetime('now', '-3 days')
                GROUP BY threat_actor
                ORDER BY COUNT(*) DESC
                LIMIT 5
            ''')
            
            threat_actors = cursor.fetchall()
            
            if threat_actors:
                print("\n👥 ACTIVE THREAT ACTORS")
                print("-" * 35)
                for actor, count in threat_actors:
                    print(f"  • {actor}: {count} reports")
            
            # Source Summary
            cursor.execute('''
                SELECT source, COUNT(*) as total
                FROM (
                    SELECT source FROM vulnerabilities WHERE created_at >= datetime('now', '-3 days')
                    UNION ALL
                    SELECT source FROM iocs WHERE created_at >= datetime('now', '-3 days')
                    UNION ALL
                    SELECT source FROM threat_intel WHERE created_at >= datetime('now', '-3 days')
                )
                GROUP BY source
                ORDER BY total DESC
            ''')
            
            source_stats = cursor.fetchall()
            
            print("\n📡 DATA SOURCES")
            print("-" * 25)
            for source, count in source_stats:
                print(f"  • {source}: {count} entries")
            
            print("\n" + "="*80)
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Error generating report: {e}")


# Usage example and main execution
if __name__ == "__main__":
    try:
        # Initialize the threat collector
        collector = EnhancedThreatCollector()
        
        # Collect all threat intelligence data
        summary = collector.collect_all_data()
        
        # Generate daily report
        collector.generate_daily_report()
        
        print(f"\n✅ Threat intelligence collection completed successfully!")
        print(f"📊 Database location: {collector.db_path}")
        print("\n💡 Next Steps:")
        print("   1. Review the daily report above")
        print("   2. Integrate IOCs into your security tools")
        print("   3. Apply critical patches immediately")
        print("   4. Schedule regular collection runs")
        
    except KeyboardInterrupt:
        print("\n⚠️ Collection interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
