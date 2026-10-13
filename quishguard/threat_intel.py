import re
import hashlib
import requests
from typing import Dict, Any, List, Optional
import tldextract
from quishguard.config import VIRUSTOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY, USER_AGENT
from quishguard.database import is_blocked

# Curated offline IOC database for high-confidence detection without requiring external API keys
KNOWN_MALICIOUS_DOMAINS = {
    # Test & Simulation phishing/malware domains
    "testsafebrowsing.appspot.com": ("Google Safe Browsing Test Site", "MALWARE"),
    "wicar.org": ("WICAR Browser Exploit Test", "MALWARE"),
    "eicar.org": ("EICAR Anti-Malware Test Suite", "MALWARE"),
    "malware-traffic-analysis.net": ("Malware Traffic Analysis Repository", "INFO"),
    
    # Real-world common simulated & sample malicious patterns
    "paypa1-security-check.xyz": ("Paypal Brand Impersonation Phishing", "PHISHING"),
    "chase-online-verify-alert.top": ("Banking Phishing Portal", "PHISHING"),
    "microsoft-account-suspended.work": ("M365 Credential Harvester", "PHISHING"),
    "appleid-verify-icloud.cam": ("Apple ID Credential Phishing", "PHISHING"),
    "urgent-docusign-envelope.xyz": ("DocuSign Lure Phishing", "PHISHING"),
    "netflix-billing-update.icu": ("Netflix Payment Phishing", "PHISHING"),
    "evil-payload-dist.org": ("Known Malware Dropper Distribution", "MALWARE"),
    "crypto-drainer-bonus.top": ("Web3 Wallet Drainer Scam", "DANGEROUS"),
    "free-giftcards-claim.buzz": ("Social Engineering Survey Scam", "SCAM"),
    "secure-banking-portal-auth.cfd": ("Financial Phishing Site", "PHISHING"),
    "update-windows-defender-patch.xyz": ("Fake AV Malware Dropper", "MALWARE")
}

KNOWN_SAFE_WHITELIST = {
    "google.com", "microsoft.com", "apple.com", "github.com", "wikipedia.org",
    "amazon.com", "cloudflare.com", "python.org", "w3.org", "mozilla.org",
    "gov", "mil", "edu"  # TLD level trusted
}

class ThreatIntelligenceManager:
    """
    Coordinates threat intelligence checks across local blocklists,
    curated IOCs, VirusTotal, and Google Safe Browsing.
    """
    def __init__(self):
        self.vt_api_key = VIRUSTOTAL_API_KEY
        self.gsb_api_key = GOOGLE_SAFE_BROWSING_API_KEY

    def check_local_blocklist(self, domain: str, url: str) -> Optional[Dict[str, Any]]:
        # Check domain
        block_rec = is_blocked(domain)
        if not block_rec:
            # Check URL
            block_rec = is_blocked(url)
            
        if block_rec:
            return {
                "provider": "QuishGuard Local Blocklist",
                "verdict": "MALICIOUS",
                "category": "ADMIN_BLOCKED",
                "confidence": 1.0,
                "details": f"Target was manually blocked by SOC Administrator. Reason: {block_rec.get('reason')}"
            }
        return None

    def check_curated_iocs(self, domain: str, url: str) -> Optional[Dict[str, Any]]:
        domain_lower = domain.lower()
        if domain_lower in KNOWN_MALICIOUS_DOMAINS:
            desc, category = KNOWN_MALICIOUS_DOMAINS[domain_lower]
            return {
                "provider": "QuishGuard Curated Threat IOCs",
                "verdict": "MALICIOUS",
                "category": category,
                "confidence": 0.95,
                "details": desc
            }
            
        # Check known safe whitelist
        ext = tldextract.extract(domain)
        reg_domain = getattr(ext, 'top_domain_under_public_suffix', None) or getattr(ext, 'registered_domain', '')
        if reg_domain in KNOWN_SAFE_WHITELIST or ext.suffix in KNOWN_SAFE_WHITELIST:
            return {
                "provider": "QuishGuard Verified Whitelist",
                "verdict": "CLEAN",
                "category": "VERIFIED_DOMAIN",
                "confidence": 0.99,
                "details": f"Well-known verified public domain ({reg_domain})"
            }

        return None

    def query_virustotal(self, url: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal v3 URL analysis API if key is set."""
        if not self.vt_api_key:
            return None

        try:
            # VT URL ID is base64 representation without padding
            url_id = hashlib.sha256(url.encode()).hexdigest()
            headers = {"x-apikey": self.vt_api_key}
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            resp = requests.get(api_url, headers=headers, timeout=4)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)

                if malicious > 0:
                    verdict = "MALICIOUS"
                elif suspicious > 0:
                    verdict = "SUSPICIOUS"
                else:
                    verdict = "CLEAN"

                return {
                    "provider": "VirusTotal v3",
                    "verdict": verdict,
                    "malicious_votes": malicious,
                    "suspicious_votes": suspicious,
                    "harmless_votes": harmless,
                    "confidence": 0.90 if malicious > 2 else 0.75,
                    "details": f"VT detection: {malicious} engines flagged malicious, {suspicious} suspicious"
                }
        except Exception:
            pass
        return None

    def query_google_safebrowsing(self, url: str) -> Optional[Dict[str, Any]]:
        """Query Google Safe Browsing Lookup API v4 if key is set."""
        if not self.gsb_api_key:
            return None

        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
            payload = {
                "client": {
                    "clientId": "quishguard-app",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            resp = requests.post(api_url, json=payload, timeout=4)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType", "MALICIOUS")
                    return {
                        "provider": "Google Safe Browsing v4",
                        "verdict": "MALICIOUS",
                        "category": threat_type,
                        "confidence": 0.95,
                        "details": f"Google Safe Browsing match: Classified as {threat_type}"
                    }
                else:
                    return {
                        "provider": "Google Safe Browsing v4",
                        "verdict": "CLEAN",
                        "category": "BENIGN",
                        "confidence": 0.85,
                        "details": "No threat matches found in Google Safe Browsing database"
                    }
        except Exception:
            pass
        return None

    def query_threat_intel(self, domain: str, url: str) -> Dict[str, Any]:
        """
        Runs tiered threat intelligence lookups across available providers.
        """
        results: Dict[str, Any] = {
            "providers_queried": [],
            "overall_verdict": "CLEAN",
            "findings": []
        }

        # 1. Local SOC Blocklist (Highest priority)
        blocklist_res = self.check_local_blocklist(domain, url)
        if blocklist_res:
            results["providers_queried"].append(blocklist_res["provider"])
            results["findings"].append(blocklist_res)
            results["overall_verdict"] = "MALICIOUS"
            return results

        # 2. Curated Offline Threat Database
        curated_res = self.check_curated_iocs(domain, url)
        if curated_res:
            results["providers_queried"].append(curated_res["provider"])
            results["findings"].append(curated_res)
            if curated_res["verdict"] == "MALICIOUS":
                results["overall_verdict"] = "MALICIOUS"
            elif curated_res["verdict"] == "CLEAN":
                results["overall_verdict"] = "CLEAN"

        # 3. VirusTotal API (if configured)
        vt_res = self.query_virustotal(url)
        if vt_res:
            results["providers_queried"].append(vt_res["provider"])
            results["findings"].append(vt_res)
            if vt_res["verdict"] == "MALICIOUS":
                results["overall_verdict"] = "MALICIOUS"
            elif vt_res["verdict"] == "SUSPICIOUS" and results["overall_verdict"] != "MALICIOUS":
                results["overall_verdict"] = "SUSPICIOUS"

        # 4. Google Safe Browsing API (if configured)
        gsb_res = self.query_google_safebrowsing(url)
        if gsb_res:
            results["providers_queried"].append(gsb_res["provider"])
            results["findings"].append(gsb_res)
            if gsb_res["verdict"] == "MALICIOUS":
                results["overall_verdict"] = "MALICIOUS"

        # Fallback summary if no findings
        if not results["findings"]:
            results["providers_queried"].append("QuishGuard Heuristic Baseline")
            results["findings"].append({
                "provider": "Heuristic Intelligence Engine",
                "verdict": "UNKNOWN",
                "details": "No external blacklists matched; evaluated via behavioral heuristics"
            })
            results["overall_verdict"] = "UNKNOWN"

        return results

threat_intel_manager = ThreatIntelligenceManager()
