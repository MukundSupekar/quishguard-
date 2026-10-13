import re
import difflib
from typing import List, Dict, Any, Tuple
import tldextract
from quishguard.url_analyzer import extract_registered_domain

# High-profile brands heavily targeted in quishing and phishing campaigns
TARGET_BRANDS = {
    "google": ["google", "gmail", "drive", "youtube"],
    "microsoft": ["microsoft", "office365", "outlook", "live", "onedrive", "azure"],
    "apple": ["apple", "icloud", "itunes", "appleid"],
    "paypal": ["paypal", "pypl"],
    "amazon": ["amazon", "aws", "prime"],
    "netflix": ["netflix"],
    "facebook": ["facebook", "meta", "fb"],
    "instagram": ["instagram", "ig"],
    "whatsapp": ["whatsapp"],
    "chase": ["chase", "jpmorgan"],
    "bankofamerica": ["bankofamerica", "bofa"],
    "wellsfargo": ["wellsfargo"],
    "citibank": ["citibank", "citi"],
    "coinbase": ["coinbase"],
    "binance": ["binance"],
    "metamask": ["metamask"],
    "steam": ["steam", "steampowered", "steamcommunity"],
    "docusign": ["docusign"],
    "dhl": ["dhl", "dhlexpress"],
    "fedex": ["fedex"],
    "usps": ["usps", "postal"],
    "dropbox": ["dropbox"],
    "spotify": ["spotify"],
    "linkedin": ["linkedin"],
    "adobe": ["adobe"]
}

# High-confidence official registered domains for targeted brands
OFFICIAL_DOMAINS = {
    "google.com", "google.co.uk", "google.ca", "google.de", "google.fr", "google.co.in",
    "youtube.com", "gmail.com",
    "microsoft.com", "office.com", "live.com", "outlook.com", "azure.com",
    "apple.com", "icloud.com",
    "paypal.com", "paypal.me",
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "aws.amazon.com",
    "netflix.com",
    "facebook.com", "fb.com", "meta.com", "instagram.com", "whatsapp.com",
    "chase.com", "jpmorgan.com",
    "bankofamerica.com", "bofa.com",
    "wellsfargo.com",
    "citibank.com", "citi.com",
    "coinbase.com",
    "binance.com",
    "metamask.io",
    "steampowered.com", "steamcommunity.com",
    "docusign.com", "docusign.net",
    "dhl.com", "fedex.com", "usps.com",
    "dropbox.com", "spotify.com", "linkedin.com", "adobe.com"
}

# Credential Harvesting Keywords
CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "authenticate", "auth", "sso",
    "oauth", "verify", "verification", "account", "wallet", "password",
    "recover", "recovery", "2fa", "mfa", "passcode", "security-check",
    "profile-update", "credential", "portal", "confirm"
]

# Urgency / Coercive Keywords
URGENCY_KEYWORDS = [
    "suspended", "suspend", "urgent", "immediate", "disabled", "action-required",
    "compromised", "blocked", "expire", "expiration", "terminated", "fraud",
    "unauthorized", "alert", "notice", "critical", "warning", "violation"
]

# Financial / Transaction Keywords
FINANCIAL_KEYWORDS = [
    "billing", "invoice", "payment", "crypto", "refund", "reward", "cash",
    "transfer", "wire", "claim", "airdrop", "bonus", "giftcard", "payout",
    "prize", "lottery", "direct-deposit", "tax-refund"
]

def levenshtein_similarity(s1: str, s2: str) -> float:
    """Returns a ratio between 0.0 and 1.0 representing string similarity."""
    return difflib.SequenceMatcher(None, s1.lower(), s2.lower()).ratio()

class PhishingDetectionEngine:
    """
    Evaluates brand impersonation, typosquatting, credential harvesting patterns,
    and domain composition to identify phishing/quishing attempts.
    """
    def __init__(self):
        pass

    def check_brand_impersonation(self, url: str, domain: str, subdomain: str) -> List[Dict[str, Any]]:
        findings = []
        full_host = f"{subdomain}.{domain}" if subdomain else domain
        clean_domain = domain.lower()
        
        # Check if it is an officially sanctioned domain
        reg_domain = extract_registered_domain(url).lower()
        if reg_domain in OFFICIAL_DOMAINS:
            return []  # Legitimate brand domain

        # 1. Direct brand name substring in an unauthorized registered domain
        for brand, aliases in TARGET_BRANDS.items():
            for alias in aliases:
                # e.g., 'paypal-update.com' or 'secure-chase-login.xyz'
                if alias in clean_domain:
                    findings.append({
                        "brand": brand,
                        "type": "BRAND_IN_DOMAIN",
                        "severity": "HIGH",
                        "points": 35,
                        "message": f"Brand impersonation detected: Unauthorized domain '{clean_domain}' incorporates trusted brand '{brand}'"
                    })
                    break
                
                # e.g., 'paypal.attacker-domain.com'
                if subdomain and alias in subdomain.lower().split('.'):
                    findings.append({
                        "brand": brand,
                        "type": "BRAND_IN_SUBDOMAIN",
                        "severity": "HIGH",
                        "points": 30,
                        "message": f"Brand subdomain spoofing: Brand name '{brand}' is nested inside subdomain of unrelated domain '{clean_domain}'"
                    })
                    break

        # 2. Typosquatting / Lookalike fuzzy matching & token inspection
        tokens = set(re.split(r'[-_.]', clean_domain))
        tokens.add(clean_domain)
        
        # Leetspeak normalization map
        LEET_MAP = str.maketrans({'1': 'l', '0': 'o', '5': 's', '3': 'e', '4': 'a', '@': 'a'})

        for brand, aliases in TARGET_BRANDS.items():
            for alias in aliases:
                matched_token = False
                for tok in tokens:
                    if len(tok) < 3:
                        continue
                    
                    # Leetspeak substitution check (e.g. 'paypa1' -> 'paypal')
                    normalized_tok = tok.translate(LEET_MAP).replace('vv', 'w')
                    if normalized_tok == alias and tok != alias:
                        findings.append({
                            "brand": brand,
                            "type": "TYPOSQUATTING",
                            "severity": "CRITICAL",
                            "points": 45,
                            "token": tok,
                            "message": f"Typosquatting leetspeak detected: Domain token '{tok}' intentionally mimics legitimate brand '{brand}'"
                        })
                        matched_token = True
                        break

                    # Fuzzy edit distance check
                    sim = levenshtein_similarity(tok, alias)
                    if 0.72 <= sim < 1.0 and len(tok) >= 4:
                        findings.append({
                            "brand": brand,
                            "type": "TYPOSQUATTING",
                            "severity": "CRITICAL",
                            "points": 40,
                            "similarity": round(sim, 2),
                            "token": tok,
                            "message": f"Typosquatting alert: Domain token '{tok}' is deceptively similar ({round(sim*100)}% match) to legitimate brand '{brand}'"
                        })
                        matched_token = True
                        break
                if matched_token:
                    break

        return findings

    def check_lexical_keywords(self, url_str: str) -> List[Dict[str, Any]]:
        findings = []
        url_lower = url_str.lower()

        # Check Credential harvesting keywords
        matched_cred = [kw for kw in CREDENTIAL_KEYWORDS if kw in url_lower]
        if matched_cred:
            points = min(25, len(matched_cred) * 8)
            findings.append({
                "type": "CREDENTIAL_HARVESTING_KEYWORDS",
                "severity": "MEDIUM",
                "points": points,
                "keywords": matched_cred,
                "message": f"URL contains credential harvesting keywords: {', '.join(matched_cred[:4])}"
            })

        # Check Urgency keywords
        matched_urg = [kw for kw in URGENCY_KEYWORDS if kw in url_lower]
        if matched_urg:
            points = min(20, len(matched_urg) * 8)
            findings.append({
                "type": "URGENCY_KEYWORDS",
                "severity": "MEDIUM",
                "points": points,
                "keywords": matched_urg,
                "message": f"URL uses coercive urgency/fear phrasing: {', '.join(matched_urg[:3])}"
            })

        # Check Financial keywords
        matched_fin = [kw for kw in FINANCIAL_KEYWORDS if kw in url_lower]
        if matched_fin:
            points = min(20, len(matched_fin) * 7)
            findings.append({
                "type": "FINANCIAL_SCAM_KEYWORDS",
                "severity": "MEDIUM",
                "points": points,
                "keywords": matched_fin,
                "message": f"URL contains financial/lure terms: {', '.join(matched_fin[:3])}"
            })

        return findings

    def check_domain_structure(self, domain: str, subdomain: str, path: str) -> List[Dict[str, Any]]:
        findings = []
        
        # Multiple hyphens (common in fake phishing landing pages)
        hyphen_count = domain.count('-')
        if hyphen_count >= 2:
            findings.append({
                "type": "EXCESSIVE_HYPHENS",
                "severity": "LOW",
                "points": 10,
                "message": f"Domain contains {hyphen_count} hyphens, a common pattern in deceptive phishing domains"
            })

        # Check for path-based brand deceptive structures (e.g. /login/paypal/verify)
        path_lower = path.lower()
        path_brands = [brand for brand in TARGET_BRANDS if f"/{brand}" in path_lower or f"_{brand}" in path_lower]
        if path_brands:
            findings.append({
                "type": "BRAND_IN_PATH",
                "severity": "MEDIUM",
                "points": 15,
                "brands": path_brands,
                "message": f"URL path references protected brand names: {', '.join(path_brands)}"
            })

        return findings

    def analyze(self, url: str, domain: str, subdomain: str, path: str) -> Dict[str, Any]:
        brand_findings = self.check_brand_impersonation(url, domain, subdomain)
        keyword_findings = self.check_lexical_keywords(url)
        structure_findings = self.check_domain_structure(domain, subdomain, path)
        
        all_indicators = brand_findings + keyword_findings + structure_findings
        total_phishing_score = sum(f.get("points", 0) for f in all_indicators)

        is_phishing = total_phishing_score >= 35
        
        return {
            "is_phishing_suspect": is_phishing,
            "phishing_score": min(total_phishing_score, 60),
            "indicators": all_indicators,
            "brand_impersonation_detected": len(brand_findings) > 0,
            "detected_brands": [f.get("brand") for f in brand_findings if "brand" in f]
        }

phishing_engine = PhishingDetectionEngine()
