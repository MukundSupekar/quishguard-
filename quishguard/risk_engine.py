from typing import Dict, Any, List
from quishguard.url_analyzer import URLAnalysisResult
from quishguard.config import (
    RISK_THRESHOLD_SAFE, RISK_THRESHOLD_LOW,
    RISK_THRESHOLD_SUSPICIOUS, RISK_THRESHOLD_HIGH
)

class RiskScoringEngine:
    """
    Synthesizes signals from URL normalization, redirect tracing,
    phishing heuristics, malware analysis, and threat intelligence into a
    normalized 0-100 risk score and explainable classification.
    """
    def __init__(self):
        pass

    def evaluate(
        self,
        url_analysis: URLAnalysisResult,
        redirect_analysis: Dict[str, Any],
        phishing_analysis: Dict[str, Any],
        malware_analysis: Dict[str, Any],
        threat_intel: Dict[str, Any]
    ) -> Dict[str, Any]:
        
        # Base score components
        lexical_points = 0
        redirect_points = 0
        phishing_points = phishing_analysis.get("phishing_score", 0)
        malware_points = malware_analysis.get("malware_score", 0)
        intel_points = 0
        
        all_indicators: List[Dict[str, Any]] = []
        threat_types: List[str] = []

        # 1. Lexical & URL Structure Signals
        if url_analysis.is_ip:
            lexical_points += 30
            all_indicators.append({
                "category": "URL Structure",
                "severity": "HIGH",
                "points": 30,
                "message": f"Host uses direct IP address ({url_analysis.ip_type}) bypassing DNS domain reputation controls"
            })
            threat_types.append("IP-Based Destination")

        if url_analysis.is_suspicious_tld:
            lexical_points += 20
            all_indicators.append({
                "category": "Domain Analysis",
                "severity": "MEDIUM",
                "points": 20,
                "message": f"Domain utilizes high-abuse top-level domain: .{url_analysis.suffix}"
            })
            threat_types.append("Suspicious TLD")

        if url_analysis.has_homograph:
            lexical_points += 35
            all_indicators.append({
                "category": "Obfuscation",
                "severity": "HIGH",
                "points": 35,
                "message": "Punycode / Homograph IDN character spoofing detected in domain"
            })
            threat_types.append("Homograph Spoofing")

        if url_analysis.is_suspicious_port:
            lexical_points += 20
            all_indicators.append({
                "category": "Network",
                "severity": "MEDIUM",
                "points": 20,
                "message": f"Non-standard HTTP port specified: :{url_analysis.port}"
            })

        if url_analysis.subdomain_count >= 3:
            lexical_points += 15
            all_indicators.append({
                "category": "URL Structure",
                "severity": "LOW",
                "points": 15,
                "message": f"Excessive subdomain nesting ({url_analysis.subdomain_count} levels)"
            })

        if url_analysis.domain_entropy > 4.2:
            lexical_points += 15
            all_indicators.append({
                "category": "Entropy Analysis",
                "severity": "MEDIUM",
                "points": 15,
                "message": f"High domain Shannon entropy ({url_analysis.domain_entropy}) indicates algorithmic domain generation"
            })

        for emb in url_analysis.embedded_urls:
            lexical_points += 20
            all_indicators.append({
                "category": "Obfuscation",
                "severity": "MEDIUM",
                "points": 20,
                "message": f"Embedded redirect URL detected within query parameters"
            })
            threat_types.append("Open Redirect / Nested URL")
            break

        # 2. Redirect Analysis Signals
        if url_analysis.is_shortener:
            redirect_points += 15
            all_indicators.append({
                "category": "Redirect Analysis",
                "severity": "LOW",
                "points": 15,
                "message": f"URL shortener ({url_analysis.registered_domain}) masks the true final destination"
            })
            threat_types.append("URL Shortener")

        redirect_count = redirect_analysis.get("redirect_count", 0)
        if redirect_count >= 2:
            redirect_points += min(25, redirect_count * 8)
            all_indicators.append({
                "category": "Redirect Analysis",
                "severity": "MEDIUM",
                "points": min(25, redirect_count * 8),
                "message": f"Multi-hop redirect chain detected ({redirect_count} intermediate hops)"
            })
            threat_types.append("Multi-Hop Redirect")

        if redirect_analysis.get("has_cross_domain_redirect"):
            redirect_points += 20
            all_indicators.append({
                "category": "Redirect Analysis",
                "severity": "HIGH",
                "points": 20,
                "message": f"Cross-domain redirect detected: initial domain differs from landing domain ({redirect_analysis.get('final_domain')})"
            })
            threat_types.append("Cross-Domain Redirect")

        if redirect_analysis.get("is_loop"):
            redirect_points += 25
            all_indicators.append({
                "category": "Redirect Analysis",
                "severity": "MEDIUM",
                "points": 25,
                "message": "Infinite redirect loop detected during destination tracing"
            })

        # 3. Phishing Signals
        for ind in phishing_analysis.get("indicators", []):
            all_indicators.append({
                "category": "Phishing Analysis",
                "severity": ind.get("severity", "MEDIUM"),
                "points": ind.get("points", 15),
                "message": ind.get("message", "")
            })
            
        if phishing_analysis.get("brand_impersonation_detected"):
            threat_types.append("Brand Impersonation")
        if any(ind.get("type") == "TYPOSQUATTING" for ind in phishing_analysis.get("indicators", [])):
            threat_types.append("Typosquatting")
        if any(ind.get("type") == "CREDENTIAL_HARVESTING_KEYWORDS" for ind in phishing_analysis.get("indicators", [])):
            threat_types.append("Credential Harvesting")

        # 4. Malware Signals
        for ind in malware_analysis.get("indicators", []):
            all_indicators.append({
                "category": "Malware Analysis",
                "severity": ind.get("severity", "HIGH"),
                "points": ind.get("points", 25),
                "message": ind.get("message", "")
            })

        if malware_analysis.get("dangerous_download"):
            threat_types.append("Malware Binary Download")
        if any(ind.get("type") == "DRIVE_BY_DOWNLOAD_PATTERN" for ind in malware_analysis.get("indicators", [])):
            threat_types.append("Drive-By Download")
        if any(ind.get("type") == "DOUBLE_EXTENSION_DECEPTION" for ind in malware_analysis.get("indicators", [])):
            threat_types.append("Double Extension Cloaking")

        # 5. Threat Intelligence Signals
        intel_verdict = threat_intel.get("overall_verdict", "UNKNOWN")
        for finding in threat_intel.get("findings", []):
            f_verdict = finding.get("verdict")
            if f_verdict == "MALICIOUS":
                intel_points += 55
                all_indicators.append({
                    "category": "Threat Intelligence",
                    "severity": "CRITICAL",
                    "points": 55,
                    "message": f"{finding.get('provider')} alert: {finding.get('details')}"
                })
                threat_types.append(f"Threat Intel: {finding.get('category', 'Malicious')}")
            elif f_verdict == "SUSPICIOUS":
                intel_points += 25
                all_indicators.append({
                    "category": "Threat Intelligence",
                    "severity": "HIGH",
                    "points": 25,
                    "message": f"{finding.get('provider')} warning: {finding.get('details')}"
                })
            elif f_verdict == "CLEAN" and "Verified Whitelist" in finding.get("provider", ""):
                # Whitelist discount for known benign public entities
                intel_points -= 20

        # Aggregate raw score
        raw_score = (
            min(lexical_points, 40) +
            min(redirect_points, 35) +
            min(phishing_points, 60) +
            min(malware_points, 60) +
            min(intel_points, 60)
        )

        # High priority overrides
        # 1. Any confirmed threat intelligence or critical typosquatting or executable download jumps to high risk
        if intel_verdict == "MALICIOUS":
            raw_score = max(raw_score, 85)
        elif malware_analysis.get("dangerous_download"):
            raw_score = max(raw_score, 75)
        elif phishing_analysis.get("brand_impersonation_detected"):
            raw_score = max(raw_score, 70)

        # Cap between 0 and 100
        final_score = max(0, min(100, raw_score))

        # Determine Classification
        if not url_analysis.is_url:
            classification = "UNKNOWN"
            recommendation = "ALLOW"
        elif final_score <= RISK_THRESHOLD_SAFE:
            classification = "SAFE"
            recommendation = "ALLOW"
        elif final_score <= RISK_THRESHOLD_LOW:
            classification = "LOW RISK"
            recommendation = "CAUTION"
        elif final_score <= RISK_THRESHOLD_SUSPICIOUS:
            classification = "SUSPICIOUS"
            recommendation = "WARN"
        elif final_score <= RISK_THRESHOLD_HIGH:
            if malware_points > phishing_points:
                classification = "HIGH RISK - MALWARE"
            else:
                classification = "HIGH RISK - PHISHING"
            recommendation = "BLOCK"
        else:
            if phishing_points >= malware_points and phishing_points > 0:
                classification = "HIGH RISK - PHISHING"
            elif malware_points > phishing_points:
                classification = "HIGH RISK - MALWARE"
            else:
                classification = "DANGEROUS WEBSITE"
            recommendation = "BLOCK"

        # De-duplicate threat types
        clean_threat_types = list(dict.fromkeys(threat_types))

        # Default explanation if safe
        if not all_indicators:
            all_indicators.append({
                "category": "Baseline Security",
                "severity": "INFO",
                "points": 0,
                "message": "No anomalous lexical patterns, brand spoofing, or malware indicators identified"
            })

        return {
            "risk_score": final_score,
            "classification": classification,
            "threat_types": clean_threat_types,
            "indicators": all_indicators,
            "recommendation": recommendation,
            "score_breakdown": {
                "lexical": min(lexical_points, 40),
                "redirects": min(redirect_points, 35),
                "phishing": min(phishing_points, 60),
                "malware": min(malware_points, 60),
                "threat_intel": max(0, min(intel_points, 60))
            }
        }

risk_scoring_engine = RiskScoringEngine()
