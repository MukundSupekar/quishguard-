import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from quishguard.url_analyzer import analyze_url
from quishguard.redirect_tracer import redirect_tracer
from quishguard.phishing_engine import phishing_engine
from quishguard.malware_engine import malware_engine
from quishguard.threat_intel import threat_intel_manager
from quishguard.risk_engine import risk_scoring_engine
from quishguard.siem import siem_service
from quishguard.database import save_scan

def process_security_pipeline(
    raw_payload: str,
    source_type: str = "image",
    filename: Optional[str] = None,
    qr_detected: bool = True,
    client_ip: str = "127.0.0.1",
    qr_metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes the full end-to-end defense-in-depth security inspection pipeline:
    Payload Normalization -> Redirect Tracing -> Threat Intel -> Phishing Analysis ->
    Malware Analysis -> Risk Scoring -> SIEM Event Dispatch -> DB Persistence.
    """
    scan_id = f"QR-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Step 1: URL Extraction & Normalization
    url_result = analyze_url(raw_payload)

    if not url_result.is_url:
        # Non-URL payload (e.g. Plain Text, WiFi Config, vCard)
        classification = "SAFE"
        recommendation = "ALLOW"
        risk_score = 0
        indicators = [{
            "category": "Payload Analysis",
            "severity": "INFO",
            "points": 0,
            "message": f"Decoded payload is non-navigable ({url_result.payload_type}); poses no automated web navigation hazard."
        }]
        
        scan_data = {
            "id": scan_id,
            "timestamp": timestamp,
            "source_type": source_type,
            "filename": filename,
            "qr_detected": qr_detected,
            "raw_payload": raw_payload,
            "payload_type": url_result.payload_type,
            "normalized_url": "",
            "domain": "",
            "protocol": "",
            "risk_score": risk_score,
            "classification": classification,
            "threat_types": [url_result.payload_type],
            "indicators": indicators,
            "redirect_chain": [],
            "threat_intel": {"overall_verdict": "CLEAN", "findings": []},
            "recommendation": recommendation,
            "client_ip": client_ip,
            "qr_metadata": qr_metadata or {}
        }
        
        save_scan(scan_data)
        siem_service.create_event(scan_data)
        return scan_data

    # Step 2: Safe Redirect Tracing
    redirect_result = redirect_tracer.trace(url_result.normalized_url)
    target_url = redirect_result["final_url"]
    target_domain = redirect_result["final_domain"] or url_result.registered_domain

    # Re-analyze final URL if redirect occurred
    target_analysis = url_result
    if redirect_result["total_hops"] > 1:
        target_analysis = analyze_url(target_url)

    # Step 3: Phishing Detection (Evaluated on both initial and landing target)
    phishing_result = phishing_engine.analyze(
        url=target_analysis.normalized_url,
        domain=target_analysis.registered_domain or target_domain,
        subdomain=target_analysis.subdomain,
        path=target_analysis.path
    )

    # Step 4: Malware & Dangerous Site Detection
    malware_result = malware_engine.analyze(
        url=target_analysis.normalized_url,
        path=target_analysis.path,
        query=target_analysis.query_string
    )

    # Step 5: Threat Intelligence Verification
    intel_result = threat_intel_manager.query_threat_intel(
        domain=target_analysis.registered_domain or target_domain,
        url=target_analysis.normalized_url
    )

    # Step 6: Multi-Factor Risk Scoring Engine
    score_result = risk_scoring_engine.evaluate(
        url_analysis=target_analysis,
        redirect_analysis=redirect_result,
        phishing_analysis=phishing_result,
        malware_analysis=malware_result,
        threat_intel=intel_result
    )

    # Consolidate complete scan result
    scan_data = {
        "id": scan_id,
        "timestamp": timestamp,
        "source_type": source_type,
        "filename": filename,
        "qr_detected": qr_detected,
        "raw_payload": raw_payload,
        "payload_type": url_result.payload_type,
        "normalized_url": target_analysis.normalized_url or url_result.normalized_url,
        "domain": target_analysis.registered_domain or url_result.registered_domain or target_domain,
        "protocol": target_analysis.scheme or url_result.scheme,
        "risk_score": score_result["risk_score"],
        "classification": score_result["classification"],
        "threat_types": score_result["threat_types"],
        "indicators": score_result["indicators"],
        "redirect_chain": redirect_result["chain"],
        "threat_intel": intel_result,
        "recommendation": score_result["recommendation"],
        "client_ip": client_ip,
        "score_breakdown": score_result.get("score_breakdown", {}),
        "qr_metadata": qr_metadata or {}
    }

    # Step 7: Persistence & SIEM Forwarding
    save_scan(scan_data)
    siem_service.create_event(scan_data)

    return scan_data
