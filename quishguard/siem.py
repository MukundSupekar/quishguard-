import json
from datetime import datetime
from typing import Dict, Any, List
from quishguard.database import log_siem_event, get_siem_events

class SIEMIntegration:
    """
    Formats and forwards security events for SIEM/XDR platforms
    (Splunk, Elastic, Microsoft Sentinel, IBM QRadar) using RFC 5424 / CEF / JSON.
    """
    def __init__(self):
        pass

    def create_event(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a standardized security event from a scan record."""
        score = scan_data.get("risk_score", 0)
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        event = {
            "version": "1.0",
            "timestamp": scan_data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "event_id": scan_data.get("id"),
            "device_vendor": "QuishGuard",
            "device_product": "Quishing_Detection_Engine",
            "severity": severity,
            "signature_id": f"QUISH-{scan_data.get('classification', 'UNKNOWN').replace(' ', '_')}",
            "threat_category": ", ".join(scan_data.get("threat_types", [])) or "None",
            "risk_score": score,
            "action_taken": scan_data.get("recommendation", "ALLOW"),
            "source": {
                "scan_method": scan_data.get("source_type"),
                "client_ip": scan_data.get("client_ip", "127.0.0.1"),
                "qr_detected": scan_data.get("qr_detected", True)
            },
            "destination": {
                "url": scan_data.get("normalized_url") or scan_data.get("raw_payload"),
                "domain": scan_data.get("domain"),
                "protocol": scan_data.get("protocol")
            },
            "indicators": [ind.get("message") for ind in scan_data.get("indicators", [])]
        }

        # Store in database audit log
        log_siem_event(
            scan_id=scan_data.get("id", ""),
            severity=severity,
            event_type=f"QR_SECURITY_SCAN_{severity}",
            details=event
        )

        return event

    def format_cef(self, event: Dict[str, Any]) -> str:
        """
        Formats event into ArcSight Common Event Format (CEF):
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        severity_map = {"LOW": "1", "MEDIUM": "5", "HIGH": "8", "CRITICAL": "10"}
        sev_num = severity_map.get(event.get("severity", "LOW"), "3")
        
        ext_parts = [
            f"cs1={event.get('threat_category', 'None')}",
            f"cs1Label=ThreatType",
            f"cn1={event.get('risk_score', 0)}",
            f"cn1Label=RiskScore",
            f"act={event.get('action_taken', 'ALLOW')}",
            f"src={event.get('source', {}).get('client_ip', '127.0.0.1')}",
            f"dhost={event.get('destination', {}).get('domain', 'unknown')}",
            f"request={event.get('destination', {}).get('url', 'unknown')}"
        ]
        
        cef_string = (
            f"CEF:0|{event['device_vendor']}|{event['device_product']}|1.0|"
            f"{event['signature_id']}|QR Code Security Alert|{sev_num}|"
            + " ".join(ext_parts)
        )
        return cef_string

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return get_siem_events(limit)

siem_service = SIEMIntegration()
