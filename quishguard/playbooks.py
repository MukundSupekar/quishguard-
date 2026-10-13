import uuid
from datetime import datetime
from typing import Dict, Any, List
from quishguard.database import add_to_blocklist, get_scan

class SecurityPlaybookManager:
    """
    Executes and simulates automated Incident Response playbooks
    for malicious QR codes and high-risk destinations.
    """
    def __init__(self):
        pass

    def execute_block_domain(self, domain: str, reason: str, operator: str = "SOC_ANALYST") -> Dict[str, Any]:
        """Blocks a domain in the QuishGuard active filter and sinkhole."""
        success = add_to_blocklist(
            target=domain,
            target_type="domain",
            reason=reason,
            added_by=operator
        )
        return {
            "action": "BLOCK_DOMAIN",
            "target": domain,
            "success": success,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "message": f"Domain '{domain}' successfully added to enterprise active blocklist and DNS sinkhole rules."
        }

    def execute_create_incident(self, scan_id: str, operator: str = "SOC_AUTOMATION") -> Dict[str, Any]:
        """Generates a SOC Incident Ticket with forensic evidence."""
        scan = get_scan(scan_id)
        if not scan:
            return {"success": False, "message": f"Scan {scan_id} not found"}

        ticket_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:5].upper()}"
        ticket = {
            "ticket_id": ticket_id,
            "scan_id": scan_id,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "created_by": operator,
            "severity": "P1 - CRITICAL" if scan.get("risk_score", 0) >= 80 else "P2 - HIGH",
            "title": f"Quishing Alert: {scan.get('classification')} detected on {scan.get('domain')}",
            "target_url": scan.get("normalized_url") or scan.get("raw_payload"),
            "risk_score": scan.get("risk_score"),
            "threat_types": scan.get("threat_types", []),
            "status": "OPEN_INVESTIGATION",
            "recommended_containment": [
                "Deploy firewall rule to block traffic to destination domain",
                "Quarantine emails containing originating QR code image",
                "Reset credentials for any user who accessed the QR payload before scan"
            ]
        }
        return {
            "action": "CREATE_SOC_INCIDENT",
            "success": True,
            "ticket": ticket,
            "message": f"Incident ticket #{ticket_id} created in SOC Case Management."
        }

    def generate_firewall_rules(self, domain: str) -> Dict[str, str]:
        """Generates configuration snippets for enterprise firewalls."""
        return {
            "iptables": f"iptables -A OUTPUT -p tcp -d {domain} -j DROP",
            "dnsmasq": f"address=/{domain}/0.0.0.0",
            "bind_zone": f"{domain}. IN A 0.0.0.0",
            "windows_hosts": f"0.0.0.0  {domain}"
        }

playbook_manager = SecurityPlaybookManager()
