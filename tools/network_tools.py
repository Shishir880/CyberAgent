"""
CyberAgent Network & WebShield Auditing Toolset
==============================================
Provides capabilities for:
- WebShield Security Scanner posture auditing
- OWASP Hardening remediation knowledge retrieval (rules.json)
- Multi-threaded TCP network service port scanning with latency
"""

import os
import sys
import json
import socket
import datetime
import concurrent.futures
from typing import Dict, Any


class NetworkToolsMixin:
    """Mixin implementing network scanning, WebShield audit, and remediation retrieval."""

    def audit_website_security(self, target_url: str) -> Dict[str, Any]:
        """
        Runs comprehensive security posture audit using WebShield Auditor.
        Checks: WAF, TLS/SSL, DNS SPF/DMARC/CAA, OWASP Security Headers,
        Exposed Ports, and Information Leaks.
        """
        if not self.scanner_available or not self.SecurityScanner:
            this_dir = os.path.dirname(os.path.abspath(__file__))
            fallback_paths = [
                os.path.abspath(os.path.join(this_dir, "..", "..", "webshield_auditor")),
                os.path.abspath(os.path.join(self.workspace_root, "tools", "webshield_auditor")),
                "d:/ML-DL/tools/webshield_auditor"
            ]
            for p in fallback_paths:
                if os.path.exists(p) and p not in sys.path:
                    sys.path.insert(0, p)
            try:
                from core.scanner import SecurityScanner
                self.SecurityScanner = SecurityScanner
                self.scanner_available = True
            except Exception as e:
                return {
                    "success": False,
                    "error": f"WebShield SecurityScanner engine could not be loaded: {str(e)}"
                }

        try:
            scanner = self.SecurityScanner()
            report = scanner.audit(target_url)

            # Summarize critical findings for clean agent context
            findings_summary = {
                "critical": [f.get("title") for f in report.get("findings", {}).get("critical", [])],
                "high": [f.get("title") for f in report.get("findings", {}).get("high", [])],
                "medium": [f.get("title") for f in report.get("findings", {}).get("medium", [])],
                "low": [f.get("title") for f in report.get("findings", {}).get("low", [])],
                "passed": [f.get("title") for f in report.get("findings", {}).get("passed", [])]
            }

            return {
                "success": True,
                "target_url": report.get("target_url"),
                "hostname": report.get("hostname"),
                "score": report.get("score"),
                "grade": report.get("grade"),
                "waf": report.get("waf"),
                "server_software": report.get("server_software"),
                "technologies": report.get("technologies", []),
                "open_ports": report.get("open_ports", []),
                "dns_security": report.get("dns_security", {}),
                "tls_details": report.get("tls_details", {}),
                "findings_summary": findings_summary
            }
        except Exception as e:
            return {"success": False, "error": f"Security audit failed: {str(e)}"}

    def get_security_remediation(self, rule_or_header_name: str) -> Dict[str, Any]:
        """
        Retrieves official OWASP hardening configs and code remediation
        from WebShield rules.json (e.g., NGINX, Apache, Cloudflare, Express, DNS records).
        """
        if not self.rules_file or not os.path.exists(self.rules_file):
            return {"success": False, "error": f"Rules file not found at {self.rules_file}"}

        try:
            with open(self.rules_file, "r", encoding="utf-8") as f:
                rules_db = json.load(f)

            query = rule_or_header_name.lower().replace("-", "_").strip()
            matched_rules = []

            # Search in headers rules
            for rule in rules_db.get("headers", []):
                h_name = rule.get("header", "").lower().replace("-", "_")
                if query in h_name or query in rule.get("name", "").lower():
                    matched_rules.append(rule)

            # Search in leaks rules
            for rule in rules_db.get("leaks", []):
                if query in rule.get("path", "").lower() or query in rule.get("name", "").lower():
                    matched_rules.append(rule)

            if matched_rules:
                return {
                    "success": True,
                    "query": rule_or_header_name,
                    "matches_found": len(matched_rules),
                    "remediation_guides": matched_rules
                }

            # Return list of available rules if no direct match
            available = [r.get("header") for r in rules_db.get("headers", [])]
            return {
                "success": False,
                "message": f"No specific rule found for '{rule_or_header_name}'.",
                "available_header_rules": available
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def probe_service_ports(self, hostname: str) -> Dict[str, Any]:
        """
        Scans common database, web, and management ports (21, 22, 80, 443, 3306, 5432, 6379, 8080, 8443)
        with fast socket connections and latency measurement.
        """
        try:
            ip = socket.gethostbyname(hostname.strip())
        except Exception as e:
            return {"success": False, "error": f"Could not resolve host '{hostname}': {str(e)}"}

        ports_to_check = [
            (21, "FTP (Plaintext Transfer)", "High"),
            (22, "SSH Remote Shell", "Medium"),
            (80, "HTTP Web Service", "Info"),
            (443, "HTTPS Encrypted Web", "Info"),
            (3306, "MySQL Database", "Critical"),
            (5432, "PostgreSQL Database", "Critical"),
            (6379, "Redis In-Memory Cache", "Critical"),
            (8080, "Alternate HTTP / Proxy", "Low"),
            (8443, "Alternate HTTPS / Admin", "Low")
        ]

        results = []

        def probe(p):
            port, service, risk = p
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            start = datetime.datetime.now()
            code = sock.connect_ex((ip, port))
            latency = (datetime.datetime.now() - start).total_seconds() * 1000
            sock.close()
            return {
                "port": port,
                "service": service,
                "state": "OPEN" if code == 0 else "CLOSED",
                "risk": risk if code == 0 else "None",
                "latency_ms": round(latency, 1) if code == 0 else None
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as executor:
            futures = [executor.submit(probe, p) for p in ports_to_check]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        results.sort(key=lambda x: x["port"])
        open_ports = [r for r in results if r["state"] == "OPEN"]

        return {
            "success": True,
            "hostname": hostname,
            "ip_address": ip,
            "total_scanned": len(results),
            "open_ports_count": len(open_ports),
            "open_ports": open_ports,
            "full_results": results
        }
