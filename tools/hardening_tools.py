"""
CyberAgent Hardening, SAST, CVE & Reporting Toolset
==================================================
Provides capabilities for:
- Static Application Security Testing (SAST code analysis)
- Production hardening configuration generation (NGINX, Cloudflare, .htaccess)
- Real-time CVE advisories and CVSS lookups
- High-resolution executive & technical PDF audit reporting
"""

import os
from typing import Dict, Any, Optional


class HardeningToolsMixin:
    """Mixin implementing SAST scanning, CVE advisory lookups, hardening configs, and PDF generation."""

    def scan_codebase_sast(self, target_dir: str = ".") -> Dict[str, Any]:
        """
        Scans source code across a directory for security flaws (SAST):
        SQL Injection, hardcoded API secrets/passwords, dangerous eval/exec,
        shell=True injection, path traversal, and permissive CORS.
        """
        try:
            try:
                from ..modules.security import scan_codebase_sast
            except Exception:
                from cyber_agent.modules.security import scan_codebase_sast
        except ImportError:
            try:
                from security_hub import scan_codebase_sast
            except ImportError:
                return {"success": False, "error": "SAST scanner module not found."}

        dir_to_scan = self._resolve_path(target_dir)
        return scan_codebase_sast(dir_to_scan)

    def generate_hardening_config(self, domain: str) -> Dict[str, Any]:
        """
        Generates ready-to-deploy production hardening configurations:
        nginx_hardened.conf, cloudflare_waf_rules.json, dns_records.txt (SPF, DMARC, CAA),
        and Apache .htaccess.
        """
        try:
            try:
                from ..modules.security.security_hub import generate_production_hardening
            except Exception:
                from cyber_agent.modules.security.security_hub import generate_production_hardening
        except ImportError:
            try:
                from security_hub import generate_production_hardening
            except ImportError:
                return {"success": False, "error": "Hardening generator module not found."}

        out_dir = os.path.abspath(os.path.join(self.workspace_root, "reports", "hardening"))
        return generate_production_hardening(domain, out_dir)

    def lookup_cve_advisory(self, tech_string: str) -> Dict[str, Any]:
        """
        Looks up known CVEs, CVSS severity scores, affected versions, and official
        vendor mitigations for a detected software string (e.g. 'Apache-Coyote/1.1', 'nginx 1.18', 'PHP 7.4').
        """
        try:
            try:
                from ..modules.security import lookup_cve_advisories
            except Exception:
                from cyber_agent.modules.security import lookup_cve_advisories
        except ImportError:
            try:
                from security_hub import lookup_cve_advisories
            except ImportError:
                return {"success": False, "error": "CVE lookup module not found."}

        return lookup_cve_advisories(tech_string)

    def generate_pdf_report(self, target_url: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs full security audit on target URL and generates a professional,
        client-ready executive & technical PDF assessment report in the reports/ folder
        under the active workspace_root.
        """
        try:
            try:
                from ..modules.security import generate_target_pdf_report
            except Exception:
                from cyber_agent.modules.security import generate_target_pdf_report
        except ImportError:
            try:
                from security_hub import generate_target_pdf_report
            except ImportError:
                return {"success": False, "error": "PDF report generator not found."}

        return generate_target_pdf_report(
            target_url=target_url,
            output_path=output_path,
            workspace_root=self.workspace_root
        )

    def remediate_and_verify_vulnerability(
        self,
        target_file: str,
        vulnerable_code: str,
        secure_code: str,
        reproduction_command: Optional[str] = None,
        expected_failure_keyword: Optional[str] = None,
        test_cwd: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes an autonomous closed-loop Find -> Patch -> Verify cycle:
        surgically patches vulnerable code in target projects/labs, re-runs verification test,
        and ensures zero regression.
        """
        try:
            from ..modules.remediation import ClosedLoopPatchVerifier
        except Exception:
            try:
                from modules.remediation import ClosedLoopPatchVerifier
            except Exception:
                from cyber_agent.modules.remediation import ClosedLoopPatchVerifier

        verifier = ClosedLoopPatchVerifier(workspace_root=self.workspace_root)
        return verifier.remediate_and_verify(
            target_file=target_file,
            vulnerable_code=vulnerable_code,
            secure_code=secure_code,
            reproduction_command=reproduction_command,
            expected_failure_keyword=expected_failure_keyword,
            test_cwd=test_cwd
        )
