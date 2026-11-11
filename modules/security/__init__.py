"""
CyberAgent Security Hub Module
==============================
Contains offensive penetration testing, fuzzing, PoC probes, and defensive hardening.
"""

from .security_hub import (
    fuzz_web_endpoints,
    verify_target_vulnerability,
    run_full_pentest_audit,
    map_mitre_attack,
    crawl_attack_surface,
    audit_php_threats,
    lookup_cve_advisories,
    generate_target_pdf_report
)

__all__ = [
    "fuzz_web_endpoints",
    "verify_target_vulnerability",
    "run_full_pentest_audit",
    "map_mitre_attack",
    "crawl_attack_surface",
    "audit_php_threats",
    "lookup_cve_advisories",
    "generate_target_pdf_report"
]
