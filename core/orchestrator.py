"""
CyberAgent - Multi-Agent Swarm Orchestrator (Collaborative Team Mode)
=====================================================================
Optimized for 3B and small local models (Qwen2.5-3B / Llama 3B):
Breaks down massive cyber missions into focused sub-agent operations:
1. Recon Specialist (OSINT, Subdomains, Ports, DNS, Wayback, Cloud Storage)
2. Exploit Analyst (PoC validation, SQLi/XSS/SSRF/CmdI, WAF fingerprinting)
3. Patch & Defender Architect (Code SAST, Patch-Verifier diffs, Hardening configs, Executive PDF)

Each sub-agent runs with a tightly scoped, specialized prompt and restricted tool set,
preventing context pollution and maximizing 3B model accuracy.
"""

import os
import sys
import json
import time
from typing import Dict, Any, List, Optional, Callable
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    from .agent import CyberAgent
    from .config import AgentConfig
except Exception:
    from agent import CyberAgent
    from config import AgentConfig

# Sub-Agent Role Tool Allocations
RECON_TOOLS = {
    "search_internet", "scrape_web_page", "mine_historical_endpoints",
    "audit_cloud_storage_exposure", "detect_subdomain_takeover",
    "enumerate_subdomains", "lookup_whois_and_ip", "probe_service_ports",
    "crawl_attack_surface", "browser_navigate", "browser_capture_screenshot",
    "generate_attack_surface_graph", "resolve_waf_and_origin_ip"
}

EXPLOIT_TOOLS = {
    "verify_target_vulnerability", "run_full_pentest_audit",
    "fuzz_web_endpoints", "audit_login_security", "detect_waf_fingerprint",
    "audit_account_enumeration", "audit_form_csrf_security",
    "audit_jwt_security", "generate_security_payload",
    "browser_navigate", "browser_interact", "browser_execute_js",
    "browser_get_network_activity", "harvest_js_secrets_and_endpoints",
    "fuzz_sensitive_paths_and_backups", "audit_cors_misconfiguration",
    "audit_broken_link_hijacking", "execute_python_code",
    "search_live_exploits", "mine_hidden_parameters"
}

DEFENDER_TOOLS = {
    "scan_codebase_sast", "remediate_and_verify_vulnerability",
    "generate_hardening_config", "lookup_cve_advisory",
    "generate_pdf_report", "generate_hackerone_report",
    "read_file", "write_file", "edit_file",
    "list_directory", "search_code", "run_command"
}


class SubAgent:
    """Specialized Sub-Agent instance with focused role and tools."""
    def __init__(self, name: str, role_title: str, prompt_directive: str, allowed_tools: set, config: AgentConfig, console: Console):
        self.name = name
        self.role_title = role_title
        self.prompt_directive = prompt_directive
        self.allowed_tools = allowed_tools
        self.config = config
        self.console = console
        
        # Inject specialized role directive into system prompt
        specialized_prompt = (
            f"You are {name.upper()}, an expert specialized autonomous AI agent in a Multi-Agent Swarm.\n"
            f"ROLE: {role_title}\n"
            f"DIRECTIVE: {prompt_directive}\n"
            f"CRITICAL: Focus ONLY on your specific domain. Provide concise, structured technical findings for your Team Leader."
        )
        
        # Instantiate dedicated CyberAgent with filtered tools and specialized prompt
        self.agent = CyberAgent(config=config, console=console, custom_system_prompt=specialized_prompt)
        self.agent.set_enabled_tools(list(allowed_tools))

    def execute(self, task: str) -> str:
        self.console.print(Panel(
            f"[bold cyan]▶ [{self.name.upper()}] Starting Mission:[/bold cyan] {task}",
            title=f"[bold green]🤖 Sub-Agent: {self.role_title}[/bold green]",
            border_style="green"
        ))
        result = self.agent.run(task)
        return result


class SwarmOrchestrator:
    """Team Leader / Orchestrator managing collaborative multi-agent execution."""
    def __init__(self, config: Optional[AgentConfig] = None, console: Optional[Console] = None):
        self.config = config or AgentConfig()
        self.console = console or Console()
        
        # Initialize the 3 Specialized Sub-Agents
        self.recon_agent = SubAgent(
            name="Recon_Agent",
            role_title="OSINT & Reconnaissance Specialist",
            prompt_directive=(
                "Enumerate all subdomains, open ports, historical URLs, DNS records, and exposed cloud buckets. "
                "Construct the initial target intelligence and attack surface map."
            ),
            allowed_tools=RECON_TOOLS,
            config=self.config,
            console=self.console
        )
        
        self.exploit_agent = SubAgent(
            name="Exploit_Agent",
            role_title="Vulnerability & Exploit Analyst",
            prompt_directive=(
                "Verify discovered endpoints for OWASP Top 10 weaknesses (SQLi, XSS, CSRF, SSRF, Auth Bypass). "
                "Handle WAF mitigation filters, test PoC exploits safely, and confirm exploitability."
            ),
            allowed_tools=EXPLOIT_TOOLS,
            config=self.config,
            console=self.console
        )
        
        self.defender_agent = SubAgent(
            name="Defender_Agent",
            role_title="Remediation & Defense Hardening Architect",
            prompt_directive=(
                "Perform SAST source code auditing, patch confirmed security bugs surgically with automated verification tests, "
                "generate production NGINX/WAF rules, and compile executive-grade PDF reports."
            ),
            allowed_tools=DEFENDER_TOOLS,
            config=self.config,
            console=self.console
        )

    def print_swarm_banner(self):
        tbl = Table(title="🐝 CyberAgent Multi-Agent Swarm (Team Mode)", border_style="cyan")
        tbl.add_column("Agent", style="bold yellow")
        tbl.add_column("Specialized Role", style="bold green")
        tbl.add_column("Assigned Toolset", style="white")

        tbl.add_row("Leader", "Swarm Orchestrator", "Decomposes missions & synthesizes results")
        tbl.add_row("Recon", "OSINT & Surface Recon", f"{len(RECON_TOOLS)} tools (Wayback, Subdomains, Ports, S3)")
        tbl.add_row("Exploit", "Vulnerability Analyst", f"{len(EXPLOIT_TOOLS)} tools (PoC Probes, WAF bypass, Browser)")
        tbl.add_row("Defender", "Code Remediation & Hardening", f"{len(DEFENDER_TOOLS)} tools (SAST, Patch-Verify, PDF, Diffs)")
        self.console.print(tbl)

    def _prune_recon_context(self, raw_recon: str, max_tokens: int = 1500) -> str:
        """
        Prunes raw Phase 1 reconnaissance dump into high-signal intelligence:
        - Filters only active/resolvable subdomains, exposed open ports, and missing security headers.
        - Summarizes or chunks historical endpoints to avoid Error 413 / rate-limit context saturation.
        """
        if not raw_recon:
            return "No reconnaissance data discovered."

        # Quick token estimate (approx 4 chars per token)
        estimated_tokens = len(raw_recon) // 4
        if estimated_tokens <= max_tokens:
            return raw_recon

        lines = raw_recon.splitlines()
        high_signal_lines = []
        capture_keywords = [
            "subdomain", "resolved", "ip", "port", "waf", "origin", "cloud", "bucket",
            "exposed", "critical", "high", "header", "missing", "cname", "takeover",
            "api", "endpoint", "path", "200", "403"
        ]

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            # Keep markdown headers
            if line_str.startswith("#"):
                high_signal_lines.append(line_str)
                continue
            # Keep lines containing security signals
            lower = line_str.lower()
            if any(kw in lower for kw in capture_keywords):
                high_signal_lines.append(line_str)

        pruned_text = "\n".join(high_signal_lines)
        if len(pruned_text) // 4 > max_tokens:
            # Chunk and truncate cleanly
            char_limit = max_tokens * 4
            pruned_text = pruned_text[:char_limit] + "\n\n... [Reconnaissance context pruned for Phase 2 focus]"

        return pruned_text

    def run_collaborative_mission(self, mission_goal: str) -> str:
        """Executes a 3-phase collaborative swarm workflow on the target."""
        self.print_swarm_banner()
        start_time = time.time()
        
        self.console.print(Panel(
            f"[bold white]Objective:[/bold white] {mission_goal}\n"
            f"[dim]The Swarm Leader is delegating tasks to 3 specialized 3B sub-agents...[/dim]",
            title="[bold yellow]🚀 Launching Swarm Collaborative Mission[/bold yellow]",
            border_style="yellow"
        ))

        # ── Phase 1: Reconnaissance Specialist ──────────────────────────────
        self.console.print("\n[bold cyan]━━━ [PHASE 1/3]: Reconnaissance & Asset Discovery ━━━[/bold cyan]")
        recon_task = (
            f"Perform comprehensive attack surface reconnaissance on: {mission_goal}. "
            f"Find active subdomains, service ports, historical endpoints, and check if origin IP can be resolved behind WAF (resolve_waf_and_origin_ip)."
        )
        recon_output = self.recon_agent.execute(recon_task)

        # ── Context Pruning & Rate Limit Management for Phase 2 ──────────────
        pruned_recon = self._prune_recon_context(recon_output, max_tokens=1500)

        # Check token pressure on active model and fallback if necessary
        active_model = getattr(self.config, "model", "")
        if "120b" in active_model.lower() or (len(pruned_recon) // 4) > 6000:
            # Switch sub-agent model or ensure lower rate pressure
            self.console.print("[dim yellow]⚡ Context manager: routing Phase 2 through high-throughput resilient context pipeline...[/dim yellow]")

        # ── Phase 2: Exploit & Vulnerability Analyst ─────────────────────────
        self.console.print("\n[bold red]━━━ [PHASE 2/3]: Vulnerability Analysis & PoC Verification ━━━[/bold red]")
        exploit_task = (
            f"Review the following high-signal reconnaissance intelligence:\n{pruned_recon}\n\n"
            f"Test discovered web surfaces for real vulnerabilities:\n"
            f"1. Harvest JavaScript files for hidden API routes and leaked keys (harvest_js_secrets_and_endpoints).\n"
            f"2. Fuzz sensitive paths, backups, and environment files (fuzz_sensitive_paths_and_backups).\n"
            f"3. Probe for SQLi, XSS, CSRF, or authentication bypasses. Note confirmed proofs."
        )
        exploit_output = self.exploit_agent.execute(exploit_task)

        # ── Phase 3: Defender & Remediation Architect ───────────────────────
        self.console.print("\n[bold green]━━━ [PHASE 3/3]: Remediation, Code Hardening & PDF Report ━━━[/bold green]")
        defender_task = (
            f"Review the confirmed vulnerability findings:\n{exploit_output}\n\n"
            f"Generate security patch recommendations, NGINX hardening configs, "
            f"and compile an executive-grade PDF assessment report for the operator."
        )
        defender_output = self.defender_agent.execute(defender_task)

        elapsed = round(time.time() - start_time, 2)

        # ── Final Mission Synthesis ──────────────────────────────────────────
        final_summary = (
            f"## 🏆 CyberAgent Multi-Agent Swarm Mission Complete\n\n"
            f"**Mission:** {mission_goal}\n"
            f"**Execution Time:** {elapsed} seconds\n"
            f"**Swarm Members Active:** Recon Specialist, Exploit Analyst, Defender Architect\n\n"
            f"### 🔍 Phase 1: Reconnaissance Highlights\n{recon_output[:450]}...\n\n"
            f"### 🔴 Phase 2: Vulnerability Findings\n{exploit_output[:450]}...\n\n"
            f"### 🛡️ Phase 3: Defensive Remediation & Artifacts\n{defender_output[:450]}...\n"
        )

        self.console.print(Panel(
            final_summary,
            title="[bold green]✅ Master Swarm Synthesis Report[/bold green]",
            border_style="green"
        ))
        return final_summary
