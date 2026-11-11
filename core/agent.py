"""
CyberAgent - Autonomous ReAct Agentic Execution Loop
Drives the cycle of:
Goal -> Reason -> Execute Tool (cmd/folder/edit/debug) -> Observe Output -> Verify -> Final Solution.
"""

import os
import sys
import re
import json
import time
import traceback
from typing import Dict, Any, List, Optional, Callable, Tuple, Set
from openai import OpenAI
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.live import Live
import urllib3

# Suppress SSL certificate warning spam in console output during pentest probes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


class StreamedFunctionCall:
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments


class StreamedToolCall:
    def __init__(self, call_id: str, name: str, arguments: str, extra_content: Optional[Dict[str, Any]] = None):
        self.id = call_id
        self.type = "function"
        self.function = StreamedFunctionCall(name, arguments)
        self.extra_content = extra_content


class StreamedMessage:
    def __init__(self, content: Optional[str], tool_calls: Optional[List[StreamedToolCall]], reasoning: Optional[str] = None):
        self.content = content
        self.tool_calls = tool_calls
        self.reasoning = reasoning


try:
    from .config import AgentConfig
except Exception:
    try:
        from config import AgentConfig
    except Exception:
        from cyber_agent.config import AgentConfig

try:
    from ..tools import AgentTools
except Exception:
    try:
        from tools import AgentTools
    except Exception:
        from cyber_agent.tools import AgentTools

try:
    from .hitl import HITLManager
except Exception:
    try:
        from hitl import HITLManager
    except Exception:
        from cyber_agent.core.hitl import HITLManager


class CyberAgent:
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        console: Optional[Console] = None,
        hitl: Optional[HITLManager] = None,
        custom_system_prompt: Optional[str] = None
    ):
        self.config = config or AgentConfig()
        self.console = console or Console()
        self.hitl = hitl or HITLManager(enabled=getattr(self.config, "hitl_enabled", True))
        self.custom_system_prompt = custom_system_prompt
        self.tools = AgentTools(workspace_root=self.config.workspace_root)
        self.all_tool_definitions = self.tools.get_tool_definitions()
        self.enabled_tools: Optional[Set[str]] = None
        self.tool_definitions = self.all_tool_definitions
        
        # Initialize Hybrid Semantic Vector Tool Router
        try:
            from .tool_router import ToolSemanticRouter
            self.router: Optional[ToolSemanticRouter] = ToolSemanticRouter(self.all_tool_definitions)
        except Exception:
            self.router = None
        
        # Build tool function dispatcher map
        self.tool_dispatcher: Dict[str, Callable] = {
            "run_command": self.tools.run_command,
            "create_folder": self.tools.create_folder,
            "read_file": self.tools.read_file,
            "write_file": self.tools.write_file,
            "edit_file": self.tools.edit_file,
            "list_directory": self.tools.list_directory,
            "search_code": self.tools.search_code,
            "audit_website_security": self.tools.audit_website_security,
            "get_security_remediation": self.tools.get_security_remediation,
            "probe_service_ports": self.tools.probe_service_ports,
            "scan_codebase_sast": self.tools.scan_codebase_sast,
            "generate_hardening_config": self.tools.generate_hardening_config,
            "lookup_cve_advisory": self.tools.lookup_cve_advisory,
            "generate_pdf_report": self.tools.generate_pdf_report,
            "recall_memory": self.tools.recall_memory,
            "fuzz_web_endpoints": self.tools.fuzz_web_endpoints,
            "verify_target_vulnerability": self.tools.verify_target_vulnerability,
            "run_full_pentest_audit": self.tools.run_full_pentest_audit,
            "map_mitre_attack": self.tools.map_mitre_attack,
            "audit_php_threats": self.tools.audit_php_threats,
            "remember_memory": self.tools.remember_memory,
            "get_target_dossier": self.tools.get_target_dossier,
            "crawl_attack_surface": self.tools.crawl_attack_surface,
            "browser_navigate": self.tools.browser_navigate,
            "browser_interact": self.tools.browser_interact,
            "browser_capture_screenshot": self.tools.browser_capture_screenshot,
            "browser_execute_js": self.tools.browser_execute_js,
            "browser_get_network_activity": self.tools.browser_get_network_activity,
            "audit_login_security": self.tools.audit_login_security,
            "detect_waf_fingerprint": self.tools.detect_waf_fingerprint,
            "audit_account_enumeration": self.tools.audit_account_enumeration,
            "extract_sensitive_leaks": self.tools.extract_sensitive_leaks,
            "audit_form_csrf_security": self.tools.audit_form_csrf_security,
            "calculate_datetime": self.tools.calculate_datetime,
            "search_internet": self.tools.search_internet,
            "scrape_web_page": self.tools.scrape_web_page,
            "enumerate_subdomains": self.tools.enumerate_subdomains,
            "audit_jwt_security": self.tools.audit_jwt_security,
            "generate_security_payload": self.tools.generate_security_payload,
            "check_proxy_health": self.tools.check_proxy_health,
            "lookup_whois_and_ip": self.tools.lookup_whois_and_ip,
            "mine_historical_endpoints": self.tools.mine_historical_endpoints,
            "scan_repository_secrets": self.tools.scan_repository_secrets,
            "audit_cloud_storage_exposure": self.tools.audit_cloud_storage_exposure,
            "parse_network_audit_scan": self.tools.parse_network_audit_scan,
            "detect_subdomain_takeover": self.tools.detect_subdomain_takeover,
            "generate_attack_surface_graph": self.tools.generate_attack_surface_graph,
            "remediate_and_verify_vulnerability": self.tools.remediate_and_verify_vulnerability,
            "harvest_js_secrets_and_endpoints": self.tools.harvest_js_secrets_and_endpoints,
            "fuzz_sensitive_paths_and_backups": self.tools.fuzz_sensitive_paths_and_backups,
            "resolve_waf_and_origin_ip": self.tools.resolve_waf_and_origin_ip,
            "audit_cors_misconfiguration": self.tools.audit_cors_misconfiguration,
            "audit_broken_link_hijacking": self.tools.audit_broken_link_hijacking,
            "execute_python_code": self.tools.execute_python_code,
            "search_live_exploits": self.tools.search_live_exploits,
            "mine_hidden_parameters": self.tools.mine_hidden_parameters,
            "generate_hackerone_report": self.tools.generate_hackerone_report
        }

        # Initialize Attack Surface Knowledge Graph
        try:
            from ..modules.graph import AttackSurfaceGraph
        except Exception:
            try:
                from modules.graph import AttackSurfaceGraph
            except Exception:
                from cyber_agent.modules.graph import AttackSurfaceGraph
        self.attack_graph = AttackSurfaceGraph(workspace_root=self.config.workspace_root)
        self.tools.attack_graph = self.attack_graph

        try:
            from ..modules.memory import get_short_term_memory
        except Exception:
            try:
                from modules.memory import get_short_term_memory
            except Exception:
                from cyber_agent.modules.memory import get_short_term_memory
        self.short_term_memory = get_short_term_memory()

    def _get_client(self) -> OpenAI:
        """Initializes the OpenAI client with current provider endpoint and key."""
        return OpenAI(
            base_url=self.config.base_url,
            api_key=self.config.api_key or "placeholder",
            timeout=60.0,
            max_retries=3
        )

    def _build_system_prompt(self) -> str:
        if self.custom_system_prompt:
            return self.custom_system_prompt
        return f"""You are CyberAgent, an elite autonomous AI Penetration Tester, Cybersecurity Architect, and Software Engineer.
You operate directly on the user's system via tool function calls to perform real offensive security assessments, vulnerability remediation, and software engineering.

Your Integrated Capabilities & Weaponry:
1. Offensive Ethical Penetration Testing (Red-Team):
   - Crawl web applications and extract attack surface entrypoints, HTML forms, and parameters (`crawl_attack_surface`).
   - Run autonomous multi-phase penetration testing audits (`run_full_pentest_audit`) against authorized legal practice targets (demo.testfire.net, ginandjuice.shop, zero.webappsecurity.com, juice-shop.herokuapp.com).
   - Fuzz web endpoints and discover sensitive file leaks (`fuzz_web_endpoints`) like /.env, /.git/HEAD, database backups, and Swagger APIs.
   - Execute safe proof-of-concept vulnerability probes (`verify_target_vulnerability`) for SQL Injection auth bypass, reflected XSS, and CORS misconfiguration.
   - Scan source code for SAST vulnerabilities (`scan_codebase_sast`) to find hardcoded credentials and dangerous execution paths.
   - Map vulnerabilities to the MITRE ATT&CK Enterprise Framework (`map_mitre_attack`).
   - Audit login brute-force defenses, rate-limiting, and lockout (`audit_login_security`).
   - Fingerprint Web Application Firewalls (`detect_waf_fingerprint`).
   - Test account enumeration timing & error message leaks (`audit_account_enumeration`).
   - Harvest exposed API keys, tokens, and developer comments (`extract_sensitive_leaks`).
   - Audit HTML form CSRF token protections (`audit_form_csrf_security`).
   - Deeply audit JavaScript bundles for hidden API endpoints and leaked credentials (`harvest_js_secrets_and_endpoints`).
   - Fuzz high-value sensitive files (.env, .git, actuator, swagger, backups) with signature verification (`fuzz_sensitive_paths_and_backups`).
   - Resolve origin IP addresses behind Cloudflare/Akamai WAFs (`resolve_waf_and_origin_ip`).

2. Defensive Security Hardening & Remediation (Blue-Team):
   - Audit web security posture, WAF, DNS CAA/SPF/DMARC, TLS, and OWASP headers (`audit_website_security`).
   - Query tested OWASP hardening configurations and code patches (`get_security_remediation`) for NGINX, Apache, and Cloudflare.
   - Generate production-ready hardening configs (`generate_hardening_config`).
   - Query CVE vulnerability intelligence and vendor patches (`lookup_cve_advisory`).
   - Generate executive-grade PDF security assessment reports (`generate_pdf_report`).

3. Autonomous Browser Automation (Playwright Chromium):
   - Navigate modern dynamic Single Page Applications (React, Vue, Angular) and render client-side JavaScript (`browser_navigate`).
   - Autonomously click buttons/links, fill form fields, press keys, and scroll (`browser_interact`).
   - Capture full-page high-resolution PNG screenshots saved into screenshots/ (`browser_capture_screenshot`).
   - Evaluate client-side JavaScript to inspect cookies, localStorage, and dynamic DOM (`browser_execute_js`).
   - Inspect background XHR/Fetch network traffic and API communications (`browser_get_network_activity`).

4. Cognitive Memory Architecture (Fast Working Session Memory by Default):
   - CyberAgent utilizes ultra-fast RAM-based Working Memory during all active sessions to minimize latency.
   - Long-Term SQLite & Vector Memory is reserved for on-demand queries (`recall_memory`, `/memory`) or explicit commits (`remember_memory`).

5. Core System & Autonomous Coding:
   - Run any PowerShell/terminal command (`run_command`).
   - Inspect files with line numbers (`read_file`) and surgically patch code (`edit_file`).
   - Create directories (`create_folder`), write files (`write_file`), and grep search code (`search_code`).

6. Time, Date & Expiration Intelligence:
   - Calculate current local and UTC time, timezones, and Unix epoch timestamps (`calculate_datetime`).
   - Date arithmetic: add/subtract days, hours, minutes, seconds from any date.
   - Calculate exact duration/difference between dates, and check SSL certificate/JWT token expirations.

7. Real-Time Web Search & Content Scraping:
   - Search the live internet in real-time for CVEs, technical blogs, and documentation (`search_internet`).
   - Deeply scrape web pages to extract clean text, articles, and links (`scrape_web_page`).

8. CRITICAL TOOL USAGE & CONVERSATIONAL RULES:
   - For greetings, conversational messages, or general questions (e.g. "hi", "hello", "hey", "who are you", "what can you do", "help", "thanks"), DO NOT CALL ANY TOOLS!
   - Directly respond in natural conversational text asking how you can assist the user with cybersecurity, penetration testing, or coding.
   - ONLY invoke tools when the user explicitly asks you to perform an action (e.g. scan a target, run a command, search code, audit endpoints, inspect or edit files).
   - NEVER invoke tools just to acknowledge the user or say hello!

9. IMMUTABLE SAFETY & CODE INTEGRITY DIRECTIVE:
   - You are STRICTLY FORBIDDEN from editing, patching, creating, deleting, or removing any files or code within CyberAgent's own project directory ('tools/cyber_agent').
   - You must NEVER use `write_file`, `edit_file`, `create_folder`, or `run_command` to alter CyberAgent's own source code, configs, or modules.
   - All file modification tools and terminal commands targeting CyberAgent's directory are permanently blocked by the system's Immutable Safety Gate.
   - Confine all file changes, vulnerability fixes, and security tests to authorized external target repositories and cyber range labs.

10. STRICT TRUTHFULNESS & ANTI-HALLUCINATION DIRECTIVE:
   - NEVER invent, hallucinate, or fabricate vulnerabilities, findings, or proof-of-concept exploits.
   - You MUST report ONLY findings that are directly backed by verified raw tool output evidence (e.g. HTTP 200 with signature body, actual open port socket, or real file leak).
   - If a target returns 403 Forbidden or 404 Not Found, you MUST NOT claim it is exposed.
   - Beware of Soft-404 pages: A 200 OK status on random paths or custom error templates is NOT an exposed vulnerability unless valid administrative authentication forms or sensitive data signatures are explicitly verified in the response.
   - If a test yields no vulnerabilities or credentials, state clearly and truthfully: "No verified exposure found on this surface." Honesty and high confidence are critical for professional client security assessments.
   - When reporting findings, always include reproducible Evidence (Status code, HTTP Response headers, or signature evidence).

Current Workspace Root: {self.config.workspace_root}
OS: Windows (Commands run via PowerShell)"""

    def _reflect_on_tool_failure(self, fn_name: str, fn_args: Dict[str, Any], tool_output: Dict[str, Any]) -> Optional[str]:
        """
        Autonomous Critic & Self-Reflection Engine.
        Analyzes tool execution failures, diagnoses root causes (WAF, connection timeout,
        syntax error, missing parameters), and formulates strategic adaptation directives.
        """
        err_msg = str(tool_output.get("error") or tool_output.get("stderr") or "").lower()
        if not err_msg and tool_output.get("success", True):
            return None

        # WAF / Cloudflare 403 blocks
        if any(w in err_msg for w in ["403", "cloudflare", "waf", "forbidden", "access denied", "blocked"]):
            diagnosis = "Target appears protected by Web Application Firewall (WAF) or bot mitigation filter."
            adaptation = "Switch strategy: run `detect_waf_fingerprint` to identify rules, or use autonomous Chromium browser (`browser_navigate`) via Playwright to bypass client-side challenges."

        # Connection / Timeout
        elif any(w in err_msg for w in ["timed out", "timeout", "connection refused", "not reachable", "unreachable"]):
            diagnosis = "Network timeout or closed port encountered."
            adaptation = "Pivot tactic: verify host reachability with `probe_service_ports` or query passive historical data via `mine_historical_endpoints` without direct connection."

        # Missing target snippet in edit_file / patch
        elif "snippet was not found" in err_msg:
            diagnosis = "Exact code snippet was not matched due to whitespace, indentation, or line variations."
            adaptation = "Use `read_file` to re-inspect exact line numbers and context surrounding the target code before calling `edit_file`."

        # Subdomain / DNS failure
        elif "dns" in err_msg or "getaddrinfo" in err_msg:
            diagnosis = "DNS resolution failed for the given hostname."
            adaptation = "Use `enumerate_subdomains` or `lookup_whois_and_ip` to verify active canonical hostnames."

        # Generic failure fallback
        else:
            diagnosis = f"Action '{fn_name}' execution encountered an issue: {err_msg[:120]}"
            adaptation = "Review parameters and select an alternative specialized tool to achieve the objective."

        return f"[Critic Diagnosis] {diagnosis}\n[Strategic Pivot] {adaptation}"

    def set_enabled_tools(self, tools: Optional[List[str]] = None) -> None:
        """Sets the subset of tools exposed to the LLM agent. None enables dynamic auto-routing."""
        if tools is None:
            self.enabled_tools = None
        else:
            self.enabled_tools = set(tools)

    def _select_dynamic_tool_names(self, prompt: str) -> Set[str]:
        """Dynamically identifies only the relevant tools for the user's specific request."""
        prompt_lower = prompt.lower()
        selected: Set[str] = {"run_command", "read_file", "search_internet"}

        tool_clusters = [
            (
                ["whois", "ip", "domain", "lookup", "dns", "subdomain", "target", "dossier", "host", "port", "open port", "ports", "service", "url", "website", "site", "bizmatepro"],
                ["lookup_whois_and_ip", "enumerate_subdomains", "probe_service_ports", "audit_website_security", "get_target_dossier"]
            ),
            (
                ["sqli", "sql", "injection", "xss", "csrf", "fuzz", "payload", "attack", "pentest", "exploit", "bypass", "vulnerability", "audit", "security", "crawl", "spider", "testfire", "juice"],
                ["crawl_attack_surface", "fuzz_web_endpoints", "verify_target_vulnerability", "run_full_pentest_audit", "generate_security_payload", "audit_form_csrf_security"]
            ),
            (
                ["browser", "screenshot", "click", "navigate", "dom", "render", "playwright", "page", "button", "headless", "spa"],
                ["browser_navigate", "browser_interact", "browser_capture_screenshot", "browser_execute_js", "browser_get_network_activity"]
            ),
            (
                ["login", "password", "brute", "waf", "cloud", "cloudflare", "token", "jwt", "account", "enumeration", "leak", "secret", "api key", "auth"],
                ["audit_login_security", "detect_waf_fingerprint", "audit_account_enumeration", "extract_sensitive_leaks", "audit_jwt_security"]
            ),
            (
                ["sast", "code review", "php", "cve", "patch", "fix", "mitre", "remediation", "harden", "hardening", "pdf", "report", "config"],
                ["scan_codebase_sast", "audit_php_threats", "lookup_cve_advisory", "get_security_remediation", "generate_hardening_config", "generate_pdf_report", "map_mitre_attack", "edit_file", "write_file"]
            ),
            (
                ["file", "folder", "write", "edit", "create", "patch file", "search code", "directory", "list", "save"],
                ["write_file", "edit_file", "create_folder", "list_directory", "search_code"]
            ),
            (
                ["date", "time", "expire", "expiry", "ssl expire", "cert", "epoch", "timestamp", "calculate"],
                ["calculate_datetime"]
            ),
            (
                ["proxy", "socks", "http proxy", "health"],
                ["check_proxy_health"]
            ),
            (
                ["remember", "recall", "memory", "save finding"],
                ["remember_memory", "recall_memory"]
            ),
            (
                ["wayback", "archive", "history", "historical", "cdx", "old url", "endpoints"],
                ["mine_historical_endpoints", "crawl_attack_surface"]
            ),
            (
                ["secret", "secrets", "api key", "token leak", "private key", "gitleaks", "credential", "hardcoded"],
                ["scan_repository_secrets", "extract_sensitive_leaks", "scan_codebase_sast"]
            ),
            (
                ["s3", "bucket", "cloud storage", "blob", "aws bucket", "gcp bucket", "storage exposure"],
                ["audit_cloud_storage_exposure"]
            ),
            (
                ["nmap", "masscan", "xml scan", "network scan", "banner", "service scan"],
                ["parse_network_audit_scan", "probe_service_ports"]
            ),
            (
                ["takeover", "subdomain takeover", "dangling", "cname"],
                ["detect_subdomain_takeover", "enumerate_subdomains"]
            ),
            (
                ["graph", "attack graph", "visual graph", "network map", "topology"],
                ["generate_attack_surface_graph"]
            ),
            (
                ["remediate", "patch", "verify fix", "fix bug", "patch verify", "remediation"],
                ["remediate_and_verify_vulnerability", "edit_file", "get_security_remediation"]
            )
        ]

        matched = False
        for keywords, tools in tool_clusters:
            if any(kw in prompt_lower for kw in keywords):
                selected.update(tools)
                matched = True

        if re.search(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', prompt_lower):
            selected.update(["lookup_whois_and_ip", "audit_website_security", "probe_service_ports", "enumerate_subdomains"])
            matched = True

        if not matched:
            selected.update(["write_file", "audit_website_security", "lookup_whois_and_ip"])

        return selected

    def get_active_tool_definitions(self, prompt: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Returns tool schemas. If self.enabled_tools is explicitly configured, honors it.
        Otherwise dynamically routes only the most relevant tools for the current prompt.
        """
        if self.enabled_tools is not None:
            return [td for td in self.all_tool_definitions if td.get("function", {}).get("name") in self.enabled_tools]

        if not prompt:
            default_tool_names = {"run_command", "read_file", "write_file", "audit_website_security", "search_internet", "lookup_whois_and_ip"}
            return [td for td in self.all_tool_definitions if td.get("function", {}).get("name") in default_tool_names]

        if getattr(self, "router", None) is not None:
            return self.router.route_tools(prompt)

        selected_names = self._select_dynamic_tool_names(prompt)
        return [td for td in self.all_tool_definitions if td.get("function", {}).get("name") in selected_names]

    def run(self, user_prompt: str, max_steps: Optional[int] = None) -> str:
        """Alias for run_task for backward compatibility and swarm execution."""
        return self.run_task(user_prompt=user_prompt)

    def run_task(
        self,
        user_prompt: str,
        on_step_callback: Optional[Callable] = None,
        approval_callback: Optional[Callable[[str, Dict[str, Any]], Tuple[bool, str]]] = None
    ) -> str:
        """
        Executes the autonomous agentic loop to solve the user's task.
        """
        client = self._get_client()
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": user_prompt}
        ]

        self.console.print(Panel(f"[bold cyan]🎯 Objective:[/bold cyan] {user_prompt}", border_style="cyan"))

        # Fast Short-Term Session Working Memory (Default, 0ms overhead)
        try:
            st_context = self.short_term_memory.get_prompt_context()
            if st_context:
                messages.insert(1, {
                    "role": "system",
                    "content": f"[⚡ Fast Working Session Memory]:\n{st_context}"
                })
        except Exception:
            pass

        # Smart greeting / conversational intent detection
        normalized_prompt = user_prompt.strip().lower().rstrip("!?. ")
        common_greetings = {
            "hi", "hello", "hey", "hola", "sup", "yo", "salam", "assalamu alaikum",
            "kemon acho", "kemon achen", "good morning", "good evening", "good afternoon",
            "who are you", "what can you do", "hi there", "hello there", "help"
        }
        is_greeting = (
            normalized_prompt in common_greetings
            or any(g in normalized_prompt for g in [
                "what can you do", "who are you", "what are you", "tumi ke", "kemon acho",
                "kemon achen", "tumi ki korte", "tumi ki", "help me understand", "introduce yourself"
            ])
        )

        step = 0
        max_steps = self.config.max_steps
        consecutive_tool_failures: Dict[str, int] = {}

        try:
            while step < max_steps:
                step += 1
                self.console.print(f"\n[bold blue]━━━ Step {step}/{max_steps} ━━━[/bold blue]")

                # Active tool schemas (suppress tools on step 1 if the user just said 'hi' or 'hello')
                active_tools = [] if (step == 1 and is_greeting) else self.get_active_tool_definitions(user_prompt)

                # Filter out tools that have already been executed repeatedly or single-shot terminal tools
                blocked_tools = {sig.split(":")[0] for sig, count in consecutive_tool_failures.items() if count >= 2}
                if blocked_tools and active_tools:
                    active_tools = [td for td in active_tools if td.get("function", {}).get("name") not in blocked_tools]

                if step == 1 and active_tools and self.enabled_tools is None:
                    tool_names_str = ", ".join([td["function"]["name"] for td in active_tools])
                    self.console.print(f"[dim cyan]🎯 Dynamic Tool Routing: {len(active_tools)} tools loaded for this task ({tool_names_str})[/dim cyan]")

                # Robust LLM Inference with Exponential Backoff for Rate Limits (429)
                max_retries = 4
                retry_delay = 2.0
                for attempt in range(max_retries):
                    try:
                        start_time = time.time()
                        self.console.print(f"[dim cyan]⚡ Querying {self.config.model} ({self.config.provider.upper()})...[/dim cyan]")

                        # Attempt real-time streaming inference
                        stream = client.chat.completions.create(
                            model=self.config.model,
                            messages=messages,
                            tools=active_tools if active_tools else None,
                            tool_choice="auto" if active_tools else "none",
                            temperature=0.0,
                            stream=True
                        )

                        full_content = ""
                        full_reasoning = ""
                        in_think_tag = False
                        live_think = None
                        live_resp = None
                        tool_calls_acc: Dict[int, Dict[str, str]] = {}

                        try:
                            for chunk in stream:
                                if not chunk.choices:
                                    continue
                                delta = chunk.choices[0].delta

                                # 1. Native reasoning / thinking content (e.g. DeepSeek-R1 / QwQ)
                                reasoning_chunk = getattr(delta, "reasoning_content", None) or getattr(delta, "reasoning", None)
                                if not reasoning_chunk and hasattr(delta, "model_extra") and delta.model_extra:
                                    reasoning_chunk = delta.model_extra.get("reasoning_content")

                                if reasoning_chunk:
                                    full_reasoning += reasoning_chunk
                                    if self.console.is_terminal and not self.console.legacy_windows:
                                        if not live_think:
                                            live_think = Live(
                                                Panel(Markdown(full_reasoning.strip()), title="[bold magenta]🧠 Model Thinking Process[/bold magenta]", border_style="magenta"),
                                                console=self.console,
                                                refresh_per_second=12
                                            )
                                            live_think.start()
                                        else:
                                            live_think.update(Panel(Markdown(full_reasoning.strip()), title="[bold magenta]🧠 Model Thinking Process[/bold magenta]", border_style="magenta"))

                                # 2. Content chunk & inline <think> tags handling
                                content_chunk = delta.content or ""
                                if content_chunk:
                                    # Check for opening <think> tag
                                    if not in_think_tag and "<think>" in content_chunk:
                                        before_think, _, after_think = content_chunk.partition("<think>")
                                        if before_think:
                                            full_content += before_think
                                            if self.console.is_terminal and not self.console.legacy_windows:
                                                if not live_resp:
                                                    live_resp = Live(
                                                        Panel(Markdown(full_content.strip()), title="[bold cyan]💬 CyberAgent Response[/bold cyan]", border_style="cyan"),
                                                        console=self.console,
                                                        refresh_per_second=12
                                                    )
                                                    live_resp.start()
                                                else:
                                                    live_resp.update(Panel(Markdown(full_content.strip()), title="[bold cyan]💬 CyberAgent Response[/bold cyan]", border_style="cyan"))
                                        in_think_tag = True
                                        content_chunk = after_think

                                    if in_think_tag:
                                        if "</think>" in content_chunk:
                                            think_part, _, after_think = content_chunk.partition("</think>")
                                            full_reasoning += think_part
                                            in_think_tag = False
                                            content_chunk = after_think
                                        else:
                                            full_reasoning += content_chunk
                                            content_chunk = ""

                                        if full_reasoning:
                                            if self.console.is_terminal and not self.console.legacy_windows:
                                                if not live_think:
                                                    live_think = Live(
                                                        Panel(Markdown(full_reasoning.strip()), title="[bold magenta]🧠 Model Thinking Process[/bold magenta]", border_style="magenta"),
                                                        console=self.console,
                                                        refresh_per_second=12
                                                    )
                                                    live_think.start()
                                                else:
                                                    live_think.update(Panel(Markdown(full_reasoning.strip()), title="[bold magenta]🧠 Model Thinking Process[/bold magenta]", border_style="magenta"))

                                    if content_chunk:
                                        # Stop thinking Live if running
                                        if live_think:
                                            try:
                                                live_think.stop()
                                            except Exception:
                                                pass
                                            live_think = None

                                        full_content += content_chunk
                                        if self.console.is_terminal and not self.console.legacy_windows:
                                            if not live_resp:
                                                live_resp = Live(
                                                    Panel(Markdown(full_content.strip()), title="[bold cyan]💬 CyberAgent Response[/bold cyan]", border_style="cyan"),
                                                    console=self.console,
                                                    refresh_per_second=12
                                                )
                                                live_resp.start()
                                            else:
                                                live_resp.update(Panel(Markdown(full_content.strip()), title="[bold cyan]💬 CyberAgent Response[/bold cyan]", border_style="cyan"))

                                # 3. Tool call streaming deltas
                                if getattr(delta, "tool_calls", None):
                                    for tc in delta.tool_calls:
                                        idx = tc.index if getattr(tc, "index", None) is not None else (len(tool_calls_acc) if not tool_calls_acc else 0)
                                        if idx not in tool_calls_acc:
                                            tool_calls_acc[idx] = {
                                                "id": tc.id or f"call_{idx}",
                                                "name": "",
                                                "arguments": "",
                                                "extra_content": None
                                            }
                                        if tc.id:
                                            tool_calls_acc[idx]["id"] = tc.id
                                        if getattr(tc, "extra_content", None):
                                            tool_calls_acc[idx]["extra_content"] = tc.extra_content
                                        if tc.function:
                                            if tc.function.name:
                                                tool_calls_acc[idx]["name"] += tc.function.name
                                            if tc.function.arguments:
                                                tool_calls_acc[idx]["arguments"] += tc.function.arguments

                        finally:
                            if live_think:
                                try:
                                    live_think.stop()
                                except Exception:
                                    pass
                                live_think = None
                            if live_resp:
                                try:
                                    live_resp.stop()
                                except Exception:
                                    pass
                                live_resp = None

                        elapsed = time.time() - start_time
                        self.console.print(f"[bold green]⏱️ Response generated in {elapsed:.2f}s[/bold green]")

                        # If in legacy Windows / non-interactive terminal, render the final complete response panel once
                        if not self.console.is_terminal or self.console.legacy_windows:
                            if full_reasoning:
                                self.console.print(Panel(Markdown(full_reasoning.strip()), title="[bold magenta]🧠 Model Thinking Process[/bold magenta]", border_style="magenta"))
                            if full_content:
                                self.console.print(Panel(Markdown(full_content.strip()), title="[bold cyan]💬 CyberAgent Response[/bold cyan]", border_style="cyan"))

                        # Reconstruct tool calls
                        constructed_tool_calls = None
                        if tool_calls_acc:
                            constructed_tool_calls = [
                                StreamedToolCall(
                                    call_id=tool_calls_acc[i]["id"],
                                    name=tool_calls_acc[i]["name"],
                                    arguments=tool_calls_acc[i]["arguments"],
                                    extra_content=tool_calls_acc[i].get("extra_content")
                                )
                                for i in sorted(tool_calls_acc.keys(), key=lambda x: (x is None, x))
                            ]

                        clean_thought = full_content.strip()
                        if not clean_thought and full_reasoning:
                            clean_thought = full_reasoning.strip()

                        message = StreamedMessage(
                            content=full_content if full_content else None,
                            tool_calls=constructed_tool_calls,
                            reasoning=full_reasoning if full_reasoning else None
                        )

                    except Exception as stream_ex:
                        # Fallback to non-streaming if stream mode fails
                        self.console.print(f"[dim yellow]⚠️ Stream mode unavailable ({str(stream_ex)[:60]}). Falling back to sync call...[/dim yellow]")
                        response = client.chat.completions.create(
                            model=self.config.model,
                            messages=messages,
                            tools=active_tools if active_tools else None,
                            tool_choice="auto" if active_tools else "none",
                            temperature=0.0,
                            stream=False
                        )
                        elapsed = time.time() - start_time
                        self.console.print(f"[bold green]⏱️ Response generated in {elapsed:.2f}s[/bold green]")
                        message = response.choices[0].message
                        clean_thought = message.content or ""
                        if "</think>" in clean_thought:
                            parts = clean_thought.split("</think>")
                            thinking_text = parts[0].replace("<think>", "").strip()
                            clean_thought = parts[-1].strip()
                            if thinking_text:
                                self.console.print(Panel(thinking_text, title="[bold magenta]🧠 Model Thinking[/bold magenta]", border_style="magenta"))
                        if clean_thought:
                            self.console.print(Panel(clean_thought, title="[bold cyan]💬 Response[/bold cyan]", border_style="cyan"))

                        # Request succeeded! Break out of retry loop
                        break

                    except Exception as e:
                        err_str = str(e).lower()
                        if ("429" in err_str or "rate limit" in err_str or "too many requests" in err_str) and attempt < max_retries - 1:
                            wait_s = retry_delay * (2 ** attempt)
                            self.console.print(f"[bold yellow]⚠️ Rate limit detected (429). Exponential backoff: Retrying in {wait_s:.1f}s (Attempt {attempt+1}/{max_retries})...[/bold yellow]")
                            time.sleep(wait_s)
                            continue
                        else:
                            err_msg = f"LLM API Error ({self.config.provider} - {self.config.model}): {str(e)}"
                            self.console.print(f"[bold red]❌ {err_msg}[/bold red]")
                            return err_msg

                thought = clean_thought

                # Convert message to dictionary for history tracking
                msg_dict: Dict[str, Any] = {"role": "assistant"}
                if message.content:
                    msg_dict["content"] = message.content
                if message.tool_calls:
                    tc_payload = []
                    for tc in message.tool_calls:
                        item = {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments
                            }
                        }
                        if hasattr(tc, "extra_content") and tc.extra_content:
                            item["extra_content"] = tc.extra_content
                        tc_payload.append(item)
                    msg_dict["tool_calls"] = tc_payload
                messages.append(msg_dict)

                # Check if assistant generated text-embedded tool calls (e.g. <tool_call> or <function=...>)
                if not message.tool_calls and message.content:
                    extracted_calls = []
                    # Match <tool_call> ... </tool_call>
                    for match in re.finditer(r"<tool_call>([\s\S]*?)</tool_call>", message.content):
                        block = match.group(1).strip()
                        try:
                            data = json.loads(block)
                            fn_n = data.get("name") or data.get("function")
                            fn_a = data.get("arguments") or data.get("parameters") or {}
                            if fn_n:
                                extracted_calls.append(StreamedToolCall(
                                    call_id=f"call_ext_{len(extracted_calls)}",
                                    name=fn_n,
                                    arguments=json.dumps(fn_a) if isinstance(fn_a, dict) else str(fn_a)
                                ))
                        except Exception:
                            pass
                    # Match <function=name>...</function>
                    for match in re.finditer(r"<function=([a-zA-Z0-9_\-]+)>([\s\S]*?)</function>", message.content):
                        fn_n = match.group(1).strip()
                        block = match.group(2).strip()
                        try:
                            fn_a = json.loads(block)
                        except Exception:
                            fn_a = {}
                        extracted_calls.append(StreamedToolCall(
                            call_id=f"call_fn_{len(extracted_calls)}",
                            name=fn_n,
                            arguments=json.dumps(fn_a)
                        ))
                    if extracted_calls:
                        message.tool_calls = extracted_calls

                # If no tools called, agent has finished its work
                if not message.tool_calls:
                    self.console.print(Panel("[bold green]✅ Task Complete! No further actions needed.[/bold green]", border_style="green"))
                    return thought or "Task completed successfully."

                # Execute tool calls
                for tool_call in message.tool_calls:
                    fn_name = tool_call.function.name
                    fn_args_raw = tool_call.function.arguments

                    try:
                        fn_args = json.loads(fn_args_raw) if isinstance(fn_args_raw, str) else (fn_args_raw or {})
                        if not isinstance(fn_args, dict):
                            fn_args = {}
                    except Exception:
                        fn_args = {}

                    # Ensure standard default arguments for known tools if missing or malformed
                    if fn_name == "mine_historical_endpoints":
                        if "limit" not in fn_args or not isinstance(fn_args["limit"], int):
                            try:
                                fn_args["limit"] = int(fn_args.get("limit", 50))
                            except Exception:
                                fn_args["limit"] = 50
                        if "domain" not in fn_args:
                            fallback_d = fn_args.get("target") or fn_args.get("target_url") or getattr(self.short_term_memory, "current_target", None) or "example.com"
                            fn_args["domain"] = str(fallback_d)

                    # Display tool execution in terminal
                    args_preview = json.dumps(fn_args, indent=2, ensure_ascii=False)
                    self.console.print(Panel(
                        Syntax(args_preview, "json", theme="monokai"),
                        title=f"[bold yellow]🔧 Tool Call: {fn_name}[/bold yellow]",
                        border_style="yellow"
                    ))

                    # Dispatch
                    handler = self.tool_dispatcher.get(fn_name)
                    if handler:
                        # Immutable Safety Gate Check: Protect CyberAgent project folder from any tampering
                        if fn_name in ("write_file", "edit_file", "create_folder"):
                            target_p = fn_args.get("file_path") or fn_args.get("path") or fn_args.get("folder_path")
                            if hasattr(self.tools, "is_protected_path") and self.tools.is_protected_path(target_p):
                                tool_output = {
                                    "success": False,
                                    "rejected": True,
                                    "error": f"Security Guard: Operation denied. CyberAgent is strictly prohibited from modifying, editing, or creating files within its own project folder ('{target_p}')."
                                }
                                self.console.print(Panel(
                                    f"[bold red]🚫 IMMUTABLE SAFETY GATE:[/bold red] Modification of CyberAgent's own code is strictly prohibited.\n[dim]Target: {target_p}[/dim]",
                                    border_style="red"
                                ))
                                messages.append({
                                    "role": "tool",
                                    "tool_call_id": tool_call.id,
                                    "name": fn_name,
                                    "content": json.dumps(tool_output)
                                })
                                continue

                        elif fn_name == "run_command":
                            cmd_str = fn_args.get("command", "")
                            cmd_cwd = fn_args.get("cwd")
                            if hasattr(self.tools, "check_command_safety"):
                                is_blocked, block_msg = self.tools.check_command_safety(cmd_str, cmd_cwd)
                                if is_blocked:
                                    tool_output = {
                                        "success": False,
                                        "rejected": True,
                                        "error": f"Security Guard: Command execution blocked. {block_msg}"
                                    }
                                    self.console.print(Panel(
                                        f"[bold red]🚫 IMMUTABLE SAFETY GATE:[/bold red] Destructive/modifying command blocked against CyberAgent project files.\n[dim]{block_msg}[/dim]",
                                        border_style="red"
                                    ))
                                    messages.append({
                                        "role": "tool",
                                        "tool_call_id": tool_call.id,
                                        "name": fn_name,
                                        "content": json.dumps(tool_output)
                                    })
                                    continue

                        # Human-in-the-Loop Security Gatekeeper Check
                        if self.hitl.needs_approval(fn_name, fn_args):
                            approved, status_msg = self.hitl.request_approval(
                                self.console,
                                fn_name,
                                fn_args,
                                approval_callback=approval_callback
                            )
                            if not approved:
                                tool_output = {
                                    "success": False,
                                    "rejected": True,
                                    "error": f"Human-in-the-Loop: Action '{fn_name}' was REJECTED by human operator.",
                                    "operator_feedback": status_msg
                                }
                                self.console.print(Panel(
                                    f"[bold red]🚫 Action Rejected by Operator:[/bold red] {fn_name}\n[dim]{status_msg}[/dim]",
                                    border_style="red"
                                ))
                            else:
                                try:
                                    tool_output = handler(**fn_args)
                                except Exception as ex:
                                    tool_output = {"success": False, "error": f"Exception executing {fn_name}: {str(ex)}"}
                        else:
                            try:
                                tool_output = handler(**fn_args)
                            except Exception as ex:
                                tool_output = {"success": False, "error": f"Exception executing {fn_name}: {str(ex)}"}
                    else:
                        valid_names = sorted(list(self.tool_dispatcher.keys()))[:15]
                        tool_output = {
                            "success": False,
                            "error": f"Tool '{fn_name}' does not exist (Hallucination Guard). You MUST choose strictly from available tools: {', '.join(valid_names)}"
                        }

                    # Display result
                    output_str = json.dumps(tool_output, indent=2, ensure_ascii=False)
                    preview = output_str if len(output_str) < 600 else output_str[:600] + "\n... [truncated]"
                    self.console.print(Panel(
                        Syntax(preview, "json", theme="monokai"),
                        title=f"[bold green]📥 Result ({fn_name})[/bold green]",
                        border_style="green"
                    ))

                    # Record action and target in Fast Short-Term Memory
                    try:
                        summary_text = str(tool_output.get("message") or tool_output.get("error") or fn_name) if isinstance(tool_output, dict) else str(tool_output)
                        self.short_term_memory.add_action(fn_name, fn_args, summary_text)
                        tgt = fn_args.get("target_url") or fn_args.get("target") or fn_args.get("domain") or (tool_output.get("root_domain") if isinstance(tool_output, dict) else None)
                        if tgt:
                            self.short_term_memory.set_target(str(tgt))
                    except Exception:
                        pass

                    # Ingest findings into Attack Surface Knowledge Graph
                    try:
                        if hasattr(self, "attack_graph") and self.attack_graph:
                            self.attack_graph.ingest_tool_result(fn_name, fn_args, tool_output)
                    except Exception:
                        pass

                    # Autonomous Self-Reflection & Auto-Correction Engine
                    reflection = self._reflect_on_tool_failure(fn_name, fn_args, tool_output)
                    if reflection:
                        if isinstance(tool_output, dict):
                            tool_output["_critic_reflection"] = reflection
                        self.console.print(Panel(
                            f"[bold magenta]⚡ Strategic Auto-Correction ({fn_name}):[/bold magenta]\n"
                            f"[italic white]{reflection}[/italic white]",
                            title="[bold magenta]🤔 Self-Reflection & Adaptation[/bold magenta]",
                            border_style="magenta"
                        ))

                    # Append tool observation for LLM
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": fn_name,
                        "content": json.dumps(tool_output)
                    })

                    # Infinite Repetition Prevention for Small 3B Models
                    tool_call_sig = f"{fn_name}:{json.dumps(fn_args, sort_keys=True)}"
                    consecutive_tool_failures[tool_call_sig] = consecutive_tool_failures.get(tool_call_sig, 0) + 1
                    if consecutive_tool_failures[tool_call_sig] >= 3:
                        messages.append({
                            "role": "system",
                            "content": f"[SYSTEM DIRECTIVE] The tool call '{fn_name}' with arguments {json.dumps(fn_args)} has been executed 3 times without new progress. DO NOT call this tool with these arguments again. Synthesize your final conclusions now and summarize your findings for the operator."
                        })

                    if on_step_callback:
                        on_step_callback(fn_name, fn_args, tool_output)

            self.console.print("[bold red]⚠️ Max steps limit reached without explicit completion.[/bold red]")
            return "Max steps limit reached."

        except KeyboardInterrupt:
            self.console.print("\n[bold red]🛑 Task execution stopped by user (Ctrl+C). Returning to prompt.[/bold red]")
            return "Task execution stopped by user."
