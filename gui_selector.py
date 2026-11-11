"""
CyberAgent - Ultra-Premium Native Desktop Tool Selector (Tkinter Glass-Dark Edition)
=====================================================================================
A luxury cybersecurity command interface for selecting / tuning CyberAgent's 57 tools:
- Cyberpunk / Modern Dark UI Theme (Deep Obsidian Slate #090d16, Cyan #38bdf8, Emerald #10b981)
- Real-time dynamic search & category filter (Instant substring match)
- Quick-switch one-click mission presets (Bug Bounty, Pentest, Recon, Code SAST, Minimal, All)
- Animated selection pills with category tag badges and live counter
- High-DPI support, smooth canvas mouse wheel scrolling, hover micro-interactions
- 100% native Python Tkinter (Zero external browser or heavy web runtime dependencies)
"""

import sys
import tkinter as tk
from tkinter import ttk
from typing import List, Set, Optional, Dict, Any

# Complete Master Catalog of CyberAgent's 57 Tools
TOOL_CATEGORIES = [
    {
        "category": "🏆 Bug Bounty & Offensive Exploitation",
        "badge": "BOUNTY",
        "color": "#f43f5e",  # Rose Red
        "tools": [
            ("harvest_js_secrets_and_endpoints", "Extract hidden developer API keys, auth tokens, and private routes from frontend JavaScript bundles"),
            ("fuzz_sensitive_paths_and_backups", "Probe for exposed .env, .git, actuator, database backups, and configs with signature verification"),
            ("resolve_waf_and_origin_ip", "Bypass Cloudflare/Akamai WAFs via historical DNS records and SSL Certificate SAN checks"),
            ("audit_cors_misconfiguration", "Test for permissive CORS policies (wildcard origin, null origin) allowing credential leakage"),
            ("audit_broken_link_hijacking", "Scan broken external social/vendor links vulnerable to hijacking and domain takeover"),
            ("search_live_exploits", "Query live Exploit-DB, Vulners, and GitHub PoC repositories for validated exploit scripts"),
            ("mine_hidden_parameters", "Extract hidden GET/POST parameters from web forms, scripts, and historical endpoints"),
            ("generate_hackerone_report", "Compile vulnerability findings into structured markdown report ready for HackerOne / Bugcrowd submission"),
            ("execute_python_code", "Execute sandboxed offensive Python scripts, custom exploit modules, and security verifications")
        ]
    },
    {
        "category": "🔍 Advanced OSINT & Attack Surface Recon",
        "badge": "RECON",
        "color": "#0ea5e9",  # Sky Blue
        "tools": [
            ("mine_historical_endpoints", "Mines Wayback Machine CDX API for past endpoints, forgotten APIs, and hidden parameters"),
            ("scan_repository_secrets", "Scan codebase & git history for exposed API keys, private keys, and high-entropy secrets"),
            ("audit_cloud_storage_exposure", "Audit AWS S3, Google Cloud Storage, and Azure Blobs for public listing exposure"),
            ("detect_subdomain_takeover", "Detect dangling CNAME DNS records allowing hostile third-party subdomain takeover"),
            ("enumerate_subdomains", "Enumerate active subdomains using Certificate Transparency (crt.sh) and DNS probing"),
            ("lookup_whois_and_ip", "WHOIS domain registration, expiry, nameservers, ASN, and IP geolocation intelligence"),
            ("parse_network_audit_scan", "Parse Nmap / Masscan XML scans into open ports, service banners, and threat intelligence"),
            ("probe_service_ports", "Multi-threaded socket port scanner across key service ports (21, 22, 80, 443, 8080)"),
            ("generate_attack_surface_graph", "Interactive visual knowledge graph of all discovered targets, ports, and weaknesses")
        ]
    },
    {
        "category": "🔴 Web Penetration Testing (OWASP Top 10)",
        "badge": "PENTEST",
        "color": "#ef4444",  # Crimson Red
        "tools": [
            ("crawl_attack_surface", "Active web crawler extracting input forms, query parameters, and REST API entrypoints"),
            ("run_full_pentest_audit", "Autonomous multi-phase penetration testing audit against authorized practice targets"),
            ("fuzz_web_endpoints", "Rapid path discovery for database backups, .env, .git leaks, and administrative portals"),
            ("verify_target_vulnerability", "Safe PoC probes for SQL Injection auth bypass, Reflected XSS, and CORS misconfiguration"),
            ("audit_login_security", "Audit login brute-force defenses, HTTP 429 rate-limiting, account lockout, and captchas"),
            ("detect_waf_fingerprint", "Fingerprint Web Application Firewalls (Cloudflare, AWS WAF, Akamai, Imperva)"),
            ("audit_account_enumeration", "Test timing discrepancies and differing error messages allowing username enumeration"),
            ("extract_sensitive_leaks", "Harvest API keys, JWT tokens, AWS credentials, and developer HTML comments"),
            ("audit_form_csrf_security", "Audit HTML forms for missing CSRF tokens and SameSite cookie protections"),
            ("audit_php_threats", "Deep audit of dangerous PHP functions (eval, system, exec) and file inclusion flaws")
        ]
    },
    {
        "category": "🌐 Autonomous Chromium Browser Automation",
        "badge": "BROWSER",
        "color": "#a855f7",  # Purple
        "tools": [
            ("browser_navigate", "Launch Playwright Chromium to render dynamic Single Page Applications (React/Vue/Angular)"),
            ("browser_interact", "Human-like interaction: click buttons, fill input fields, press Tab/Enter, hover, and scroll"),
            ("browser_capture_screenshot", "Capture full-page high-resolution PNG audit screenshots into screenshots/ directory"),
            ("browser_execute_js", "Evaluate arbitrary JavaScript in active browser context to inspect cookies, DOM, and localStorage"),
            ("browser_get_network_activity", "Inspect background XHR/Fetch network traffic, API endpoints, and response headers")
        ]
    },
    {
        "category": "🛡️ Blue-Team Hardening & Compliance",
        "badge": "DEFENSE",
        "color": "#10b981",  # Emerald Green
        "tools": [
            ("audit_website_security", "Comprehensive WebShield audit: WAF, TLS 1.3, DNS CAA/SPF/DMARC, and OWASP headers"),
            ("generate_pdf_report", "Generate executive and technical client-ready 3-page PDF assessment reports"),
            ("generate_hardening_config", "One-click generation of hardened NGINX configs, Cloudflare WAF rules, and .htaccess"),
            ("get_security_remediation", "Query tested OWASP hardening configurations and code patches from knowledge database"),
            ("lookup_cve_advisory", "Query official CVE vulnerability intelligence, vendor security advisories, and fixes"),
            ("map_mitre_attack", "Map discovered vulnerabilities to MITRE ATT&CK Enterprise tactics and techniques"),
            ("remediate_and_verify_vulnerability", "Autonomous closed-loop Find -> Patch -> Verify code remediation engine")
        ]
    },
    {
        "category": "💻 Core System & Autonomous Engineering",
        "badge": "SYSTEM",
        "color": "#f59e0b",  # Amber Orange
        "tools": [
            ("run_command", "Execute terminal / PowerShell commands on host system with safety verification"),
            ("read_file", "Inspect source code files with line numbers for surgical vulnerability analysis"),
            ("write_file", "Create or overwrite source code files with exact syntax and integrity checks"),
            ("edit_file", "Surgically patch specific code blocks without corrupting existing code comments"),
            ("list_directory", "Explore workspace directories, project structures, and file trees"),
            ("search_code", "Recursively search codebase for keywords, security bugs, hardcoded secrets, and patterns"),
            ("create_folder", "Create directory structures and parent folders on demand"),
            ("scan_codebase_sast", "Static Application Security Testing (SAST) for hardcoded secrets and dangerous functions")
        ]
    },
    {
        "category": "🧠 Memory & Cognitive Intelligence",
        "badge": "MEMORY",
        "color": "#ec4899",  # Pink
        "tools": [
            ("recall_memory", "Search past audit scores, targets, and findings via Stemmed BM25 + Vector similarity"),
            ("remember_memory", "Explicitly commit critical intelligence into permanent SQLite memory database"),
            ("get_target_dossier", "Retrieve complete historical intelligence dossier on target domain or IP")
        ]
    },
    {
        "category": "🌍 Live Web Intelligence & Utilities",
        "badge": "INTEL",
        "color": "#06b6d4",  # Cyan
        "tools": [
            ("search_internet", "Live search engine query returning verified technical URLs and summaries"),
            ("scrape_web_page", "Deep web scraping extracting clean readability text while stripping ads and popups"),
            ("audit_jwt_security", "Audit JWT tokens for alg:none, weak HMAC secrets, and claim tampering"),
            ("generate_security_payload", "Generate obfuscated security test payloads across 17 encoding schemes"),
            ("check_proxy_health", "Diagnostic health, latency, and anonymity tester for HTTP/SOCKS proxies"),
            ("calculate_datetime", "Date arithmetic (+/- days), duration differences, timestamp conversions, and expiry checks")
        ]
    }
]


class PremiumCyberToolSelector:
    """Ultra-modern native desktop window for CyberAgent tool management."""

    def __init__(self, root: tk.Tk, initial_enabled: Optional[List[str]] = None):
        self.root = root
        self.root.title("CYBERAGENT  |  Mission Weaponry & Autonomous Tool Arsenal")
        self.root.geometry("820x760")
        self.root.minsize(680, 560)
        self.root.configure(bg="#090d16")

        # Center Window
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        w, h = 820, 760
        self.root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        self.result = {"saved": False, "tools": []}
        self.check_vars: Dict[str, tk.BooleanVar] = {}
        self.tool_widgets: Dict[str, tk.Frame] = {}

        # Collect full tool list
        self.all_tool_names = []
        for cat in TOOL_CATEGORIES:
            for tname, _ in cat["tools"]:
                self.all_tool_names.append(tname)

        self.initial_set = set(initial_enabled if initial_enabled is not None else self.all_tool_names)

        self._build_header()
        self._build_toolbar()
        self._build_search_bar()
        self._build_scrollable_tool_catalog()
        self._build_footer()
        self._update_counter()

    def _build_header(self):
        """Top Cyberpunk Header with glow badge and live status."""
        header = tk.Frame(self.root, bg="#0d1424", padx=20, pady=14, highlightbackground="#1e293b", highlightthickness=1)
        header.pack(fill="x")

        # Top row: Brand & Status Pill
        row1 = tk.Frame(header, bg="#0d1424")
        row1.pack(fill="x")

        title_lbl = tk.Label(
            row1,
            text="⚡ CYBERAGENT",
            font=("Segoe UI", 15, "bold"),
            fg="#38bdf8",
            bg="#0d1424"
        )
        title_lbl.pack(side="left")

        subtitle = tk.Label(
            row1,
            text="  //  TOOL WEAPONRY ARSENAL",
            font=("Segoe UI", 10, "bold"),
            fg="#64748b",
            bg="#0d1424"
        )
        subtitle.pack(side="left", pady=(3, 0))

        # Pill Status Badge
        badge_frame = tk.Frame(row1, bg="#064e3b", padx=8, pady=2, highlightbackground="#10b981", highlightthickness=1)
        badge_frame.pack(side="right")
        tk.Label(badge_frame, text="● ACTIVE SWARM ARMED", font=("Segoe UI", 8, "bold"), fg="#34d399", bg="#064e3b").pack()

        # Instruction subtitle
        desc = tk.Label(
            header,
            text="Configure active tool capabilities for your autonomous agent. Only armed tools will be dispatched by LLM.",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0d1424"
        )
        desc.pack(anchor="w", pady=(6, 0))

    def _build_toolbar(self):
        """Mission Preset Buttons with distinct role badges."""
        preset_bar = tk.Frame(self.root, bg="#090d16", padx=16, pady=8)
        preset_bar.pack(fill="x")

        lbl_preset = tk.Label(preset_bar, text="MISSION PRESETS:", font=("Segoe UI", 8, "bold"), fg="#64748b", bg="#090d16")
        lbl_preset.pack(side="left", padx=(0, 6))

        presets = [
            ("⭐ All (57)", lambda: self._set_all(True), "#1e293b", "#38bdf8"),
            ("❌ None", lambda: self._set_all(False), "#1e293b", "#94a3b8"),
            ("🏆 Bounty (9)", lambda: self._apply_preset("bounty"), "#3b0764", "#c084fc"),
            ("🔴 Pentest (10)", lambda: self._apply_preset("pentest"), "#450a0a", "#f87171"),
            ("🔍 Recon (9)", lambda: self._apply_preset("recon"), "#082f49", "#38bdf8"),
            ("🛡️ Defense (7)", lambda: self._apply_preset("defense"), "#064e3b", "#34d399"),
            ("💻 Coding (8)", lambda: self._apply_preset("code"), "#451a03", "#fbbf24")
        ]

        for text, cmd, bg_col, fg_col in presets:
            btn = tk.Button(
                preset_bar,
                text=text,
                command=cmd,
                bg=bg_col,
                fg=fg_col,
                activebackground="#334155",
                activeforeground="#ffffff",
                relief="flat",
                font=("Segoe UI", 8, "bold"),
                padx=8,
                pady=3,
                cursor="hand2",
                highlightbackground="#334155",
                highlightthickness=1
            )
            btn.pack(side="left", padx=3)

    def _build_search_bar(self):
        """Live search input filter."""
        search_frame = tk.Frame(self.root, bg="#0f172a", padx=16, pady=6, highlightbackground="#1e293b", highlightthickness=1)
        search_frame.pack(fill="x", padx=16, pady=(0, 6))

        tk.Label(search_frame, text="🔎 Search Arsenal:", font=("Segoe UI", 9, "bold"), fg="#94a3b8", bg="#0f172a").pack(side="left", padx=(0, 8))

        self.search_var = tk.StringVar()
        self.search_var.trace("w", self._on_search)

        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            bg="#1e293b",
            fg="#f8fafc",
            insertbackground="#38bdf8",
            relief="flat",
            font=("Consolas", 10),
            highlightbackground="#334155",
            highlightthickness=1
        )
        search_entry.pack(side="left", fill="x", expand=True, ipady=3)

        btn_clear = tk.Button(
            search_frame,
            text="✕ Clear",
            command=lambda: self.search_var.set(""),
            bg="#334155",
            fg="#94a3b8",
            relief="flat",
            font=("Segoe UI", 8),
            cursor="hand2"
        )
        btn_clear.pack(side="left", padx=(6, 0))

    def _build_scrollable_tool_catalog(self):
        """High-resolution scrollable catalog with card-based rows and hover effects."""
        container = tk.Frame(self.root, bg="#090d16")
        container.pack(fill="both", expand=True, padx=16, pady=2)

        self.canvas = tk.Canvas(container, bg="#090d16", highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.scroll_frame = tk.Frame(self.canvas, bg="#090d16")

        self.scroll_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas_window = self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Stretch inner frame to match canvas width
        def _configure_canvas(event):
            self.canvas.itemconfig(self.canvas_window, width=event.width)
        self.canvas.bind("<Configure>", _configure_canvas)

        # Mouse wheel support
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Build category groups & tool cards
        self.category_frames = []

        for cat in TOOL_CATEGORIES:
            cat_frame = tk.Frame(self.scroll_frame, bg="#090d16", pady=4)
            cat_frame.pack(fill="x", expand=True)
            self.category_frames.append((cat_frame, cat))

            # Header with category badge
            cat_header = tk.Frame(cat_frame, bg="#0d1424", padx=10, pady=5, highlightbackground="#1e293b", highlightthickness=1)
            cat_header.pack(fill="x", pady=(8, 4))

            tk.Label(
                cat_header,
                text=cat["category"],
                font=("Segoe UI", 10, "bold"),
                fg=cat["color"],
                bg="#0d1424"
            ).pack(side="left")

            badge = tk.Label(
                cat_header,
                text=f"[{cat['badge']}]",
                font=("Segoe UI", 8, "bold"),
                fg="#64748b",
                bg="#0d1424"
            )
            badge.pack(side="right")

            # Tools inside category
            for tname, tdesc in cat["tools"]:
                var = tk.BooleanVar(value=(tname in self.initial_set))
                self.check_vars[tname] = var

                row = tk.Frame(
                    cat_frame,
                    bg="#0f172a",
                    padx=10,
                    pady=5,
                    highlightbackground="#1e293b",
                    highlightthickness=1
                )
                row.pack(fill="x", pady=2)
                self.tool_widgets[tname] = (row, tdesc, cat["category"])

                # Checkbox
                cb = tk.Checkbutton(
                    row,
                    text=f" {tname}",
                    variable=var,
                    command=self._update_counter,
                    font=("Consolas", 10, "bold"),
                    fg="#f8fafc",
                    bg="#0f172a",
                    activebackground="#0f172a",
                    activeforeground=cat["color"],
                    selectcolor="#090d16",
                    cursor="hand2"
                )
                cb.pack(side="left")

                # Description label
                desc_lbl = tk.Label(
                    row,
                    text=f" //  {tdesc}",
                    font=("Segoe UI", 8.5),
                    fg="#64748b",
                    bg="#0f172a",
                    anchor="w"
                )
                desc_lbl.pack(side="left", padx=(6, 0))

                # Hover micro-interaction
                def _make_hover(r=row, c=cat["color"]):
                    def _enter(e):
                        r.config(highlightbackground=c, bg="#131c31")
                    def _leave(e):
                        r.config(highlightbackground="#1e293b", bg="#0f172a")
                    r.bind("<Enter>", _enter)
                    r.bind("<Leave>", _leave)
                _make_hover()

    def _build_footer(self):
        """Bottom Command Bar with Counter, Select Summary, and Save Button."""
        footer = tk.Frame(self.root, bg="#0d1424", padx=20, pady=12, highlightbackground="#1e293b", highlightthickness=1)
        footer.pack(fill="x", side="bottom")

        self.lbl_counter = tk.Label(
            footer,
            text="",
            font=("Segoe UI", 10, "bold"),
            fg="#38bdf8",
            bg="#0d1424"
        )
        self.lbl_counter.pack(side="left")

        btn_cancel = tk.Button(
            footer,
            text="Cancel",
            command=self.root.destroy,
            bg="#1e293b",
            fg="#94a3b8",
            activebackground="#334155",
            activeforeground="#fff",
            font=("Segoe UI", 9),
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2"
        )
        btn_cancel.pack(side="right", padx=(8, 0))

        btn_save = tk.Button(
            footer,
            text="✔ Arm & Apply Weaponry",
            command=self._on_save,
            bg="#0284c7",
            fg="#ffffff",
            activebackground="#0369a1",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=18,
            pady=6,
            cursor="hand2"
        )
        btn_save.pack(side="right")

    def _update_counter(self):
        active = sum(1 for v in self.check_vars.values() if v.get())
        total = len(self.all_tool_names)
        pct = int((active / total) * 100) if total else 0
        self.lbl_counter.config(text=f"Armed Tools: {active} / {total}  ({pct}% Coverage)")

    def _set_all(self, state: bool):
        for var in self.check_vars.values():
            var.set(state)
        self._update_counter()

    def _apply_preset(self, preset_name: str):
        self._set_all(False)
        targets = []
        if preset_name == "bounty":
            targets = [
                "harvest_js_secrets_and_endpoints", "fuzz_sensitive_paths_and_backups",
                "resolve_waf_and_origin_ip", "audit_cors_misconfiguration", "audit_broken_link_hijacking",
                "search_live_exploits", "mine_hidden_parameters", "generate_hackerone_report",
                "execute_python_code"
            ]
        elif preset_name == "pentest":
            targets = [
                "crawl_attack_surface", "run_full_pentest_audit", "fuzz_web_endpoints",
                "verify_target_vulnerability", "audit_login_security", "detect_waf_fingerprint",
                "audit_account_enumeration", "extract_sensitive_leaks", "audit_form_csrf_security",
                "audit_php_threats"
            ]
        elif preset_name == "recon":
            targets = [
                "mine_historical_endpoints", "scan_repository_secrets", "audit_cloud_storage_exposure",
                "detect_subdomain_takeover", "enumerate_subdomains", "lookup_whois_and_ip",
                "parse_network_audit_scan", "probe_service_ports", "generate_attack_surface_graph"
            ]
        elif preset_name == "defense":
            targets = [
                "audit_website_security", "generate_pdf_report", "generate_hardening_config",
                "get_security_remediation", "lookup_cve_advisory", "map_mitre_attack",
                "remediate_and_verify_vulnerability"
            ]
        elif preset_name == "code":
            targets = [
                "run_command", "read_file", "write_file", "edit_file",
                "list_directory", "search_code", "create_folder", "scan_codebase_sast"
            ]

        for t in targets:
            if t in self.check_vars:
                self.check_vars[t].set(True)
        self._update_counter()

    def _on_search(self, *args):
        """Filters tool cards in real time as the user types."""
        query = self.search_var.get().strip().lower()
        for tname, (row, desc, cat_name) in self.tool_widgets.items():
            if not query:
                row.pack(fill="x", pady=2)
            elif query in tname.lower() or query in desc.lower() or query in cat_name.lower():
                row.pack(fill="x", pady=2)
            else:
                row.pack_forget()

    def _on_save(self):
        selected = [t for t, v in self.check_vars.items() if v.get()]
        if not selected:
            selected = ["run_command", "read_file", "write_file"]
        self.result["saved"] = True
        self.result["tools"] = selected
        self.root.destroy()


def launch_mouse_tool_selector(
    currently_enabled: Optional[List[str]] = None,
    all_tools: Optional[List[str]] = None
) -> Optional[List[str]]:
    """
    Launches the premium native desktop Tkinter interface.
    Returns list of armed tools or None if cancelled.
    """
    root = tk.Tk()
    app = PremiumCyberToolSelector(root, initial_enabled=currently_enabled)
    root.mainloop()

    if app.result["saved"]:
        return app.result["tools"]
    return None


if __name__ == "__main__":
    sel = launch_mouse_tool_selector()
    print("Selected tools:", sel)
