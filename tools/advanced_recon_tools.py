"""
CyberAgent Advanced Reconnaissance & Attack Surface Intelligence Toolset
========================================================================
Implements cutting-edge OSINT, attack surface, secret auditing, and network parsing tools:
1. mine_historical_endpoints: Wayback Machine CDX API mining for forgotten APIs, .env, and endpoints
2. scan_repository_secrets: High-speed codebase secret & API token hunter (regex + Shannon entropy)
3. audit_cloud_storage_exposure: S3, GCP, and Azure public bucket exposure auditor
4. parse_network_audit_scan: Deep Nmap XML & service banner intelligence parser
5. detect_subdomain_takeover: Dangling DNS CNAME & orphaned cloud service takeover analyzer
"""

import os
import re
import math
import socket
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Set
import requests


class AdvancedReconToolsMixin:
    """Mixin implementing advanced OSINT, secret auditing, and attack surface discovery tools."""

    # -------------------------------------------------------------------------
    # 1. Historical URL & Forgotten Endpoint Miner (Wayback Machine CDX API)
    # -------------------------------------------------------------------------
    def mine_historical_endpoints(self, domain: Optional[str] = None, target: Optional[str] = None, target_url: Optional[str] = None, limit: Any = 50) -> Dict[str, Any]:
        """
        Mines the Wayback Machine (web.archive.org) CDX API for historical URLs,
        past API versions, sensitive file paths, and hidden parameters for the target domain.
        Robustly validates parameters with fallback defaults so schema validation never aborts the pipeline.
        """
        raw_target = domain or target or target_url or ""
        if not isinstance(raw_target, str):
            raw_target = str(raw_target)

        clean_domain = raw_target.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        if not clean_domain:
            return {"success": False, "error": "Invalid or empty domain supplied. Please specify a valid domain (e.g. 'example.com')."}

        try:
            limit_val = int(limit)
            if limit_val <= 0 or limit_val > 500:
                limit_val = 50
        except (ValueError, TypeError):
            limit_val = 50

        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx?"
            f"url=*.{clean_domain}/*&output=json&collapse=urlkey&fl=original,mimetype,statuscode&limit={limit_val}"
        )

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberAgent/3.5 HistoricalMiner"
        }

        try:
            resp = requests.get(cdx_url, headers=headers, timeout=12)
            if resp.status_code != 200:
                return {
                    "success": False,
                    "domain": clean_domain,
                    "error": f"Wayback CDX API returned HTTP {resp.status_code}"
                }

            data = resp.json()
            if not data or len(data) <= 1:
                return {
                    "success": True,
                    "domain": clean_domain,
                    "total_urls_found": 0,
                    "message": "No historical URLs found in web archive for this domain."
                }

            rows = data[1:]  # First row is column headers
            discovered_urls: Set[str] = set()
            sensitive_files: Set[str] = set()
            api_endpoints: Set[str] = set()
            admin_portals: Set[str] = set()
            parameters: Set[str] = set()

            sensitive_extensions = (
                ".env", ".sql", ".bak", ".backup", ".zip", ".tar", ".tar.gz", ".7z",
                ".json", ".xml", ".conf", ".config", ".yaml", ".yml", ".log", ".key"
            )

            for row in rows:
                if not row:
                    continue
                url = row[0]
                discovered_urls.add(url)
                url_lower = url.lower()

                # Extract parameters
                parsed = urllib.parse.urlparse(url)
                if parsed.query:
                    for param in urllib.parse.parse_qs(parsed.query).keys():
                        parameters.add(param)

                # Check sensitive files
                path = parsed.path.lower()
                if any(path.endswith(ext) for ext in sensitive_extensions) or any(
                    s in path for s in ["/.git", "/.env", "/backup", "/dump", "/config.php", "/wp-config"]
                ):
                    sensitive_files.add(url)

                # Check APIs
                if any(api in path for api in ["/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/swagger", "/openapi"]):
                    api_endpoints.add(url)

                # Check admin / authentication
                if any(adm in path for adm in ["/admin", "/login", "/dashboard", "/cpanel", "/portal", "/signin"]):
                    admin_portals.add(url)

            return {
                "success": True,
                "domain": clean_domain,
                "total_urls_found": len(discovered_urls),
                "summary": {
                    "sensitive_file_candidates": len(sensitive_files),
                    "api_endpoints": len(api_endpoints),
                    "admin_portals": len(admin_portals),
                    "parameters_discovered": len(parameters)
                },
                "findings": {
                    "sensitive_files": list(sensitive_files)[:25],
                    "api_endpoints": list(api_endpoints)[:35],
                    "admin_portals": list(admin_portals)[:20],
                    "query_parameters": sorted(list(parameters))[:40],
                    "sample_urls": list(discovered_urls)[:30]
                }
            }
        except requests.Timeout:
            return {"success": False, "domain": clean_domain, "error": "Request to Wayback CDX API timed out."}
        except Exception as e:
            return {"success": False, "domain": clean_domain, "error": str(e)}

    # -------------------------------------------------------------------------
    # 2. High-Speed Git & Codebase Secret Hunter (Regex + Shannon Entropy)
    # -------------------------------------------------------------------------
    def scan_repository_secrets(self, dir_path: str = ".", max_files: int = 250) -> Dict[str, Any]:
        """
        Recursively scans local source code, environment configs, and repos for exposed API keys,
        tokens, database connection strings, and private keys using regex rules and Shannon entropy.
        """
        target = self._resolve_path(dir_path)
        if not os.path.exists(target):
            return {"success": False, "error": f"Directory not found: {dir_path}"}

        patterns = [
            ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
            ("Google Cloud API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
            ("GitHub Personal Token", re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b")),
            ("OpenAI API Key", re.compile(r"\b(sk-[a-zA-Z0-9]{20,48}|sk-proj-[a-zA-Z0-9_\-]{40,120})\b")),
            ("Slack Bot / Webhook Token", re.compile(r"(xox[pboa]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}|https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+)")),
            ("Stripe Secret Key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,34}|rk_live_[0-9a-zA-Z]{24,34})\b")),
            ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
            ("Database Connection String", re.compile(r"(?:postgres|mysql|mongodb|mongodb\+srv|redis)://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.-]+:[0-9]+/[a-zA-Z0-9_.-]+")),
            ("Generic Secret Variable Assignment", re.compile(r"""(?i)(?:api_key|apikey|secret_key|app_secret|auth_token|access_token|password)\s*[:=]\s*['"]([a-zA-Z0-9\-_]{16,64})['"]"""))
        ]

        def shannon_entropy(data: str) -> float:
            if not data:
                return 0.0
            entropy = 0.0
            for x in set(data):
                p_x = float(data.count(x)) / len(data)
                entropy -= p_x * math.log2(p_x)
            return entropy

        def mask_secret(secret_str: str) -> str:
            if len(secret_str) <= 8:
                return "****"
            return secret_str[:4] + "*" * (len(secret_str) - 8) + secret_str[-4:]

        ignored_dirs = {
            ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
            "dist", "build", "site-packages", ".idea", ".vscode"
        }
        ignored_extensions = {
            ".png", ".jpg", ".jpeg", ".ico", ".svg", ".gif", ".pdf",
            ".exe", ".dll", ".so", ".bin", ".zip", ".tar", ".gz", ".pyc"
        }

        findings = []
        files_scanned = 0

        try:
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in ignored_extensions:
                        continue

                    f_path = os.path.join(root, fname)
                    files_scanned += 1
                    if files_scanned > max_files:
                        break

                    try:
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as f:
                            for lno, line in enumerate(f, 1):
                                line_stripped = line.strip()
                                if not line_stripped or len(line_stripped) > 500:
                                    continue

                                for rule_name, regex in patterns:
                                    matches = regex.findall(line_stripped)
                                    for m in matches:
                                        match_val = m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
                                        ent = shannon_entropy(match_val)
                                        try:
                                            rel_path = os.path.relpath(f_path, self.workspace_root)
                                        except ValueError:
                                            rel_path = f_path
                                        findings.append({
                                            "rule": rule_name,
                                            "file": rel_path,
                                            "line": lno,
                                            "masked_value": mask_secret(match_val),
                                            "entropy": round(ent, 2),
                                            "severity": "CRITICAL" if "Private Key" in rule_name or "AWS" in rule_name or "GitHub" in rule_name else "HIGH"
                                        })
                                        if len(findings) >= 50:
                                            break
                    except Exception:
                        continue
                if files_scanned > max_files or len(findings) >= 50:
                    break

            return {
                "success": True,
                "target_directory": target,
                "files_scanned": files_scanned,
                "secrets_detected": len(findings),
                "findings": findings
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # -------------------------------------------------------------------------
    # 3. Cloud Storage & Public Bucket Exposure Auditor
    # -------------------------------------------------------------------------
    def audit_cloud_storage_exposure(self, target_name: str, custom_permutations: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Probes AWS S3, Google Cloud Storage, and Azure Blob storage endpoints
        for public exposure, listing permissions, and unauthenticated access based on company/domain name.
        """
        # Strip protocol, paths, and generic prefixes like 'www.' to avoid false bucket naming
        clean_name = target_name.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        if clean_name.startswith("www."):
            clean_name = clean_name[4:]
        # Get brand/company identifier (e.g. 'mercadolibre' from 'mercadolibre.com')
        clean_name = clean_name.split(".")[0].strip()
        if not clean_name or clean_name in ("com", "org", "net", "io", "gov", "co"):
            return {"success": False, "error": "Invalid target name supplied."}

        suffixes = custom_permutations or [
            "", "-backup", "-backups", "-assets", "-static", "-public",
            "-dev", "-data", "-staging", "-media", "-logs"
        ]

        tested_buckets = []
        exposed_buckets = []
        protected_buckets = []

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberAgent/3.5 CloudAuditor"}

        for suffix in suffixes:
            b_name = f"{clean_name}{suffix}"
            # Test AWS S3
            s3_url = f"https://{b_name}.s3.amazonaws.com"
            try:
                resp = requests.get(s3_url, headers=headers, timeout=4)
                status = resp.status_code
                if status == 200 and "ListBucketResult" in resp.text:
                    entry = {"provider": "AWS S3", "bucket": b_name, "url": s3_url, "status": "200_PUBLIC_LISTABLE", "risk": "CRITICAL"}
                    exposed_buckets.append(entry)
                    tested_buckets.append(entry)
                elif status == 200:
                    entry = {"provider": "AWS S3", "bucket": b_name, "url": s3_url, "status": "200_PUBLIC_ACCESSIBLE", "risk": "HIGH"}
                    exposed_buckets.append(entry)
                    tested_buckets.append(entry)
                elif status in (403, 401):
                    entry = {"provider": "AWS S3", "bucket": b_name, "url": s3_url, "status": "403_EXISTS_PRIVATE", "risk": "INFO"}
                    protected_buckets.append(entry)
                    tested_buckets.append(entry)
            except Exception:
                pass

            # Test Google Cloud Storage
            gcp_url = f"https://storage.googleapis.com/{b_name}"
            try:
                resp = requests.get(gcp_url, headers=headers, timeout=4)
                status = resp.status_code
                if status == 200 and "ListBucketResult" in resp.text:
                    entry = {"provider": "Google Cloud Storage", "bucket": b_name, "url": gcp_url, "status": "200_PUBLIC_LISTABLE", "risk": "CRITICAL"}
                    exposed_buckets.append(entry)
                    tested_buckets.append(entry)
                elif status in (403, 401):
                    entry = {"provider": "Google Cloud Storage", "bucket": b_name, "url": gcp_url, "status": "403_EXISTS_PRIVATE", "risk": "INFO"}
                    protected_buckets.append(entry)
                    tested_buckets.append(entry)
            except Exception:
                pass

        return {
            "success": True,
            "target": clean_name,
            "total_candidates_tested": len(suffixes) * 2,
            "total_existing_buckets": len(tested_buckets),
            "exposed_public_buckets_count": len(exposed_buckets),
            "exposed_buckets": exposed_buckets,
            "protected_private_buckets": protected_buckets
        }

    # -------------------------------------------------------------------------
    # 4. Deep Network Scan & Nmap Service Intelligence Parser
    # -------------------------------------------------------------------------
    def parse_network_audit_scan(self, file_path_or_xml: str) -> Dict[str, Any]:
        """
        Parses Nmap / Masscan XML scan files or raw XML strings into actionable
        threat intelligence: open ports, banner versions, plaintext protocols, and CVE vectors.
        """
        xml_content = ""
        resolved_path = self._resolve_path(file_path_or_xml)
        if os.path.exists(resolved_path) and os.path.isfile(resolved_path):
            try:
                with open(resolved_path, "r", encoding="utf-8", errors="ignore") as f:
                    xml_content = f.read()
            except Exception as e:
                return {"success": False, "error": f"Failed to read XML file: {str(e)}"}
        else:
            xml_content = file_path_or_xml

        if not xml_content or "<nmaprun" not in xml_content:
            return {"success": False, "error": "Invalid input: Must be valid Nmap XML output or file path."}

        try:
            root = ET.fromstring(xml_content)
        except Exception as e:
            return {"success": False, "error": f"XML parsing failed: {str(e)}"}

        critical_ports = {
            21: ("FTP", "Plaintext authentication & potential anonymous login"),
            23: ("Telnet", "Unencrypted plaintext administration protocol"),
            445: ("SMB", "File sharing - Potential EternalBlue / Null Session vectors"),
            1433: ("MSSQL", "Database port exposed to host network"),
            3306: ("MySQL", "Database port exposed to host network"),
            3389: ("RDP", "Remote Desktop Protocol exposed to brute-force"),
            5432: ("PostgreSQL", "Database port exposed to host network"),
            6379: ("Redis", "In-memory database often deployed without authentication"),
            9200: ("Elasticsearch", "Search cluster often vulnerable to unauthenticated data dumps"),
            27017: ("MongoDB", "NoSQL database often vulnerable to unauthenticated access")
        }

        hosts_parsed = []
        critical_findings = []

        for host in root.findall("host"):
            status_elem = host.find("status")
            if status_elem is not None and status_elem.get("state") != "up":
                continue

            # Get IP
            ip_elem = host.find("address[@addrtype='ipv4']")
            ip_addr = ip_elem.get("addr") if ip_elem is not None else "Unknown"

            # Hostnames
            hostnames = []
            for hn in host.findall("hostnames/hostname"):
                name = hn.get("name")
                if name:
                    hostnames.append(name)

            # Ports
            open_ports = []
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = int(port.get("portid", 0))
                proto = port.get("protocol", "tcp")
                service_elem = port.find("service")

                srv_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""
                banner = f"{product} {version}".strip() or srv_name

                # Scripts output
                scripts = {}
                for sc in port.findall("script"):
                    scripts[sc.get("id")] = sc.get("output", "")

                port_info = {
                    "port": port_id,
                    "protocol": proto,
                    "service": srv_name,
                    "banner": banner,
                    "scripts": scripts
                }
                open_ports.append(port_info)

                if port_id in critical_ports:
                    srv_title, desc = critical_ports[port_id]
                    critical_findings.append({
                        "ip": ip_addr,
                        "port": port_id,
                        "service": srv_title,
                        "severity": "HIGH",
                        "description": desc,
                        "banner": banner
                    })

            hosts_parsed.append({
                "ip": ip_addr,
                "hostnames": hostnames,
                "open_ports_count": len(open_ports),
                "open_ports": open_ports
            })

        return {
            "success": True,
            "hosts_discovered": len(hosts_parsed),
            "critical_risk_services_count": len(critical_findings),
            "critical_findings": critical_findings,
            "hosts": hosts_parsed
        }

    # -------------------------------------------------------------------------
    # 5. Passive Subdomain Takeover & Dangling DNS Detector
    # -------------------------------------------------------------------------
    def detect_subdomain_takeover(self, domain_or_subdomains: Any) -> Dict[str, Any]:
        """
        Analyzes subdomains for dangling CNAME records and orphaned third-party cloud services
        (AWS S3, GitHub Pages, Heroku, Fastly, Shopify, Zendesk) that allow hostile subdomain takeover.
        """
        subdomains: List[str] = []
        if isinstance(domain_or_subdomains, list):
            subdomains = [str(s).strip() for s in domain_or_subdomains if s]
        elif isinstance(domain_or_subdomains, str):
            clean = domain_or_subdomains.strip()
            # If a root domain is given, run a quick prefix scan or treat as list if comma-separated
            if "," in clean:
                subdomains = [s.strip() for s in clean.split(",") if s.strip()]
            else:
                base = clean.replace("https://", "").replace("http://", "").split("/")[0]
                prefixes = ["dev", "api", "staging", "blog", "docs", "test", "shop", "app", "help", "support", "status"]
                subdomains = [f"{p}.{base}" for p in prefixes]
                subdomains.append(base)
        else:
            return {"success": False, "error": "Invalid input: Expected string domain or list of subdomains."}

        # Known takeover CNAME fingerprints & response signatures
        takeover_signatures = [
            ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
            ("Heroku", "herokudns.com", "No such app"),
            ("Heroku", "herokuapp.com", "No such app"),
            ("AWS S3", "s3.amazonaws.com", "The specified bucket does not exist"),
            ("Cloudfront", "cloudfront.net", "Bad request"),
            ("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
            ("Zendesk", "zendesk.com", "Help Center Closed"),
            ("Ghost", "ghost.io", "The thing you were looking for is no longer here"),
            ("Surge.sh", "surge.sh", "project not found"),
            ("Bitbucket", "bitbucket.io", "Repository not found")
        ]

        tested = []
        vulnerabilities = []
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberAgent/3.5 SubdomainTakeover"}

        for sub in subdomains[:40]:
            sub_clean = sub.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()
            if not sub_clean:
                continue

            # Perform DNS lookup to find canonical name / CNAME
            cname = ""
            try:
                canonical, aliases, _ = socket.gethostbyname_ex(sub_clean)
                if aliases:
                    cname = aliases[0]
                elif canonical != sub_clean:
                    cname = canonical
            except Exception:
                continue

            cname_lower = cname.lower()
            matched_service = None
            signature_text = None

            for srv_name, cname_pattern, body_sig in takeover_signatures:
                if cname_pattern in cname_lower:
                    matched_service = srv_name
                    signature_text = body_sig
                    break

            is_vulnerable = False
            resp_body_snippet = ""

            if matched_service and signature_text:
                # Active verification probe on the endpoint
                try:
                    resp = requests.get(f"http://{sub_clean}", headers=headers, timeout=5)
                    if signature_text.lower() in resp.text.lower():
                        is_vulnerable = True
                        resp_body_snippet = resp.text[:200]
                except Exception:
                    pass

            result_entry = {
                "subdomain": sub_clean,
                "cname": cname or "Direct A Record",
                "service": matched_service,
                "vulnerable_to_takeover": is_vulnerable
            }
            tested.append(result_entry)

            if is_vulnerable:
                vulnerabilities.append({
                    "subdomain": sub_clean,
                    "cname": cname,
                    "orphaned_provider": matched_service,
                    "severity": "CRITICAL",
                    "impact": "Attacker can claim the third-party resource and execute full subdomain takeover",
                    "proof_of_concept": resp_body_snippet
                })

        return {
            "success": True,
            "subdomains_analyzed": len(tested),
            "takeover_vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "tested_subdomains": tested
        }

    # -------------------------------------------------------------------------
    # 6. Interactive Visual Attack Surface Graph Generator
    # -------------------------------------------------------------------------
    def generate_attack_surface_graph(self, output_html_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Exports the live Attack Surface Knowledge Graph into a standalone interactive HTML
        visualization powered by Vis.js Network with physics simulation and color-coded entity nodes.
        """
        try:
            from ..modules.graph import AttackSurfaceGraph
        except Exception:
            try:
                from modules.graph import AttackSurfaceGraph
            except Exception:
                from modules.graph import AttackSurfaceGraph

        graph = getattr(self, "attack_graph", None) or AttackSurfaceGraph(workspace_root=self.workspace_root)
        html_file = graph.export_interactive_html(output_html_path)
        summary = graph.get_summary()

        return {
            "success": True,
            "report_path": html_file,
            "total_entities": summary["total_nodes"],
            "total_relationships": summary["total_edges"],
            "critical_risks": summary["critical_risks"],
            "message": f"Interactive Attack Surface Visual Graph successfully generated at: {html_file}"
        }
