"""
CyberAgent Attack Surface Knowledge Graph Engine
=================================================
Maintains an in-memory & persistent Node-Edge Cyber Knowledge Graph representing
all discovered assets, hosts, ports, services, cloud storage buckets, secret leaks,
and confirmed vulnerabilities.

Generates rich, standalone, interactive HTML visualizations powered by Vis.js Network.
"""

import os
import json
import time
from typing import Dict, Any, List, Optional, Set


class AttackSurfaceGraph:
    """
    Maintains graph database of target attack surface and generates interactive visual DAGs.
    """

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = os.path.abspath(workspace_root or os.getcwd())
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._edge_set: Set[str] = set()
        self.last_updated = time.time()

    def add_node(self, node_id: str, label: str, group: str, properties: Optional[Dict[str, Any]] = None) -> None:
        """Adds or updates a node in the attack surface graph."""
        clean_id = str(node_id).strip()
        if not clean_id:
            return

        self.nodes[clean_id] = {
            "id": clean_id,
            "label": label,
            "group": group,
            "properties": properties or {},
            "timestamp": time.time()
        }
        self.last_updated = time.time()

    def add_edge(self, source_id: str, target_id: str, label: str = "") -> None:
        """Creates a directional edge between two nodes."""
        s = str(source_id).strip()
        t = str(target_id).strip()
        if not s or not t or s == t:
            return

        edge_key = f"{s}->{t}:{label}"
        if edge_key not in self._edge_set:
            self._edge_set.add(edge_key)
            self.edges.append({
                "from": s,
                "to": t,
                "label": label
            })
            self.last_updated = time.time()

    def ingest_tool_result(self, tool_name: str, args: Dict[str, Any], output: Dict[str, Any]) -> None:
        """
        Autonomously ingests tool execution findings and dynamically updates graph entities.
        """
        if not isinstance(output, dict) or not output.get("success", False):
            return

        # 1. WHOIS & IP Geolocation
        if tool_name == "lookup_whois_and_ip":
            domain = str(args.get("target") or output.get("domain", "")).strip().lower()
            if domain:
                d_id = f"domain:{domain}"
                self.add_node(d_id, domain, "domain", {
                    "registrar": output.get("registrar"),
                    "created": output.get("created_date"),
                    "expires": output.get("expires_date")
                })
                # Add IP if resolved
                for ip in output.get("ip_addresses", []):
                    ip_id = f"ip:{ip}"
                    self.add_node(ip_id, ip, "ip", {"isp": output.get("isp"), "country": output.get("country")})
                    self.add_edge(d_id, ip_id, "RESOLVES_TO")

        # 2. Subdomain Enumeration
        elif tool_name == "enumerate_subdomains":
            base_domain = str(args.get("domain", "")).strip().lower()
            d_id = f"domain:{base_domain}"
            self.add_node(d_id, base_domain, "domain")

            for sub in output.get("subdomains", []):
                sub_str = str(sub).strip().lower()
                if sub_str:
                    sub_id = f"subdomain:{sub_str}"
                    self.add_node(sub_id, sub_str, "subdomain")
                    self.add_edge(d_id, sub_id, "HAS_SUBDOMAIN")

            for resolved in output.get("resolved_hosts", []):
                host = resolved.get("host")
                ip = resolved.get("ip")
                if host and ip:
                    sub_id = f"subdomain:{host.lower()}"
                    ip_id = f"ip:{ip}"
                    self.add_node(ip_id, ip, "ip")
                    self.add_edge(sub_id, ip_id, "RESOLVES_TO")

        # 3. Port Scanning / Network Audit
        elif tool_name in ("probe_service_ports", "parse_network_audit_scan"):
            target_host = str(args.get("target_host") or args.get("file_path_or_xml") or "host").strip()
            parent_id = f"host:{target_host}"
            self.add_node(parent_id, target_host, "ip" if target_host.replace(".", "").isdigit() else "domain")

            # Ports from probe_service_ports
            for p in output.get("open_ports", []):
                if isinstance(p, dict):
                    port_num = p.get("port")
                    service = p.get("service", "unknown")
                    banner = p.get("banner", "")
                else:
                    port_num = p
                    service = "open"
                    banner = ""

                port_id = f"port:{target_host}:{port_num}"
                self.add_node(port_id, f"Port {port_num} ({service})", "service", {
                    "service": service,
                    "banner": banner
                })
                self.add_edge(parent_id, port_id, "EXPOSES_PORT")

            # High risk findings
            for crit in output.get("critical_findings", []):
                vuln_title = f"{crit.get('service')} Exposure ({crit.get('port')})"
                vuln_id = f"vuln:{target_host}:{crit.get('port')}"
                self.add_node(vuln_id, vuln_title, "vulnerability", {
                    "severity": crit.get("severity", "HIGH"),
                    "description": crit.get("description", "")
                })
                port_id = f"port:{target_host}:{crit.get('port')}"
                self.add_edge(port_id, vuln_id, "AFFECTED_BY")

        # 4. Secret & Token Leaks
        elif tool_name in ("scan_repository_secrets", "extract_sensitive_leaks"):
            for sec in output.get("findings", []) or output.get("secrets", []):
                rule = sec.get("rule") or sec.get("type", "Secret")
                f_path = sec.get("file") or sec.get("source", "Codebase")
                masked = sec.get("masked_value") or sec.get("sample", "****")
                sec_id = f"secret:{rule}:{f_path}:{sec.get('line', 0)}"

                self.add_node(sec_id, f"LEAK: {rule}", "secret", {
                    "rule": rule,
                    "file": f_path,
                    "line": sec.get("line"),
                    "masked": masked,
                    "severity": sec.get("severity", "HIGH")
                })
                # Link to file/repo
                file_id = f"file:{f_path}"
                self.add_node(file_id, os.path.basename(f_path), "file")
                self.add_edge(file_id, sec_id, "EXPOSES_SECRET")

        # 5. Cloud Storage Buckets
        elif tool_name == "audit_cloud_storage_exposure":
            target = output.get("target", "brand")
            parent_id = f"brand:{target}"
            self.add_node(parent_id, target, "domain")

            for eb in output.get("exposed_buckets", []):
                b_name = eb.get("bucket")
                b_id = f"bucket:{b_name}"
                self.add_node(b_id, f"EXPOSED S3: {b_name}", "vulnerability", {
                    "provider": eb.get("provider"),
                    "url": eb.get("url"),
                    "status": eb.get("status"),
                    "severity": "CRITICAL"
                })
                self.add_edge(parent_id, b_id, "EXPOSES_PUBLIC_STORAGE")

        # 6. Subdomain Takeover
        elif tool_name == "detect_subdomain_takeover":
            for vuln in output.get("vulnerabilities", []):
                sub = vuln.get("subdomain")
                prov = vuln.get("orphaned_provider")
                v_id = f"takeover:{sub}"
                self.add_node(v_id, f"TAKEOVER: {sub} ({prov})", "vulnerability", {
                    "cname": vuln.get("cname"),
                    "provider": prov,
                    "severity": "CRITICAL"
                })
                sub_id = f"subdomain:{sub}"
                self.add_node(sub_id, sub, "subdomain")
                self.add_edge(sub_id, v_id, "VULNERABLE_TO_TAKEOVER")

        # 7. Historical Endpoints
        elif tool_name == "mine_historical_endpoints":
            domain = output.get("domain", "target")
            d_id = f"domain:{domain}"
            self.add_node(d_id, domain, "domain")

            findings = output.get("findings", {})
            for sensitive_url in findings.get("sensitive_files", [])[:10]:
                u_id = f"endpoint:{sensitive_url}"
                self.add_node(u_id, f"Sensitive URL: {os.path.basename(sensitive_url)}", "endpoint", {
                    "url": sensitive_url,
                    "severity": "HIGH"
                })
                self.add_edge(d_id, u_id, "ARCHIVED_SENSITIVE_PATH")

    def get_summary(self) -> Dict[str, Any]:
        """Returns statistics and high-priority findings in the graph."""
        group_counts: Dict[str, int] = {}
        vuln_count = 0
        critical_count = 0

        for n in self.nodes.values():
            grp = n.get("group", "other")
            group_counts[grp] = group_counts.get(grp, 0) + 1
            if grp == "vulnerability":
                vuln_count += 1
                if n.get("properties", {}).get("severity") == "CRITICAL":
                    critical_count += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "entities_by_group": group_counts,
            "vulnerabilities_detected": vuln_count,
            "critical_risks": critical_count,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_updated))
        }

    def export_interactive_html(self, output_path: Optional[str] = None) -> str:
        """
        Generates an interactive, force-directed 3D/2D network visualization HTML using Vis.js.
        """
        if not output_path:
            out_dir = os.path.join(self.workspace_root, "reports")
            os.makedirs(out_dir, exist_ok=True)
            output_path = os.path.join(out_dir, "attack_surface_graph.html")

        # Format nodes for Vis.js
        color_map = {
            "domain": {"background": "#0ea5e9", "border": "#38bdf8", "highlight": "#7dd3fc"},       # Sky Blue
            "subdomain": {"background": "#6366f1", "border": "#818cf8", "highlight": "#a5b4fc"},    # Indigo
            "ip": {"background": "#8b5cf6", "border": "#a78bfa", "highlight": "#c4b5fd"},           # Purple
            "service": {"background": "#10b981", "border": "#34d399", "highlight": "#6ee7b7"},      # Emerald
            "file": {"background": "#64748b", "border": "#94a3b8", "highlight": "#cbd5e1"},         # Slate
            "endpoint": {"background": "#eab308", "border": "#fde047", "highlight": "#fef08a"},     # Yellow
            "secret": {"background": "#f97316", "border": "#fb923c", "highlight": "#fdba74"},       # Orange
            "vulnerability": {"background": "#ef4444", "border": "#f87171", "highlight": "#fca5a5"} # Red
        }

        vis_nodes = []
        for n in self.nodes.values():
            grp = n.get("group", "domain")
            c = color_map.get(grp, {"background": "#0ea5e9", "border": "#38bdf8", "highlight": "#7dd3fc"})
            shape = "box" if grp in ("vulnerability", "secret") else "ellipse"
            size = 28 if grp in ("domain", "vulnerability") else 20

            tooltip = f"<b>{n['label']}</b><br>Type: {grp}<br>"
            for k, v in n.get("properties", {}).items():
                tooltip += f"{k}: {v}<br>"

            vis_nodes.append({
                "id": n["id"],
                "label": n["label"][:35],
                "title": tooltip,
                "group": grp,
                "shape": shape,
                "color": c,
                "font": {"color": "#ffffff", "face": "Segoe UI, Arial"},
                "size": size
            })

        vis_edges = []
        for e in self.edges:
            vis_edges.append({
                "from": e["from"],
                "to": e["to"],
                "label": e.get("label", ""),
                "arrows": "to",
                "color": {"color": "#475569", "highlight": "#38bdf8"},
                "font": {"color": "#94a3b8", "size": 10, "align": "middle"}
            })

        summary = self.get_summary()

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CyberAgent - Live Attack Surface Knowledge Graph</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: #0b0f19;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }}
    header {{
      background: #111827;
      border-bottom: 1px solid #1f2937;
      padding: 14px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      z-index: 10;
    }}
    .logo {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .logo h1 {{
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.025em;
      color: #38bdf8;
    }}
    .badge {{
      background: rgba(56, 189, 248, 0.15);
      color: #38bdf8;
      border: 1px solid rgba(56, 189, 248, 0.3);
      padding: 3px 8px;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .metrics {{
      display: flex;
      gap: 18px;
      font-size: 0.85rem;
    }}
    .metric-item {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .metric-val {{
      font-weight: 700;
      color: #f1f5f9;
    }}
    .crit-val {{
      color: #ef4444;
      font-weight: 800;
    }}
    #network-container {{
      flex: 1;
      width: 100%;
      height: 100%;
      background: radial-gradient(circle at center, #131b2e 0%, #0b0f19 100%);
    }}
    .legend {{
      position: absolute;
      bottom: 24px;
      left: 24px;
      background: rgba(17, 24, 39, 0.85);
      backdrop-filter: blur(8px);
      border: 1px solid #374151;
      border-radius: 10px;
      padding: 14px 18px;
      z-index: 20;
      display: flex;
      flex-direction: column;
      gap: 8px;
      font-size: 0.8rem;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .dot {{
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }}
    .controls {{
      position: absolute;
      top: 75px;
      right: 24px;
      display: flex;
      gap: 10px;
      z-index: 20;
    }}
    .btn {{
      background: #1f2937;
      color: #f1f5f9;
      border: 1px solid #374151;
      padding: 8px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
      font-weight: 600;
      transition: background 0.15s;
    }}
    .btn:hover {{
      background: #374151;
      border-color: #4b5563;
    }}
  </style>
</head>
<body>
  <header>
    <div class="logo">
      <h1>🛡️ CyberAgent Attack Surface Intelligence</h1>
      <span class="badge">Live Knowledge Graph</span>
    </div>
    <div class="metrics">
      <div class="metric-item">Total Entities: <span class="metric-val">{summary['total_nodes']}</span></div>
      <div class="metric-item">Relationships: <span class="metric-val">{summary['total_edges']}</span></div>
      <div class="metric-item">Vulnerabilities: <span class="metric-val">{summary['vulnerabilities_detected']}</span></div>
      <div class="metric-item">Critical Exposures: <span class="metric-val crit-val">{summary['critical_risks']}</span></div>
    </div>
  </header>

  <div class="controls">
    <button class="btn" onclick="network.fit({{animation: true}})">Fit View (Auto-Zoom)</button>
    <button class="btn" onclick="togglePhysics()">Toggle Physics</button>
  </div>

  <div id="network-container"></div>

  <div class="legend">
    <div style="font-weight: 700; margin-bottom: 4px; color: #94a3b8;">GRAPH ENTITIES</div>
    <div class="legend-item"><span class="dot" style="background: #0ea5e9;"></span> Root Domains</div>
    <div class="legend-item"><span class="dot" style="background: #6366f1;"></span> Subdomains</div>
    <div class="legend-item"><span class="dot" style="background: #8b5cf6;"></span> IP Addresses</div>
    <div class="legend-item"><span class="dot" style="background: #10b981;"></span> Services & Ports</div>
    <div class="legend-item"><span class="dot" style="background: #f97316;"></span> Secret & Token Leaks</div>
    <div class="legend-item"><span class="dot" style="background: #ef4444;"></span> Critical Vulnerabilities</div>
  </div>

  <script type="text/javascript">
    const nodes = new vis.DataSet({json.dumps(vis_nodes)});
    const edges = new vis.DataSet({json.dumps(vis_edges)});

    const container = document.getElementById("network-container");
    const data = {{ nodes: nodes, edges: edges }};
    const options = {{
      nodes: {{
        borderWidth: 2,
        shadow: true
      }},
      edges: {{
        width: 1.5,
        smooth: {{
          type: "continuous"
        }}
      }},
      physics: {{
        barnesHut: {{
          gravitationalConstant: -3000,
          centralGravity: 0.3,
          springLength: 95,
          springConstant: 0.04,
          damping: 0.09
        }},
        maxVelocity: 50,
        minVelocity: 0.1
      }},
      interaction: {{
        hover: true,
        tooltipDelay: 100,
        navigationButtons: true,
        keyboard: true
      }}
    }};

    const network = new vis.Network(container, data, options);
    let physicsEnabled = true;

    function togglePhysics() {{
      physicsEnabled = !physicsEnabled;
      network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
    }}
  </script>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)

        return os.path.abspath(output_path)

