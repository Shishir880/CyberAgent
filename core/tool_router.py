"""
CyberAgent - Semantic ML Tool Router
====================================
Uses vector embeddings (via local Ollama 'nomic-embed-text') and cosine similarity
to dynamically filter and route only the most relevant tools for each user request.
Provides ultra-low latency, zero token waste, and 100% fault-tolerant fallback.
"""

import os
import re
import json
import numpy as np
import requests
from typing import List, Dict, Any, Set, Optional


class ToolSemanticRouter:
    def __init__(self, tool_definitions: List[Dict[str, Any]], storage_dir: Optional[str] = None):
        self.tool_definitions = tool_definitions
        self.tool_dict = {t.get("function", {}).get("name"): t for t in tool_definitions if "function" in t}
        self.tool_names = list(self.tool_dict.keys())

        if storage_dir is None:
            try:
                from .config import STORAGE_DIR
                storage_dir = STORAGE_DIR
            except Exception:
                this_dir = os.path.dirname(os.path.abspath(__file__))
                storage_dir = os.path.abspath(os.path.join(this_dir, "..", "storage"))
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        self.cache_file = os.path.join(self.storage_dir, "tool_embeddings.json")

        self.tool_vectors: Optional[np.ndarray] = None
        self._initialize_embeddings()

    def _get_embedding(self, text: str) -> Optional[List[float]]:
        """Queries local Ollama nomic-embed-text for a single vector embedding."""
        try:
            res = requests.post(
                "http://localhost:11434/api/embed",
                json={"model": "nomic-embed-text", "input": text},
                timeout=5
            )
            if res.status_code == 200:
                data = res.json()
                embs = data.get("embeddings", [])
                if embs:
                    return embs[0]
        except Exception:
            pass
        return None

    def _initialize_embeddings(self):
        """Loads cached tool embeddings or precomputes them in a single batch request."""
        # Try loading from cache
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                if isinstance(cached_data, dict):
                    # Check if at least most tools are cached
                    first_vec = next(iter(cached_data.values()), None) if cached_data else None
                    dim = len(first_vec) if first_vec else 768
                    vectors = [cached_data.get(name, [0.0] * dim) for name in self.tool_names]
                    self.tool_vectors = np.array(vectors, dtype=np.float32)
                    # If all present, done
                    if all(name in cached_data for name in self.tool_names):
                        return
            except Exception:
                pass

        # Compute embeddings for all tools in ONE single batch request (fast timeout probe)
        texts = []
        for name in self.tool_names:
            t = self.tool_dict[name].get("function", {})
            desc = t.get("description", "")
            texts.append(f"Tool: {name}. Description: {desc}")

        try:
            res = requests.post(
                "http://localhost:11434/api/embed",
                json={"model": "nomic-embed-text", "input": texts},
                timeout=2.0
            )
            if res.status_code == 200:
                embs = res.json().get("embeddings", [])
                if len(embs) == len(self.tool_names):
                    cached_data = {name: embs[i] for i, name in enumerate(self.tool_names)}
                    self.tool_vectors = np.array(embs, dtype=np.float32)
                    with open(self.cache_file, "w", encoding="utf-8") as f:
                        json.dump(cached_data, f)
        except Exception:
            pass

    def rank_tools_semantically(self, prompt: str, top_k: int = 5) -> List[str]:
        """Returns top_k tool names ranked by semantic cosine similarity."""
        if self.tool_vectors is None:
            return []

        prompt_emb = self._get_embedding(prompt)
        if not prompt_emb:
            return []

        p_vec = np.array(prompt_emb, dtype=np.float32)
        norm_tools = np.linalg.norm(self.tool_vectors, axis=1)
        norm_prompt = np.linalg.norm(p_vec)

        if norm_prompt == 0:
            return []

        # Cosine similarity
        similarities = np.dot(self.tool_vectors, p_vec) / (norm_tools * norm_prompt + 1e-9)
        top_indices = np.argsort(similarities)[::-1][:top_k]

        return [self.tool_names[i] for i in top_indices]

    def _heuristic_rule_match(self, prompt: str) -> Set[str]:
        """Fast keyword & regex matcher for critical security intents."""
        prompt_lower = prompt.lower()
        matched: Set[str] = set()

        # Domain / URL / IP detection
        if re.search(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b', prompt_lower) or re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', prompt_lower):
            matched.update(["lookup_whois_and_ip", "audit_website_security", "probe_service_ports", "enumerate_subdomains"])

        # Pentest / Exploit
        if any(w in prompt_lower for w in ["sqli", "sql", "injection", "xss", "csrf", "attack", "pentest", "exploit", "fuzz", "payload"]):
            matched.update(["crawl_attack_surface", "fuzz_web_endpoints", "verify_target_vulnerability", "run_full_pentest_audit", "generate_security_payload"])

        # Browser automation
        if any(w in prompt_lower for w in ["browser", "screenshot", "click", "navigate", "dom", "playwright", "gui", "webpage"]):
            matched.update(["browser_navigate", "browser_interact", "browser_capture_screenshot", "browser_execute_js", "browser_get_network_activity"])

        # File & code operations
        if any(w in prompt_lower for w in ["file", "folder", "read", "write", "edit", "code", "directory"]):
            matched.update(["read_file", "write_file", "edit_file", "create_folder", "list_directory", "search_code"])

        # SAST & CVE
        if any(w in prompt_lower for w in ["cve", "sast", "patch", "remediation", "harden", "pdf", "report"]):
            matched.update(["scan_codebase_sast", "lookup_cve_advisory", "get_security_remediation", "generate_hardening_config", "generate_pdf_report"])

        # Advanced Recon & Secret Hunting
        if any(w in prompt_lower for w in ["wayback", "archive", "history", "historical"]):
            matched.update(["mine_historical_endpoints"])

        if any(w in prompt_lower for w in ["secret", "secrets", "api key", "token leak", "private key", "gitleaks"]):
            matched.update(["scan_repository_secrets", "extract_sensitive_leaks"])

        if any(w in prompt_lower for w in ["s3", "bucket", "cloud storage", "blob", "aws", "gcp"]):
            matched.update(["audit_cloud_storage_exposure"])

        if any(w in prompt_lower for w in ["nmap", "masscan", "xml", "network scan", "banner"]):
            matched.update(["parse_network_audit_scan", "probe_service_ports"])

        if any(w in prompt_lower for w in ["takeover", "subdomain takeover", "dangling"]):
            matched.update(["detect_subdomain_takeover", "enumerate_subdomains"])

        # Bug Bounty & Deep Recon
        if any(w in prompt_lower for w in ["js", "javascript", "script", "bundle", "extract endpoints", "endpoint leak"]):
            matched.update(["harvest_js_secrets_and_endpoints", "crawl_attack_surface"])

        if any(w in prompt_lower for w in [".env", ".git", "actuator", "swagger", "backup", "sensitive path", "sensitive file"]):
            matched.update(["fuzz_sensitive_paths_and_backups", "fuzz_web_endpoints"])

        if any(w in prompt_lower for w in ["origin", "origin ip", "bypass waf", "real ip", "cloudflare ip"]):
            matched.update(["resolve_waf_and_origin_ip", "detect_waf_fingerprint"])

        if any(w in prompt_lower for w in ["cors", "origin reflection", "allow-origin", "cross-origin"]):
            matched.update(["audit_cors_misconfiguration", "audit_website_security"])

        if any(w in prompt_lower for w in ["broken link", "social takeover", "hijack", "twitter takeover", "github takeover"]):
            matched.update(["audit_broken_link_hijacking", "crawl_attack_surface"])

        if any(w in prompt_lower for w in ["python script", "write script", "custom script", "run script", "poc script", "code script"]):
            matched.update(["execute_python_code", "run_command"])

        if any(w in prompt_lower for w in ["live exploit", "exploit-db", "exploitdb", "github poc", "1-day", "poc"]):
            matched.update(["search_live_exploits", "lookup_cve_advisory"])

        if any(w in prompt_lower for w in ["param", "parameter", "hidden parameter", "debug param", "backdoor param"]):
            matched.update(["mine_hidden_parameters", "fuzz_web_endpoints"])

        if any(w in prompt_lower for w in ["hackerone", "bugcrowd", "bounty report", "submission report"]):
            matched.update(["generate_hackerone_report", "generate_pdf_report"])

        return matched

    def route_tools(self, prompt: str, top_k: int = 5, max_total: int = 10) -> List[Dict[str, Any]]:
        """
        Hybrid router: combines semantic embedding similarity + keyword triggers + baseline core tools.
        Returns final list of tool definitions ready for LLM consumption.
        """
        # Always available core tools
        selected: Set[str] = {"run_command", "read_file", "search_internet"}

        # 1. Rule & keyword triggers
        rule_tools = self._heuristic_rule_match(prompt)
        selected.update(rule_tools)

        # 2. Semantic vector ranking (ML)
        semantic_tools = self.rank_tools_semantically(prompt, top_k=top_k)
        selected.update(semantic_tools)

        # If still minimal, ensure at least versatile general set
        if len(selected) < 4:
            selected.update(["write_file", "audit_website_security", "lookup_whois_and_ip"])

        # Build list preserving max limit
        final_list = [self.tool_dict[name] for name in selected if name in self.tool_dict]
        return final_list[:max_total]
