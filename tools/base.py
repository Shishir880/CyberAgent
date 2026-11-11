"""
CyberAgent Base Tool Configuration & Path Resolution
====================================================
Provides foundation for AgentTools:
- Workspace root resolution
- WebShield SecurityScanner dynamic loader
- CyberRange battleground path discovery
"""

import os
import sys
import re
from typing import Optional, Tuple


class BaseTools:
    """Base class establishing workspace root and core service paths."""
    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = os.path.abspath(workspace_root or os.getcwd())

        # Determine actual base/workspace root
        this_dir = os.path.dirname(os.path.abspath(__file__))
        pkg_root = os.path.abspath(os.path.join(this_dir, ".."))
        derived_root = os.path.abspath(os.path.join(this_dir, "..", "..", ".."))

        # Look for webshield_auditor across all possible locations
        candidates = [
            os.path.abspath(os.path.join(pkg_root, "..", "webshield_auditor")),
            os.path.abspath(os.path.join(self.workspace_root, "tools", "webshield_auditor")),
            os.path.abspath(os.path.join(derived_root, "tools", "webshield_auditor")),
            os.path.abspath(os.path.join(self.workspace_root, "webshield_auditor")),
            "d:/ML-DL/tools/webshield_auditor"
        ]

        self.webshield_dir = None
        for p in candidates:
            if os.path.exists(p):
                self.webshield_dir = p
                break

        self.rules_file = os.path.join(self.webshield_dir, "data", "rules.json") if self.webshield_dir else None
        self.scanner_available = False
        self.SecurityScanner = None

        if self.webshield_dir:
            if self.webshield_dir not in sys.path:
                sys.path.insert(0, self.webshield_dir)
            try:
                from core.scanner import SecurityScanner
                self.SecurityScanner = SecurityScanner
                self.scanner_available = True
            except Exception:
                self.SecurityScanner = None

        # Look for CyberRange directory
        range_candidates = [
            os.path.abspath(os.path.join(derived_root, "labs", "cyber_range")),
            os.path.abspath(os.path.join(self.workspace_root, "labs", "cyber_range")),
            "d:/ML-DL/labs/cyber_range"
        ]
        self.cyber_range_dir = None
        for r_path in range_candidates:
            if os.path.exists(r_path):
                self.cyber_range_dir = r_path
                break

    def _resolve_path(self, path: str) -> str:
        """Resolves relative paths against workspace root safely."""
        if os.path.isabs(path):
            return os.path.abspath(path)
        return os.path.abspath(os.path.join(self.workspace_root, path))

    @property
    def cyber_agent_dir(self) -> str:
        """Returns canonical absolute path of CyberAgent's own project directory."""
        this_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.realpath(os.path.abspath(os.path.join(this_dir, "..")))

    def is_protected_path(self, path: Optional[str]) -> bool:
        """
        Determines whether the given path targets or resides within CyberAgent's project folder.
        Protects CyberAgent's own code, scripts, configurations, and core modules from any modification.
        """
        if not path or not isinstance(path, str):
            return False
        try:
            target_resolved = os.path.realpath(self._resolve_path(path))
            protected = self.cyber_agent_dir
            norm_target = os.path.normcase(target_resolved)
            norm_protected = os.path.normcase(protected)

            if norm_target == norm_protected:
                return True
            if norm_target.startswith(norm_protected + os.sep):
                return True
            return False
        except Exception:
            return True  # Fail-safe (fail-closed)

    def check_command_safety(self, command: str, cwd: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validates terminal / PowerShell commands against destructive or mutating actions
        targeting the CyberAgent project folder.

        Returns:
            Tuple[bool, str]: (is_blocked, reason_if_blocked)
        """
        if not command or not isinstance(command, str):
            return False, ""

    @staticmethod
    def normalize_target_input(raw_target: str) -> dict:
        """
        Universal Target Sanitizer & URL Normalizer:
        Parses whatever the user or model supplies (e.g. 'https://www.bdjobs.com/default.asp?id=12',
        'mercadolibre.com:443/login', 'demo.testfire.net') into clean structured components:
        - domain: clean hostname (e.g. 'bdjobs.com' or 'sub.example.com')
        - root_domain: bare apex brand domain (e.g. 'bdjobs.com')
        - base_url: scheme + host (e.g. 'https://bdjobs.com')
        - path: clean URI path (e.g. '/default.asp')
        """
        if not raw_target or not isinstance(raw_target, str):
            return {"domain": "localhost", "root_domain": "localhost", "base_url": "http://localhost", "path": "/"}

        target_str = raw_target.strip()
        scheme = "https" if "https://" in target_str else "http"
        
        # Ensure scheme for urlparse
        if not target_str.startswith(("http://", "https://")):
            parsed_str = f"https://{target_str}"
        else:
            parsed_str = target_str

        try:
            from urllib.parse import urlparse
            p = urlparse(parsed_str)
            hostname = (p.hostname or "").lower().strip()
            path = p.path or "/"
            if not hostname:
                hostname = target_str.split("/")[0].split(":")[0].lower().strip()
        except Exception:
            hostname = target_str.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower().strip()
            path = "/"

        # Extract root domain (strip leading www.)
        root_domain = hostname
        if root_domain.startswith("www."):
            root_domain = root_domain[4:]

        base_url = f"{scheme}://{hostname}"

        return {
            "domain": hostname,
            "root_domain": root_domain,
            "base_url": base_url,
            "path": path,
            "original": target_str
        }


        work_dir = self._resolve_path(cwd) if cwd else self.workspace_root
        cmd_clean = command.strip()
        cmd_lower = cmd_clean.lower()
        protected_dir = self.cyber_agent_dir
        protected_norm = os.path.normcase(protected_dir)
        protected_name = os.path.basename(protected_dir).lower()

        # 1. If cwd is inside CyberAgent's project directory
        if self.is_protected_path(work_dir):
            dangerous_cwd_patterns = [
                r"\b(rm|del|erase|rd|rmdir|remove-item|ri|clear-content|clc)\b",
                r"\b(set-content|sc|add-content|ac|out-file|new-item|ni|copy-item|cp|copy|move-item|mv|move|mi|rename-item|ren|rename)\b",
                r"(>>|>)",
                r"\bgit\s+(checkout|reset|clean|restore|rm)\b",
                r"python.*-c.*(os\.|shutil\.|open\(|write|unlink)"
            ]
            for pat in dangerous_cwd_patterns:
                if re.search(pat, cmd_lower):
                    return True, f"Modifying or destructive command blocked while working inside CyberAgent project directory ({work_dir})."

        # 2. Check if the command references cyber_agent or its subpaths
        targets_cyber_agent = (
            protected_name in cmd_lower or
            "cyber_agent" in cmd_lower or
            "cyberagent" in cmd_lower or
            protected_norm in os.path.normcase(cmd_lower) or
            re.search(r"tools[/\\]cyber_agent", cmd_lower) is not None
        )

        if targets_cyber_agent:
            destructive_patterns = [
                r"\b(rm|del|erase|rd|rmdir|remove-item|ri|clear-content|clc)\b",
                r"\b(set-content|sc|add-content|ac|out-file|new-item|ni|copy-item|cp|copy|move-item|mv|move|mi|rename-item|ren|rename)\b",
                r"(>>|>)",
                r"\bgit\s+(checkout|reset|clean|restore|rm)\b",
                r"python.*-c.*(os\.|shutil\.|open\(|write|unlink)",
                r"\b(truncate|format)\b"
            ]
            for pat in destructive_patterns:
                if re.search(pat, cmd_lower):
                    return True, "Detected attempt to delete, remove, overwrite, or mutate files within CyberAgent's project folder."

        # 3. Check for blanket / wildcard recursive wipes from workspace root or parent
        blanket_wipe_patterns = [
            r"remove-item\s+.*-(recurse|force).*(\*|\.|\btools\b)",
            r"rm\s+-[rf]{1,3}\s+(\*|\.|\btools\b)",
            r"del\s+.*(/s|/q).*(\*|\btools\b)",
            r"rmdir\s+.*(/s|/q).*(\*|\.|\btools\b)"
        ]
        for pat in blanket_wipe_patterns:
            if re.search(pat, cmd_lower):
                return True, "Blanket recursive deletion blocked to safeguard CyberAgent project files."

        return False, ""

    @staticmethod
    def normalize_target_input(raw_target: str) -> dict:
        """
        Universal Target Sanitizer & URL Normalizer:
        Parses whatever the user or model supplies (e.g. 'https://www.bdjobs.com/default.asp?id=12',
        'mercadolibre.com:443/login', 'demo.testfire.net') into clean structured components:
        - domain: clean hostname (e.g. 'bdjobs.com' or 'sub.example.com')
        - root_domain: bare apex brand domain (e.g. 'bdjobs.com')
        - base_url: scheme + host (e.g. 'https://bdjobs.com')
        - path: clean URI path (e.g. '/default.asp')
        """
        if not raw_target or not isinstance(raw_target, str):
            return {"domain": "localhost", "root_domain": "localhost", "base_url": "http://localhost", "path": "/"}

        target_str = raw_target.strip()
        scheme = "https" if "https://" in target_str else "http"
        
        # Ensure scheme for urlparse
        if not target_str.startswith(("http://", "https://")):
            parsed_str = f"https://{target_str}"
        else:
            parsed_str = target_str

        try:
            from urllib.parse import urlparse
            p = urlparse(parsed_str)
            hostname = (p.hostname or "").lower().strip()
            path = p.path or "/"
            if not hostname:
                hostname = target_str.split("/")[0].split(":")[0].lower().strip()
        except Exception:
            hostname = target_str.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower().strip()
            path = "/"

        # Extract root domain (strip leading www.)
        root_domain = hostname
        if root_domain.startswith("www."):
            root_domain = root_domain[4:]

        base_url = f"{scheme}://{hostname}"

        return {
            "domain": hostname,
            "root_domain": root_domain,
            "base_url": base_url,
            "path": path,
            "original": target_str
        }


    @staticmethod
    def normalize_target_input(raw_target: str) -> dict:
        """
        Universal Target Sanitizer & URL Normalizer:
        Parses whatever the user or model supplies (e.g. 'https://www.bdjobs.com/default.asp?id=12',
        'mercadolibre.com:443/login', 'demo.testfire.net') into clean structured components:
        - domain: clean hostname (e.g. 'bdjobs.com' or 'sub.example.com')
        - root_domain: bare apex brand domain (e.g. 'bdjobs.com')
        - base_url: scheme + host (e.g. 'https://bdjobs.com')
        - path: clean URI path (e.g. '/default.asp')
        """
        if not raw_target or not isinstance(raw_target, str):
            return {"domain": "localhost", "root_domain": "localhost", "base_url": "http://localhost", "path": "/"}

        target_str = raw_target.strip()
        scheme = "https" if "https://" in target_str else "http"
        
        # Ensure scheme for urlparse
        if not target_str.startswith(("http://", "https://")):
            parsed_str = f"https://{target_str}"
        else:
            parsed_str = target_str

        try:
            from urllib.parse import urlparse
            p = urlparse(parsed_str)
            hostname = (p.hostname or "").lower().strip()
            path = p.path or "/"
            if not hostname:
                hostname = target_str.split("/")[0].split(":")[0].lower().strip()
        except Exception:
            hostname = target_str.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower().strip()
            path = "/"

        # Extract root domain (strip leading www.)
        root_domain = hostname
        if root_domain.startswith("www."):
            root_domain = root_domain[4:]

        base_url = f"{scheme}://{hostname}"

        return {
            "domain": hostname,
            "root_domain": root_domain,
            "base_url": base_url,
            "path": path,
            "original": target_str
        }

