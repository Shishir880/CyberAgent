"""
CyberAgent Modular Tool Execution Engine
========================================
Combines modular toolsets:
- BaseTools: Workspace root and WebShield scanner resolution
- SystemToolsMixin: Terminal execution, file management, code patching
- NetworkToolsMixin: Port scanning, WebShield audit, OWASP remediations
- HardeningToolsMixin: SAST code analysis, CVE lookups, PDF generation
- BrowserToolsMixin: Autonomous Playwright Chromium automation
- PentestToolsMixin: Web spider, endpoint fuzzing, vulnerability verification
- MemoryToolsMixin: Working session and cognitive memory operations
- AuthToolsMixin: Login rate-limiting/lockout audits, WAF fingerprinting, CSRF validation, leak extraction
- DateTimeToolsMixin: Comprehensive date/time arithmetic & expiration calculations
- WebSearchToolsMixin: Live internet search & structured web scraping
- ExtendedSecurityToolsMixin: Subdomain enumeration, JWT token auditing, security payload encoding, proxy diagnostics
"""

from typing import List, Dict, Any, Optional

from .base import BaseTools
from .system_tools import SystemToolsMixin
from .network_tools import NetworkToolsMixin
from .hardening_tools import HardeningToolsMixin
from .browser_tools import BrowserToolsMixin
from .pentest_tools import PentestToolsMixin
from .memory_tools import MemoryToolsMixin
from .auth_tools import AuthToolsMixin
from .datetime_tools import DateTimeToolsMixin
from .web_search_tools import WebSearchToolsMixin
from .extended_security_tools import ExtendedSecurityToolsMixin
from .advanced_recon_tools import AdvancedReconToolsMixin
from .bounty_tools import BountyHunterToolsMixin
from .definitions import get_tool_definitions


class AgentTools(
    BaseTools,
    SystemToolsMixin,
    NetworkToolsMixin,
    HardeningToolsMixin,
    BrowserToolsMixin,
    PentestToolsMixin,
    MemoryToolsMixin,
    AuthToolsMixin,
    DateTimeToolsMixin,
    WebSearchToolsMixin,
    ExtendedSecurityToolsMixin,
    AdvancedReconToolsMixin,
    BountyHunterToolsMixin
):
    """
    Unified Autonomous Tool Execution Engine for CyberAgent.
    Exposes 45 specialized cybersecurity, red-team penetration testing, blue-team hardening, and reconnaissance tools.
    """
    def __init__(self, workspace_root: Optional[str] = None):
        super().__init__(workspace_root=workspace_root)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns standard OpenAI/JSON Schema tool specifications for function calling."""
        return get_tool_definitions()


__all__ = [
    "AgentTools",
    "BaseTools",
    "SystemToolsMixin",
    "NetworkToolsMixin",
    "HardeningToolsMixin",
    "BrowserToolsMixin",
    "PentestToolsMixin",
    "MemoryToolsMixin",
    "AuthToolsMixin",
    "DateTimeToolsMixin",
    "WebSearchToolsMixin",
    "ExtendedSecurityToolsMixin",
    "AdvancedReconToolsMixin",
    "get_tool_definitions"
]
