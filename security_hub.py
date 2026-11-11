"""
CyberAgent Security Hub (Backward Compatibility Wrapper)
Real implementation resides in: cyber_agent.modules.security.security_hub
"""

try:
    from .modules.security.security_hub import *
except ImportError:
    try:
        from modules.security.security_hub import *
    except ImportError:
        from cyber_agent.modules.security.security_hub import *
