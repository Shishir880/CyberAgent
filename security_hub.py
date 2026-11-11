"""
CyberAgent Security Hub (Backward Compatibility Wrapper)
Real implementation resides in: modules.security.security_hub
"""

try:
    from .modules.security.security_hub import *
except ImportError:
    try:
        from modules.security.security_hub import *
    except ImportError:
        from modules.security.security_hub import *
