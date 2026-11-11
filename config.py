"""
CyberAgent Configuration (Backward Compatibility Wrapper)
Real implementation resides in: core.config
"""

try:
    from .core.config import AgentConfig, PROVIDER_PRESETS
except ImportError:
    try:
        from core.config import AgentConfig, PROVIDER_PRESETS
    except ImportError:
        from core.config import AgentConfig, PROVIDER_PRESETS

__all__ = ["AgentConfig", "PROVIDER_PRESETS"]
