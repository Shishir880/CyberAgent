"""
CyberAgent - Autonomous ReAct Agentic Execution Loop (Backward Compatibility Wrapper)
Real implementation resides in: core.agent
"""

try:
    from .core.agent import CyberAgent
except ImportError:
    try:
        from core.agent import CyberAgent
    except ImportError:
        from core.agent import CyberAgent

__all__ = ["CyberAgent"]
