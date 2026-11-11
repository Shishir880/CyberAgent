"""
CyberAgent Autonomous Browser Controller (Backward Compatibility Wrapper)
Real implementation resides in: cyber_agent.modules.browser.browser_controller
"""

try:
    from .modules.browser.browser_controller import (
        AutonomousBrowserController,
        get_browser_controller
    )
except ImportError:
    try:
        from modules.browser.browser_controller import (
            AutonomousBrowserController,
            get_browser_controller
        )
    except ImportError:
        from cyber_agent.modules.browser.browser_controller import (
            AutonomousBrowserController,
            get_browser_controller
        )

__all__ = ["AutonomousBrowserController", "get_browser_controller"]
