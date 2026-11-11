"""
CyberAgent Autonomous Browser Module
====================================
Playwright Chromium Headless Automation & SPA JavaScript Renderer.
"""

from .browser_controller import (
    AutonomousBrowserController,
    get_browser_controller
)

__all__ = [
    "AutonomousBrowserController",
    "get_browser_controller"
]
