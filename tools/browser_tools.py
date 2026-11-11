"""
CyberAgent Autonomous Browser Toolset (Playwright Chromium)
==========================================================
Provides autonomous web automation capabilities:
- Modern Single Page Application (SPA) navigation & JavaScript execution
- Human-like interactions: clicking, typing, pressing keys, scrolling
- Full-page PNG screenshot capturing into screenshots/ directory
- Custom JavaScript evaluation within the live DOM context
- Background network activity and XHR/Fetch API inspection
"""

from typing import Dict, Any, Optional


class BrowserToolsMixin:
    """Mixin implementing autonomous Playwright Chromium browser execution."""

    def _get_browser_controller(self):
        try:
            try:
                from ..modules.browser import get_browser_controller
            except Exception:
                from cyber_agent.modules.browser import get_browser_controller
        except ImportError:
            from browser_controller import get_browser_controller
        return get_browser_controller(workspace_root=self.workspace_root)

    def browser_navigate(self, url: str, wait_until: str = "load") -> Dict[str, Any]:
        """
        Navigates to URL using autonomous Playwright Chromium browser.
        Renders full JavaScript (React, Vue, SPAs), extracts page title, status code,
        interactive buttons, links, inputs, and text preview.
        """
        try:
            bc = self._get_browser_controller()
            return bc.navigate(url=url, wait_until=wait_until)
        except Exception as e:
            return {"success": False, "error": f"Browser navigation failed: {str(e)}"}

    def browser_interact(self, action: str, selector: str, value: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs interactive actions on the active autonomous browser page:
        - action: 'click' (clicks element by CSS selector or XPath)
        - action: 'fill' (types text into input/textarea, requires 'value')
        - action: 'press' (presses keyboard key like 'Enter', 'Tab')
        - action: 'hover' (hovers mouse over element)
        - action: 'scroll' (scrolls down/up by pixels)
        """
        try:
            bc = self._get_browser_controller()
            return bc.interact(action=action, selector=selector, value=value)
        except Exception as e:
            return {"success": False, "error": f"Browser interaction failed: {str(e)}"}

    def browser_capture_screenshot(self, filename: Optional[str] = None, full_page: bool = True) -> Dict[str, Any]:
        """
        Captures a high-resolution PNG screenshot of the currently active browser page
        and saves it into screenshots/ folder.
        """
        try:
            bc = self._get_browser_controller()
            return bc.capture_screenshot(filename=filename, full_page=full_page)
        except Exception as e:
            return {"success": False, "error": f"Screenshot capture failed: {str(e)}"}

    def browser_execute_js(self, script: str) -> Dict[str, Any]:
        """
        Executes arbitrary JavaScript in the active browser page context to inspect
        cookies, localStorage, window variables, or dynamic DOM states.
        """
        try:
            bc = self._get_browser_controller()
            return bc.execute_js(script=script)
        except Exception as e:
            return {"success": False, "error": f"JS execution failed: {str(e)}"}

    def browser_get_network_activity(self) -> Dict[str, Any]:
        """
        Retrieves recent network requests, internal API endpoints, and XHR/Fetch calls
        made by the web application during browsing.
        """
        try:
            bc = self._get_browser_controller()
            return bc.get_network_activity()
        except Exception as e:
            return {"success": False, "error": f"Network inspection failed: {str(e)}"}
